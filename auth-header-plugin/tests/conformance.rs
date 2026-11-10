// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Compares this plugin's linked and dropped-in doors through the loader.

use std::ffi::c_void;
use std::mem::zeroed;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::auth::{
    self, slot, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, OpenOutboundIn, OpenOutboundOut,
    OutboundReadyIn, OutboundReadyOut, RequestFacts, VerifyIn, FIELD_SENSITIVE, MODE_OWN,
    MODE_PASSTHROUGH,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Op, Outcome, RawOutcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, GenIn, OpenIn, OpenOut, RefreshIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Diagnostic, DispatchConfig,
    Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &'static str) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &'static str, fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

/// A caller's credential of raw `bytes` (not necessarily UTF-8).
fn octets(b: &'static [u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    }
}

fn json(b: &'static str) -> Blob {
    blob(b, BLOB_JSON, 0)
}

fn secret(b: &'static str) -> Blob {
    blob(b, BLOB_OCTETS, BLOB_SECRET)
}

/// THE ENVELOPE FOLD: every diagnostic the host was handed, as `(id, severity, text)`.
#[derive(Default)]
struct Folds(Mutex<Vec<String>>);

impl EnvelopeSink for Folds {
    fn metric(&self, m: Metric<'_>) {
        self.0.lock().unwrap().push(format!("metric {}", m.family));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.0.lock().unwrap().push(format!(
            "diag {} sev={} {}",
            d.id,
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

fn bind(folds: &Arc<Folds>, dispatcher: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("conformance"),
        max_inflight_cap: 64,
        sink: folds.clone(),
        dispatcher: dispatcher.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    }
}

/// The compiled-in row `door` states: its Statement rendering and the door.
fn row(door: DoorFn) -> LinkedRow {
    LinkedRow::of(door).expect("the door states its Statement")
}

fn linked(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    load_linked::<Auth>(&row(busbar_auth_header::door), bind(folds, d))
        .expect("the linked door loads")
}

/// This crate's own cdylib, beside the test executable's `deps/`. Under CI a missing artifact is a
/// failure, never a skip.
fn dropped(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    let path = cdylib();
    let stated = rendering_of(busbar_auth_header::door).expect("the door renders its Statement");
    load_dropped::<Auth>(&path, &stated, bind(folds, d)).expect("the dropped door loads")
}

fn err(e: &Option<Vec<u8>>) -> String {
    e.as_deref()
        .map(|e| String::from_utf8_lossy(e).replace('\n', " | "))
        .unwrap_or_default()
}

/// The host's buffers one `fields` call writes into.
struct Buffers {
    buf: Vec<u8>,
    spans: Vec<FieldSpan>,
}

impl Buffers {
    fn new(bytes: usize, fields: usize) -> Self {
        Self {
            buf: vec![0; bytes],
            spans: vec![z(); fields],
        }
    }

    /// What the answer wrote: `name: value` per field, and the flags.
    fn read(&self, n: u32) -> String {
        (0..n as usize)
            .map(|i| {
                let f = self.spans[i];
                let at = |sp: busbar_contract::abi::mechanism::call::Span| {
                    String::from_utf8_lossy(
                        &self.buf[sp.offset as usize..sp.offset as usize + sp.len as usize],
                    )
                    .into_owned()
                };
                format!("{}: {} [flags={}]", at(f.name), at(f.value), f.flags)
            })
            .collect::<Vec<_>>()
            .join(" ; ")
    }
}

fn facts() -> RequestFacts {
    RequestFacts {
        method: s("POST"),
        authority: s("runtime.signer.example"),
        canonical_path: s("/model/m/converse"),
        query: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        timestamp: 1_440_938_160,
    }
}

/// One `fields` call over `bytes`/`fields` of host capacity; a SHORT answer earns its ONE re-call
/// with the capacity it named.
fn fields(p: &Plugin<Auth>, handle: u64, mode: u32, caller: Blob, cap: (usize, usize)) -> String {
    let mut b = Buffers::new(cap.0, cap.1);
    let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    f.input.mode = mode;
    f.input.point = auth::POINT_HEAD;
    f.input.request = facts();
    f.input.caller_credential = caller;
    (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
    (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
    let c = one_header_crossing(p, || p.call(slot::FIELDS, &mut f));
    let mut line = format!("fields {:?} {}", c.outcome, err(&c.error));
    let mut outcome = c.outcome;
    if let Some(token) = c.recall {
        line.push_str(&format!(
            " short(needed_fields={} needed_bytes={})",
            f.out.needed_fields, f.out.needed_bytes
        ));
        b = Buffers::new(f.out.needed_bytes as usize, f.out.needed_fields as usize);
        (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
        (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
        f.out = z();
        f.out.head = out_head();
        let c = one_header_crossing(p, || p.recall(token, slot::FIELDS, &mut f));
        line.push_str(&format!(" -> recall {:?}", c.outcome));
        outcome = c.outcome;
    }

    if outcome == Outcome::Ready {
        line.push_str(&format!(" {}", b.read(f.out.fields_len)));
    }
    line
}

/// `open_outbound`, answering `(line, handle)`.
fn open_outbound(
    p: &Plugin<Auth>,
    style: &'static str,
    credential: Option<&'static str>,
    settings: &'static str,
) -> (String, u64) {
    let mut f: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.style = s(style);
    f.input.credential = credential.map_or(z(), secret);
    f.input.settings = json(settings);
    let c = one_header_crossing(p, || p.call(slot::OPEN_OUTBOUND, &mut f));
    (
        format!("open_outbound {style} {:?} {}", c.outcome, err(&c.error)),
        f.out.handle,
    )
}

fn ready(p: &Plugin<Auth>, handle: u64) -> String {
    let mut f: Frame<OutboundReadyIn, OutboundReadyOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    let c = one_header_crossing(p, || p.call(slot::OUTBOUND_READY, &mut f));
    format!("ready {:?} {}", c.outcome, f.out.ready)
}

/// THE SCRIPT: every auth op, each answer read back.
fn script(p: &Plugin<Auth>) -> Vec<String> {
    let mut t = Vec::new();

    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json("[1]"),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    let c = one_header_crossing(p, || p.call(life::VALIDATE, &mut v));
    t.push(format!("validate [1] {:?} {}", c.outcome, err(&c.error)));
    v.input.settings = json("{}");
    t.push(format!(
        "validate {:?}",
        one_header_crossing(p, || p.call(life::VALIDATE, &mut v)).outcome
    ));

    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    t.push(format!(
        "open {:?}",
        one_header_crossing(p, || p.call(life::OPEN, &mut o)).outcome
    ));

    let before = p.test_invocations().0;
    let resumes = p.test_invocations().1;
    p.ready(
        &Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ),
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(p.test_invocations().0 - before, u64::from(p.has_ready()));
    assert_eq!(p.test_invocations().1 - resumes, 0);

    let (l, bearer) = open_outbound(p, "bearer", Some("sk-test-123"), "{}");
    t.push(l);
    let (l, api_key) = open_outbound(p, "api-key", Some("azure-key"), "{}");
    t.push(l);
    let (l, goog) = open_outbound(p, "x-goog-api-key", Some("goog-key"), "{}");
    t.push(l);
    let (l, bad_bytes) = open_outbound(p, "bearer", Some("sk\r\ninjected"), "{}");
    t.push(l);
    let (l, keyless) = open_outbound(p, "x-goog-api-key", None, "{}");
    t.push(l);
    t.push(open_outbound(p, "sigv4", Some("k"), "{}").0);
    t.push(open_outbound(p, "kerberos", Some("k"), "{}").0);

    t.push(fields(p, bearer, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, bearer, MODE_OWN, z(), (8, 0)));
    t.push(fields(p, api_key, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, goog, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, bad_bytes, MODE_OWN, z(), (256, 4)));
    t.push(fields(
        p,
        keyless,
        MODE_PASSTHROUGH,
        secret("caller-tok"),
        (256, 4),
    ));
    t.push(fields(
        p,
        bearer,
        MODE_PASSTHROUGH,
        secret("caller-tok"),
        (256, 4),
    ));

    t.push(fields(
        p,
        bearer,
        MODE_PASSTHROUGH,
        secret("caller\ntok"),
        (256, 4),
    ));
    t.push(fields(
        p,
        bearer,
        MODE_PASSTHROUGH,
        octets(b"caller\xfftok"),
        (256, 4),
    ));
    t.push(fields(p, keyless, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, 999, MODE_OWN, z(), (256, 4)));

    let (l, query) = open_outbound(p, "query-key", Some("gem-key"), "{}");
    t.push(l);
    let (l, named) = open_outbound(p, "query-key", Some("gem-key"), r#"{"param":"api_key"}"#);
    t.push(l);
    t.push(fields(p, query, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, named, MODE_OWN, z(), (256, 4)));
    t.push(fields(
        p,
        query,
        MODE_PASSTHROUGH,
        secret("caller-tok"),
        (256, 4),
    ));

    for h in [bearer, api_key, goog, keyless] {
        t.push(ready(p, h));
    }

    let mut k = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 1_000,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    );
    let c = one_header_crossing(p, || p.call(life::TICK, &mut k));
    t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

    let mut vf: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
    vf.input.head = in_head();
    vf.out.head = out_head();
    t.push(format!(
        "verify {:?}",
        one_header_crossing(p, || p.call(slot::VERIFY, &mut vf)).outcome
    ));

    let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
    x.input.head = in_head();
    x.out.head = out_head();
    let c = one_header_crossing(p, || p.call(life::CANCEL, &mut x));
    t.push(format!("cancel {:?}", c.outcome));

    let mut r: Frame<RefreshIn, _> = Frame::new(z(), out_head());
    r.input.head = in_head();
    r.input.generation = 2;
    t.push(format!(
        "refresh {:?}",
        one_header_crossing(p, || p.call(life::REFRESH, &mut r)).outcome
    ));
    let (l, bearer2) = open_outbound(p, "bearer", Some("sk-test-123"), "{}");
    t.push(l);
    let mut g = Frame::new(
        GenIn {
            head: in_head(),
            generation: 1,
        },
        out_head(),
    );
    t.push(format!(
        "retire 1 {:?}",
        one_header_crossing(p, || p.call(life::RETIRE, &mut g)).outcome
    ));
    t.push(format!(
        "after retire {}",
        fields(p, bearer, MODE_OWN, z(), (256, 4))
    ));
    t.push(format!(
        "gen 2 {}",
        fields(p, bearer2, MODE_OWN, z(), (256, 4))
    ));

    let mut e = Frame::new(in_head(), out_head());
    t.push(format!(
        "close {:?}",
        one_header_crossing(p, || p.call(life::CLOSE, &mut e)).outcome
    ));
    t
}

/// The transcript every build must answer: the 1.5.5 header bytes flagged sensitive, the query
/// parameters flagged as query fields, a short answer's one re-call, and each refusal in its own
/// words.
const EXPECTED: &[&str] = &[
    "validate [1] Failed settings: must be a JSON object",
    "validate Ready",
    "open Ready",
    "open_outbound bearer Ready ",
    "open_outbound api-key Ready ",
    "open_outbound x-goog-api-key Ready ",
    "open_outbound bearer Ready ",
    "open_outbound x-goog-api-key Ready ",
    "open_outbound sigv4 Failed settings: outbound auth style `sigv4` is not served by this plugin",
    "open_outbound kerberos Failed settings: outbound auth style `kerberos` is not served by this \
     plugin",
    "fields Ready  authorization: Bearer sk-test-123 [flags=1]",
    "fields Failed  short(needed_fields=1 needed_bytes=31) -> recall Ready authorization: Bearer \
     sk-test-123 [flags=1]",
    "fields Ready  api-key: azure-key [flags=1]",
    "fields Ready  x-goog-api-key: goog-key [flags=1]",
    "fields Ready  ",
    "fields Ready  x-goog-api-key: caller-tok [flags=1]",
    "fields Ready  authorization: Bearer caller-tok [flags=1]",
    "fields Ready  ",
    "fields Ready  ",
    "fields Ready  ",
    "fields Refused the auth plugin refused the request's fields and gave no reason",
    "open_outbound query-key Ready ",
    "open_outbound query-key Ready ",
    "fields Ready  key: gem-key [flags=3]",
    "fields Ready  api_key: gem-key [flags=3]",
    "fields Ready  key: caller-tok [flags=3]",
    "ready Ready 1",
    "ready Ready 1",
    "ready Ready 1",
    "ready Ready 1",
    "tick Ready next=0",
    "verify Refused",
    "cancel Ready",
    "refresh Ready",
    "open_outbound bearer Ready ",
    "retire 1 Ready",
    "after retire fields Refused the auth plugin refused the request's fields and gave no reason",
    "gen 2 fields Ready  authorization: Bearer sk-test-123 [flags=1]",
    "close Ready",
];

/// The folds every build must hand the host: the INFO line of an own credential that opens
/// unpresentable, each refusal's INFO line (`module = "header"`, its reason, never a credential:
/// AUTH-STANDARD S5), and the bearer's WARN line on each request whose own or caller credential it
/// could not present, naming the bound protocol (none bound here: empty) and the reason (a control
/// character, or a caller credential that is not valid UTF-8).
const EXPECTED_FOLDS: &[&str] = &[
    "diag 4294967295 sev=0 busbar_auth_header::instance: header settings refused \
     module=\"header\" reason=\"not_object\"",
    "diag 4294967295 sev=0 busbar_auth_header::instance: header binding opened with a \
     credential it cannot present module=\"header\" style=\"bearer\" \
     reason=\"unpresentable_credential\" header=\"authorization\" protocol=\"\"",
    "diag 4294967295 sev=0 busbar_auth_header::instance: header binding refused \
     module=\"header\" style=\"sigv4\" reason=\"binding_refused\" refusal=settings: outbound \
     auth style `sigv4` is not served by this plugin",
    "diag 4294967295 sev=0 busbar_auth_header::instance: header binding refused \
     module=\"header\" style=\"kerberos\" reason=\"binding_refused\" refusal=settings: \
     outbound auth style `kerberos` is not served by this plugin",
    "diag 1 sev=1 authorization credential contains invalid header bytes (ASCII control \
     character); omitting auth header — upstream will reject with 401 protocol=",
    "diag 1 sev=1 authorization credential contains invalid header bytes (ASCII control \
     character); omitting auth header — upstream will reject with 401 protocol=",
    "diag 1 sev=1 authorization credential contains invalid header bytes (not valid UTF-8); \
     omitting auth header — upstream will reject with 401 protocol=",
    "diag 4294967295 sev=0 busbar_auth_header::instance: header fields refused \
     module=\"header\" handle=999 reason=\"unknown_handle\"",
    "diag 4294967295 sev=0 busbar_auth_header::instance: header fields refused \
     module=\"header\" handle=1 reason=\"unknown_handle\"",
];

fn run(p: &Plugin<Auth>, folds: &Folds) -> (Vec<String>, Vec<String>) {
    let t = script(p);
    (t, std::mem::take(&mut *folds.0.lock().unwrap()))
}

#[test]
fn compiled_in_and_dropped_in_answer_every_op_identically() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let (linked_t, linked_f) = run(&linked(&folds, &d), &folds);
    assert_eq!(linked_t, EXPECTED, "the linked door");
    assert_eq!(linked_f, EXPECTED_FOLDS, "the linked door's folds");
    let folds = Arc::new(Folds::default());
    {
        let p = dropped(&folds, &d);
        let (dropped_t, dropped_f) = run(&p, &folds);
        assert_eq!(dropped_t, linked_t, "the dropped door");
        assert_eq!(dropped_f, linked_f, "the dropped door's folds");
        println!(
            "PROOF auth-header: linked and dropped answered {} ops and {} folds identically",
            linked_t.len(),
            linked_f.len()
        );
    }
}

/// The door with `fields` replaced by `op`.
fn door_with_fields(op: Op) -> &'static Door {
    // SAFETY: the plugin's `'static` door and its auth table.
    let (d, ops) = unsafe {
        let d = busbar_auth_header::door();
        (d, *d.ops().cast::<auth::Ops>())
    };
    let mut ops = ops;
    ops.fields = Some(op);
    let ops: &'static auth::Ops = Box::leak(Box::new(ops));
    // SAFETY: the plugin's own door parts, with `ops` at a `'static` auth table whose every slot is
    // the plugin's or one of this file's call-convention ops.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            ops: std::ptr::from_ref(ops).cast(),
            ..d.parts()
        })
    }))
}

fn real_fields() -> Op {
    // SAFETY: the plugin's `'static` door and its auth table.
    unsafe {
        (*busbar_auth_header::door().ops().cast::<auth::Ops>())
            .fields
            .unwrap()
    }
}

/// The real `fields`, then every written field's `FIELD_SENSITIVE` cleared: the unflagged
/// credential headers 1.5.5 sent indexable.
unsafe extern "C" fn unflagged_fields(
    inst: *mut c_void,
    i: *const c_void,
    o: *mut c_void,
) -> RawOutcome {
    // SAFETY: this callback replaces only this plugin's FIELDS slot. The loader lends the same
    // live instance and aligned, initialized FieldsIn/FieldsOut that the real slot expects. The
    // synchronous forward preserves those frames and their backing buffers for the entire call,
    // and neither callback retains them.
    let r = unsafe { real_fields()(inst, i, o) };
    // SAFETY: the host's live `FieldsIn`/`FieldsOut` for this call.
    unsafe {
        let (i, o) = (&*i.cast::<FieldsIn>(), &*o.cast::<FieldsOut>());
        if r.outcome() == Outcome::Ready {
            for k in 0..o.fields_len as usize {
                (*i.fields.add(k)).flags &= !FIELD_SENSITIVE;
            }
        }
    }
    r
}

extern "C" fn unflagged_door() -> &'static Door {
    door_with_fields(unflagged_fields)
}

/// A credential header without `FIELD_SENSITIVE` (an h2 encoder may then index it into the shared
/// HPACK table) loads and passes the kind's checks, yet diverges from the pinned transcript, which
/// holds the 1.6.0 rule: every credential header is flagged sensitive.
#[test]
fn red_an_unflagged_credential_header_is_not_the_pinned_bytes() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let red = load_linked::<Auth>(&row(unflagged_door), bind(&folds, &d)).expect("the door loads");
    let t = script(&red);
    assert_ne!(t, EXPECTED, "an unflagged credential header must not pass");
    assert!(
        t.iter().any(|l| l.contains("[flags=0]")),
        "the kind's check admits no flag; only the pinned transcript refuses it"
    );
}

/// A `fields` that ignores the host's capacity and reports more fields than it was given room for.
extern "C" fn overrunning_fields(_: *mut c_void, i: *const c_void, o: *mut c_void) -> RawOutcome {
    // SAFETY: the host's live `FieldsOut` for this call; nothing is written past its `out`.
    unsafe {
        let (i, o) = (&*i.cast::<FieldsIn>(), &mut *o.cast::<FieldsOut>());
        o.fields_len = i.fields_cap + 1;
        o.head.outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn overrunning_door() -> &'static Door {
    door_with_fields(overrunning_fields)
}

#[test]
fn red_a_writer_that_ignores_the_host_capacity_faults() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let red =
        load_linked::<Auth>(&row(overrunning_door), bind(&folds, &d)).expect("the door loads");
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    assert_eq!(red.call(life::OPEN, &mut o).outcome, Outcome::Ready);
    let (_, h) = open_outbound(&red, "bearer", Some("sk"), "{}");
    assert!(fields(&red, h, MODE_OWN, z(), (256, 4)).starts_with("fields Fault"));
}

fn cdylib() -> std::path::PathBuf {
    let path = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(|named| {
            let named = std::path::PathBuf::from(named);
            assert!(
                named.is_absolute(),
                "BUSBAR_PLUGIN_CDYLIB must name an absolute fresh product image"
            );
            named
        })
        .unwrap_or_else(|| {
            std::env::current_exe()
                .expect("test executable")
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join(format!(
                    "{}busbar_auth_header_plugin{}",
                    std::env::consts::DLL_PREFIX,
                    std::env::consts::DLL_SUFFIX
                ))
        });
    assert!(
        path.is_file(),
        "build this product's fresh cdylib before conformance: {}",
        path.display()
    );
    path
}

#[test]
fn a_changed_statement_is_refused_linked_and_dropped() {
    use busbar_plugin_loader::dispatch::LoadError;
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let statement = rendering_of(another_version_door).unwrap();
    busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the alternative Statement is validly rendered");
    let row = LinkedRow {
        statement: statement.clone(),
        door: busbar_plugin_loader::dispatch::load::raw(busbar_auth_header::door),
    };
    assert_eq!(
        load_linked::<Auth>(&row, bind(&folds, &d)).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Auth>(&cdylib(), &statement, bind(&folds, &d)).err(),
        Some(LoadError::StatementMismatch)
    );
}

#[test]
fn the_door_refuses_every_other_kind_linked_and_dropped() {
    use busbar_plugin_loader::dispatch::kinds::{
        export::Export, hook::Hook, plane::Plane, secret::Secret, store_v4::StoreV4 as Store,
        transport::Transport,
    };
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let row = row(busbar_auth_header::door);
    let path = cdylib();
    assert_eq!(
        load_linked::<Export>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Export
        })
    );
    assert_eq!(
        load_dropped::<Export>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Export
        })
    );
    assert_eq!(
        load_linked::<Hook>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Hook
        })
    );
    assert_eq!(
        load_dropped::<Hook>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Hook
        })
    );
    assert_eq!(
        load_linked::<Plane>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Plane
        })
    );
    assert_eq!(
        load_dropped::<Plane>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Plane
        })
    );
    assert_eq!(
        load_linked::<Secret>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Secret
        })
    );
    assert_eq!(
        load_dropped::<Secret>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Secret
        })
    );
    assert_eq!(
        load_linked::<Store>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Store
        })
    );
    assert_eq!(
        load_dropped::<Store>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Store
        })
    );
    assert_eq!(
        load_linked::<Transport>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Transport
        })
    );
    assert_eq!(
        load_dropped::<Transport>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Transport
        })
    );
}

#[test]
fn conformance_honors_the_requested_release_profile() {
    assert!(!(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()));
}

extern "C" fn wrong_abi_door<const UP: bool>() -> &'static Door {
    let real = busbar_auth_header::door();
    let abi = if UP {
        real.kind_abi() + 1
    } else {
        real.kind_abi().wrapping_sub(1)
    };
    // SAFETY: preserve every pointer and its lifetime, changing only the refused ABI number.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            kind_abi: abi,
            ..real.parts()
        })
    }))
}

#[test]
fn another_kind_abi_is_refused() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    for door in [wrong_abi_door::<true> as DoorFn, wrong_abi_door::<false>] {
        let host = busbar_auth_header::door().kind_abi();
        let abi = door().kind_abi();
        let want = busbar_plugin_loader::dispatch::LoadError::KindAbi {
            kind: busbar_contract::abi::mechanism::KindCode::Auth,
            door: abi,
            host,
        };
        assert_eq!(rendering_of(door).err(), Some(want.clone()));
        let refused = LinkedRow::of(door)
            .and_then(|r| load_linked::<Auth>(&r, bind(&folds, &d)))
            .err()
            .unwrap();
        assert_eq!(refused, want);
        assert!(refused.to_string().contains("rebuild"));
        let mut statement = rendering_of(busbar_auth_header::door).unwrap();
        let at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        statement[at..at + 4].copy_from_slice(&door().kind_abi().to_le_bytes());
        assert_eq!(
            load_dropped::<Auth>(&cdylib(), &statement, bind(&folds, &d)).err(),
            Some(busbar_plugin_loader::dispatch::LoadError::ManifestKindAbi { stated: abi, host })
        );
    }
}

static READY_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
unsafe extern "C" fn failing_ready(
    _: *mut c_void,
    _: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    READY_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let failed = RawOutcome::of(Outcome::Failed);
    // SAFETY: READY receives the host's live OutHead.
    unsafe {
        let head = &mut *out.cast::<busbar_contract::abi::mechanism::call::OutHead>();
        head.outcome = failed;
        head.error = s("header readiness witness refused");
    }
    failed
}
extern "C" fn failing_ready_door() -> &'static Door {
    // SAFETY: retain this product's static data and substitute one call-convention callback.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            ready: Some(failing_ready),
            ..busbar_auth_header::door().parts()
        })
    }))
}
#[test]
fn a_failing_ready_is_refused_once() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let p = load_linked::<Auth>(&row(failing_ready_door), bind(&folds, &d)).unwrap();
    let mut open: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    open.input.head = in_head();
    open.out.head = out_head();
    open.input.generation = 1;
    assert_eq!(
        one_header_crossing(&p, || p.call(life::OPEN, &mut open)).outcome,
        Outcome::Ready
    );
    let before = p.test_invocations().0;
    let resumes = p.test_invocations().1;
    let refused = p.ready(&d, std::time::Duration::from_secs(5)).unwrap_err();
    assert_eq!(p.test_invocations().0 - before, 1);
    assert_eq!(p.test_invocations().1 - resumes, 0);
    assert!(
        refused
            == format!(
                "plugin '{}' ready failed: header readiness witness refused",
                p.name()
            ),
        "{refused}"
    );
    assert_eq!(READY_CALLS.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn declared_needs_match_the_real_statement() {
    let bytes = rendering_of(busbar_auth_header::door).unwrap();
    let statement = busbar_contract::abi::mechanism::rendering::read(&bytes).unwrap();
    assert!(statement.needs.is_empty());
    assert!(!include_str!("../../auth-header/declares.json").contains("\"needs\""));
}

extern "C" fn another_version_door() -> &'static Door {
    let real = busbar_auth_header::door();
    // SAFETY: real's Statement points at immutable static product data; copy it and change only version.
    let mut statement = unsafe { *real.statement() };
    statement.version = s("0.0.0-wrong-version");
    let statement = Box::leak(Box::new(statement));
    // SAFETY: the replacement Statement and all original door pointers remain static.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            statement: std::ptr::from_ref(statement),
            ..real.parts()
        })
    }))
}
#[test]
fn a_restated_version_does_not_match_the_honest_row() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let row = LinkedRow {
        statement: rendering_of(busbar_auth_header::door).unwrap(),
        door: busbar_plugin_loader::dispatch::load::raw(another_version_door),
    };
    assert_eq!(
        load_linked::<Auth>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::StatementMismatch)
    );
}

// Each header operation is synchronous: exactly one entry, with no resumed invocation.
fn one_header_crossing(
    p: &Plugin<Auth>,
    call: impl FnOnce() -> busbar_plugin_loader::dispatch::Called,
) -> busbar_plugin_loader::dispatch::Called {
    let before = p.test_invocations().0;
    let resumes = p.test_invocations().1;
    let result = call();
    assert_eq!(result.lease, 0, "header calls retain no output lease");
    if result.outcome == Outcome::Ready {
        assert!(
            result.error.is_none(),
            "successful header call has no error"
        );
    }
    assert_eq!(p.test_invocations().0 - before, 1);
    assert_eq!(p.test_invocations().1 - resumes, 0);
    result
}

#[test]
fn the_actual_header_instance_refuses_connections_without_a_table() {
    use busbar_contract::abi::host::conn::connector::{service, EstablishIn};
    use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
    use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
    use busbar_plugin_loader::dispatch::conn_services::CONN_SLOTS;
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let mut products = vec![linked(&folds, &d)];
    products.push(dropped(&folds, &d));
    for p in products {
        p.test_in_host_operation(|| {
            for need in [0, 1, u32::MAX] {
                let i = EstablishIn {
                    head: ServiceHead {
                        size: std::mem::size_of::<EstablishIn>() as u32,
                        op: service::ESTABLISH,
                        handle: CompletionHandle {
                            ticket: Ticket::NONE,
                            seq: 0,
                            _reserved: 0,
                        },
                    },
                    need,
                    timeout_ms: 5000,
                    target: s("127.0.0.1:8080"),
                    within: z(),
                    member: z(),
                };
                let mut o: ServiceOut = z();
                o.size = std::mem::size_of::<ServiceOut>() as u32;
                // SAFETY: the real instance context and stack-backed service frames live through this synchronous call.
                let result = unsafe {
                    CONN_SLOTS.establish.unwrap()(
                        p.test_host_context(),
                        std::ptr::from_ref(&i).cast(),
                        &mut o,
                    )
                };
                assert_eq!(result.outcome(), Outcome::Refused);
                // SAFETY: the host's error remains readable for this synchronous service answer.
                let text = unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) };
                assert_eq!(text, b"this plugin was handed no connection table");
            }
        });
    }
}

#[test]
fn each_declared_header_style_retains_the_original_outbound_cases() {
    use auth::{BeginLoginIn, BeginLoginOut, CompleteLoginIn};
    let cases = [
        (
            "bearer",
            "sk-test-123",
            "{}",
            "fields Ready  authorization: Bearer sk-test-123 [flags=1]",
        ),
        (
            "api-key",
            "azure-key",
            "{}",
            "fields Ready  api-key: azure-key [flags=1]",
        ),
        (
            "x-goog-api-key",
            "goog-key",
            "{}",
            "fields Ready  x-goog-api-key: goog-key [flags=1]",
        ),
        (
            "query-key",
            "gem-key",
            r#"{"param":"api_key"}"#,
            "fields Ready  api_key: gem-key [flags=3]",
        ),
    ];
    for is_dropped in [false, true] {
        for (style, credential, settings, expected) in cases {
            let d = Dispatcher::new(
                DispatchConfig::default(),
                busbar_contract::services::test_caller_binding(),
            );
            let folds = Arc::new(Folds::default());
            let p = if is_dropped {
                dropped(&folds, &d)
            } else {
                linked(&folds, &d)
            };
            let mut validate = Frame::new(
                ValidateIn {
                    head: in_head(),
                    settings: json(settings),
                    err_buf: std::ptr::null_mut(),
                    err_cap: 0,
                },
                out_head(),
            );
            assert_eq!(
                one_header_crossing(&p, || p.call(life::VALIDATE, &mut validate)).outcome,
                Outcome::Ready
            );
            let mut open: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
            open.input.head = in_head();
            open.out.head = out_head();
            open.input.settings = json(settings);
            open.input.generation = 1;
            assert_eq!(
                one_header_crossing(&p, || p.call(life::OPEN, &mut open)).outcome,
                Outcome::Ready
            );
            let before = p.test_invocations().0;
            let resumed = p.test_invocations().1;
            p.ready(&d, std::time::Duration::from_secs(5)).unwrap();
            assert_eq!(p.test_invocations().0 - before, u64::from(p.has_ready()));
            assert_eq!(p.test_invocations().1, resumed);
            let (line, handle) = open_outbound(&p, style, Some(credential), settings);
            assert_eq!(line, format!("open_outbound {style} Ready "));
            for _ in 0..2 {
                assert_eq!(fields(&p, handle, MODE_OWN, z(), (256, 4)), expected);
            }
            assert_eq!(ready(&p, handle), "ready Ready 1");
            let mut verify: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
            verify.input.head = in_head();
            verify.input.point = auth::POINT_HEAD;
            verify.out.head = out_head();
            assert_eq!(
                one_header_crossing(&p, || p.call(slot::VERIFY, &mut verify)).outcome,
                Outcome::Refused
            );
            let mut begin: Frame<BeginLoginIn, BeginLoginOut> = Frame::new(z(), z());
            begin.input.head = in_head();
            begin.out.head = out_head();
            assert_eq!(
                one_header_crossing(&p, || p.call(slot::BEGIN_LOGIN, &mut begin)).outcome,
                Outcome::Refused
            );
            let mut complete: Frame<CompleteLoginIn, IdentifyOut> = Frame::new(z(), z());
            complete.input.head = in_head();
            complete.out.head = out_head();
            assert_eq!(
                one_header_crossing(&p, || p.call(slot::COMPLETE_LOGIN, &mut complete)).outcome,
                Outcome::Refused
            );
            let mut close = Frame::new(in_head(), out_head());
            assert_eq!(
                one_header_crossing(&p, || p.call(life::CLOSE, &mut close)).outcome,
                Outcome::Ready
            );
            let mut closed: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
            closed.input.head = in_head();
            closed.out.head = out_head();
            closed.input.handle = handle;
            closed.input.point = auth::POINT_HEAD;
            closed.input.mode = MODE_OWN;
            closed.input.request = facts();
            let before = p.test_invocations().0;
            let resumed = p.test_invocations().1;
            assert_eq!(p.call(slot::FIELDS, &mut closed).outcome, Outcome::Fault);
            assert_eq!(p.test_invocations().0, before);
            assert_eq!(p.test_invocations().1, resumed);
        }
    }
}

extern "C" fn wrong_layout_door<const ZERO: bool>() -> &'static Door {
    let real = busbar_auth_header::door();
    let layout = if ZERO { 0 } else { real.parts().layout ^ 1 };
    // SAFETY: all original static pointers are retained; only layout is deliberately malformed.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            layout,
            ..real.parts()
        })
    }))
}
#[test]
fn both_wrong_layout_fingerprints_are_refused() {
    use busbar_plugin_loader::dispatch::LoadError;
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let host = busbar_auth_header::door().parts().layout;
    for door in [
        wrong_layout_door::<false> as DoorFn,
        wrong_layout_door::<true>,
    ] {
        let refused = rendering_of(door).unwrap_err();
        let LoadError::KindLayout {
            kind,
            stated,
            host: read,
            ..
        } = &refused
        else {
            panic!("{refused:?}")
        };
        assert_eq!(
            (*kind, *stated, *read),
            (
                busbar_contract::abi::mechanism::KindCode::Auth,
                door().parts().layout,
                host
            )
        );
        assert!(refused
            .to_string()
            .contains("rebuild against this busbar-contract"));
        let row = LinkedRow {
            statement: rendering_of(busbar_auth_header::door).unwrap(),
            door: busbar_plugin_loader::dispatch::load::raw(door),
        };
        assert_eq!(
            load_linked::<Auth>(&row, bind(&folds, &d)).err(),
            Some(refused.clone())
        );
        assert_eq!(
            LinkedRow::of(door)
                .and_then(|row| load_linked::<Auth>(&row, bind(&folds, &d)))
                .err(),
            Some(refused)
        );
    }
}

#[test]
fn linked_and_dropped_use_distinct_actual_door_and_ops_addresses() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let _linked = linked(&folds, &d);
    let _dropped = dropped(&folds, &d);
    let (door, ops) = busbar_plugin_loader::dispatch::load::door_addresses_of_library(&cdylib())
        .unwrap()
        .unwrap();
    assert_ne!(
        door,
        std::ptr::from_ref(busbar_auth_header::door()) as usize
    );
    assert_ne!(ops, busbar_auth_header::door().ops() as usize);
}

/// Fresh real images complete the successful lifecycle and refuse use after CLOSE.
#[test]
fn linked_and_dropped_complete_successful_open_ready_close_lifecycle() {
    for is_dropped in [false, true] {
        let d = Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        );
        let folds = Arc::new(Folds::default());
        let p = if is_dropped {
            dropped(&folds, &d)
        } else {
            linked(&folds, &d)
        };
        let mut open: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
        open.input.head = in_head();
        open.out.head = out_head();
        open.input.settings = json("{}");
        open.input.generation = 1;
        assert_eq!(
            one_header_crossing(&p, || p.call(life::OPEN, &mut open)).outcome,
            Outcome::Ready
        );
        p.ready(&d, std::time::Duration::from_secs(5))
            .expect("the real header image completes READY");
        let (line, handle) = open_outbound(&p, "bearer", Some("lifecycle-key"), "{}");
        assert_eq!(line, "open_outbound bearer Ready ");
        assert_eq!(ready(&p, handle), "ready Ready 1");
        assert_eq!(
            fields(&p, handle, MODE_OWN, z(), (256, 4)),
            "fields Ready  authorization: Bearer lifecycle-key [flags=1]"
        );

        let mut close = Frame::new(in_head(), out_head());
        assert_eq!(
            one_header_crossing(&p, || p.call(life::CLOSE, &mut close)).outcome,
            Outcome::Ready
        );
        // The closed instance cannot present the credential it owned before CLOSE.
        let mut closed: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
        closed.input.head = in_head();
        closed.out.head = out_head();
        closed.input.handle = handle;
        closed.input.point = auth::POINT_HEAD;
        closed.input.mode = MODE_OWN;
        closed.input.request = facts();
        let crossings = p.test_invocations().0;
        let resumes = p.test_invocations().1;
        assert_eq!(p.call(slot::FIELDS, &mut closed).outcome, Outcome::Fault);
        assert_eq!(p.test_invocations().0, crossings);
        assert_eq!(p.test_invocations().1, resumes);
    }
}

#[test]
fn outbound_statement_facts_cover_exactly_the_four_exercised_styles() {
    use busbar_contract::abi::mechanism::rendering::{read, read_auth_tail};
    let bytes = rendering_of(busbar_auth_header::door).unwrap();
    let statement = read(&bytes).unwrap();
    let tail = read_auth_tail(&statement.kind_tail).unwrap();
    assert_eq!(tail.caps, auth::CAP_OUTBOUND);
    assert_eq!(tail.facts, auth::FACT_DEFAULT_INBOUND_STYLE);
    let mut styles = tail
        .styles
        .iter()
        .map(|style| style.name.as_str())
        .collect::<Vec<_>>();
    styles.sort_unstable();
    assert_eq!(styles, ["api-key", "bearer", "query-key", "x-goog-api-key"]);
    for style in &tail.styles {
        assert_eq!(style.points, auth::POINT_HEAD);
        assert_eq!(style.flags & auth::STYLE_NEEDS_HEADERS, 0);
    }
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let linked = linked(&folds, &d);
    let dropped = dropped(&folds, &d);
    assert_eq!(
        (linked.kind(), linked.name(), linked.max_inflight()),
        (dropped.kind(), dropped.name(), dropped.max_inflight())
    );
    assert_eq!(
        linked.kind(),
        busbar_contract::abi::mechanism::KindCode::Auth
    );
}

/// A PASSTHROUGH CALL THE HOST LENT NO CALLER CREDENTIAL presents nothing and answers Ready, as
/// before, but says so in the plugin's log (an empty lent credential stays silent: nothing to report).
#[test]
fn a_passthrough_call_with_no_lent_caller_credential_is_logged() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let folds = Arc::new(Folds::default());
    let p = linked(&folds, &d);
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    assert_eq!(p.call(life::OPEN, &mut o).outcome, Outcome::Ready);
    let (_, bearer) = open_outbound(&p, "bearer", Some("sk-test-123"), "{}");
    folds.0.lock().unwrap().clear();
    assert_eq!(
        fields(&p, bearer, MODE_PASSTHROUGH, secret(""), (256, 4)),
        "fields Ready  "
    );
    assert!(
        folds.0.lock().unwrap().is_empty(),
        "an empty caller credential is not logged"
    );
    assert_eq!(
        fields(&p, bearer, MODE_PASSTHROUGH, z(), (256, 4)),
        "fields Ready  "
    );
    let logged = std::mem::take(&mut *folds.0.lock().unwrap());
    assert_eq!(logged.len(), 1, "{logged:?}");
    assert!(
        logged[0].contains("reason=\"no_caller_credential\""),
        "{logged:?}"
    );
    assert!(!logged[0].contains("sk-test-123"), "{logged:?}");
}
