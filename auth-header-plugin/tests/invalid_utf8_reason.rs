// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A caller's credential that is not valid UTF-8 presents nothing, and its diagnostic names that
//! reason, not 1.5.5's "(ASCII control character)": the bytes hold no control character. A real
//! control character keeps the 1.5.5 wording. Driven through the real loaded door, every style.

use std::mem::zeroed;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::auth::{
    slot, FieldSpan, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut, RequestFacts,
    MODE_PASSTHROUGH,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, out_head, Bind, Diagnostic, DispatchConfig, Dispatcher, Dropped,
    EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
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

fn blob(b: &'static [u8], fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

/// Every diagnostic the host was handed, as its text.
#[derive(Default)]
struct Texts(Mutex<Vec<String>>);

impl EnvelopeSink for Texts {
    fn metric(&self, _: Metric<'_>) {}
    fn diag(&self, d: Diagnostic<'_>) {
        if d.id != u32::MAX {
            self.0
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(d.text).into_owned());
        }
    }
    fn dropped(&self, _: Dropped) {}
}

fn plugin(texts: &Arc<Texts>, d: &Dispatcher) -> Plugin<Auth> {
    let bind = Bind {
        instance: Arc::from("utf8"),
        max_inflight_cap: 64,
        sink: texts.clone(),
        dispatcher: d.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    };
    let row = LinkedRow::of(busbar_auth_header::door).expect("the door states its Statement");
    let p = load_linked::<Auth>(&row, bind).expect("the linked door loads");
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    assert_eq!(p.call(life::OPEN, &mut o).outcome, Outcome::Ready);
    p
}

/// A keyless binding of `style` under `settings`.
fn open(p: &Plugin<Auth>, style: &'static str, settings: &'static str) -> u64 {
    let mut f: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.style = s(style);
    f.input.settings = blob(settings.as_bytes(), BLOB_JSON, 0);
    assert_eq!(p.call(slot::OPEN_OUTBOUND, &mut f).outcome, Outcome::Ready);
    f.out.handle
}

/// One passthrough `fields` call over the caller's `credential`; answers how many fields it wrote.
fn fields(p: &Plugin<Auth>, handle: u64, credential: &'static [u8]) -> u32 {
    let mut buf = vec![0u8; 256];
    let mut spans: Vec<FieldSpan> = vec![z(); 4];
    let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    f.input.mode = MODE_PASSTHROUGH;
    f.input.request = RequestFacts {
        method: s("POST"),
        authority: s("api.example"),
        canonical_path: s("/v1/messages"),
        query: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        timestamp: 1_440_938_160,
    };
    f.input.caller_credential = blob(credential, BLOB_OCTETS, BLOB_SECRET);
    (f.input.field_buf, f.input.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
    (f.input.fields, f.input.fields_cap) = (spans.as_mut_ptr(), spans.len() as u32);
    assert_eq!(p.call(slot::FIELDS, &mut f).outcome, Outcome::Ready);
    f.out.fields_len
}

const FAMILIES: &str = r#"{"protocol":"fam","families":[{"prefix":"sk-ant-oat"}],"passthrough":{"header":"x-api-key"}}"#;

/// Each style's binding, and the line its unpresentable caller credential raises for `reason`.
fn cases(p: &Plugin<Auth>, reason: &str) -> Vec<(u64, String)> {
    vec![
        (
            open(p, "bearer", r#"{"protocol":"twin"}"#),
            format!(
                "authorization credential contains invalid header bytes ({reason}); omitting \
                 auth header — upstream will reject with 401 protocol=twin"
            ),
        ),
        (
            open(p, "api-key", "{}"),
            format!(
                "egress credential contains invalid header bytes ({reason}); omitting auth \
                 header — upstream will reject with 401 header=api-key"
            ),
        ),
        (
            open(p, "query-key", "{}"),
            format!(
                "egress credential contains invalid bytes ({reason}); omitting the auth query \
                 parameter — upstream will reject with 401 param=key"
            ),
        ),
        (
            open(p, "api-key", FAMILIES),
            format!(
                "auth credential contains bytes invalid for an HTTP header value ({reason}); \
                 omitting the credential header — upstream will return 401, check the key \
                 configuration protocol=fam header=x-api-key"
            ),
        ),
    ]
}

#[test]
fn a_caller_credential_that_is_not_utf8_is_reported_as_such() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let texts = Arc::new(Texts::default());
    let p = plugin(&texts, &d);
    for (handle, want) in cases(&p, "not valid UTF-8") {
        assert_eq!(fields(&p, handle, b"caller\xfftok"), 0, "nothing presented");
        let got = std::mem::take(&mut *texts.0.lock().unwrap());
        assert_eq!(got, [want]);
        assert!(!got[0].contains("ASCII control"), "{got:?}");
    }
}

#[test]
fn a_caller_credential_with_a_control_character_keeps_the_1_5_5_reason() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let texts = Arc::new(Texts::default());
    let p = plugin(&texts, &d);
    let control = "(e.g. a trailing newline)";
    for (i, (handle, want)) in cases(&p, "ASCII control character").into_iter().enumerate() {
        assert_eq!(fields(&p, handle, b"caller\ntok"), 0, "nothing presented");
        let got = std::mem::take(&mut *texts.0.lock().unwrap());
        // The family line's 1.5.5 reason is its example, not "ASCII control character".
        let want = if i == 3 {
            want.replace("(ASCII control character)", control)
        } else {
            want
        };
        assert_eq!(got, [want]);
    }
}
