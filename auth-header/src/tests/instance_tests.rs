// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HANDLE BOOKKEEPING over the plugin's own `OutboundPlugin` methods — no mint, no wire, no
//! waiting ticket. The `fields` call itself is driven through the door, both ways, by the twin's
//! `tests/conformance.rs` and `tests/fields_alloc.rs`.

use super::*;

fn open(h: &Header, style: &str, cred: Option<&str>, settings: &str) -> (u64, Diags) {
    let mut diags = Diags::default();
    let handle = h
        .open_outbound(
            style,
            cred.map(str::as_bytes),
            Some(settings.as_bytes()),
            None,
            &mut diags,
        )
        .expect("the binding opens");
    (handle, diags)
}

#[test]
fn a_handle_is_ready_until_its_generation_retires() {
    let h = Header::new(1);
    let (first, _) = open(&h, style::BEARER, Some("sk-1"), "{}");
    assert!(h.outbound_ready(first));
    h.refresh(b"{}", &[], 2).expect("the reload is taken");
    let (second, _) = open(&h, style::BEARER, Some("sk-1"), "{}");
    h.retire(1);
    assert!(!h.outbound_ready(first), "generation 1's handle is gone");
    assert!(h.outbound_ready(second), "generation 2's stays");
    assert!(!h.outbound_ready(999), "a handle never opened");
}

/// BAD PLUGIN SETTINGS ANSWER FAILED, ALIKE AT VALIDATE, OPEN AND REFRESH (AUTH-STANDARD S2), in
/// the contract's instance-relative lines: settings that are not an object, and every key no style
/// reads, by name. The keys a style reads are accepted (the instance is opened over a binding's
/// settings), and a refused refresh leaves the instance serving its old generation. RED before the
/// fix: REFUSED in the plugin's own words, and any key accepted.
#[test]
fn bad_settings_fail_alike_at_validate_open_and_refresh() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::lifecycle::check_validate_refusal;
    let cases: [(&[u8], &str); 4] = [
        (b"[1]", "settings: must be a JSON object"),
        (b"nope", "settings: must be a JSON object"),
        (br#"{"heder":"x"}"#, "settings.heder: unknown key"),
        (
            br#"{"a":1,"param":"key","b":2}"#,
            "settings.a: unknown key\nsettings.b: unknown key",
        ),
    ];
    for (bad, text) in cases {
        let h = Header::new(1);
        let (handle, _) = open(&h, style::BEARER, Some("sk-1"), "{}");
        for r in [
            Header::validate(bad).expect_err("validate refuses"),
            Header::open(bad, &[], 1).expect_err("open refuses"),
            h.refresh(bad, &[], 2).expect_err("refresh refuses"),
        ] {
            assert_eq!(r.outcome(), Outcome::Failed);
            assert_eq!(r.text(), Some(text));
            check_validate_refusal(text.as_bytes()).expect("the contract's line form");
        }
        h.retire(1);
        assert!(
            !h.outbound_ready(handle),
            "the refused refresh moved no generation"
        );
    }
    for good in [
        &b""[..],
        b"{}",
        br#"{"param":"key","header":"x-api-key","families":[],"own":{},"passthrough":{},"protocol":"p"}"#,
        br#"{"token_url":"https://t.example/","token_uri":"u","scope":"s","subject":"x"}"#,
    ] {
        assert!(Header::validate(good).is_ok());
        assert!(Header::open(good, &[], 1).is_ok());
        assert!(Header::new(1).refresh(good, &[], 2).is_ok());
    }
}

#[test]
fn a_refused_binding_answers_one_line_per_finding() {
    let h = Header::new(1);
    let mut diags = Diags::default();
    let refusal = h
        .open_outbound("sigv4", Some(b"k"), Some(b"{}"), None, &mut diags)
        .expect_err("not served");
    assert_eq!(
        refusal.lines(),
        ["settings: outbound auth style `sigv4` is not served by this plugin"]
    );
}

/// AN UNPRESENTABLE OWN CREDENTIAL IS NOTED ON EACH REQUEST, NOT AT OPEN: 1.5.5 built the header
/// per request and logged its builder's WARN line each time (v1.5.5
/// `crates/busbar/src/proxy/egress.rs:122-129`, `crates/busbar/src/egress_auth/mod.rs:215-229`).
/// The binding opens with no line and holds the note `fields` raises per call. RED before the fix:
/// the line was raised once, at open.
#[test]
fn an_unpresentable_own_credential_is_noted_on_each_request_not_at_open() {
    let h = Header::new(1);
    let (handle, diags) = open(
        &h,
        style::API_KEY,
        Some("bad\nkey"),
        r#"{"header":"api-key"}"#,
    );
    assert_eq!(diags.iter().count(), 0, "nothing at open");
    let note = h
        .with_binding(handle, |b| b.own_note().cloned())
        .flatten()
        .expect("the per-request note");
    let (id, severity, text) = note_line(&note);
    assert_eq!(id, diag::APIKEY_INVALID_BYTES);
    assert_eq!(severity, SEVERITY_WARN);
    assert!(text.ends_with("upstream will reject with 401 header=api-key"));
    let (fine, _) = open(&h, style::API_KEY, Some("good"), r#"{"header":"api-key"}"#);
    assert_eq!(h.with_binding(fine, |b| b.own_note().cloned()), Some(None));
}

#[test]
fn note_line_reports_each_note_in_its_own_line() {
    let lines: Vec<_> = [
        style::Note::Header("api-key".to_string()),
        style::Note::Bearer("twin".to_string()),
        style::Note::Family("twin".to_string(), "x-api-key".to_string()),
    ]
    .iter()
    .map(note_line)
    .collect();
    assert_eq!(lines[0].0, diag::APIKEY_INVALID_BYTES);
    assert_eq!(lines[1].0, diag::AUTH_INVALID_HEADER_BYTES);
    assert_eq!(lines[2].0, diag::CREDENTIAL_INVALID_BYTES);
    assert_eq!(
        (lines[0].1, lines[1].1, lines[2].1),
        (SEVERITY_WARN, SEVERITY_WARN, SEVERITY_WARN)
    );
    assert!(lines[0]
        .2
        .ends_with("upstream will reject with 401 header=api-key"));
    assert!(lines[1]
        .2
        .ends_with("upstream will reject with 401 protocol=twin"));
    assert!(lines[2]
        .2
        .ends_with("check the key configuration protocol=twin header=x-api-key"));
}

/// A caller's credential is presented by reference with the bytes the owned presentation builds,
/// a bearer longer than the stack stage included; one no header value may carry emits nothing.
#[test]
fn a_callers_credential_is_presented_by_reference_with_the_owned_bytes() {
    let h = Header::new(1);
    let (handle, _) = open(&h, style::BEARER, None, "{}");
    let long = "k".repeat(crate::present::STACK_VALUE * 2);
    for caller in ["caller-tok", long.as_str()] {
        let by_ref = h
            .with_binding(handle, |b| {
                let mut got = None;
                let presented = b.present_passthrough(caller, |n, v| {
                    got = Some((n.to_vec(), v.to_vec()));
                });
                assert!(presented);
                got
            })
            .flatten()
            .expect("a field");
        let owned = h
            .with_binding(handle, |b| b.passthrough(caller))
            .expect("the binding");
        assert_eq!(by_ref.0, owned[0].0.as_bytes());
        assert_eq!(by_ref.1, owned[0].1.as_bytes());
    }
    let none = h.with_binding(handle, |b| b.present_passthrough("bad\nkey", |_, _| ()));
    assert_eq!(none, Some(false));
    let none = h.with_binding(handle, |b| b.present_passthrough("", |_, _| ()));
    assert_eq!(none, Some(false));
}

#[test]
fn a_bindings_debug_never_prints_its_credential() {
    let h = Header::new(1);
    let (handle, _) = open(&h, style::BEARER, Some("operator-secret"), "{}");
    let shown = h
        .with_binding(handle, |b| format!("{b:?}"))
        .expect("the binding");
    assert!(!shown.contains("operator-secret"), "{shown}");
}

/// EVERY REFUSAL IS LOGGED ONCE AT INFO, `module = "header"`, with a reason and never the
/// credential (AUTH-STANDARD S5): bad plugin settings at validate, open and refresh, and a binding
/// `open_outbound` refuses. RED before the fix: the crate logged nothing.
#[test]
fn every_refusal_is_logged_once_at_info_without_the_credential() {
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        let _ = Header::validate(b"[1]");
        let _ = Header::open(br#"{"heder":1}"#, &[], 1);
        let h = Header::new(1);
        let _ = h.refresh(b"nope", &[], 2);
        let mut diags = Diags::default();
        let _ = h.open_outbound(
            style::BEARER,
            Some(b"sk-operator-secret"),
            Some(br#"{"heder":"x"}"#),
            None,
            &mut diags,
        );
        let _ = h.open_outbound(
            style::BEARER,
            Some(b"\xffsk-operator-secret"),
            None,
            None,
            &mut diags,
        );
    });
    let lines = cap.messages();
    assert_eq!(lines.len(), 5, "{lines:?}");
    for line in &lines {
        assert!(
            line.contains("module=\"header\"") || line.contains("module=header"),
            "{line}"
        );
        assert!(line.contains("reason="), "{line}");
        assert!(!line.contains("sk-operator-secret"), "{line}");
    }
    assert_eq!(cap.count("settings refused"), 3, "{lines:?}");
    assert_eq!(cap.count("binding refused"), 2, "{lines:?}");
}

/// A BINDING THAT CANNOT PRESENT IS NOT READY (AUTH-STANDARD S3): an own credential no header value
/// may carry opens (each request is noted) but the health prober sees it unready. A keyless binding
/// (no credential: a keyless upstream, or a passthrough lane) and a presentable one stay ready.
/// RED before the fix: every held handle answered ready.
#[test]
fn a_binding_whose_own_credential_cannot_be_presented_is_not_ready() {
    let h = Header::new(1);
    let (bad, _) = open(&h, style::BEARER, Some("sk\r\ninjected"), "{}");
    let (keyless, _) = open(&h, style::BEARER, None, "{}");
    let (fine, _) = open(&h, style::API_KEY, Some("k"), "{}");
    assert!(!h.outbound_ready(bad));
    assert!(h.outbound_ready(keyless));
    assert!(h.outbound_ready(fine));
}

/// F5: an own credential that cannot be presented opens, and the open logs ONE info line
/// (`module = "header"`, a reason word, the header or protocol name), never the credential. A
/// presentable or keyless credential logs nothing.
#[test]
fn an_unpresentable_own_credential_logs_one_info_line_at_open() {
    let cap = busbar_test_kit::warn_capture::WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        let h = Header::new(1);
        let _ = open(&h, style::API_KEY, Some("sk-secret\nx"), r#"{"header":"x-key"}"#);
        let _ = open(&h, style::BEARER, Some("sk-secret\nx"), r#"{"protocol":"twin"}"#);
        let _ = open(&h, style::API_KEY, Some("fine"), "{}");
        let _ = open(&h, style::API_KEY, None, "{}");
    });
    let lines = cap.messages();
    assert_eq!(lines.len(), 2, "{lines:?}");
    for line in &lines {
        assert!(line.contains("module=\"header\"") || line.contains("module=header"), "{line}");
        assert!(line.contains("reason=\"unpresentable_credential\""), "{line}");
        assert!(!line.contains("sk-secret"), "{line}");
    }
    assert!(lines[0].contains("x-key"), "{}", lines[0]);
    assert!(lines[1].contains("twin"), "{}", lines[1]);
}

/// F6: THE LOCK RULE. `keep` reads the generation while holding the handles write lock, and
/// `refresh` stores the new generation under that same lock, so keep / refresh / retire are
/// ordered: a handle that was waiting for the lock when a refresh landed is stored under the NEW
/// generation, never under one a retire may already have swept. Driven deterministically: the test
/// holds the write lock (as `refresh` does while it stores), a `keep` queues behind it, the
/// generation moves, and the lock is released.
#[test]
fn a_handle_kept_while_the_generation_moves_takes_the_new_generation() {
    let h = std::sync::Arc::new(Header::new(1));
    let guard = h.handles.write().unwrap();
    let (started, wait) = std::sync::mpsc::channel();
    let kept = {
        let h = h.clone();
        std::thread::spawn(move || {
            let binding = style::open_binding(style::BEARER, Some(b"sk-1"), None).unwrap();
            started.send(()).unwrap();
            h.keep(binding)
        })
    };
    wait.recv().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    h.generation.store(2, Ordering::Release);
    drop(guard);
    let handle = kept.join().unwrap();
    h.retire(1);
    assert!(h.outbound_ready(handle), "kept after the move: generation 2's");
    h.retire(2);
    assert!(!h.outbound_ready(handle));
}

/// F6, the API sequence: open, refresh, retire(old), open again; the new handles carry the new
/// generation and nothing is left under the retired one.
#[test]
fn keep_refresh_retire_are_ordered() {
    let h = Header::new(1);
    let (a, _) = open(&h, style::BEARER, Some("k"), "{}");
    h.refresh(b"{}", &[], 2).unwrap();
    let (b, _) = open(&h, style::BEARER, Some("k"), "{}");
    h.retire(1);
    let held: Vec<u64> = h.handles.read().unwrap().values().map(|(g, _)| *g).collect();
    assert_eq!(held, [2]);
    assert!(!h.outbound_ready(a) && h.outbound_ready(b));
}
