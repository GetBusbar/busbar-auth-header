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

#[test]
fn settings_that_are_not_an_object_are_refused_in_the_plugins_words() {
    for bad in [&b"[1]"[..], b"nope"] {
        let r = Header::validate(bad).expect_err("refused");
        assert_eq!(
            r.outcome(),
            busbar_contract::abi::mechanism::call::Outcome::Refused
        );
        assert_eq!(r.text(), Some(SETTINGS_NOT_OBJECT));
    }
    assert!(Header::validate(b"").is_ok(), "absent settings");
    assert!(Header::validate(b"{}").is_ok());
    assert!(Header::open(b"[1]", &[], 1).is_err());
    assert!(Header::new(1).refresh(b"[1]", &[], 2).is_err());
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
