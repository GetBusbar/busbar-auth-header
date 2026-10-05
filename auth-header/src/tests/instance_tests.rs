// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HANDLE BOOKKEEPING AND `fields` SLOT, both credential modes, over the trampoline the door
//! macro builds — no mint, no wire, no waiting ticket: a header binding is synchronous end to end.

use super::*;
use crate::style;
use crate::Fields;
use busbar_contract::abi::auth::{FieldSpan, FieldsIn, FieldsOut, MODE_OWN, MODE_PASSTHROUGH};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_OCTETS};
use busbar_contract::abi::sdk::door::Slot;
use std::ffi::c_void;

fn auth_span() -> busbar_contract::abi::mechanism::call::Span {
    busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 }
}

/// One `fields` call through the slot body, as the trampoline makes it.
fn fields(h: &Header, handle: u64, mode: u32, caller: &str) -> (Outcome, String) {
    let mut buf = [0_u8; 512];
    let mut spans = [FieldSpan {
        name: auth_span(),
        value: auth_span(),
        flags: 0,
        _reserved: 0,
    }; 4];
    let mut i: FieldsIn = crate::abi::zeroed_in();
    i.handle = handle;
    i.mode = mode;
    i.caller_credential = if caller.is_empty() {
        Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: 0,
            flags: 0,
        }
    } else {
        Blob {
            ptr: caller.as_ptr(),
            len: caller.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    };
    (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
    (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 4);
    let mut out: FieldsOut = crate::abi::zeroed_out();
    let inst = std::ptr::from_ref(h).cast_mut().cast::<c_void>();
    let outcome = Fields::call(inst, &i, &mut out);
    let written = (0..out.fields_len as usize)
        .map(|k| {
            let at = |sp: busbar_contract::abi::mechanism::call::Span| {
                String::from_utf8_lossy(&buf[sp.offset as usize..(sp.offset + sp.len) as usize])
                    .into_owned()
            };
            format!("{}: {}", at(spans[k].name), at(spans[k].value))
        })
        .collect::<Vec<_>>()
        .join(" ; ");
    (outcome, written)
}

fn open(h: &Header, style: &str, cred: Option<&str>, settings: &str) -> u64 {
    let binding = style::open_binding(
        style,
        cred.map(str::as_bytes),
        Some(settings.as_bytes()),
        &mut Vec::new(),
    )
    .expect("the binding opens");
    h.keep(binding)
}

#[test]
fn a_handle_presents_its_own_credential_then_the_callers() {
    let h = Header::new(1);
    let handle = open(&h, style::BEARER, Some("sk-1"), "{}");
    assert_eq!(
        fields(&h, handle, MODE_OWN, ""),
        (Outcome::Ready, "authorization: Bearer sk-1".to_string())
    );
    assert_eq!(
        fields(&h, handle, MODE_PASSTHROUGH, "caller-tok"),
        (
            Outcome::Ready,
            "authorization: Bearer caller-tok".to_string()
        )
    );
    assert_eq!(
        fields(&h, handle, MODE_PASSTHROUGH, ""),
        (Outcome::Ready, String::new()),
        "no caller credential presented: no header"
    );
}

#[test]
fn retire_drops_the_generations_handles() {
    let h = Header::new(1);
    let handle = open(&h, style::BEARER, Some("sk-1"), "{}");
    h.retire(1);
    assert_eq!(
        fields(&h, handle, MODE_OWN, ""),
        (Outcome::Refused, String::new())
    );
}

#[test]
fn note_reports_each_note_in_its_own_line() {
    let mut env = EnvStore::default();
    Header::note(
        &mut env,
        &[
            style::Note::Header("api-key".to_string()),
            style::Note::Bearer("twin".to_string()),
            style::Note::Family("twin".to_string(), "x-api-key".to_string()),
        ],
    );
    assert_eq!(env.diags().len(), 3);
    assert_eq!(env.diags()[0].id_idx, diag::APIKEY_INVALID_BYTES);
    assert_eq!(env.diags()[1].id_idx, diag::AUTH_INVALID_HEADER_BYTES);
    assert_eq!(env.diags()[2].id_idx, diag::CREDENTIAL_INVALID_BYTES);
    let text = |k: usize| env.texts()[k].clone();
    assert!(text(0).ends_with("upstream will reject with 401 header=api-key"));
    assert!(text(1).ends_with("upstream will reject with 401 protocol=twin"));
    assert!(text(2).ends_with("check the key configuration protocol=twin header=x-api-key"));
}

/// A caller's credential no header value may carry presents nothing and raises its builder's note
/// on THAT `fields` call's envelope, per request; a presentable one raises none.
#[test]
fn a_callers_unpresentable_credential_is_noted_on_its_fields_call() {
    let h = Header::new(1);
    let handle = open(&h, style::BEARER, None, r#"{"protocol":"twin"}"#);
    let call = |caller: &str| {
        let mut buf = [0_u8; 512];
        let mut spans = [FieldSpan {
            name: auth_span(),
            value: auth_span(),
            flags: 0,
            _reserved: 0,
        }; 4];
        let mut i: FieldsIn = crate::abi::zeroed_in();
        i.handle = handle;
        i.mode = MODE_PASSTHROUGH;
        i.caller_credential = Blob {
            ptr: caller.as_ptr(),
            len: caller.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
        (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 4);
        let mut out: FieldsOut = crate::abi::zeroed_out();
        let inst = std::ptr::from_ref(&h).cast_mut().cast::<c_void>();
        let outcome = Fields::call(inst, &i, &mut out);
        (outcome, out.fields_len, out.head.envelope.diags_len)
    };
    assert_eq!(call("bad\nkey"), (Outcome::Ready, 0, 1));
    assert_eq!(call("bad\nkey"), (Outcome::Ready, 0, 1), "every request");
    assert_eq!(call("good-key"), (Outcome::Ready, 1, 0));
}
