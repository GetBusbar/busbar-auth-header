// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Statement this row states beside its outbound styles: the host's default inbound style
//! and its carrier marks, the style flags, and the diagnostic ids.

use super::*;

/// The row states `FACT_DEFAULT_INBOUND_STYLE`, and its carrier marks are 1.5.5's client-token lines
/// in 1.5.5's precedence order: the Bearer on `authorization`, then `x-api-key`, then
/// `x-goog-api-key`.
#[test]
fn the_default_inbound_style_is_the_1_5_5_client_token_lines_in_order() {
    assert_eq!(
        TAIL.facts & FACT_DEFAULT_INBOUND_STYLE,
        FACT_DEFAULT_INBOUND_STYLE
    );
    assert_eq!(
        CARRIER_LINES,
        ["authorization", "x-api-key", "x-goog-api-key"]
    );
    assert!(CARRIERS
        .iter()
        .all(|w| w.class == busbar_contract::abi::mechanism::door::MARK_WORD_CARRIER));
    assert_eq!(STATEMENT.mark_words_len, 3);
}

#[test]
fn the_header_styles_rank_1_5_5_s_two_first_and_state_no_token_endpoint() {
    use busbar_contract::abi::auth::{
        check_style_decl, style_rank, STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL,
    };

    let ranks: Vec<u32> = STYLE_DECLS.iter().map(|d| style_rank(d.flags)).collect();
    assert_eq!(ranks, [1, 2, 0, 0]);
    for d in STYLE_DECLS {
        assert_eq!(
            d.flags & (STYLE_ENDPOINT_TOKEN_URL | STYLE_ENDPOINT_FROM_CREDENTIAL),
            0
        );
        assert!(check_style_decl(d.flags, d.points).is_ok());
    }
}

/// Every declared style serves the caller's verified credential as well as the operator's own, and
/// states its auth points as the head alone.
#[test]
fn every_declared_style_carries_the_caller_credential_flag_and_the_head_point() {
    use busbar_contract::abi::auth::{AuthPoints, STYLE_CALLER_CREDENTIAL};
    assert_eq!(STYLE_DECLS.len(), 4);
    for d in STYLE_DECLS {
        assert_eq!(
            d.flags & STYLE_CALLER_CREDENTIAL,
            STYLE_CALLER_CREDENTIAL,
            "flags {:#x}",
            d.flags
        );
        assert_eq!(AuthPoints(d.points), AuthPoints::HEAD);
    }
}

/// The Statement's diagnostic ids are indexed by `instance::diag`: each index names its code, and
/// each note raises the id of the code the Statement states at that index.
#[test]
fn each_diag_index_is_pinned_to_its_busbar_code() {
    use crate::instance::{diag, note_line, Cause};
    use crate::style::Note;
    assert_eq!(DIAG_IDS.len(), 3);
    for (index, code) in [
        (diag::APIKEY_INVALID_BYTES, "BUSBAR-4013"),
        (diag::AUTH_INVALID_HEADER_BYTES, "BUSBAR-7087"),
        (diag::CREDENTIAL_INVALID_BYTES, "BUSBAR-4030"),
    ] {
        let i = index as usize;
        assert_eq!(DIAG_CODES[i], code);

        assert_eq!(DIAG_IDS[i].len, code.len());
        assert!(std::ptr::eq(DIAG_IDS[i].ptr, DIAG_CODES[i].as_ptr()));
    }
    let raised = |n: Note| DIAG_CODES[note_line(&n, Cause::InvalidByte).0 as usize];
    assert_eq!(raised(Note::Header("h".into())), "BUSBAR-4013");
    assert_eq!(raised(Note::Query("p".into())), "BUSBAR-4013");
    assert_eq!(raised(Note::Bearer("x".into())), "BUSBAR-7087");
    assert_eq!(raised(Note::Family("x".into(), "h".into())), "BUSBAR-4030");
}
