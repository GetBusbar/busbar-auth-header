// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Statement this row states beside its outbound styles: the host's default inbound style
//! (busbar row 159, K3#1).

use super::*;

/// The row states `FACT_DEFAULT_INBOUND_STYLE`, and its carrier marks are 1.5.5's client-token lines
/// in 1.5.5's precedence order: the Bearer on `authorization`, then `x-api-key`, then
/// `x-goog-api-key`. RED before the row states them (busbar's core read them from its own table).
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

/// RED (busbar arch-audit u29 F1): a provider's `auth:` is an opaque word some loaded plugin
/// declares, and the host lists the declared words ranked first. This row ranks 1.5.5's two header
/// styles first, in 1.5.5's order (`bearer` 1, `api-key` 2), so a configuration 1.5.5 refused for an
/// unknown word is refused with 1.5.5's list as the prefix of the host's; the styles 1.5.5 never
/// named (`x-goog-api-key`, `query-key`) are unranked. None states a token endpoint: a header style
/// mints nothing. Every declaration is one the host loads.
#[test]
fn the_header_styles_rank_1_5_5_s_two_first_and_state_no_token_endpoint() {
    use busbar_contract::abi::auth::{
        check_style_decl, style_rank, STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL,
    };
    // `STYLE_DECLS` order: bearer, api-key, x-goog-api-key, query-key.
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
