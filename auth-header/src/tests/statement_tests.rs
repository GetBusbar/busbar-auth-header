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

/// THE LIST RANKS (busbar arch-audit u29 F1; BUSBAR-1.6.0.md #50: the auth styles a provider may
/// name are the ones the loaded auth plugins declare): the host lists the declared styles ranked
/// first, so an unknown `auth:` is refused naming 1.5.5's styles first, in 1.5.5's order. This row
/// ranks its two 1.5.5 styles first and second and leaves its newer styles unranked. RED: no style
/// was ranked, so the host listed this row's newer styles between 1.5.5's.
#[test]
fn the_1_5_5_styles_are_ranked_first_and_second() {
    use busbar_contract::abi::auth::style_rank;
    // The rows in their declared order, each named by its length (the crate reads no raw pointer;
    // the four names have distinct lengths).
    let declared: Vec<(usize, u32)> = STYLE_DECLS
        .iter()
        .map(|d| (d.name.len, style_rank(d.flags)))
        .collect();
    assert_eq!(
        declared,
        [
            (style::BEARER.len(), 1),
            (style::API_KEY.len(), 2),
            (style::X_GOOG_API_KEY.len(), 0),
            (style::QUERY_KEY.len(), 0),
        ]
    );
}
