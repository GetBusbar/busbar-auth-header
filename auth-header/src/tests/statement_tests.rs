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
