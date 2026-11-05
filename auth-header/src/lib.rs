// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-header — the header-presentation auth styles, one auth-kind plugin
//!
//! `bearer`, `api-key`, `x-goog-api-key` and `query-key` are one mechanism: a credential presented
//! in an HTTP header (or, for `query-key`, as a query parameter). Each style serves both the
//! operator's own bound credential and the caller's verified credential (passthrough).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod instance;
mod present;
mod style;

use busbar_contract::abi::auth::{
    ranked, AuthPoints, AuthTail, StyleDecl, FACT_DEFAULT_INBOUND_STYLE, STYLE_CALLER_CREDENTIAL,
};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{carrier, with_tail};
use busbar_contract::abi::sdk::auth_outbound::{outbound_tail, style as declare};
use busbar_contract::abi::sdk::door::{abi_str, statement};

/// The styles, as the tail declares them: every one of them also serves the caller's verified
/// credential.
const STYLE_DECLS: &[StyleDecl] = &[
    declare(
        style::BEARER,
        STYLE_CALLER_CREDENTIAL | ranked(1),
        AuthPoints::HEAD,
    ),
    declare(
        style::API_KEY,
        STYLE_CALLER_CREDENTIAL | ranked(2),
        AuthPoints::HEAD,
    ),
    declare(
        style::X_GOOG_API_KEY,
        STYLE_CALLER_CREDENTIAL,
        AuthPoints::HEAD,
    ),
    declare(style::QUERY_KEY, STYLE_CALLER_CREDENTIAL, AuthPoints::HEAD),
];

/// The host's default inbound style's lines: where a caller's credential sits on an inbound
/// request (1.5.5's client-token lines, in order).
const CARRIER_LINES: [&str; 3] = ["authorization", "x-api-key", "x-goog-api-key"];

/// [`CARRIER_LINES`] as the Statement's carrier word marks.
const CARRIERS: [MarkWord; CARRIER_LINES.len()] = [
    carrier(CARRIER_LINES[0]),
    carrier(CARRIER_LINES[1]),
    carrier(CARRIER_LINES[2]),
];

/// The auth Statement tail: outbound styles, no login, and the host's default inbound style (the
/// [`CARRIERS`] marks).
const TAIL: &AuthTail = &outbound_tail(FACT_DEFAULT_INBOUND_STYLE, STYLE_DECLS);

/// The diagnostic codes, in `instance::diag` order. `BUSBAR-4013` covers both egress-credential
/// notes, a static header's and a query parameter's; `BUSBAR-7087` is the bearer's; `BUSBAR-4030`,
/// declared by this plugin, is a credential-family table's.
const DIAG_CODES: [&str; 3] = ["BUSBAR-4013", "BUSBAR-7087", "BUSBAR-4030"];

/// The diagnostic ids as the Statement states them, [`DIAG_CODES`] in the same order.
const DIAG_IDS: [AbiStr; DIAG_CODES.len()] = [
    abi_str(DIAG_CODES[0]),
    abi_str(DIAG_CODES[1]),
    abi_str(DIAG_CODES[2]),
];

/// The concurrency the plugin states: calls the host may run on one instance at once. The instance
/// never pends and its per-request path holds only a read lock, so the bound is generous.
const CONCURRENCY: u32 = 1024;

busbar_contract::statement_extensions!(
    EXTENSIONS: [
        (
            busbar_contract::abi::mechanism::extensions::EXT_DECLARES,
            include_bytes!("../declares.json")
        ),
    ]
);

/// What the plugin states: its name, version, concurrency, diagnostics and auth tail.
/// JSON Schema for the lifecycle settings document, embedded in the signed Statement.
const SETTINGS_SCHEMA: &[u8] = include_bytes!("../settings.schema.json");

const STATEMENT: Statement = with_tail(
    Statement {
        settings_schema: busbar_contract::abi::mechanism::call::Blob::json(SETTINGS_SCHEMA),
        extensions: EXTENSIONS,
        diag_ids: DIAG_IDS.as_ptr(),
        diag_ids_len: DIAG_IDS.len(),
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            CONCURRENCY,
        )
    },
    TAIL,
);

busbar_contract::auth_outbound_door!(instance::Header, STATEMENT);

/// THE COMPILED-IN ENTRY a composition root's `auths` row names: the door at
/// `compiled_in::door::door`, the same [`door`] the dropped-in build exports (compiled-in =
/// dropped-in).
pub mod compiled_in {
    /// The door and its `MACRO_DOOR` (the `plugin_door!` door a linked table names).
    pub mod door {
        pub use crate::{door, MACRO_DOOR};
    }
}

#[cfg(test)]
#[path = "tests/statement_tests.rs"]
mod statement_tests;

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

#[cfg(test)]
#[path = "tests/support.rs"]
mod test_support;

#[cfg(test)]
mod settings_schema_tests;
