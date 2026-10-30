// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-header — the header-presentation auth styles, one auth-kind plugin
//!
//! *"bearer"*, *"api-key"* and *"x-goog-api-key"* are ONE mechanism — a credential presented
//! verbatim in an HTTP header, either the `authorization` bearer scheme or a raw custom header —
//! and live in one plugin, `busbar-auth-header`, loaded when some provider uses one of them. Its
//! fourth style, *"query-key"*, presents the credential verbatim as a query parameter instead. It
//! speaks the auth kind's memory ABI (`busbar_contract::abi::auth`, v3):
//!
//! * `open_outbound` binds one style to its credential and settings and answers a handle
//!   (generation data). It never touches the network.
//! * `fields` is the per-request op (the auth kind's memory ABI): the auth fields for this
//!   attempt, written into the host's buffer, which join the head before the framer encodes it. It
//!   serves BOTH credential modes a style with [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]
//!   declares: the operator's own bound credential ([`busbar_contract::abi::auth::MODE_OWN`]), and the
//!   caller's verified credential passed per-request
//!   ([`busbar_contract::abi::auth::MODE_PASSTHROUGH`]). A credential SOURCE is not a mechanism, so
//!   there is no separate `caller-credential` style; each mechanism plugin serves both modes of its
//!   own styles.
//! * `outbound_ready` is the handle's `ready` fact for the health prober: ready unless its own
//!   credential cannot be presented — a header binding never mints.
//! * `tick` does nothing: nothing here refreshes ahead of a deadline.
//!
//! Each binding builds its header once, at `open_outbound` ([`style::Binding`]). The kernel
//! holds no auth cache and does no per-plugin branching.
//!
//! The door is the contract SDK's safe outbound door kit (`auth_outbound_door!` over
//! `instance::Header`, an `OutboundPlugin`): the kit reads the host's frames, writes the fields
//! under the short-buffer rule and keeps every answer's memory in the answering instance, so this
//! crate is `#![forbid(unsafe_code)]` and holds no per-thread or process-global state. The
//! inbound operations (`verify`, the login pair) are not served and answer REFUSED (the tail
//! declares only `CAP_OUTBOUND`). Its Statement also states the host's default inbound style: the
//! lines a caller's credential sits on.

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
/// credential, and reads nothing past the head. The two long-standing header styles (`bearer`,
/// `api-key`) are RANKED first: the host lists the words a provider's `auth:` may name ranked first,
/// so the refusal of an unknown word keeps the same prefix.
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

/// The host's default inbound style's lines: where a caller's credential sits
/// on every line the operator's config leaves without a style, in precedence order: the
/// Bearer on `authorization`, then the raw key on `x-api-key` (the Anthropic SDK's line), then on
/// `x-goog-api-key` (the Gemini SDK's). The host walks them in this order and strips all three from
/// what a plane sees; busbar's core names none of them.
const CARRIER_LINES: [&str; 3] = ["authorization", "x-api-key", "x-goog-api-key"];

/// [`CARRIER_LINES`] as the Statement's carrier word marks.
const CARRIERS: [MarkWord; 3] = [
    carrier(CARRIER_LINES[0]),
    carrier(CARRIER_LINES[1]),
    carrier(CARRIER_LINES[2]),
];

/// The auth Statement tail: outbound styles, no login, and the host's default inbound style (the
/// Statement's carrier marks, [`CARRIERS`]); `verify` is not served.
const TAIL: &AuthTail = &outbound_tail(FACT_DEFAULT_INBOUND_STYLE, STYLE_DECLS);

/// The diagnostic ids, in `instance::diag` order. `BUSBAR-4013` covers both egress-credential lines
/// that omit an api-key credential: the header line, and the query-parameter line, which says
/// `param=` where the header line says `header=`; the named value tells the two apart.
const DIAG_IDS: &[AbiStr] = &[
    abi_str("BUSBAR-4013"),
    abi_str("BUSBAR-7087"),
    abi_str("BUSBAR-4030"),
];

/// What the plugin states: its name, version, concurrency, diagnostics and auth tail.
const STATEMENT: Statement = with_tail(
    Statement {
        diag_ids: DIAG_IDS.as_ptr(),
        diag_ids_len: DIAG_IDS.len(),
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement("busbar-auth-header", env!("CARGO_PKG_VERSION"), 1024)
    },
    TAIL,
);

busbar_contract::auth_outbound_door!(instance::Header, STATEMENT);

/// THE COMPILED-IN ENTRY a composition root's `auths` row names: the door at
/// `compiled_in::door::door`, the same [`door`] the dropped-in build
/// (`busbar-auth-header-plugin`) exports (compiled-in = dropped-in).
pub mod compiled_in {
    /// The door and its `MACRO_DOOR` (the `plugin_door!` door a linked table names).
    pub mod door {
        pub use crate::{door, MACRO_DOOR};
    }
}

#[cfg(test)]
#[path = "tests/statement_tests.rs"]
mod statement_tests;
