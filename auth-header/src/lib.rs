// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-header — the header-presentation auth styles, one auth-kind plugin
//!
//! BUSBAR-1.6.0.md THE DESIGN, §6 (OWNER-LOCKED 2026-09-27, split by mechanism per ARCHITECT ruling 2026-09-29):
//! *"bearer"*, *"api-key"* and *"x-goog-api-key"* are ONE mechanism — a credential presented
//! verbatim in an HTTP header, either the `authorization` bearer scheme or a raw custom header —
//! and live in one plugin, `busbar-auth-header`, loaded when some provider uses one of them. It
//! speaks the auth kind's memory ABI (`busbar_contract::abi::auth`, v3):
//!
//! * `open_outbound` binds one style to its credential and settings and answers a handle
//!   (generation data). It never touches the network.
//! * `fields` is the ONE per-request call the kernel makes (BUSBAR-1.6.0.md §6.4, §11.6): the auth fields for this
//!   attempt, written into the host's buffer, which join the head before the framer encodes it. It
//!   serves BOTH credential modes a style with [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]
//!   declares: the operator's own bound credential ([`busbar_contract::abi::auth::MODE_OWN`]), and the
//!   caller's verified credential passed per-request
//!   ([`busbar_contract::abi::auth::MODE_PASSTHROUGH`]) — ARCHITECT ruling 2026-09-29: a credential
//!   SOURCE is not a mechanism, so there is no separate `caller-credential` style; each mechanism
//!   plugin serves both modes of its own styles.
//! * `outbound_ready` is the handle's `ready` fact for the health prober: always ready — a header
//!   binding never mints.
//! * `tick` does nothing: nothing here refreshes ahead of a deadline.
//!
//! EACH BINDING BUILDS ITS HEADER ONCE, AT `open_outbound` (BUSBAR-1.6.0.md §6.5, [`style::Binding`]). The kernel
//! holds no auth cache and does no per-plugin branching.
//!
//! THE DOOR is the contract SDK's safe outbound door kit (`auth_outbound_door!` over
//! `instance::Header`, an `OutboundPlugin`): the kit reads the host's frames, writes the fields
//! under the short-buffer rule and keeps every answer's memory in the answering instance, so this
//! crate is `#![forbid(unsafe_code)]` and holds no per-thread or process-global state (THE DESIGN
//! §2). The inbound operations (`verify`, the login pair) are not served and answer REFUSED (the
//! tail declares only `CAP_OUTBOUND`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod instance;
mod present;
mod style;

use busbar_contract::abi::auth::{AuthPoints, AuthTail, StyleDecl, STYLE_CALLER_CREDENTIAL};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::sdk::auth_door::with_tail;
use busbar_contract::abi::sdk::auth_outbound::{outbound_tail, style as declare};
use busbar_contract::abi::sdk::door::{abi_str, statement};

/// The styles, as the tail declares them: every one of them also serves the caller's verified
/// credential, and reads nothing past the head.
const STYLE_DECLS: &[StyleDecl] = &[
    declare(style::BEARER, STYLE_CALLER_CREDENTIAL, AuthPoints::HEAD),
    declare(style::API_KEY, STYLE_CALLER_CREDENTIAL, AuthPoints::HEAD),
    declare(
        style::X_GOOG_API_KEY,
        STYLE_CALLER_CREDENTIAL,
        AuthPoints::HEAD,
    ),
    declare(style::QUERY_KEY, STYLE_CALLER_CREDENTIAL, AuthPoints::HEAD),
];

/// THE AUTH STATEMENT TAIL: outbound only, no login, no inbound carriers.
const TAIL: &AuthTail = &outbound_tail(0, STYLE_DECLS);

/// The diagnostic ids, in `instance::diag` order: 1.5.5's catalog codes where the line had one.
const DIAG_IDS: &[AbiStr] = &[
    abi_str("BUSBAR-4013"),
    abi_str("BUSBAR-7087"),
    abi_str("auth.credential-invalid-bytes"),
];

/// What the plugin states: its name, version, concurrency, diagnostics and auth tail.
const STATEMENT: Statement = with_tail(
    Statement {
        diag_ids: DIAG_IDS.as_ptr(),
        diag_ids_len: DIAG_IDS.len(),
        ..statement("busbar-auth-header", env!("CARGO_PKG_VERSION"), 1024)
    },
    TAIL,
);

busbar_contract::auth_outbound_door!(instance::Header, STATEMENT);

/// THE COMPILED-IN ENTRY a composition root's `auths` row names: the door at
/// `compiled_in::door::door`, the same [`door`] the dropped-in build
/// (`busbar-auth-header-plugin`) exports (compiled-in = dropped-in).
pub mod compiled_in {
    /// The door.
    pub mod door {
        pub use crate::door;
    }
}
