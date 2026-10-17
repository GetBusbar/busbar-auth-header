// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEADER PRESENTATION: `bearer`, `api-key`, `x-goog-api-key`, and a dialect's credential-family
//! table. MOVED VERBATIM from the identity unit's `egress_auth/mod.rs` in the kernel (the header builders
//! and their one legality rule) and `.../declared.rs` (the credential-family presentation,
//! `presentation`/`present`), staged `busbar-auth-outbound::present` (KERNEL<>PLUGINS step 22), then
//! here (AUTH-SPLIT: bearer/api-key/x-goog-api-key are one mechanism, header presentation, and this
//! is its own crate). The legality rule itself, [`is_legal_header_value`](busbar_contract::header::is_legal_header_value),
//! lives in `busbar-contract` now, a shared pure helper the auth kind's mechanisms use alike.
//!
//! What did NOT move: the `Grant<Sign>` / `SecretSlot` / `substitute` indirection. It existed so the
//! kernel could write a secret onto a request without a plane ever holding it; the auth plugin
//! holds the credential itself (BUSBAR-1.6.0.md THE DESIGN, §6: "The auth plugin holds it"), so the header is built
//! here directly — the same bytes `decorate` + `substitute` wrote, which the ported
//! `*_builder_and_decorated_slot_agree_on_every_key` vectors pin.

use busbar_contract::header::{is_legal_header_value, token_value};
use serde::Deserialize;
use zeroize::Zeroizing;

/// One presented field: its name and its value, the value (credential material) wiped on drop
/// (BUSBAR-1.6.0.md THE DESIGN §6: "auth material is zeroised").
pub type Field = (String, Zeroizing<String>);

/// The static bearer credential: `authorization: Bearer <key>`, or NO header when the key carries a
/// byte that is not a legal header value (the upstream then answers 401). The omission is the whole
/// policy; reporting it is the caller's ([`crate::envelope`]), and the key is never logged.
pub fn bearer_auth_headers(key: &str) -> Vec<Field> {
    if !is_legal_header_value(key) {
        return Vec::new();
    }
    vec![(
        "authorization".to_string(),
        Zeroizing::new(token_value(key)),
    )]
}

/// The static custom-header credential (`api-key`, `x-goog-api-key`, …) carrying the raw key
/// verbatim, or NO header when the key carries a byte that is not a legal header value. `header` is
/// the lowercase header name the style presents under.
pub fn api_key_auth_headers(header: &str, key: &str) -> Vec<Field> {
    if !is_legal_header_value(key) {
        return Vec::new();
    }
    vec![(header.to_string(), Zeroizing::new(key.to_string()))]
}

/// How one static credential is presented (the contract's `CredentialHeader`, as settings data):
/// `authorization: Bearer <credential>` (`header` absent), or the credential verbatim in `header`,
/// leading whitespace trimmed first when `trim_start`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    /// The raw header; absent = bearer.
    #[serde(default)]
    pub header: Option<String>,
    /// Trim the credential's leading whitespace before presenting it raw.
    #[serde(default)]
    pub trim_start: bool,
}

impl Presentation {
    /// `authorization: Bearer <credential>`.
    pub const BEARER: Presentation = Presentation {
        header: None,
        trim_start: false,
    };

    /// The credential verbatim in `header`.
    pub fn raw(header: &str) -> Self {
        Self {
            header: Some(header.to_string()),
            trim_start: false,
        }
    }
}

/// One credential-family row (the contract's `CredentialFamily`): a credential starting with
/// `prefix` (leading whitespace trimmed) is presented as `presented`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Family {
    /// The credential prefix.
    pub prefix: String,
    /// How a credential of the family is presented.
    #[serde(flatten)]
    pub presented: Presentation,
}

/// The mode a credential is presented in: the binding's own, or a forwarded caller credential
/// ([`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The credential the binding was opened with.
    Own,
    /// The caller's verified credential.
    Passthrough,
}

/// A static style's whole presentation (the contract's `EgressScheme::Static`): the family table,
/// then the presentation by mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScheme {
    /// The credential-family table, in precedence order (may be empty).
    pub families: Vec<Family>,
    /// How an own credential that matches no family is presented.
    pub own: Presentation,
    /// How a forwarded caller credential that matches no family is presented.
    pub passthrough: Presentation,
}

impl StaticScheme {
    /// The same presentation whatever the credential or mode.
    pub fn uniform(p: Presentation) -> Self {
        Self {
            families: Vec::new(),
            own: p.clone(),
            passthrough: p,
        }
    }

    /// How `credential` is presented in `mode`: the first credential-family row whose prefix the
    /// credential (leading whitespace trimmed) starts with, else the presentation for the mode.
    pub fn presentation(&self, credential: &str, mode: Mode) -> &Presentation {
        let trimmed = credential.trim_start();
        self.families
            .iter()
            .find(|family| trimmed.starts_with(family.prefix.as_str()))
            .map(|family| &family.presented)
            .unwrap_or(match mode {
                Mode::Own => &self.own,
                Mode::Passthrough => &self.passthrough,
            })
    }

    /// Present `credential` in `mode` BY REFERENCE, the per-request path (THE DESIGN §11.2: "no
    /// allocation and no blocking on the hot path"): `emit(name, value)` once, with the bytes
    /// [`Self::present`] builds, or never when the credential cannot be presented. A raw value is
    /// the credential's own bytes; a bearer value is staged on the stack (wiped when it drops) up
    /// to [`STACK_VALUE`] bytes, in a zeroised heap buffer only past that. Answers whether it
    /// emitted.
    pub fn present_with(
        &self,
        credential: &str,
        mode: Mode,
        emit: impl FnOnce(&[u8], &[u8]),
    ) -> bool {
        match self.presentation(credential, mode) {
            Presentation {
                header: Some(header),
                trim_start,
            } => {
                let key = if *trim_start {
                    credential.trim_start()
                } else {
                    credential
                };
                if !is_legal_header_value(key) {
                    return false;
                }
                emit(header.as_bytes(), key.as_bytes());
                true
            }
            Presentation { header: None, .. } => {
                if !is_legal_header_value(credential) {
                    return false;
                }
                with_bearer(credential, |value| emit(b"authorization", value));
                true
            }
        }
    }

    /// Present `credential` in `mode`: the header pairs to attach, or NONE when the credential
    /// cannot be presented (a byte that is not a legal header value).
    pub fn present(&self, credential: &str, mode: Mode) -> Vec<Field> {
        match self.presentation(credential, mode) {
            Presentation {
                header: Some(header),
                trim_start,
            } => api_key_auth_headers(
                header,
                if *trim_start {
                    credential.trim_start()
                } else {
                    credential
                },
            ),
            Presentation { header: None, .. } => bearer_auth_headers(credential),
        }
    }
}

/// The longest bearer value [`StaticScheme::present_with`] stages on the stack.
pub const STACK_VALUE: usize = 1024;

/// The bearer scheme's prefix, as [`token_value`] writes it.
const BEARER_PREFIX: &[u8] = b"Bearer ";

/// Run `f` over `Bearer <key>` (the bytes [`token_value`] builds), staged on the stack when it
/// fits [`STACK_VALUE`], else in a heap buffer; either is wiped when it drops.
fn with_bearer(key: &str, f: impl FnOnce(&[u8])) {
    let len = BEARER_PREFIX.len() + key.len();
    if len <= STACK_VALUE {
        let mut buf = Zeroizing::new([0_u8; STACK_VALUE]);
        buf[..BEARER_PREFIX.len()].copy_from_slice(BEARER_PREFIX);
        buf[BEARER_PREFIX.len()..len].copy_from_slice(key.as_bytes());
        f(&buf[..len]);
    } else {
        let mut value = Zeroizing::new(Vec::with_capacity(len));
        value.extend_from_slice(BEARER_PREFIX);
        value.extend_from_slice(key.as_bytes());
        f(&value);
    }
}

#[cfg(test)]
#[path = "tests/present_tests.rs"]
mod tests;
