// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEADER PRESENTATION: `bearer`, `api-key`, `x-goog-api-key`, and a dialect's credential-family
//! table. The legality rule itself,
//! [`is_legal_header_value`](busbar_contract::header::is_legal_header_value), lives in
//! `busbar-contract`, a shared pure helper.

use busbar_contract::abi::sdk::cred::Cred;
use busbar_contract::header::is_legal_header_value;
use serde::Deserialize;
use zeroize::Zeroizing;

/// One presented field: its name and its value, the value (credential material) wiped on drop
/// (BUSBAR-1.6.0.md THE DESIGN §6: "auth material is zeroised").
pub type Field = (String, Cred);

/// How one static credential is presented (the contract's `CredentialHeader`, as settings data):
/// `authorization: Bearer <credential>` (`header` absent), or the credential in `header`.
/// Nonblank credential bytes are preserved. A raw header's `trim_start` removes leading
/// Unicode whitespace when explicitly selected.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    /// The raw header; absent = bearer.
    #[serde(default)]
    pub header: Option<String>,
    /// Also trim leading Unicode whitespace before presenting a raw header value.
    #[serde(default)]
    pub trim_start: bool,
}

impl Presentation {
    /// `authorization: Bearer <credential>`.
    pub const BEARER: Presentation = Presentation {
        header: None,
        trim_start: false,
    };

    /// The credential in `header`, preserving its nonblank bytes.
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
    /// Whether the selected presentation trims the credential to nothing. Empty material is an
    /// absent credential, not an invalid one: it presents no field and raises no note.
    pub(crate) fn empty_after_trim(&self, credential: &str, mode: Mode) -> bool {
        let credential = trim_ows(credential);
        credential.is_empty()
            || matches!(
                self.presentation(credential, mode),
                Presentation {
                    header: Some(_),
                    trim_start: true,
                }
            ) && credential.trim_start().is_empty()
    }

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

    /// Present `credential` in `mode` BY REFERENCE: `emit(name, value)` once, with the bytes
    /// [`Self::present`] would own, or never when the credential cannot be presented. Answers
    /// whether it emitted.
    pub fn present_with(
        &self,
        credential: &str,
        mode: Mode,
        emit: impl FnOnce(&[u8], &[u8]),
    ) -> bool {
        if trim_ows(credential).is_empty() {
            return false;
        }
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
                if key.is_empty() || !is_legal_header_value(key) {
                    return false;
                }
                emit(header.as_bytes(), key.as_bytes());
                true
            }
            Presentation { header: None, .. } => {
                if !is_legal_header_value(credential) {
                    return false;
                }
                with_bearer(credential, |value| emit(BEARER_HEADER.as_bytes(), value));
                true
            }
        }
    }

    /// Present `credential` in `mode`: the header pairs to attach, or NONE when the credential
    /// cannot be presented (a byte that is not a legal header value).
    pub fn present(&self, credential: &str, mode: Mode) -> Vec<Field> {
        let mut fields = Vec::new();
        self.present_with(credential, mode, |name, value| {
            fields.push((
                String::from_utf8_lossy(name).into_owned(),
                Cred::captured(Zeroizing::new(value.to_vec())),
            ));
        });
        fields
    }
}

/// `s` with its leading and trailing optional whitespace (SP and HTAB, RFC 9110 §5.6.3) removed:
/// empty for a blank credential, which presents no field.
pub(crate) fn trim_ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// The longest bearer value [`StaticScheme::present_with`] stages on the stack.
pub const STACK_VALUE: usize = 1024;

/// The header a bearer presents in.
pub(crate) const BEARER_HEADER: &str = "authorization";

/// The bearer scheme's prefix, as `busbar_contract::header::token_value` writes it.
const BEARER_PREFIX: &[u8] = b"Bearer ";

/// Run `f` over `Bearer <key>` (the bytes `token_value` builds), staged on the stack when it
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
