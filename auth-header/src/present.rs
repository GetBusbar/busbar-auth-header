// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEADER PRESENTATION: `bearer`, `api-key`, `x-goog-api-key`, and a dialect's credential-family
//! table. The legality rule, [`is_legal_header_value`](busbar_contract::header::is_legal_header_value),
//! is the contract's, shared by every auth mechanism. The plugin holds the credential itself, so the
//! header is built here directly.

use busbar_contract::header::is_legal_header_value;
use serde::Deserialize;
use zeroize::Zeroizing;

/// One presented field: its name and its value, the value (credential material) wiped on drop
/// (auth material is zeroised).
pub type Field = (String, Zeroizing<String>);

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

    /// Present `credential` in `mode` BY REFERENCE, the per-request path (no
    /// allocation and no blocking on the hot path): `emit(name, value)` once, with the bytes
    /// [`Self::present`] builds, or never when the credential cannot be presented. A raw value is
    /// the credential's own bytes; a bearer value is built on the stack (wiped when it drops) up
    /// to [`STACK_VALUE`] bytes, in a zeroised heap buffer only past that. What `emit` does with
    /// the bytes is its own: the per-request path hands them to the SDK writer, which copies them
    /// into its zeroising staging buffer (`FieldsWriter::push`). Answers whether it emitted.
    pub fn present_with(
        &self,
        credential: &str,
        mode: Mode,
        emit: impl FnOnce(&[u8], &[u8]),
    ) -> bool {
        // A field value never has leading or trailing whitespace (RFC 9110 §5.5): every
        // presentation carries the credential with its surrounding SP/HTAB removed, and a
        // credential that is empty after trimming presents nothing.
        let credential = trim_ows(credential);
        if credential.is_empty() {
            return false;
        }
        match self.presentation(credential, mode) {
            Presentation {
                header: Some(header),
                trim_start,
            } => {
                // `trim_start` is subsumed by the trim above; kept for the Unicode whitespace it
                // alone removed.
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
                with_bearer(credential, |value| emit(b"authorization", value));
                true
            }
        }
    }

    /// Present `credential` in `mode`: the header pairs to attach, or NONE when the credential
    /// cannot be presented (a byte that is not a legal header value). The owned form of
    /// [`Self::present_with`].
    pub fn present(&self, credential: &str, mode: Mode) -> Vec<Field> {
        let mut fields = Vec::new();
        self.present_with(credential, mode, |name, value| {
            let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
            fields.push((text(name), Zeroizing::new(text(value))));
        });
        fields
    }
}

/// `s` with its leading and trailing optional whitespace (SP and HTAB, RFC 9110 §5.6.3) removed:
/// what an HTTP receiver sees of a field value.
pub(crate) fn trim_ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// The longest bearer value [`StaticScheme::present_with`] stages on the stack.
pub const STACK_VALUE: usize = 1024;

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
