// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One instance: the handles (generation data), served through the SDK's safe outbound door kit
//! ([`OutboundPlugin`]). No token cache, no waker, no waiting tickets: a header binding never mints
//! and never pends.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::auth::{FIELD_QUERY, FIELD_SENSITIVE};
use busbar_contract::abi::mechanism::call::SEVERITY_WARN;
use busbar_contract::abi::sdk::auth_outbound::{
    Diags, FieldsAnswer, FieldsView, FieldsWriter, Mode as CredentialMode, OpenRefusal,
    OutboundPlugin,
};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::cred::Parts;
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::life::{self, Refusal as LifecycleRefusal};

use crate::style::{self, Binding, Note};

/// The index of each diagnostic id in the Statement (`crate::DIAG_IDS`).
pub(crate) mod diag {
    /// A static header, or a query parameter ([`super::Note::Query`]), omitted for invalid bytes
    /// (`BUSBAR-4013`; the named value, `header=` or `param=`, tells the two apart).
    pub const APIKEY_INVALID_BYTES: u32 = 0;
    /// A bearer omitted for invalid bytes.
    pub const AUTH_INVALID_HEADER_BYTES: u32 = 1;
    /// A credential-family table's credential omitted for invalid bytes.
    pub const CREDENTIAL_INVALID_BYTES: u32 = 2;
}

/// The flags every header field this plugin writes carries: [`FIELD_SENSITIVE`], so an h2 encoder
/// sends the credential never-indexed and it never enters a shared HPACK table. A query parameter
/// carries [`FIELD_QUERY`] alone: the flag governs header indexing only (an own query credential
/// also reads [`FIELD_SENSITIVE`] because `push_sealed` sets it on every sealed field).
const FIELD_FLAGS: u32 = FIELD_SENSITIVE;

/// The instance-level settings grammar, judged alike at `validate`, `open` and `refresh`.
/// Every key is read by a style or is a provider key the kernel writes into each style's settings
/// ([`style::known_key`]); unknown keys are refused by name.
fn settings(b: &[u8]) -> Result<(), LifecycleRefusal> {
    let m = life::settings_object(b).inspect_err(|_| {
        tracing::info!(
            module = "header",
            reason = "not_object",
            "header settings refused"
        );
    })?;
    let unknown: Vec<String> = m
        .keys()
        .filter(|k| !style::known_key(k))
        .map(|k| format!("settings.{k}: unknown key"))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        let lines = unknown.join("\n");
        tracing::info!(
            module = "header",
            reason = "unknown_key",
            refusal = %lines,
            "header settings refused"
        );
        Err(LifecycleRefusal::failed(lines))
    }
}

/// Why a credential presented nothing: the reason a note's line gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cause {
    /// The credential holds a byte no header value may carry (1.5.5's reason).
    InvalidByte,
    /// A caller's credential is not valid UTF-8.
    NotUtf8,
}

/// The diagnostic a note raises for `cause`: the message, then the line's named values as
/// ` name=value` (names and reasons only, never credential bytes). A caller credential that is not
/// valid UTF-8 says so, in place of 1.5.5's reason (it need hold no control character).
pub(crate) fn note_line(n: &Note, cause: Cause) -> (u32, u8, String) {
    let (control, family) = match cause {
        Cause::InvalidByte => ("ASCII control character", "e.g. a trailing newline"),
        Cause::NotUtf8 => ("not valid UTF-8", "not valid UTF-8"),
    };
    match n {
        Note::Header(header) => (
            diag::APIKEY_INVALID_BYTES,
            SEVERITY_WARN,
            format!(
                "egress credential contains invalid header bytes ({control}); omitting auth \
                 header — upstream will reject with 401 header={header}"
            ),
        ),
        Note::Bearer(protocol) => (
            diag::AUTH_INVALID_HEADER_BYTES,
            SEVERITY_WARN,
            format!(
                "authorization credential contains invalid header bytes ({control}); omitting \
                 auth header — upstream will reject with 401 protocol={protocol}"
            ),
        ),
        Note::Query(param) => (
            diag::APIKEY_INVALID_BYTES,
            SEVERITY_WARN,
            format!(
                "egress credential contains invalid bytes ({control}); omitting the auth query \
                 parameter — upstream will reject with 401 param={param}"
            ),
        ),
        Note::Family(protocol, header) => (
            diag::CREDENTIAL_INVALID_BYTES,
            SEVERITY_WARN,
            format!(
                "auth credential contains bytes invalid for an HTTP header value ({family}); \
                 omitting the credential header — upstream will return 401, check the key \
                 configuration protocol={protocol} header={header}"
            ),
        ),
    }
}

/// Raise `note`'s diagnostic for `cause` ([`note_line`]) in this call's reply.
fn raise(out: &mut FieldsWriter<'_>, note: &Note, cause: Cause) {
    let (id, severity, text) = note_line(note, cause);
    out.diag(id, severity, text);
}

/// One plugin instance.
#[derive(Debug)]
pub struct Header {
    generation: AtomicU64,
    next_handle: AtomicU64,
    handles: RwLock<HashMap<u64, (u64, Binding)>>,
}

impl Header {
    /// An instance at `generation`.
    pub(crate) fn new(generation: u64) -> Self {
        Self {
            generation: AtomicU64::new(generation),
            next_handle: AtomicU64::new(1),
            handles: RwLock::new(HashMap::new()),
        }
    }

    /// Keep `binding` under a new handle of the current generation.
    pub(crate) fn keep(&self, binding: Binding) -> u64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let mut handles = self.handles.write().unwrap_or_else(PoisonError::into_inner);
        let generation = self.generation.load(Ordering::Acquire);
        handles.insert(handle, (generation, binding));
        handle
    }

    /// Run `f` over the binding behind `handle`, under the read lock.
    pub(crate) fn with_binding<T>(&self, handle: u64, f: impl FnOnce(&Binding) -> T) -> Option<T> {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .map(|(_, b)| f(b))
    }
}

impl OutboundPlugin for Header {
    fn validate(b: &[u8]) -> Result<(), LifecycleRefusal> {
        settings(b)
    }

    fn open(b: &[u8], _secrets: &[&[u8]], generation: u64) -> Result<Self, LifecycleRefusal> {
        settings(b)?;
        Ok(Self::new(generation))
    }

    /// Bind a style; FAILED carries one `credential: …` / `settings: …` line per finding.
    fn open_outbound(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
        _host: Option<&Host>,
        _diags: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        let opened = style::open_binding(style, credential, settings);
        match opened {
            Ok(binding) => {
                match binding.own_note() {
                    // A query parameter is named as one, not as a header.
                    Some(Note::Query(param)) => tracing::info!(
                        module = "header",
                        style,
                        reason = "unpresentable_credential",
                        param = param.as_str(),
                        "header binding opened with a credential it cannot present"
                    ),
                    Some(note) => {
                        let (header, protocol) = note.names();
                        tracing::info!(
                            module = "header",
                            style,
                            reason = "unpresentable_credential",
                            header,
                            protocol,
                            "header binding opened with a credential it cannot present"
                        );
                    }
                    None => {}
                }
                Ok(self.keep(binding))
            }
            Err(refusals) => {
                let lines: Vec<String> = refusals.iter().map(style::Refusal::line).collect();

                tracing::info!(
                    module = "header",
                    style,
                    reason = "binding_refused",
                    refusal = %lines.join("; "),
                    "header binding refused"
                );
                let mut lines = lines.into_iter();
                let first = lines.next().unwrap_or_default();
                Err(lines.fold(OpenRefusal::new(first), OpenRefusal::and))
            }
        }
    }

    /// The one per-request call, both credential modes. Own fields are staged from their sealed
    /// values; a caller's credential is presented by reference. A credential that cannot be
    /// presented raises its note on each request.
    fn fields(
        &self,
        request: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        _op: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        let handle = request.handle();
        let answered = match request.mode() {
            CredentialMode::Own => self.with_binding(handle, |b| {
                let flags = if b.query() { FIELD_QUERY } else { FIELD_FLAGS };
                for (name, value) in b.own() {
                    out.push_sealed(name.as_bytes(), Parts::new().sealed(value.field()), flags);
                }

                if let Some(note) = b.own_note() {
                    raise(out, note, Cause::InvalidByte);
                }
            }),
            CredentialMode::Passthrough => {
                let lent = request.caller_credential();
                let raw = lent.unwrap_or_default();
                let caller = std::str::from_utf8(raw).unwrap_or("");
                self.with_binding(handle, |b| {
                    if lent.is_none() {
                        // Passthrough with no lent credential is a host fault, not an empty
                        // credential: log it rather than send the request unauthenticated silently.
                        tracing::info!(
                            module = "header",
                            handle,
                            reason = "no_caller_credential",
                            "header passthrough presented nothing: the host lent no caller credential"
                        );
                        return;
                    }
                    if !raw.is_empty() && caller.is_empty() {
                        let mut lossy = zeroize::Zeroizing::new(String::with_capacity(
                            raw.len().saturating_mul(3),
                        ));
                        for chunk in raw.utf8_chunks() {
                            lossy.push_str(chunk.valid());
                            if !chunk.invalid().is_empty() {
                                lossy.push(char::REPLACEMENT_CHARACTER);
                            }
                        }
                        if let Some(note) = b.passthrough_note(&lossy) {
                            raise(out, &note, Cause::NotUtf8);
                        }
                        return;
                    }
                    let flags = if b.query() { FIELD_QUERY } else { FIELD_FLAGS };
                    let presented = b.present_passthrough(caller, |name, value| {
                        out.push(name, value, flags);
                    });

                    if !presented {
                        if let Some(note) = b.passthrough_note(caller) {
                            raise(out, &note, Cause::InvalidByte);
                        }
                    }
                })
            }
        };
        Poll::Ready(match answered {
            Some(()) => FieldsAnswer::Ready,
            None => {
                tracing::info!(
                    module = "header",
                    handle,
                    reason = "unknown_handle",
                    "header fields refused"
                );
                FieldsAnswer::Refused
            }
        })
    }

    /// Ready for a handle it holds unless its own credential cannot be presented (a header binding
    /// never mints; one whose credential no header value may carry presents nothing).
    fn outbound_ready(&self, handle: u64) -> bool {
        self.with_binding(handle, |b| b.own_note().is_none())
            .unwrap_or(false)
    }

    /// The new generation, later handles belong to.
    fn refresh(
        &self,
        b: &[u8],
        _secrets: &[&[u8]],
        generation: u64,
    ) -> Result<(), LifecycleRefusal> {
        settings(b)?;

        let _handles = self.handles.write().unwrap_or_else(PoisonError::into_inner);
        self.generation.store(generation, Ordering::Release);
        Ok(())
    }

    /// The generation's handles go.
    fn retire(&self, generation: u64) {
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (g, _)| *g != generation);
    }
}

#[cfg(test)]
#[path = "tests/instance_tests.rs"]
mod tests;
