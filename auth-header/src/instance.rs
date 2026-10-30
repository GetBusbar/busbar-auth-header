// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One instance: the handles (generation data), served through the SDK's safe outbound door kit
//! ([`OutboundPlugin`]). No token cache, no waker, no waiting tickets: a header binding never mints
//! and never pends.
//!
//! Every answer's own memory (an error text, the envelope's diagnostics) is the kit's, kept by the
//! instance that answered (`busbar_contract::abi::sdk::out`): this crate holds no per-thread and
//! no process-global state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::auth::FIELD_QUERY;
use busbar_contract::abi::mechanism::call::SEVERITY_WARN;
use busbar_contract::abi::sdk::auth_outbound::{
    Diags, FieldsAnswer, FieldsView, FieldsWriter, Mode, OpenRefusal, OutboundPlugin,
};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::life::{self, Refusal};

use crate::style::{self, Binding, Note};

/// The index of each diagnostic id in the Statement (`crate::DIAG_IDS`).
pub(crate) mod diag {
    /// A static header omitted for invalid bytes.
    pub const APIKEY_INVALID_BYTES: u32 = 0;
    /// A bearer omitted for invalid bytes.
    pub const AUTH_INVALID_HEADER_BYTES: u32 = 1;
    /// A credential-family table's credential omitted for invalid bytes.
    pub const CREDENTIAL_INVALID_BYTES: u32 = 2;
}

/// The flags every header field this plugin writes carries: NONE. Credential headers go
/// out indexable, and an h2 encoder that honoured `FIELD_SENSITIVE` would send them never-indexed,
/// which is different bytes on the wire.
const FIELD_FLAGS: u32 = 0;

/// The plugin's own settings, judged alike at `validate`, `open` and `refresh`: none are read. The
/// instance is opened over a binding's settings, so present settings must be a JSON object whose
/// every key some style reads ([`style::known_key`]); anything else is FAILED, one
/// `settings.<key>: unknown key` line per key.
fn settings(b: &[u8]) -> Result<(), Refusal> {
    let m = life::settings_object(b)?;
    let unknown: Vec<String> = m
        .keys()
        .filter(|k| !style::known_key(k))
        .map(|k| format!("settings.{k}: unknown key"))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(Refusal::failed(unknown.join("\n")))
    }
}

/// The diagnostic a note raises: the message, then the line's named values as ` name=value`
/// (`protocol`, then `header`). The host writes a declared diagnostic to the plugin's main log in
/// that shape.
pub(crate) fn note_line(n: &Note) -> (u32, u8, String) {
    match n {
        Note::Header(header) => (
            diag::APIKEY_INVALID_BYTES,
            SEVERITY_WARN,
            format!(
                "egress credential contains invalid header bytes (ASCII control character); \
                 omitting auth header — upstream will reject with 401 header={header}"
            ),
        ),
        Note::Bearer(protocol) => (
            diag::AUTH_INVALID_HEADER_BYTES,
            SEVERITY_WARN,
            format!(
                "authorization credential contains invalid header bytes (ASCII control \
                 character); omitting auth header — upstream will reject with 401 \
                 protocol={protocol}"
            ),
        ),
        Note::Query(param) => (
            diag::APIKEY_INVALID_BYTES,
            SEVERITY_WARN,
            format!(
                "egress credential contains invalid bytes (ASCII control character); omitting the \
                 auth query parameter — upstream will reject with 401 param={param}"
            ),
        ),
        Note::Family(protocol, header) => (
            diag::CREDENTIAL_INVALID_BYTES,
            SEVERITY_WARN,
            format!(
                "auth credential contains bytes invalid for an HTTP header value (e.g. a trailing \
                 newline); omitting the credential header — upstream will return 401, check the \
                 key configuration protocol={protocol} header={header}"
            ),
        ),
    }
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
        let generation = self.generation.load(Ordering::Acquire);
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handle, (generation, binding));
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
    fn validate(b: &[u8]) -> Result<(), Refusal> {
        settings(b)
    }

    fn open(b: &[u8], _secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
        settings(b)?;
        Ok(Self::new(generation))
    }

    /// Bind a style; FAILED carries one `credential: …` / `settings: …` line per finding
    /// An own credential no header value may carry opens (the request goes with no auth header) and
    /// is noted on each request, by `fields`.
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
            Ok(binding) => Ok(self.keep(binding)),
            Err(refusals) => {
                let mut lines = refusals.iter().map(style::Refusal::line);
                let first = lines.next().unwrap_or_default();
                Err(lines.fold(OpenRefusal::new(first), OpenRefusal::and))
            }
        }
    }

    /// The one per-request call, both credential modes. Each field is handed to the SDK writer by
    /// reference (the binding's own straight from where it is held, under the read lock; a
    /// caller's as the bytes it arrived in), and the writer COPIES it into its own staging buffer,
    /// a `Zeroizing<Vec<u8>>` wiped when the call ends (busbar-contract
    /// `abi/sdk/auth_outbound.rs`, `FieldsWriter::push` staging name and value into `staged`), until
    /// it is written into the host's field buffer. This plugin makes no copy of its own on the
    /// presentable path: auth material is zeroised.
    fn fields(
        &self,
        request: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        _op: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        let handle = request.handle();
        let answered = match request.mode() {
            Mode::Own => self.with_binding(handle, |b| {
                let flags = if b.query() { FIELD_QUERY } else { FIELD_FLAGS };
                for (name, value) in b.own() {
                    out.push(name.as_bytes(), value.as_bytes(), flags);
                }
                // The operator's own credential no header value may carry: reported on each
                // request it presents nothing for.
                if let Some(note) = b.own_note() {
                    let (id, severity, text) = note_line(note);
                    out.diag(id, severity, text);
                }
            }),
            Mode::Passthrough => {
                let raw = request.caller_credential().unwrap_or_default();
                let caller = std::str::from_utf8(raw).unwrap_or("");
                self.with_binding(handle, |b| {
                    // A caller's credential that is not UTF-8 presents nothing, and raises the note
                    // its scheme's builder raises for any unpresentable credential (classified on
                    // a lossy reading; the note names the protocol and header, never the bytes).
                    // The reading is a copy of the caller's credential, so it is wiped on drop
                    // (auth material is zeroised); only this refused case makes it.
                    if !raw.is_empty() && caller.is_empty() {
                        // Built into a buffer sized for the worst case up front (every byte one
                        // replacement character, three bytes), so it never reallocates and leaves
                        // no unwiped earlier buffer behind.
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
                            let (id, severity, text) = note_line(&note);
                            out.diag(id, severity, text);
                        }
                        return;
                    }
                    let flags = if b.query() { FIELD_QUERY } else { FIELD_FLAGS };
                    let presented = b.present_passthrough(caller, |name, value| {
                        out.push(name, value, flags);
                    });
                    // A caller's credential no header value may carry: reported on each request
                    // that presents nothing.
                    if !presented {
                        if let Some(note) = b.passthrough_note(caller) {
                            let (id, severity, text) = note_line(&note);
                            out.diag(id, severity, text);
                        }
                    }
                })
            }
        };
        Poll::Ready(match answered {
            Some(()) => FieldsAnswer::Ready,
            None => FieldsAnswer::Refused,
        })
    }

    /// Always ready for a handle it holds — a header binding never mints.
    fn outbound_ready(&self, handle: u64) -> bool {
        self.with_binding(handle, |_| ()).is_some()
    }

    /// The new generation, later handles belong to.
    fn refresh(&self, b: &[u8], _secrets: &[&[u8]], generation: u64) -> Result<(), Refusal> {
        settings(b)?;
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
