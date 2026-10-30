// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STYLES AND THEIR BINDINGS: `open_outbound` binds one style to its credential and settings
//! ([`open_binding`]); the per-request call presents through the binding ([`Binding`]) in either
//! credential mode — the operator's own, or the caller's verified credential
//! ([`Binding::passthrough`], [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]).
//!
//! The settings schema: the kernel resolves the dialect's declared
//! parameters at seal into `OpenOutboundIn::settings`, a JSON object whose shape per style is:
//!
//! | style | settings |
//! |---|---|
//! | `bearer` | `{families?, own?, passthrough?, protocol?}` (default: `Bearer` whatever the credential) |
//! | `api-key` | `{header?: "api-key", families?, own?, passthrough?, protocol?}` |
//! | `x-goog-api-key` | `{header?: "x-goog-api-key", families?, own?, passthrough?, protocol?}` |
//! | `query-key` | `{param?: "key"}` (the dialect's default parameter name) |
//!
//! `families` is a dialect's credential-family table, `[{prefix, header?, trim_start?}]` (a row
//! without `header` presents as a bearer); `own` / `passthrough` are `{header?, trim_start?}`.
//! `protocol` is the lane's protocol name, which a bearer's and a credential-family table's
//! unpresentable-credential line names (the `protocol=` field; empty when absent).
//! A key the style does not read is refused by name (`settings: unknown key `<key>``), except the
//! provider keys the kernel writes into every style's settings ([`PROVIDER_KEYS`]), read by none.
//!
//! The notes: a credential with bytes no header value may carry presents nothing, and raises a
//! [`Note`] at WARN on each request that would have carried it, the operator's own and a caller's
//! alike.
//!
//! The refusals: a binding that cannot open answers FAILED with one line per finding, each
//! `credential: <text>` or `settings: <text>`. The kernel composes the sentence —
//! `provider '<p>' <style> credential (from <src>) is invalid: <text>`, or `provider '<p>' <text>`.

use busbar_contract::abi::sdk::auth_kit::json_error;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::present::{trim_ows, Family, Mode, Presentation, StaticScheme};

/// `authorization: Bearer <credential>`.
pub const BEARER: &str = "bearer";
/// The credential verbatim in a custom header (`api-key` unless the settings name another).
pub const API_KEY: &str = "api-key";
/// The credential verbatim in `x-goog-api-key`.
pub const X_GOOG_API_KEY: &str = "x-goog-api-key";
/// The credential verbatim as a QUERY PARAMETER on the request target (`?key=<credential>` unless
/// the settings name another `param`), never a header: its fields carry
/// [`FIELD_QUERY`](busbar_contract::abi::auth::FIELD_QUERY).
pub const QUERY_KEY: &str = "query-key";
/// The query parameter [`QUERY_KEY`] presents under when the settings name none.
pub const QUERY_KEY_DEFAULT_PARAM: &str = "key";

/// The keys the kernel writes into every style's settings beside the dialect's (busbar
/// `root/door_steps.rs`, `StyleParams::to_json`): a minting style's endpoint, scope and subject. A
/// header style reads none of them, as 1.5.5 ignored them on a header provider.
pub(crate) const PROVIDER_KEYS: &[&str] = &["token_url", "token_uri", "scope", "subject"];
/// The keys `api-key` and `x-goog-api-key` read.
const RAW_KEYS: &[&str] = &["header", "families", "own", "passthrough", "protocol"];
/// The keys `bearer` reads (its header is always `authorization`).
const BEARER_KEYS: &[&str] = &["families", "own", "passthrough", "protocol"];
/// The keys `query-key` reads.
const QUERY_KEYS: &[&str] = &["param"];

/// The keys `style` reads, `None` for a style this plugin does not serve.
fn style_keys(style: &str) -> Option<&'static [&'static str]> {
    match style {
        BEARER => Some(BEARER_KEYS),
        API_KEY | X_GOOG_API_KEY => Some(RAW_KEYS),
        QUERY_KEY => Some(QUERY_KEYS),
        _ => None,
    }
}

/// Whether some style reads `key`, or the kernel writes it into every style's settings.
pub(crate) fn known_key(key: &str) -> bool {
    [RAW_KEYS, QUERY_KEYS, PROVIDER_KEYS]
        .iter()
        .any(|keys| keys.contains(&key))
}

/// One refusal per key `style` does not read, naming it, in the settings' key order.
fn unknown_keys(m: &Map<String, Value>, keys: &[&str]) -> Vec<Refusal> {
    m.keys()
        .filter(|k| !keys.contains(&k.as_str()) && !PROVIDER_KEYS.contains(&k.as_str()))
        .map(|k| Refusal::Settings(format!("unknown key `{k}`")))
        .collect()
}

/// One finding that refuses a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The credential is invalid: the kernel wraps it in `<style> credential (from <src>) is
    /// invalid:`.
    Credential(String),
    /// The settings are: the kernel prefixes `provider '<p>' `.
    Settings(String),
}

impl Refusal {
    /// The line `open_outbound` answers.
    pub fn line(&self) -> String {
        match self {
            Refusal::Credential(t) => format!("credential: {t}"),
            Refusal::Settings(t) => format!("settings: {t}"),
        }
    }
}

/// A credential a binding could not present for bytes invalid in a header value, as the
/// diagnostic it raises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// A static header omitted for invalid bytes (`EGRESS_APIKEY_INVALID_BYTES`), naming the header.
    Header(String),
    /// A bearer omitted for invalid bytes (`PROTO_AUTH_INVALID_HEADER_BYTES`), naming the protocol.
    Bearer(String),
    /// A credential-family table's credential omitted for invalid bytes, naming the protocol, then
    /// the header.
    Family(String, String),
    /// A query-parameter credential ([`QUERY_KEY`]) omitted for invalid bytes, naming the
    /// parameter.
    Query(String),
}

/// One open binding: the scheme, the fields its own credential presents (built once), and the
/// protocol its notes name.
pub struct Binding {
    scheme: StaticScheme,
    own: Vec<crate::present::Field>,
    /// The note the operator's own credential raises on each request that would have carried it
    /// (none when it presents, or when there is no credential).
    own_note: Option<Note>,
    query: bool,
    protocol: String,
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the presented values: they are credential material.
        f.debug_struct("Binding")
            .field("own", &self.own.len())
            .field("query", &self.query)
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl Binding {
    /// Whether this binding's fields are query parameters ([`QUERY_KEY`]), not headers.
    pub fn query(&self) -> bool {
        self.query
    }

    /// The fields the binding's own credential presents (empty: no header) — [`Mode::Own`].
    pub fn own(&self) -> &[crate::present::Field] {
        &self.own
    }

    /// The note the binding's own credential raises on EACH request it presents nothing for.
    pub fn own_note(&self) -> Option<&Note> {
        self.own_note.as_ref()
    }

    /// Present a caller's `credential` by reference — [`Mode::Passthrough`], the per-request path:
    /// `emit(name, value)` once, or never (no credential, or one that cannot be presented).
    /// Answers whether it emitted.
    pub fn present_passthrough(&self, credential: &str, emit: impl FnOnce(&[u8], &[u8])) -> bool {
        !credential.is_empty()
            && self
                .scheme
                .present_with(credential, Mode::Passthrough, emit)
    }

    /// The fields a caller's credential presents — [`Mode::Passthrough`], as owned fields (what
    /// [`Self::present_passthrough`] emits by reference).
    #[cfg(test)]
    pub fn passthrough(&self, credential: &str) -> Vec<crate::present::Field> {
        if credential.is_empty() {
            return Vec::new();
        }
        self.scheme.present(credential, Mode::Passthrough)
    }

    /// The note for a caller's `credential` that [`Self::passthrough`] presented as nothing; none
    /// for an empty one (no credential, nothing to report).
    pub fn passthrough_note(&self, credential: &str) -> Option<Note> {
        (!trim_ows(credential).is_empty()).then(|| {
            unpresented(
                &self.scheme,
                credential,
                (Mode::Passthrough, self.query),
                &self.protocol,
            )
        })
    }
}

/// The settings object (`{}` when absent).
fn object(settings: Option<&[u8]>) -> Result<Map<String, Value>, Refusal> {
    let Some(bytes) = settings.filter(|b| !b.is_empty()) else {
        return Ok(Map::new());
    };
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(Refusal::Settings(
            "outbound auth settings must be a JSON object".to_string(),
        )),
        Err(e) => Err(Refusal::Settings(json_error(
            "outbound auth settings are not JSON",
        )(e))),
    }
}

fn field<T: for<'de> Deserialize<'de>>(
    m: &Map<String, Value>,
    key: &str,
) -> Result<Option<T>, Refusal> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone()).map(Some).map_err(|e| {
            let why = json_error("is invalid")(e);
            Refusal::Settings(format!("outbound auth setting `{key}` {why}"))
        }),
    }
}

/// A string setting: absent (or null) is `None`; present but blank is refused by name.
fn text(m: &Map<String, Value>, key: &str) -> Result<Option<String>, Refusal> {
    match field::<String>(m, key)? {
        Some(s) if s.trim().is_empty() => Err(blank(key)),
        other => Ok(other),
    }
}

/// The refusal for a blank string setting (`setting`: its name as the operator wrote it).
fn blank(setting: &str) -> Refusal {
    Refusal::Settings(format!("outbound auth setting `{setting}` must not be blank"))
}

/// A style's scheme: its default presentation, overridden by the settings.
fn static_scheme(style: &str, m: &Map<String, Value>) -> Result<StaticScheme, Refusal> {
    if style == QUERY_KEY {
        // One parameter, the credential verbatim; the header settings do not apply to it.
        let param = text(m, "param")?;
        return Ok(StaticScheme::uniform(Presentation::raw(
            param.as_deref().unwrap_or(QUERY_KEY_DEFAULT_PARAM),
        )));
    }
    let mut default = match style {
        BEARER => Presentation::BEARER,
        API_KEY => Presentation::raw(text(m, "header")?.as_deref().unwrap_or(API_KEY)),
        X_GOOG_API_KEY => {
            Presentation::raw(text(m, "header")?.as_deref().unwrap_or(X_GOOG_API_KEY))
        }
        other => {
            return Err(Refusal::Settings(format!(
                "outbound auth style `{other}` is not served by this plugin"
            )))
        }
    };
    header_name("header", &mut default)?;
    let mut scheme = StaticScheme::uniform(default);
    if let Some(mut families) = field::<Vec<Family>>(m, "families")? {
        for (i, family) in families.iter_mut().enumerate() {
            header_name(&format!("families[{i}].header"), &mut family.presented)?;
        }
        scheme.families = families;
    }
    if let Some(mut own) = field::<Presentation>(m, "own")? {
        header_name("own.header", &mut own)?;
        scheme.own = own;
    }
    if let Some(mut passthrough) = field::<Presentation>(m, "passthrough")? {
        header_name("passthrough.header", &mut passthrough)?;
        scheme.passthrough = passthrough;
    }
    Ok(scheme)
}

/// A header name the settings supply (`setting`), judged here: the host checks a plane's fields
/// only, so a name this plugin presents is its own to hold to an RFC 9110 token. Any case is
/// accepted and the name is lower-cased as it is read, the field lines' own spelling: `header: X-API-Key`
/// is presented as `x-api-key`. A name
/// that is no token is refused at open, naming the setting.
fn header_name(setting: &str, p: &mut Presentation) -> Result<(), Refusal> {
    let Some(name) = p.header.as_mut() else {
        return Ok(());
    };
    if !busbar_contract::header::is_header_name_token(name.as_bytes()) {
        return Err(Refusal::Settings(format!(
            "outbound auth setting `{setting}` is not a header name (an RFC 9110 token)"
        )));
    }
    name.make_ascii_lowercase();
    Ok(())
}

/// The note for a credential a static scheme could not present, in the line its builder logged.
/// `query`: the binding presents a query parameter ([`QUERY_KEY`]), whose note names the parameter.
fn unpresented(
    scheme: &StaticScheme,
    credential: &str,
    (mode, query): (Mode, bool),
    protocol: &str,
) -> Note {
    let p = scheme.presentation(credential, mode);
    let header = p
        .header
        .clone()
        .unwrap_or_else(|| "authorization".to_string());
    if query {
        Note::Query(header)
    } else if !scheme.families.is_empty() {
        Note::Family(protocol.to_string(), header)
    } else if p.header.is_some() {
        Note::Header(header)
    } else {
        Note::Bearer(protocol.to_string())
    }
}

/// Bind `style` to `credential` under `settings` — `open_outbound`'s body. Never touches the
/// network.
///
/// # Errors
///
/// Every finding that refuses the binding, in check order.
pub fn open_binding(
    style: &str,
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
) -> Result<Binding, Vec<Refusal>> {
    let m = object(settings).map_err(|r| vec![r])?;
    if let Some(keys) = style_keys(style) {
        let unknown = unknown_keys(&m, keys);
        if !unknown.is_empty() {
            return Err(unknown);
        }
    }
    let credential_text = match credential.map(std::str::from_utf8) {
        None => None,
        Some(Ok(s)) => Some(s),
        Some(Err(_)) => {
            return Err(vec![Refusal::Credential(
                "the credential is not UTF-8".to_string(),
            )])
        }
    };
    let scheme = static_scheme(style, &m).map_err(|r| vec![r])?;
    let protocol = text(&m, "protocol")
        .map_err(|r| vec![r])?
        .unwrap_or_default();
    // NO CREDENTIAL ⇒ NO AUTH HEADER: an empty key is a keyless upstream
    // (`api_key: none`), and an empty `Authorization: Bearer ` is strictly worse than nothing.
    // (blank after trimming SP/HTAB counts as empty: a field value never carries them).
    let credential_text = credential_text.unwrap_or("");
    let own = if trim_ows(credential_text).is_empty() {
        Vec::new()
    } else {
        scheme.present(credential_text, Mode::Own)
    };
    let own_note = (!trim_ows(credential_text).is_empty() && own.is_empty()).then(|| {
        unpresented(
            &scheme,
            credential_text,
            (Mode::Own, style == QUERY_KEY),
            &protocol,
        )
    });
    Ok(Binding {
        scheme,
        own,
        own_note,
        query: style == QUERY_KEY,
        protocol,
    })
}

#[cfg(test)]
#[path = "tests/style_tests.rs"]
mod tests;
