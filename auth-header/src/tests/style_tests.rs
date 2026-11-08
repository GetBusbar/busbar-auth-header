// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body: every style binds from its settings, and every refusal is 1.5.5's own
//! words in the `credential:` / `settings:` lines the kernel composes; and `Binding::passthrough`,
//! the caller-credential mode on this mechanism's own styles rather than a separate style.

use super::*;

use crate::test_support::Plain;

impl Binding {
    /// The fields a caller's credential presents — [`Mode::Passthrough`]: what the production
    /// [`Self::present_passthrough`] emits by reference, copied into owned fields.
    pub(crate) fn passthrough(&self, credential: &str) -> Vec<Field> {
        let mut fields = Vec::new();
        let emitted = self.present_passthrough(credential, |name, value| {
            fields.push((
                String::from_utf8(name.to_vec()).expect("a header name is text"),
                busbar_contract::abi::sdk::cred::Cred::captured(zeroize::Zeroizing::new(
                    value.to_vec(),
                )),
            ));
        });
        assert_eq!(
            emitted,
            !fields.is_empty(),
            "the answer matches what was emitted"
        );
        fields
    }
}

fn open(
    style: &str,
    credential: Option<&str>,
    settings: &str,
) -> (Result<Binding, Vec<Refusal>>, Vec<Note>) {
    let r = open_binding(
        style,
        credential.map(str::as_bytes),
        Some(settings.as_bytes()),
    );
    let notes = r
        .as_ref()
        .ok()
        .and_then(Binding::own_note)
        .cloned()
        .into_iter()
        .collect();
    (r, notes)
}

fn lines(r: Result<Binding, Vec<Refusal>>) -> Vec<String> {
    r.expect_err("the binding is refused")
        .iter()
        .map(Refusal::line)
        .collect()
}

fn own(r: Result<Binding, Vec<Refusal>>) -> Vec<(String, String)> {
    r.expect("the binding opens").own().plain()
}

/// The static styles build their header ONCE, at open, from the default presentation or the
/// dialect's settings.
#[test]
fn the_static_styles_build_their_header_at_open() {
    assert_eq!(
        own(open(BEARER, Some("sk-1"), "{}").0),
        vec![("authorization".to_string(), "Bearer sk-1".to_string())]
    );
    assert_eq!(
        own(open(API_KEY, Some("az-1"), "{}").0),
        vec![("api-key".to_string(), "az-1".to_string())]
    );
    assert_eq!(
        own(open(X_GOOG_API_KEY, Some("g-1"), "").0),
        vec![("x-goog-api-key".to_string(), "g-1".to_string())]
    );
    let table = r#"{"header":"x-api-key","families":[{"prefix":"sk-ant-api","header":"x-api-key","trim_start":true},{"prefix":"sk-ant-oat"}],"passthrough":{}}"#;
    assert_eq!(
        own(open(API_KEY, Some(" sk-ant-api03-k"), table).0),
        vec![("x-api-key".to_string(), "sk-ant-api03-k".to_string())]
    );
    assert_eq!(
        own(open(API_KEY, Some("sk-ant-oat01-k"), table).0),
        vec![(
            "authorization".to_string(),
            "Bearer sk-ant-oat01-k".to_string()
        )]
    );
}

/// No credential (`api_key: none`) presents no header; an un-encodable one presents none and is
/// noted.
#[test]
fn a_keyless_or_unencodable_credential_presents_nothing() {
    let (r, notes) = open(BEARER, None, "{}");
    assert!(own(r).is_empty());
    assert!(notes.is_empty(), "keyless is not a fault");
    let (r, notes) = open(BEARER, Some(""), "{}");
    assert!(own(r).is_empty());
    assert!(notes.is_empty());
    let (r, notes) = open(BEARER, Some("sk\r\nx"), "{}");
    assert!(own(r).is_empty());
    assert_eq!(notes, [Note::Bearer(String::new())]);
    let (r, notes) = open(API_KEY, Some("k\u{0}"), "{}");
    assert!(own(r).is_empty());
    assert_eq!(notes, [Note::Header("api-key".to_string())]);
}

/// The `protocol` setting is the name a bearer's and a credential-family table's note carry (1.5.5's
/// `protocol=`); a caller's unpresentable credential raises its note per request, an empty one none.
#[test]
fn a_note_names_the_bound_protocol_and_a_callers_credential_raises_its_own() {
    let (r, notes) = open(BEARER, Some("sk\r\nx"), r#"{"protocol":"twin-bearer"}"#);
    assert!(own(r).is_empty());
    assert_eq!(notes, [Note::Bearer("twin-bearer".to_string())]);
    let families = r#"{"protocol":"twin-fam","families":[{"prefix":"sk-ant-api","header":"x-api-key","trim_start":true},{"prefix":"sk-ant-oat"}],"own":{"header":"x-api-key"}}"#;
    let (_, notes) = open(API_KEY, Some("sk-ant-oat01-bad\ntoken"), families);
    assert_eq!(
        notes,
        [Note::Family(
            "twin-fam".to_string(),
            "authorization".to_string()
        )]
    );
    let (r, notes) = open(API_KEY, None, families);
    assert!(notes.is_empty());
    let binding = r.expect("the binding opens keyless");
    assert!(binding
        .passthrough("sk-ant-api03-bad\nkey")
        .plain()
        .is_empty());
    assert_eq!(
        binding.passthrough_note("sk-ant-api03-bad\nkey"),
        Some(Note::Family(
            "twin-fam".to_string(),
            "x-api-key".to_string()
        ))
    );
    assert_eq!(binding.passthrough_note(""), None);
}

/// A style with no configured credential still presents the CALLER's, in caller mode
/// ([`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]).
#[test]
fn a_style_with_no_own_credential_still_presents_the_callers() {
    let (r, _) = open(X_GOOG_API_KEY, None, "{}");
    let binding = r.expect("the binding opens keyless");
    assert!(
        binding.own().plain().is_empty(),
        "no own credential: no own header"
    );
    assert_eq!(
        binding.passthrough("caller-key").plain(),
        vec![("x-goog-api-key".to_string(), "caller-key".to_string())]
    );
    assert!(
        binding.passthrough("").plain().is_empty(),
        "a tokenless caller: no header"
    );
}

/// A family table decides the caller's presentation exactly as it decides the operator's own.
#[test]
fn passthrough_honours_the_family_table_too() {
    let table = r#"{"families":[{"prefix":"sk-ant-oat","header":null}],"own":{"header":"x-api-key"},"passthrough":{"header":"x-api-key"}}"#;
    let (r, _) = open(API_KEY, None, table);
    let binding = r.expect("the binding opens");
    assert_eq!(
        binding.passthrough("sk-ant-oat01-xyz").plain(),
        vec![(
            "authorization".to_string(),
            "Bearer sk-ant-oat01-xyz".to_string()
        )],
        "the family wins over the passthrough default"
    );
    assert_eq!(
        binding.passthrough("other").plain(),
        vec![("x-api-key".to_string(), "other".to_string())]
    );
}

/// Distinct own and passthrough presentations: the operator's credential takes `own`, the
/// caller's takes `passthrough`, never the other's.
#[test]
fn own_and_passthrough_presentations_stay_distinct() {
    let settings = r#"{"own":{"header":"x-own"},"passthrough":{"header":"x-caller"}}"#;
    let binding = open(API_KEY, Some("op-key"), settings)
        .0
        .expect("the binding opens");
    assert_eq!(
        binding.own().plain(),
        vec![("x-own".to_string(), "op-key".to_string())]
    );
    assert_eq!(
        binding.passthrough("caller-key").plain(),
        vec![("x-caller".to_string(), "caller-key".to_string())]
    );
}

#[test]
fn an_unknown_style_or_malformed_settings_is_refused() {
    assert_eq!(
        lines(open("kerberos", Some("k"), "{}").0),
        ["settings: outbound auth style `kerberos` is not served by this plugin"]
    );
    assert_eq!(
        lines(open(BEARER, Some("k"), "[1]").0),
        ["settings: outbound auth settings must be a JSON object"]
    );
    assert_eq!(
        lines(open("sigv4", Some("k"), "{}").0),
        ["settings: outbound auth style `sigv4` is not served by this plugin"],
        "sigv4 is a different mechanism, busbar-auth-sigv4"
    );
    assert_eq!(
        lines(open("jwt-bearer", Some("k"), "{}").0),
        ["settings: outbound auth style `jwt-bearer` is not served by this plugin"],
        "jwt-bearer is a different mechanism, busbar-auth-oauth"
    );
}

/// THE QUERY STYLE: the credential verbatim under the dialect's parameter (`key` by default), its
/// binding marked as query parameters, never a header; the header styles are not.
#[test]
fn the_query_style_presents_a_query_parameter() {
    let b = open(QUERY_KEY, Some("gem-1"), "{}").0.expect("opens");
    assert!(b.query());
    assert_eq!(b.own().plain(), &[("key".to_string(), "gem-1".to_string())]);
    assert_eq!(
        b.passthrough("caller-1").plain(),
        vec![("key".to_string(), "caller-1".to_string())]
    );
    let named = open(QUERY_KEY, Some("gem-1"), r#"{"param":"api_key"}"#)
        .0
        .expect("opens");
    assert_eq!(
        named.own().plain(),
        &[("api_key".to_string(), "gem-1".to_string())]
    );
    for style in [BEARER, API_KEY, X_GOOG_API_KEY] {
        assert!(
            !open(style, Some("k"), "{}").0.expect("opens").query(),
            "{style}"
        );
    }
    assert!(
        own(open(QUERY_KEY, None, "{}").0).is_empty(),
        "no credential, no parameter"
    );
}

#[test]
fn binding_debug_does_not_reveal_its_sealed_credential() {
    let binding = open(BEARER, Some("operator-key"), "{}")
        .0
        .expect("the binding opens");
    assert!(!format!("{binding:?}").contains("operator-key"));
    assert!(binding.own()[0].1.verify_eq(b"Bearer operator-key"));
}

/// A SETTINGS-SUPPLIED HEADER NAME IS AN RFC 9110 TOKEN, or the binding is refused at open, naming
/// the setting: the host checks a plane's fields only, so a name the settings carry is this
/// plugin's to judge.
#[test]
fn a_header_name_that_is_no_token_is_refused_at_open() {
    for (settings, setting) in [
        (r#"{"header": "x api key"}"#, "header"),
        (r#"{"header": "X-API-Key "}"#, "header"),
        (r#"{"own": {"header": "x-key\r\n"}}"#, "own.header"),
        (
            r#"{"passthrough": {"header": "x:key"}}"#,
            "passthrough.header",
        ),
        (
            r#"{"families": [{"prefix": "sk-", "header": "bad name"}]}"#,
            "families[0].header",
        ),
    ] {
        let refused = lines(open(API_KEY, Some("k"), settings).0);
        assert_eq!(refused.len(), 1, "{settings}: {refused:?}");
        assert!(
            refused[0].starts_with(&format!("settings: outbound auth setting `{setting}` ")),
            "{settings}: {refused:?}"
        );
    }
    assert!(open(API_KEY, Some("k"), r#"{"header": "x-api-key"}"#)
        .0
        .is_ok());
}

/// A MIXED-CASE HEADER NAME LOADS AND IS PRESENTED LOWER-CASE, as 1.5.5 loaded `header: X-API-Key`
#[test]
fn a_mixed_case_header_name_is_presented_lower_case_as_in_1_5_5() {
    assert_eq!(
        own(open(API_KEY, Some("sk-1"), r#"{"header": "X-API-Key"}"#).0),
        vec![("x-api-key".to_string(), "sk-1".to_string())]
    );
    let families = r#"{"families":[{"prefix":"sk-","header":"X-Family-Key"}]}"#;
    assert_eq!(
        own(open(API_KEY, Some("sk-2"), families).0),
        vec![("x-family-key".to_string(), "sk-2".to_string())]
    );
    let passthrough = r#"{"passthrough":{"header":"X-Pass-Key"}}"#;
    let binding = open(API_KEY, None, passthrough)
        .0
        .expect("the binding opens");
    assert_eq!(
        binding.passthrough("other").plain(),
        vec![("x-pass-key".to_string(), "other".to_string())]
    );
}

/// A QUERY-PARAMETER credential no request target may carry is noted as the parameter it omitted,
/// not as an auth header.
#[test]
fn an_unpresentable_query_credential_is_noted_by_its_parameter() {
    let (r, notes) = open(QUERY_KEY, Some("k\u{0}"), "{}");
    assert!(own(r).is_empty());
    assert_eq!(notes, [Note::Query(QUERY_KEY_DEFAULT_PARAM.to_string())]);
}

#[test]
fn a_settings_value_is_never_quoted_in_a_refusal() {
    for settings in [
        r#"{"own":"sk-pasted-secret"}"#,
        r#"{"protocol":["sk-pasted-secret"]}"#,
        r#"{"families":[{"prefix":"sk-pasted-secret","header":7}]}"#,
        r#"{"own": sk-pasted-secret}"#,
    ] {
        let refused = lines(open(API_KEY, Some("k"), settings).0);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].starts_with("settings: "), "{refused:?}");
        assert!(!refused[0].contains("sk-pasted-secret"), "{refused:?}");
    }
    let refused = lines(open(API_KEY, Some("k"), r#"{"own":"sk-pasted-secret"}"#).0);
    assert!(refused[0].contains("`own`"), "names the key: {refused:?}");
}

/// AN UNKNOWN PER-STYLE KEY IS REFUSED BY NAME (AUTH-STANDARD S2): a typo'd optional key must not
/// silently fall back to its default. Every dialect's parameter set and the provider keys the
/// kernel hands every style (`token_url`, `token_uri`, `scope`, `subject`) still open.
#[test]
fn an_unknown_settings_key_is_refused_by_name() {
    assert_eq!(
        lines(open(API_KEY, Some("k"), r#"{"heder":"x-api-key"}"#).0),
        ["settings: unknown key `heder`"]
    );
    assert_eq!(
        lines(open(BEARER, Some("k"), r#"{"header":"x-api-key","param":"key"}"#).0),
        [
            "settings: unknown key `header`",
            "settings: unknown key `param`"
        ]
    );
    assert_eq!(
        lines(open(QUERY_KEY, Some("k"), r#"{"header":"x"}"#).0),
        ["settings: unknown key `header`"]
    );
    let dialects = [
        (
            API_KEY,
            r#"{"header":"x-api-key","families":[{"prefix":"sk-ant-api","header":"x-api-key","trim_start":true},{"prefix":"sk-ant-oat"}],"own":{"header":"x-api-key"},"passthrough":{},"protocol":"anthropic"}"#,
        ),
        (
            BEARER,
            r#"{"families":[],"own":{},"passthrough":{},"protocol":"openai"}"#,
        ),
        (
            X_GOOG_API_KEY,
            r#"{"families":[],"own":{"header":"x-goog-api-key"},"passthrough":{"header":"x-goog-api-key"},"protocol":"gemini"}"#,
        ),
        (QUERY_KEY, r#"{"param":"key"}"#),
    ];
    for (style, settings) in dialects {
        assert!(
            open(style, Some("k"), settings).0.is_ok(),
            "{style} {settings}"
        );
    }
    for style in [BEARER, API_KEY, X_GOOG_API_KEY, QUERY_KEY] {
        let provider = r#"{"token_url":"https://t.example/","token_uri":"https://u.example/","scope":"s","subject":"x"}"#;
        assert!(open(style, Some("k"), provider).0.is_ok(), "{style}");
    }
}

#[test]
fn a_nonblank_credential_keeps_its_bytes_unless_its_raw_trim_is_selected() {
    let pair = |n: &str, v: &str| vec![(n.to_string(), v.to_string())];
    for (style, settings, name, own, caller) in [
        (API_KEY, "{}", "api-key", " \t sk-1 \t ", "\t sk-1  "),
        (
            BEARER,
            "{}",
            "authorization",
            "Bearer  \t sk-1 \t ",
            "Bearer \t sk-1  ",
        ),
        (
            X_GOOG_API_KEY,
            "{}",
            "x-goog-api-key",
            " \t sk-1 \t ",
            "\t sk-1  ",
        ),
        (QUERY_KEY, "{}", "key", " \t sk-1 \t ", "\t sk-1  "),
        (
            API_KEY,
            r#"{"own":{"header":"api-key","trim_start":true},"passthrough":{"header":"api-key","trim_start":true}}"#,
            "api-key",
            "sk-1 \t ",
            "sk-1  ",
        ),
    ] {
        let (b, _) = open(style, Some(" \t sk-1 \t "), settings);
        let b = b.expect("opens");
        assert_eq!(b.own().plain(), pair(name, own), "own {style} {settings}");
        assert_eq!(
            b.passthrough("\t sk-1  ").plain(),
            pair(name, caller),
            "passthrough {style} {settings}"
        );
    }
    for style in [BEARER, API_KEY, QUERY_KEY] {
        let (b, notes) = open(style, Some(" \t "), "{}");
        let b = b.expect("opens");
        assert!(
            b.own().is_empty(),
            "{style}: a blank credential presents nothing"
        );
        assert!(
            notes.is_empty(),
            "{style}: and is no unpresentable credential"
        );
        assert!(b.passthrough(" \t").is_empty());
        assert!(!b.present_passthrough("  ", |_, _| panic!("emitted")));
        assert_eq!(b.passthrough_note("  "), None);
    }
}

/// A family prefix with leading whitespace can never match (the credential is trimmed before the
/// prefix test), so it is refused by name at open rather than left a silently dead row.
#[test]
fn a_family_prefix_with_leading_whitespace_is_refused_by_name() {
    for prefix in [" sk-ant-", "\\tsk-ant-", "\u{00a0}sk-ant-"] {
        let settings = format!(r#"{{"families":[{{"prefix":"{prefix}","header":"x-api-key"}}]}}"#);
        assert_eq!(
            lines(open(BEARER, Some("k"), &settings).0),
            ["settings: outbound auth setting `families[0].prefix` must not start with whitespace"],
            "{settings}"
        );
    }
}

/// F2: a present-but-blank top-level `header` / `param` / `protocol` is refused by name like the
/// nested ones; absent (or null) keeps the default.
#[test]
fn a_blank_top_level_string_setting_is_refused_by_name() {
    for (style, key) in [
        (API_KEY, "header"),
        (X_GOOG_API_KEY, "header"),
        (QUERY_KEY, "param"),
        (BEARER, "protocol"),
        (API_KEY, "protocol"),
    ] {
        for blank in ["", "  ", "\\t"] {
            let settings = format!(r#"{{"{key}":"{blank}"}}"#);
            assert_eq!(
                lines(open(style, Some("k"), &settings).0),
                [format!(
                    "settings: outbound auth setting `{key}` must not be blank"
                )],
                "{style} {settings}"
            );
        }
        let settings = format!(r#"{{"{key}":null}}"#);
        assert!(open(style, Some("k"), &settings).0.is_ok(), "{settings}");
    }
}

#[test]
fn a_blank_family_prefix_is_refused_by_name() {
    for prefix in ["", " ", "\\t"] {
        let settings = format!(r#"{{"families":[{{"prefix":"sk-"}},{{"prefix":"{prefix}"}}]}}"#);
        assert_eq!(
            lines(open(BEARER, Some("k"), &settings).0),
            ["settings: outbound auth setting `families[1].prefix` must not be blank"],
            "{settings}"
        );
    }
}

#[test]
fn param_and_protocol_are_validated() {
    for bad in [
        "a b",
        "a=b",
        "a&b",
        "a#b",
        "a\\nb",
        "a\\u0000b",
        "a\\u007fb",
        "é",
    ] {
        let settings = format!(r#"{{"param":"{bad}"}}"#);
        assert_eq!(
            lines(open(QUERY_KEY, Some("k"), &settings).0),
            ["settings: outbound auth setting `param` is not a query parameter name"],
            "{settings}"
        );
    }
    for good in ["key", "api_key", "api-key", "X.Key~1"] {
        let settings = format!(r#"{{"param":"{good}"}}"#);
        assert!(
            open(QUERY_KEY, Some("k"), &settings).0.is_ok(),
            "{settings}"
        );
    }
    for bad in ["a\\nb", "a\\r\\nb", "a\\u0000b", "a\\u001bb", "a\\u007fb"] {
        let settings = format!(r#"{{"protocol":"{bad}"}}"#);
        assert_eq!(
            lines(open(BEARER, Some("k"), &settings).0),
            ["settings: outbound auth setting `protocol` has a control character"],
            "{settings}"
        );
    }
    assert!(open(BEARER, Some("k"), r#"{"protocol":"open ai-1"}"#)
        .0
        .is_ok());
}

#[test]
fn framing_and_routing_fields_are_not_credential_carriers_in_any_presentation() {
    for name in [
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Keep-Alive",
        "TE",
        "Trailer",
        "Upgrade",
        "Proxy-Connection",
    ] {
        for (style, settings) in [
            (API_KEY, serde_json::json!({"header":name})),
            (X_GOOG_API_KEY, serde_json::json!({"header":name})),
            (BEARER, serde_json::json!({"own":{"header":name}})),
            (BEARER, serde_json::json!({"passthrough":{"header":name}})),
            (
                BEARER,
                serde_json::json!({"families":[{"prefix":"sk-","header":name}]}),
            ),
        ] {
            let errors = lines(open(style, Some("CREDENTIAL-CANARY"), &settings.to_string()).0);
            assert!(
                errors
                    .iter()
                    .any(|line| line.contains("credential carrier")),
                "{name}: {errors:?}"
            );
            assert!(errors
                .iter()
                .all(|line| !line.contains("CREDENTIAL-CANARY")));
        }
    }
    for name in [
        "Authorization",
        "X-API-Key",
        "Proxy-Authorization",
        "Cookie",
        "x-custom-key",
    ] {
        let settings = serde_json::json!({"header":name}).to_string();
        let binding = open(API_KEY, Some("safe-key"), &settings).0.unwrap();
        assert_eq!(
            binding.own().plain(),
            [(name.to_ascii_lowercase(), "safe-key".to_string())]
        );
    }
    assert_eq!(
        own(open(
            QUERY_KEY,
            Some("safe-key"),
            r#"{"param":"Host"}"#
        )
        .0),
        [(
            "Host".to_string(),
            "safe-key".to_string()
        )]
    );
}

#[test]
fn unicode_whitespace_removed_by_the_selected_raw_trim_is_absence_not_invalid_bytes() {
    for whitespace in ["\u{2003}", "\u{3000}", "\u{00a0}", " \t\u{2003}\t "] {
        let settings = r#"{"own":{"header":"x-key","trim_start":true},"passthrough":{"header":"x-key","trim_start":true}}"#;
        let binding = open(API_KEY, Some(whitespace), settings).0.unwrap();
        assert!(binding.own().is_empty());
        assert!(
            binding.own_note().is_none(),
            "whitespace has no invalid header byte"
        );
        assert!(binding.passthrough(whitespace).is_empty());
        assert!(binding.passthrough_note(whitespace).is_none());
    }
    let binding = open(API_KEY, Some("\u{2003}sk-key"), r#"{"own":{"header":"x-key","trim_start":true},"passthrough":{"header":"x-key","trim_start":true}}"#).0.unwrap();
    assert_eq!(
        binding.own().plain(),
        [("x-key".to_string(), "sk-key".to_string())]
    );
    assert_eq!(
        binding.passthrough("\u{2003}sk-key").plain(),
        [("x-key".to_string(), "sk-key".to_string())]
    );
    let retained = open(API_KEY, Some("\u{2003}sk-key"), r#"{"header":"x-key"}"#)
        .0
        .unwrap();
    assert_eq!(
        retained.own().plain(),
        [("x-key".to_string(), "\u{2003}sk-key".to_string())]
    );
}

#[test]
fn malformed_nested_settings_are_refused_without_echoing_values_and_null_defaults_remain_valid() {
    for settings in [
        serde_json::json!({"own":{"header":17}}),
        serde_json::json!({"passthrough":{"trim_start":"SETTINGS-CANARY"}}),
        serde_json::json!({"families":[{"prefix":"sk-","unknown":"SETTINGS-CANARY"}]}),
        serde_json::json!({"families":[{"prefix":17}]}),
        serde_json::json!({"own":{"header":"x-key","unknown":"SETTINGS-CANARY"}}),
        serde_json::json!({"protocol":"SETTINGS-CANARY\nINJECT"}),
    ] {
        let errors = lines(open(BEARER, Some("CREDENTIAL-CANARY"), &settings.to_string()).0);
        assert!(!errors.is_empty());
        assert!(
            errors
                .iter()
                .all(|error| !error.contains("SETTINGS-CANARY")
                    && !error.contains("CREDENTIAL-CANARY")),
            "{errors:?}"
        );
    }
    for style in [BEARER, API_KEY, X_GOOG_API_KEY, QUERY_KEY] {
        let settings = if style == QUERY_KEY {
            r#"{"param":null}"#
        } else {
            r#"{"families":null,"own":null,"passthrough":null,"protocol":null}"#
        };
        assert!(open(style, Some("key"), settings).0.is_ok());
    }
}

/// `trim_start` WITH NO `header` IS REFUSED BY NAME: a presentation without `header` is a bearer,
/// which is never trimmed, so `{"own":{"trim_start":true}}` under `api-key` must not quietly present
/// `authorization: Bearer <key>` in place of the trimmed `api-key` header the operator asked for.
#[test]
fn a_trim_start_with_no_header_is_refused_by_name() {
    for (style, settings, setting) in [
        (API_KEY, r#"{"own":{"trim_start":true}}"#, "own"),
        (
            API_KEY,
            r#"{"passthrough":{"trim_start":true}}"#,
            "passthrough",
        ),
        (
            BEARER,
            r#"{"own":{"header":null,"trim_start":true}}"#,
            "own",
        ),
        (
            X_GOOG_API_KEY,
            r#"{"families":[{"prefix":"sk-","header":"x-key"},{"prefix":"tok-","trim_start":true}]}"#,
            "families[1]",
        ),
    ] {
        assert_eq!(
            lines(open(style, Some("k"), settings).0),
            [format!(
                "settings: outbound auth setting `{setting}.trim_start` applies only to a raw \
                 header: `{setting}` names no `header`, so it presents a bearer"
            )],
            "{style} {settings}"
        );
    }
    // No `header` and no `trim_start` is the contract's bearer (a dialect's passthrough default).
    assert_eq!(
        own(open(
            API_KEY,
            Some("k"),
            r#"{"own":{},"passthrough":{"trim_start":false}}"#
        )
        .0),
        vec![("authorization".to_string(), "Bearer k".to_string())]
    );
    assert!(open(
        API_KEY,
        Some("k"),
        r#"{"own":{"header":"x-key","trim_start":true}}"#
    )
    .0
    .is_ok());
}

/// A caller's unpresentable credential is noted by the PASSTHROUGH presentation: as the query
/// parameter on `query-key`, and as the passthrough header (not the own one) where they differ.
#[test]
fn a_callers_unpresentable_credential_is_noted_by_its_passthrough_presentation() {
    let query = open(QUERY_KEY, None, "{}").0.expect("opens");
    assert_eq!(
        query.passthrough_note("bad\nkey"),
        Some(Note::Query(QUERY_KEY_DEFAULT_PARAM.to_string()))
    );
    let named = open(QUERY_KEY, None, r#"{"param":"api_key"}"#)
        .0
        .expect("opens");
    assert_eq!(
        named.passthrough_note("bad\nkey"),
        Some(Note::Query("api_key".to_string()))
    );
    let split = open(
        API_KEY,
        Some("bad\nown"),
        r#"{"own":{"header":"x-own"},"passthrough":{"header":"x-caller"}}"#,
    )
    .0
    .expect("opens");
    assert_eq!(split.own_note(), Some(&Note::Header("x-own".to_string())));
    assert_eq!(
        split.passthrough_note("bad\ncaller"),
        Some(Note::Header("x-caller".to_string()))
    );
}

/// A note names the field it omits: a bearer's is `authorization`, never an empty name.
#[test]
fn a_bearer_note_names_the_authorization_header() {
    assert_eq!(
        Note::Bearer("openai".to_string()).names(),
        ("authorization", "openai")
    );
    assert_eq!(
        Note::Header("x-api-key".to_string()).names(),
        ("x-api-key", "")
    );
    assert_eq!(Note::Query("key".to_string()).names(), ("key", ""));
    assert_eq!(
        Note::Family("p".to_string(), "x-k".to_string()).names(),
        ("x-k", "p")
    );
}
