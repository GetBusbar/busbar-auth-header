// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The static styles, ported from the identity unit's `egress_auth/tests.rs` in the kernel and
//! `declared_tests.rs`: the same vectors, now asserted on the headers the plugin builds.

use super::*;

use crate::test_support::Plain;
use busbar_contract::header::is_legal_header_value;

/// Keys, and whether the wire admits them (the `HeaderValue::from_str` rule).
const KEY_VECTORS: &[(&str, bool)] = &[
    ("sk-test-123", true),
    ("", true),
    ("sk\tkey", true),
    ("klucz-\u{142}-\u{e9}", true),
    ("sk\r\ninjected", false),
    ("sk\nkey", false),
    ("sk\u{0}key", false),
    ("sk\u{1}key", false),
    ("sk\u{7f}key", false),
];

/// Bearer: `authorization: Bearer <key>` for every key the wire admits, nothing for the rest.
#[test]
fn bearer_builder_presents_every_admitted_key_and_omits_the_rest() {
    for &(key, legal) in KEY_VECTORS {
        let expected = if legal && !key.is_empty() {
            vec![("authorization".to_string(), format!("Bearer {key}"))]
        } else {
            Vec::new()
        };
        assert_eq!(
            StaticScheme::uniform(Presentation::BEARER)
                .present(key, Mode::Own)
                .plain(),
            expected,
            "the bearer style, key {key:?}"
        );
    }
}

/// The custom-header builder carries the raw key verbatim under the declared name, with the same
/// omission rule, and the style presents exactly the builder's bytes.
#[test]
fn custom_header_builder_presents_the_raw_key_under_its_own_name() {
    for &(key, legal) in KEY_VECTORS {
        let expected = if legal && !key.is_empty() {
            vec![("x-goog-api-key".to_string(), key.to_string())]
        } else {
            Vec::new()
        };
        assert_eq!(
            StaticScheme::uniform(Presentation::raw("x-goog-api-key"))
                .present(key, Mode::Own)
                .plain(),
            expected,
            "the x-goog-api-key style, key {key:?}"
        );
    }
}

/// `api-key` and `x-goog-api-key` never cross-contaminate each other's header name.
#[test]
fn the_two_custom_header_styles_keep_their_own_names() {
    assert_eq!(
        StaticScheme::uniform(Presentation::raw("api-key"))
            .present("azure-key-xyz", Mode::Own)
            .plain(),
        vec![("api-key".to_string(), "azure-key-xyz".to_string())]
    );
    assert_eq!(
        StaticScheme::uniform(Presentation::raw("x-goog-api-key"))
            .present("goog-key", Mode::Own)
            .plain(),
        vec![("x-goog-api-key".to_string(), "goog-key".to_string())]
    );
}

/// A raw-header key carrying CR/LF is a header-split request smuggled upstream: the style omits it.
#[test]
fn a_custom_header_style_omits_a_key_with_crlf_in_it() {
    for (header, secret) in [
        ("api-key", "azure-key-\r\nX-Forwarded-For: 10.0.0.1"),
        ("x-goog-api-key", "goog-key-\r\ninjected"),
        ("api-key", "azure-key-\u{0}-nul"),
    ] {
        assert!(
            StaticScheme::uniform(Presentation::raw(header))
                .present(secret, Mode::Own)
                .plain()
                .is_empty(),
            "{header} put an un-encodable key on the wire"
        );
    }
}

/// The legality rule is the `HeaderValue::from_str` rule, written out over every ASCII byte
/// ([`busbar_contract::header::is_legal_header_value`], the shared pure helper this crate uses).
#[test]
fn header_value_rule_is_the_header_value_type_rule() {
    for b in 0u8..=0x7F {
        let refused = (b < 0x20 && b != b'\t') || b == 0x7F;
        let s = format!("k{}k", b as char);
        assert_eq!(is_legal_header_value(&s), !refused, "byte {b:#04x}");
    }
    for &(key, legal) in KEY_VECTORS {
        assert_eq!(is_legal_header_value(key), legal, "key {key:?}");
    }
}

/// A dialect's credential-family table (as a dialect declares one): an API key
/// presents as `x-api-key` with its leading whitespace trimmed, an OAuth token as a bearer, and a
/// credential of neither family by the mode — own as `x-api-key`, a caller's as a bearer.
fn family_scheme() -> StaticScheme {
    StaticScheme {
        families: vec![
            Family {
                prefix: "sk-ant-api".to_string(),
                presented: Presentation {
                    header: Some("x-api-key".to_string()),
                    trim_start: true,
                },
            },
            Family {
                prefix: "sk-ant-oat".to_string(),
                presented: Presentation::BEARER,
            },
        ],
        own: Presentation::raw("x-api-key"),
        passthrough: Presentation::BEARER,
    }
}

#[test]
fn a_family_table_presents_by_prefix_then_by_mode() {
    let s = family_scheme();
    assert_eq!(
        s.present("  sk-ant-api03-abc", Mode::Own).plain(),
        vec![("x-api-key".to_string(), "sk-ant-api03-abc".to_string())],
        "an API key: x-api-key, leading whitespace trimmed"
    );
    assert_eq!(
        s.present("sk-ant-api03-abc", Mode::Passthrough).plain(),
        vec![("x-api-key".to_string(), "sk-ant-api03-abc".to_string())],
        "the family decides whatever the mode"
    );
    assert_eq!(
        s.present("sk-ant-oat01-xyz", Mode::Own).plain(),
        vec![(
            "authorization".to_string(),
            "Bearer sk-ant-oat01-xyz".to_string()
        )]
    );
    assert_eq!(
        s.present("other", Mode::Own).plain(),
        vec![("x-api-key".to_string(), "other".to_string())],
        "no family, own: the own presentation"
    );
    assert_eq!(
        s.present("other", Mode::Passthrough).plain(),
        vec![("authorization".to_string(), "Bearer other".to_string())],
        "no family, a caller's: the passthrough presentation"
    );
}

/// Overlapping rows: the first matching row wins, not the most specific or the last.
#[test]
fn the_first_matching_family_row_wins() {
    let s = StaticScheme {
        families: vec![
            Family {
                prefix: "sk-".to_string(),
                presented: Presentation::BEARER,
            },
            Family {
                prefix: "sk-ant-".to_string(),
                presented: Presentation::raw("x-api-key"),
            },
        ],
        own: Presentation::raw("x-own"),
        passthrough: Presentation::BEARER,
    };
    assert_eq!(
        s.present("sk-ant-x", Mode::Own).plain(),
        vec![("authorization".to_string(), "Bearer sk-ant-x".to_string())],
        "the broader first row wins over the narrower later one"
    );
}

/// The family table reads as settings data, exactly the shape the kernel resolves at seal.
#[test]
fn a_family_table_reads_from_settings_json() {
    let families: Vec<Family> = serde_json::from_str(
        r#"[{"prefix":"sk-ant-api","header":"x-api-key","trim_start":true},{"prefix":"sk-ant-oat"}]"#,
    )
    .expect("the family table parses");
    assert_eq!(families, family_scheme().families);
}

#[test]
fn nonblank_opaque_credentials_preserve_spaces_and_tabs_in_both_modes() {
    for credential in [
        " leading",
        "trailing ",
        "\tleading\t",
        "  sk-ant-api03-abc",
        " sk-ant-oat01-abc",
    ] {
        for mode in [Mode::Own, Mode::Passthrough] {
            assert_eq!(
                StaticScheme::uniform(Presentation::BEARER)
                    .present(credential, mode)
                    .plain(),
                vec![("authorization".into(), format!("Bearer {credential}"))]
            );
            for header in ["api-key", "x-goog-api-key", "x-api-key"] {
                assert_eq!(
                    StaticScheme::uniform(Presentation::raw(header))
                        .present(credential, mode)
                        .plain(),
                    vec![(header.into(), credential.into())]
                );
            }
            let selected = Presentation {
                header: Some("x-api-key".into()),
                trim_start: true,
            };
            assert_eq!(
                StaticScheme::uniform(selected)
                    .present(credential, mode)
                    .plain(),
                vec![("x-api-key".into(), credential.trim_start().into())]
            );
        }
    }
}
