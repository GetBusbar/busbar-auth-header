// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed schema and the real lifecycle validator agree on representative settings.

use super::*;
use serde_json::{json, Value};

fn check(cases: &[(Value, bool)]) {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("valid settings schema");
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    for (settings, accepted) in cases {
        let bytes = serde_json::to_vec(settings).expect("settings JSON");
        assert_eq!(
            validator.is_valid(settings),
            *accepted,
            "schema: {settings}"
        );
        assert_eq!(<instance::Header as busbar_contract::abi::sdk::auth_outbound::OutboundPlugin>::validate(&bytes).is_ok(), *accepted, "lifecycle: {settings}");
    }
}

#[test]
fn settings_schema_matches_key_only_lifecycle() {
    check(&[
        (json!({}), true),
        (
            json!({"header":"x-api-key","families":[],"protocol":"http"}),
            true,
        ),
        // Lifecycle admits these values; the selected outbound binding validates them later.
        (
            json!({"header":42,"families":false,"own":null,"passthrough":[]}),
            true,
        ),
        (
            json!({"param":{},"token_url":false,"token_uri":[],"scope":4,"subject":null}),
            true,
        ),
        (json!({"unknown":null}), false),
        (json!({"credential":"secret"}), false),
        (json!([]), false),
        (Value::Null, false),
    ]);
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    for key in schema["properties"].as_object().unwrap().keys() {
        assert!(style::known_key(key), "schema invented {key}");
    }
}
