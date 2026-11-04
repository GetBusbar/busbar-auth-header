// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test-only helpers shared by the side test modules: a presented field's bytes as text.

use busbar_contract::abi::sdk::cred::{Cred, Parts, SealedWrite};

use crate::present::Field;

/// The bytes a presented field's sealed value writes, as text.
pub(crate) fn field_text(value: &Cred) -> String {
    let mut wire = SealedWrite::new(Parts::new().sealed(value.field()));
    let mut bytes = Vec::new();
    let answer =
        busbar_contract::abi::sdk::test_support::chip::drive_sealed::<()>(&mut wire, |part| {
            bytes.extend_from_slice(part);
            std::task::Poll::Ready(Ok(part.len()))
        });
    assert!(answer.is_ready());
    String::from_utf8(bytes).expect("a header value is text")
}

/// The fields as plain pairs, to compare (test-only; the plugin holds them wiped on drop).
pub(crate) trait Plain {
    fn plain(&self) -> Vec<(String, String)>;
}

impl Plain for [Field] {
    fn plain(&self) -> Vec<(String, String)> {
        self.iter()
            .map(|(n, v)| (n.clone(), field_text(v)))
            .collect()
    }
}
