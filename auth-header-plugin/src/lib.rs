// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `header` auth as a droppable busbar plugin: the `cdylib` a signed tarball carries
//! (`kind: auth`, key `header`). The logic crate exposes only its registration entry, and its door
//! (`busbar_auth_header::door`) is exported as this image's one symbol (`export_door!`), so the
//! library carries exactly the door a busbar build links.

#![deny(unsafe_code)]

pub use busbar_auth_header::{door, MACRO_DOOR};

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_auth_header::door);
}
