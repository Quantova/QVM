#![forbid(unsafe_code)]
#![allow(clippy::chunks_exact_to_as_chunks)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::assertions_on_constants)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod abi;
pub mod asm;
pub mod container;
pub mod crypto;
pub mod interp;
pub mod isa;
pub mod meter;
pub mod state;
