//! XNT-SDK: Bindings for Neptune Privacy Core
//!
//! Provides offline signing capabilities for mobile/desktop wallets.
//!
//! # Features
//!
//! - `ffi`: Pure C FFI with manual memory management
//! - `napi`: Node.js native module via napi-rs (automatic GC)

#[cfg(all(feature = "ffi", feature = "napi"))]
compile_error!("Features 'ffi' and 'napi' are mutually exclusive");

pub mod core;

#[cfg(feature = "ffi")]
#[macro_use]
pub mod ffi;

#[cfg(feature = "ffi")]
pub use ffi::*;

#[cfg(feature = "napi")]
pub mod napi;
