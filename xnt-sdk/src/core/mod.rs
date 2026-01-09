//! Shared core types and logic for FFI and NAPI bindings.
//!
//! This module contains the actual implementation that both
//! FFI and NAPI wrappers use. No platform-specific code here.

pub mod address;
pub mod crypto;
pub mod error;
pub mod json_rpc;
pub mod sync;
pub mod transaction;
pub mod types;
pub mod utxo;
pub mod wallet;

pub use address::*;
pub use crypto::*;
pub use error::*;
pub use json_rpc::*;
pub use sync::*;
pub use transaction::*;
pub use types::*;
pub use utxo::*;
pub use wallet::*;
