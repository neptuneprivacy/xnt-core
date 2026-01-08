//! XNT-FFI: C bindings for Neptune Privacy Core
//!
//! Provides offline signing capabilities for mobile/desktop wallets.
//!
//! ## Types
//!
//! All complex types are opaque handles wrapping xnt-core types:
//! - `WalletEntropyHandle` - wraps `WalletEntropy`
//! - `SpendingKeyHandle` - wraps `GenerationSpendingKey`
//! - `AddressHandle` - wraps `GenerationReceivingAddress`
//! - `UtxoHandle` - wraps `Utxo`
//!
//! ## Memory Management
//!
//! Every `*_create` or `*_new` function has a corresponding `*_free` function.
//! Caller is responsible for freeing allocated memory.

// Macros must be declared before modules that use them
#[macro_use]
pub mod macros;

pub mod address;
pub mod crypto;
pub mod error;
pub mod helpers;
pub mod json_rpc;
pub mod seed;
pub mod sync;
pub mod transaction;
pub mod types;
pub mod utxo;

pub use address::*;
pub use crypto::*;
pub use error::*;
pub use json_rpc::*;
pub use seed::*;
pub use sync::*;
pub use transaction::*;
pub use types::*;
pub use utxo::*;

/// Library version
#[no_mangle]
pub extern "C" fn xnt_version() -> *const std::ffi::c_char {
    // Using byte string with null terminator for cbindgen compatibility
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const std::ffi::c_char
}
