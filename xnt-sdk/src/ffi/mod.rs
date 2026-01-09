//! Pure C FFI bindings for xnt-core
//!
//! Manual memory management with *_free functions.

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

// Re-export all public items
pub use address::*;
pub use crypto::*;
pub use error::*;
pub use helpers::*;
pub use json_rpc::*;
pub use seed::*;
pub use sync::*;
pub use transaction::*;
pub use types::*;
pub use utxo::*;
