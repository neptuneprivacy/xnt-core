//! Error types for xnt-ffi

use thiserror::Error;

/// Error type for xnt-ffi operations
#[derive(Debug, Error)]
pub enum XntError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("crypto error: {0}")]
    CryptoError(String),

    #[error("encoding error: {0}")]
    EncodingError(String),

    #[error("rpc error: {0}")]
    RpcError(String),

    #[error("transaction error: {0}")]
    TransactionError(String),

    #[error("sync error: {0}")]
    SyncError(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, XntError>;
