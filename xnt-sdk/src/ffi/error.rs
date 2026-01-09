//! FFI error handling
//!
//! Thread-local last_error + error codes for robust C interop.

use std::cell::RefCell;
use std::ffi::{c_char, CString};

/// Error codes returned by FFI functions
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XntErrorCode {
    Ok = 0,
    InvalidInput = 1,
    NullPointer = 2,
    InvalidMnemonic = 3,
    InvalidAddress = 4,
    DecryptionFailed = 5,
    EncodingFailed = 6,
    NetworkError = 7,
    InsufficientFunds = 8,
    ProofGenerationFailed = 9,
    DeserializeFailed = 10,
    RpcError = 11,
    InternalError = 99,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

#[allow(dead_code)] // Used in later phases
pub(crate) fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = CString::new(msg).ok();
    });
}

pub(crate) fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

/// Get last error message. Returns NULL if no error.
/// Caller must NOT free this pointer.
#[no_mangle]
pub extern "C" fn xnt_get_last_error() -> *const c_char {
    LAST_ERROR.with(|e| match e.borrow().as_ref() {
        Some(msg) => msg.as_ptr(),
        None => std::ptr::null(),
    })
}

/// Clear the last error message
#[no_mangle]
pub extern "C" fn xnt_clear_error() {
    clear_last_error();
}

/// Get library version
#[no_mangle]
pub extern "C" fn xnt_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

// Type aliases for backwards compatibility
pub type WalletHandle = super::seed::WalletEntropyHandle;
