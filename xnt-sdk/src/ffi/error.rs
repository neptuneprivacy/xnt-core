//! FFI error handling
//!
//! Thread-local last_error + error codes for robust C interop.

use std::cell::RefCell;
use std::ffi::{c_char, CString};

/// Error codes returned by FFI functions
///
/// `InternalError` is also returned when the library hit an internal error
/// (a Rust panic); the last error message then starts with "internal error".
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

/// Run the body of an exported function. A panic does not unwind into the
/// caller: it sets the last error to "internal error: ..." and returns
/// `on_panic`, which is [XntErrorCode::InternalError] for functions returning
/// an error code and the documented failure value (NULL, false, 0, -1 or an
/// empty result) otherwise.
///
/// Requires the library to be built with `panic = "unwind"` (the default for
/// release builds); with `panic = "abort"` a panic aborts the process.
pub(crate) fn ffi_guard<R>(on_panic: R, body: impl FnOnce() -> R) -> R {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            let detail = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            set_last_error(&format!("internal error: {detail}"));
            on_panic
        }
    }
}

/// Get last error message. Returns NULL if no error.
/// Caller must NOT free this pointer.
#[no_mangle]
pub extern "C" fn xnt_get_last_error() -> *const c_char {
    ffi_guard(std::ptr::null(), || {
        LAST_ERROR.with(|e| match e.borrow().as_ref() {
            Some(msg) => msg.as_ptr(),
            None => std::ptr::null(),
        })
    })
}

/// Clear the last error message
#[no_mangle]
pub extern "C" fn xnt_clear_error() {
    ffi_guard((), || {
        clear_last_error();
    })
}

/// Get library version
#[no_mangle]
pub extern "C" fn xnt_version() -> *const c_char {
    ffi_guard(std::ptr::null(), || {
        static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
        VERSION.as_ptr() as *const c_char
    })
}

// Type aliases for backwards compatibility
pub type WalletHandle = super::seed::WalletEntropyHandle;

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    fn last_error() -> String {
        let ptr = xnt_get_last_error();
        assert!(!ptr.is_null());
        unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string()
    }

    #[test]
    fn a_panic_becomes_an_internal_error() {
        let code = ffi_guard(XntErrorCode::Ok, || -> XntErrorCode { panic!("boom") });
        assert_eq!(XntErrorCode::Ok, code);
        assert_eq!("internal error: boom", last_error());

        let detail = String::from("formatted");
        let ptr = ffi_guard(std::ptr::null_mut(), || -> *mut u8 { panic!("{detail}") });
        assert!(ptr.is_null());
        assert_eq!("internal error: formatted", last_error());

        xnt_clear_error();
        assert_eq!(7, ffi_guard(0, || 7));
        assert!(xnt_get_last_error().is_null());
    }
}
