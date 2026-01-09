//! FFI macros for reducing boilerplate
//!
//! Common patterns across FFI functions.

/// Generate a free function for an opaque handle type
/// Usage: ffi_free!(xnt_wallet_free, WalletHandle);
#[macro_export]
macro_rules! ffi_free {
    ($fn_name:ident, $handle_type:ty) => {
        #[no_mangle]
        pub extern "C" fn $fn_name(handle: *mut $handle_type) {
            if !handle.is_null() {
                unsafe { drop(Box::from_raw(handle)) }
            }
        }
    };
}

/// Convert string to CString and return raw pointer
/// Returns null on failure, optionally sets error
/// Usage: ffi_cstring!(string_expr) or ffi_cstring!(string_expr, "error msg")
#[macro_export]
macro_rules! ffi_cstring {
    ($str:expr) => {
        std::ffi::CString::new($str)
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut())
    };
    ($str:expr, $msg:expr) => {
        std::ffi::CString::new($str).map(|c| c.into_raw()).unwrap_or_else(|e| {
            $crate::ffi::error::set_last_error(&format!("{}: {e}", $msg));
            std::ptr::null_mut()
        })
    };
}

/// Make JSON-RPC call and return null type on error
/// Usage: rpc_try!(client, "method", params, NullType::null())
#[macro_export]
macro_rules! rpc_try {
    ($client:expr, $method:expr, $params:expr, $null:expr) => {
        match $crate::json_rpc::rpc_call($client, $method, $params) {
            Ok(r) => r,
            Err(e) => {
                $crate::ffi::error::set_last_error(&e);
                return $null;
            }
        }
    };
}

/// Free a Vec that was converted to raw parts
/// Usage: free_vec!(ptr, len) or free_vec!(ptr, len, cap)
#[macro_export]
macro_rules! free_vec {
    ($ptr:expr, $len:expr) => {
        if !$ptr.is_null() && $len > 0 {
            unsafe { drop(Vec::from_raw_parts($ptr, $len, $len)) }
        }
    };
    ($ptr:expr, $len:expr, $cap:expr) => {
        if !$ptr.is_null() && $len > 0 {
            unsafe { drop(Vec::from_raw_parts($ptr, $len, $cap)) }
        }
    };
}

/// Check pointer is not null, return error if null
/// Usage: check_null!(ptr, "message", std::ptr::null_mut());
#[macro_export]
macro_rules! check_null {
    ($ptr:expr, $msg:expr, $ret:expr) => {
        if $ptr.is_null() {
            $crate::ffi::error::set_last_error($msg);
            return $ret;
        }
    };
    // Shorthand for pointer return
    ($ptr:expr, $msg:expr) => {
        check_null!($ptr, $msg, std::ptr::null_mut())
    };
    // Shorthand for XntErrorCode return
    ($ptr:expr) => {
        check_null!($ptr, "null pointer", $crate::ffi::error::XntErrorCode::NullPointer)
    };
}

/// FFI function preamble: clear error + null checks
/// Usage: ffi_begin!(handle1, handle2);
#[macro_export]
macro_rules! ffi_begin {
    () => {
        $crate::ffi::error::clear_last_error();
    };
    ($($ptr:expr),+ $(,)?) => {
        $crate::ffi::error::clear_last_error();
        $(
            check_null!($ptr);
        )+
    };
}

/// Wrap Result into FFI pointer, setting error on Err
/// Usage: ffi_result!(result, Handle, "operation failed");
#[macro_export]
macro_rules! ffi_result {
    ($result:expr, $handle:ident) => {
        match $result {
            Ok(val) => Box::into_raw(Box::new($handle(val))),
            Err(e) => {
                $crate::ffi::error::set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    };
    ($result:expr, $handle:ident, $msg:expr) => {
        match $result {
            Ok(val) => Box::into_raw(Box::new($handle(val))),
            Err(e) => {
                $crate::ffi::error::set_last_error(&format!("{}: {e}", $msg));
                std::ptr::null_mut()
            }
        }
    };
}

/// Copy fixed-size bytes to output buffer
/// Usage: copy_bytes_out!(bytes, out, 40);
#[macro_export]
macro_rules! copy_bytes_out {
    ($src:expr, $dst:expr, $len:expr) => {{
        unsafe { std::ptr::copy_nonoverlapping($src.as_ptr(), $dst, $len) };
        $crate::ffi::error::XntErrorCode::Ok
    }};
}

/// Dereference FFI handle safely
/// Usage: let wallet = ffi_ref!(handle);
#[macro_export]
macro_rules! ffi_ref {
    ($handle:expr) => {
        unsafe { &*$handle }
    };
}

/// Dereference FFI handle mutably
#[macro_export]
macro_rules! ffi_mut {
    ($handle:expr) => {
        unsafe { &mut *$handle }
    };
}

/// Allocate ByteBuffer and return raw pointer
/// Usage: ffi_buffer!(vec_data) or ffi_buffer!(vec_data, "error msg")
#[macro_export]
macro_rules! ffi_buffer {
    ($vec:expr) => {
        $crate::ffi::types::ByteBuffer::from_vec($vec).into_ptr()
    };
    ($result:expr, $msg:expr) => {
        match $result {
            Ok(vec) => $crate::ffi::types::ByteBuffer::from_vec(vec).into_ptr(),
            Err(e) => {
                $crate::ffi::error::set_last_error(&format!("{}: {e}", $msg));
                std::ptr::null_mut()
            }
        }
    };
}

/// Serialize to ByteBuffer using bincode
/// Usage: ffi_serialize!(obj) or ffi_serialize!(obj, "error msg")
#[macro_export]
macro_rules! ffi_serialize {
    ($obj:expr) => {
        ffi_buffer!(bincode::serialize(&$obj), "serialize failed")
    };
    ($obj:expr, $msg:expr) => {
        ffi_buffer!(bincode::serialize(&$obj), $msg)
    };
}

/// Extract JSON array from RPC result or return null type
/// Usage: rpc_array!(result, "field_name", NullType::null())
#[macro_export]
macro_rules! rpc_array {
    ($result:expr, $field:expr, $null:expr) => {
        match $result.get($field) {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => {
                $crate::ffi::error::set_last_error("invalid response format");
                return $null;
            }
        }
    };
}

/// Check data pointer with length validation
/// Usage: check_data!(ptr, len) or check_data!(ptr, len, $null)
#[macro_export]
macro_rules! check_data {
    ($ptr:expr, $len:expr) => {
        if $ptr.is_null() && $len > 0 {
            $crate::ffi::error::set_last_error("data is null");
            return $crate::ffi::error::XntErrorCode::NullPointer;
        }
    };
    ($ptr:expr, $len:expr, $null:expr) => {
        if $ptr.is_null() && $len > 0 {
            $crate::ffi::error::set_last_error("data is null");
            return $null;
        }
    };
}
