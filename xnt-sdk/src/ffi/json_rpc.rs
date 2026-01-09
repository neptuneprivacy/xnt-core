//! JSON-RPC client FFI
//!
//! Wraps core::RpcClient for C FFI.

use std::ffi::c_char;

use crate::core::RpcClient;

use super::error::{set_last_error, XntErrorCode};
use super::helpers::parse_cstr;

/// Opaque handle to RPC client
pub struct RpcClientHandle(pub(crate) RpcClient);

/// Create RPC client
#[no_mangle]
pub extern "C" fn xnt_rpc_client_create(url: *const c_char) -> *mut RpcClientHandle {
    xnt_rpc_client_create_with_auth(url, std::ptr::null(), std::ptr::null())
}

/// Create RPC client with optional basic auth
#[no_mangle]
pub extern "C" fn xnt_rpc_client_create_with_auth(
    url: *const c_char,
    username: *const c_char,
    password: *const c_char,
) -> *mut RpcClientHandle {
    ffi_begin!();

    let Some(url_str) = parse_cstr(url) else {
        set_last_error("invalid url");
        return std::ptr::null_mut();
    };

    let auth = parse_cstr(username).zip(parse_cstr(password));

    match RpcClient::with_auth(&url_str, auth) {
        Ok(client) => Box::into_raw(Box::new(RpcClientHandle(client))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

ffi_free!(xnt_rpc_client_free, RpcClientHandle);

/// Make a JSON-RPC call
/// Returns result as JSON string, caller must free with xnt_string_free()
#[no_mangle]
pub extern "C" fn xnt_rpc_call(
    client: *const RpcClientHandle,
    method: *const c_char,
    params_json: *const c_char,
) -> *mut c_char {
    ffi_begin!();
    check_null!(client, "null client");

    let Some(method_str) = parse_cstr(method) else {
        set_last_error("invalid method");
        return std::ptr::null_mut();
    };

    let params: serde_json::Value = if params_json.is_null() {
        serde_json::json!({})
    } else {
        let Some(params_str) = parse_cstr(params_json) else {
            set_last_error("invalid params");
            return std::ptr::null_mut();
        };
        match serde_json::from_str(&params_str) {
            Ok(v) => v,
            Err(e) => {
                set_last_error(&format!("invalid params JSON: {e}"));
                return std::ptr::null_mut();
            }
        }
    };

    let client = ffi_ref!(client);
    match client.0.call(&method_str, params) {
        Ok(result) => {
            let json_str = serde_json::to_string(&result).unwrap_or_default();
            ffi_cstring!(json_str)
        }
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Check if RPC client is connected (simple ping)
#[no_mangle]
pub extern "C" fn xnt_rpc_client_ping(client: *const RpcClientHandle) -> XntErrorCode {
    ffi_begin!();
    check_null!(client);

    let client = ffi_ref!(client);
    match client.0.ping() {
        Ok(_) => XntErrorCode::Ok,
        Err(e) => {
            set_last_error(&format!("{e}"));
            XntErrorCode::NetworkError
        }
    }
}

/// Get current chain height
#[no_mangle]
pub extern "C" fn xnt_rpc_chain_height(client: *const RpcClientHandle) -> i64 {
    if client.is_null() {
        return -1;
    }

    let client = ffi_ref!(client);
    match client.0.chain_height() {
        Ok(height) => height as i64,
        Err(e) => {
            set_last_error(&format!("{e}"));
            -1
        }
    }
}
