//! JSON-RPC client for FFI
//!
//! Reusable RPC client for all JSON-RPC interactions with Neptune nodes.

use std::ffi::c_char;
use std::time::Duration;

use serde_json::{json, Value};

use crate::error::{set_last_error, XntErrorCode};
use crate::helpers::parse_cstr;

/// JSON-RPC client handle
pub struct RpcClientHandle {
    pub(crate) url: String,
    pub(crate) client: reqwest::blocking::Client,
    pub(crate) auth: Option<(String, String)>,
}

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

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .tcp_keepalive(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(10))  // Short idle timeout to avoid stale connections
        .pool_max_idle_per_host(0)  // Don't keep idle connections
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("failed to create client: {e}"));
            return std::ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(RpcClientHandle { url: url_str, client, auth }))
}

ffi_free!(xnt_rpc_client_free, RpcClientHandle);

/// Make a JSON-RPC call and return the result
pub fn rpc_call(client: &RpcClientHandle, method: &str, params: Value) -> Result<Value, String> {
    let request = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    // Pre-serialize JSON to avoid issues with large bodies in .json() method
    let body = serde_json::to_vec(&request).map_err(|e| format!("JSON serialize failed: {e}"))?;
    let body_len = body.len();

    let mut req_builder = client.client
        .post(&client.url)
        .header("Content-Type", "application/json")
        .header("Content-Length", body_len.to_string())
        .body(body);

    if let Some((ref username, ref password)) = client.auth {
        req_builder = req_builder.basic_auth(username, Some(password));
    }

    let response = req_builder
        .send()
        .map_err(|e| {
            // Include underlying cause for better debugging
            let mut msg = format!("request failed: {e}");
            if let Some(source) = std::error::Error::source(&e) {
                msg.push_str(&format!(" (cause: {source})"));
            }
            if e.is_timeout() {
                msg.push_str(" [timeout]");
            }
            if e.is_connect() {
                msg.push_str(" [connection]");
            }
            if e.is_request() {
                msg.push_str(" [request build]");
            }
            msg
        })?;

    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()));
    }

    let json: Value = response.json().map_err(|e| format!("parse failed: {e}"))?;

    if let Some(error) = json.get("error") {
        let msg = error.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        return Err(format!("RPC error: {msg}"));
    }

    json.get("result").cloned().ok_or_else(|| "missing result".to_string())
}

/// Make a JSON-RPC call (FFI wrapper)
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

    let params: Value = if params_json.is_null() {
        json!({})
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
    match rpc_call(client, &method_str, params) {
        Ok(result) => {
            let json_str = serde_json::to_string(&result).unwrap_or_default();
            ffi_cstring!(json_str)
        }
        Err(e) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
    }
}

/// Check if RPC client is connected (simple ping via chain_height)
#[no_mangle]
pub extern "C" fn xnt_rpc_client_ping(client: *const RpcClientHandle) -> XntErrorCode {
    ffi_begin!();
    check_null!(client);

    let client = ffi_ref!(client);
    match rpc_call(client, "chain_height", json!({})) {
        Ok(_) => XntErrorCode::Ok,
        Err(e) => {
            set_last_error(&e);
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
    match rpc_call(client, "chain_height", json!({})) {
        Ok(result) => result.get("blockHeight")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1),
        Err(e) => {
            set_last_error(&e);
            -1
        }
    }
}
