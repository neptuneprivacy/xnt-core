//! JSON-RPC client for Neptune nodes
//!
//! Shared RPC client logic for both FFI and NAPI bindings.

use std::time::Duration;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::error::{Result, XntError};

/// RPC client for Neptune node communication
#[derive(Clone)]
pub struct RpcClient {
    pub(crate) url: String,
    pub(crate) client: reqwest::blocking::Client,
    /// Auth credentials with password zeroized on drop
    pub(crate) auth: Option<(String, Zeroizing<String>)>,
}

impl RpcClient {
    /// Create new RPC client
    pub fn new(url: &str) -> Result<Self> {
        Self::with_auth(url, None)
    }

    /// Create RPC client with optional basic auth
    pub fn with_auth(url: &str, auth: Option<(String, String)>) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .tcp_keepalive(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(0)
            .tls_built_in_root_certs(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()
            .map_err(|e| XntError::RpcError(format!("failed to create client: {e}")))?;

        let auth = auth.map(|(user, pass)| (user, Zeroizing::new(pass)));

        Ok(Self {
            url: url.to_string(),
            client,
            auth,
        })
    }

    /// Make a JSON-RPC call
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let body = serde_json::to_vec(&request)
            .map_err(|e| XntError::RpcError(format!("JSON serialize failed: {e}")))?;
        let body_len = body.len();

        let mut req_builder = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Content-Length", body_len.to_string())
            .body(body);

        if let Some((ref username, ref password)) = self.auth {
            req_builder = req_builder.basic_auth(username, Some(&**password));
        }

        let response = req_builder.send().map_err(|e| {
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
            XntError::RpcError(msg)
        })?;

        if !response.status().is_success() {
            return Err(XntError::RpcError(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let json: Value = response
            .json()
            .map_err(|e| XntError::RpcError(format!("parse failed: {e}")))?;

        if let Some(error) = json.get("error") {
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(XntError::RpcError(format!("RPC error: {msg}")));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| XntError::RpcError("missing result".to_string()))
    }

    /// Ping the node (check connectivity)
    pub fn ping(&self) -> Result<()> {
        self.call("chain_height", json!([]))?;
        Ok(())
    }

    /// Get current chain height
    pub fn chain_height(&self) -> Result<u64> {
        let result = self.call("chain_height", json!([]))?;
        result
            .get("height")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| XntError::RpcError("missing height".to_string()))
    }

    /// Get URL
    pub fn url(&self) -> &str {
        &self.url
    }
}
