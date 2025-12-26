use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Json;
use axum::Router;
use base64::prelude::*;
use tokio::net::TcpListener;

use crate::application::json_rpc::core::api::ops::RpcMethods;
use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::api::server::router::RpcRouter;
use crate::application::json_rpc::core::model::json::JsonError;
use crate::application::json_rpc::core::model::json::JsonRequest;
use crate::application::json_rpc::core::model::json::JsonResponse;
use crate::application::json_rpc::server::rpc::RpcAuth;
use crate::application::json_rpc::server::rpc::RpcServer;

#[derive(Clone)]
struct AppState {
    router: Arc<RpcRouter>,
    auth: Option<RpcAuth>,
}

impl RpcServer {
    /// Starts the HTTP RPC server.
    ///
    /// All RPC endpoints are accessible via `POST` requests to the root path `/`.
    /// The specific method is selected using the `method` field in the JSON request body,
    /// formatted as `namespace_method`.
    pub async fn serve_http(&self, listener: TcpListener) {
        let api: Arc<dyn RpcApi> = Arc::new(self.clone());
        let namespaces = self.enabled_namespaces().await;
        let router = RpcMethods::new_router(api, namespaces);

        let state = AppState {
            router: Arc::new(router),
            auth: self.rpc_auth.clone(),
        };

        let app = Router::new()
            .route("/", post(Self::rpc_handler))
            .with_state(state);

        axum::serve(listener, app).await.unwrap();
    }

    /// Handles incoming RPC requests.
    ///
    /// # Request Body
    ///
    /// Expects a JSON-RPC 2.0 compliant body with the following fields:
    /// - `jsonrpc`: `"2.0"`
    /// - `method`: The RPC method to call, formatted as `namespace_method`
    /// - `params`: An array of parameters to pass to the method
    /// - `id` (optional): Request identifier for matching responses
    ///
    /// # Response
    ///
    /// Returns a JSON-RPC 2.0 response:
    /// - On success:  
    ///   `{
    ///       "jsonrpc": "2.0",
    ///       "id": <request_id>,
    ///       "result": <method_result>
    ///   }`
    ///
    /// - On error:  
    ///   `{
    ///       "jsonrpc": "2.0",
    ///       "id": <request_id>,
    ///       "error": {
    ///           "code": <error_code>,
    ///           "message": <error_message>
    ///       }
    ///   }`
    ///
    /// # Example
    ///
    /// Request:
    /// ```json
    /// POST /
    /// {
    ///     "method": "node_network",
    ///     "params": [],
    ///     "id": 1
    /// }
    /// ```
    ///
    /// Success Response:
    /// ```json
    /// {
    ///     "jsonrpc": "2.0",
    ///     "id": 1,
    ///     "result": { "network": "main" }
    /// }
    /// ```
    ///
    /// Error Response:
    /// ```json
    /// {
    ///     "jsonrpc": "2.0",
    ///     "id": 1,
    ///     "error": {
    ///         "code": -32601,
    ///         "message": "Method not found"
    ///     }
    /// }
    /// ```
    async fn rpc_handler(
        State(state): State<AppState>,
        headers: HeaderMap,
        // An optimization to avoid deserializing 2 times
        body: Result<Json<JsonRequest>, JsonRejection>,
    ) -> Result<Json<JsonResponse>, StatusCode> {
        // Check authentication if configured
        if let Some(ref expected_auth) = state.auth {
            if !Self::verify_basic_auth(&headers, expected_auth) {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }

        let Ok(Json(request)) = body else {
            return Ok(Json(JsonResponse::error(None, JsonError::ParseError)));
        };

        let res = state.router.dispatch(&request.method, request.params).await;
        let response = match res {
            Ok(result) => JsonResponse::success(request.id, result),
            Err(error) => JsonResponse::error(request.id, error),
        };

        Ok(Json(response))
    }

    /// Verifies HTTP Basic Authentication credentials.
    fn verify_basic_auth(headers: &HeaderMap, expected: &RpcAuth) -> bool {
        let Some(auth_header) = headers.get(AUTHORIZATION) else {
            return false;
        };

        let Ok(auth_str) = auth_header.to_str() else {
            return false;
        };

        let Some(encoded) = auth_str.strip_prefix("Basic ") else {
            return false;
        };

        let Ok(decoded) = BASE64_STANDARD.decode(encoded) else {
            return false;
        };

        let Ok(credentials) = String::from_utf8(decoded) else {
            return false;
        };

        let Some((username, password)) = credentials.split_once(':') else {
            return false;
        };

        username == expected.username && password == expected.password
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::Json;
    use macro_rules_attr::apply;
    use serde_json::json;

    use super::AppState;
    use crate::application::json_rpc::core::api::ops::Namespace;
    use crate::application::json_rpc::core::api::ops::RpcMethods;
    use crate::application::json_rpc::core::model::json::JsonError;
    use crate::application::json_rpc::core::model::json::JsonRequest;
    use crate::application::json_rpc::core::model::json::JsonResponse;
    use crate::application::json_rpc::server::rpc::RpcServer;
    use crate::application::json_rpc::server::service::tests::test_rpc_server;
    use crate::tests::shared_tokio_runtime;

    async fn test_state() -> AppState {
        let api = Arc::new(test_rpc_server().await);
        let router = Arc::new(RpcMethods::new_router(api, [Namespace::Node].into()));

        AppState { router, auth: None }
    }

    #[apply(shared_tokio_runtime)]
    async fn handles_common_scenarios_properly() {
        const TEST_METHOD: &str = "node_network";
        const UNKNOWN_TEST_METHOD: &str = "node_crash";

        let state = test_state().await;
        let headers = HeaderMap::new();

        // 1. Valid -> Success
        let valid_req = JsonRequest {
            jsonrpc: Some("2.0".into()),
            method: TEST_METHOD.into(),
            params: json!([]),
            id: Some(json!(1)),
        };
        let Json(valid_res) =
            RpcServer::rpc_handler(State(state.clone()), headers.clone(), Ok(Json(valid_req)))
                .await
                .unwrap();
        assert!(
            matches!(valid_res, JsonResponse::Success { id: Some(id), result, .. }
                if id == json!(1) && result.is_object() // shouldn't be null
            )
        );

        // 2. Bad params -> InvalidParams
        let bad_req = JsonRequest {
            jsonrpc: Some("2.0".into()),
            method: TEST_METHOD.into(),
            params: json!([1, "x"]),
            id: Some(json!(2)),
        };
        let Json(bad_res) =
            RpcServer::rpc_handler(State(state.clone()), headers.clone(), Ok(Json(bad_req)))
                .await
                .unwrap();
        assert!(
            matches!(bad_res, JsonResponse::Error { id: Some(id), error: JsonError::InvalidParams, .. }
                if id == json!(2)
            )
        );

        // 3. Unknown method -> MethodNotFound
        let unknown_req = JsonRequest {
            jsonrpc: Some("2.0".into()),
            method: UNKNOWN_TEST_METHOD.into(),
            params: json!([]),
            id: Some(json!(3)),
        };
        let Json(unknown_res) = RpcServer::rpc_handler(State(state), headers, Ok(Json(unknown_req)))
            .await
            .unwrap();
        assert!(
            matches!(unknown_res, JsonResponse::Error { id: Some(id), error: JsonError::MethodNotFound, .. }
                if id == json!(3)
            )
        );
    }
}
