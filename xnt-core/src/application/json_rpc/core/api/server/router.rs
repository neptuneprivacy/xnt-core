use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::api::rpc::RpcResult;
use crate::application::json_rpc::core::model::json::JsonError;
use crate::application::json_rpc::core::model::json::JsonResult;

/// Helper function to convert RPC method results to JsonResult
/// Handles both methods that return RpcResult<T> and methods that return T directly
pub fn to_json_result<T>(result: impl RpcMethodResult<T>) -> Result<T, JsonError> {
    result.into_json_result()
}

/// Helper trait to convert RPC method results to JsonResult
pub trait RpcMethodResult<T> {
    fn into_json_result(self) -> Result<T, JsonError>;
}

impl<T> RpcMethodResult<T> for RpcResult<T> {
    fn into_json_result(self) -> Result<T, JsonError> {
        self.map_err(JsonError::from)
    }
}

impl<T> RpcMethodResult<T> for T
where
    T: 'static,
{
    fn into_json_result(self) -> Result<T, JsonError> {
        Ok(self)
    }
}

type HandlerFn = Box<
    dyn Fn(serde_json::Value) -> Pin<Box<dyn Future<Output = JsonResult<serde_json::Value>> + Send>>
        + Send
        + Sync,
>;

#[allow(missing_debug_implementations)]
pub struct Router<A: ?Sized> {
    routes: HashMap<&'static str, HandlerFn>,
    api: Arc<A>,
}

impl<A> Router<A>
where
    A: Send + Sync + 'static + ?Sized,
{
    pub fn new(api: Arc<A>) -> Self {
        Self {
            routes: HashMap::new(),
            api,
        }
    }

    pub fn insert<F, Fut>(&mut self, name: &'static str, f: F)
    where
        F: Fn(Arc<A>, serde_json::Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = JsonResult<serde_json::Value>> + Send + 'static,
    {
        let api = self.api.clone();
        self.routes.insert(
            name,
            Box::new(move |params| Box::pin(f(api.clone(), params))),
        );
    }

    pub async fn dispatch(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> JsonResult<serde_json::Value> {
        if let Some(handler) = self.routes.get(method) {
            handler(params).await
        } else {
            Err(JsonError::MethodNotFound)
        }
    }
}

pub type RpcRouter = Router<dyn RpcApi>;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;

    use macro_rules_attr::apply;
    use serde_json::json;

    use crate::application::json_rpc::core::api::server::router::Router;
    use crate::application::json_rpc::core::model::json::JsonError;
    use crate::tests::shared_tokio_runtime;

    struct DummyApi;

    #[apply(shared_tokio_runtime)]
    async fn dispatch_known_method() {
        let api = Arc::new(DummyApi);
        let mut router = Router::new(api.clone());

        router.insert("echo", |_api, params| async move {
            Ok(json!({ "echo": params }))
        });

        let params = json!({ "message": "hello" });
        let result = router.dispatch("echo", params.clone()).await.unwrap();

        assert_eq!(result, json!({ "echo": params }));
    }

    #[apply(shared_tokio_runtime)]
    async fn dispatch_unknown_method() {
        let api = Arc::new(DummyApi);
        let router = Router::new(api);

        let err = router.dispatch("nonexistent", json!({})).await.unwrap_err();
        assert!(matches!(err, JsonError::MethodNotFound));
    }
}
