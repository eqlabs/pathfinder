use std::collections::HashMap;

use axum::async_trait;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures::{Future, FutureExt};
use http::HeaderValue;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::Value;

use crate::context::RpcContext;
use crate::jsonrpc::error::RpcError;
use crate::jsonrpc::request::RpcRequest;
use crate::jsonrpc::response::{RpcResponse, RpcResult};

#[derive(Clone)]
pub struct RpcRouter {
    methods: &'static HashMap<&'static str, Box<dyn RpcMethod>>,
    version: &'static str,
}

pub struct RpcRouterBuilder {
    methods: HashMap<&'static str, Box<dyn RpcMethod>>,
    version: &'static str,
}

impl RpcRouterBuilder {
    pub fn register<I, O, S, M: IntoRpcMethod<I, O, S>>(
        mut self,
        method_name: &'static str,
        method: M,
    ) -> Self {
        self.methods
            .insert(method_name, IntoRpcMethod::into_method(method));
        self
    }

    pub fn build(self) -> RpcRouter {
        // Intentionally leak the hashmap to give it a static lifetime.
        //
        // Since the router is expected to be long lived, this shouldn't be an issue.
        let methods = Box::new(self.methods);
        let methods = Box::leak(methods);
        RpcRouter {
            methods,
            version: self.version,
        }
    }

    fn new(version: &'static str) -> Self {
        RpcRouterBuilder {
            methods: Default::default(),
            version,
        }
    }
}

impl RpcRouter {
    pub fn builder(version: &'static str) -> RpcRouterBuilder {
        RpcRouterBuilder::new(version)
    }

    /// Parses and executes a request. Returns [None] if its a notification.
    async fn run_request<'a>(
        &self,
        state: RpcContext,
        request: &'a str,
    ) -> Option<RpcResponse<'a>> {
        let Ok(request) = serde_json::from_str::<RpcRequest>(request) else {
                return Some(RpcResponse::INVALID_REQUEST);
            };

        // Ignore notification requests.
        let Some(id) = request.id else {
            return None;
        };

        // Also grab the method_name as it is a static str, which is required by the metrics.
        let Some((&method_name, method)) = self.methods.get_key_value(request.method.as_str()) else {
            return Some(RpcResponse::method_not_found(id, request.method));
        };

        metrics::increment_counter!("rpc_method_calls_total", "method" => method_name, "version" => self.version);

        let method = method.invoke(state, request.params);
        let result = std::panic::AssertUnwindSafe(method).catch_unwind().await;

        let output = match result {
            Ok(output) => output,
            Err(_e) => {
                tracing::warn!(method = request.method, "RPC method panic'd");
                Err(RpcError::InternalError(anyhow::anyhow!("Method panic'd")))
            }
        };

        if output.is_err() {
            metrics::increment_counter!("rpc_method_calls_failed_total", "method" => method_name, "version" => self.version);
        }

        Some(RpcResponse { output, id })
    }
}

#[axum::async_trait]
pub trait RpcMethod: Send + Sync {
    async fn invoke(&self, state: RpcContext, input: Value) -> RpcResult;
}

// Ideally this would have been an axum handler function, but turning the RPC router into
// an async fn proved to be above my knowledge. This works and is pretty straight-forward,
// but one does have to manually deal with body and header checks.
impl axum::handler::Handler<(), RpcContext, axum::body::Body> for RpcRouter {
    type Future = std::pin::Pin<Box<dyn Future<Output = axum::response::Response> + Send>>;

    fn call(self, req: axum::http::Request<axum::body::Body>, state: RpcContext) -> Self::Future {
        Box::pin(async move {
            // Only allow json content.
            const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
            match req.headers().get(http::header::CONTENT_TYPE) {
                Some(header) if header == APPLICATION_JSON => {}
                Some(_other) => return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "Missing `Content-Type: application/json` header".to_string(),
                    )
                        .into_response()
                }
            }

            let body = match hyper::body::to_bytes(req.into_body()).await {
                Ok(body) => body,
                Err(e) => {
                    tracing::trace!(reason=%e, "Failed to buffer body");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to buffer request body".to_string(),
                    )
                        .into_response();
                }
            };

            // Unfortunately due to this https://github.com/serde-rs/json/issues/497
            // we cannot use an enum with borrowed raw values inside to do a single deserialization
            // for us. Instead we have to distinguish manually between a single request and a batch
            // request which we do by checking the first byte.
            if body.as_ref().first() != Some(&b'[') {
                let Ok(request) = serde_json::from_slice::<&RawValue>(&body) else {
                    return RpcResponse::PARSE_ERROR.into_response();
                };

                match self.run_request(state, request.get()).await {
                    Some(response) => response.into_response(),
                    None => ().into_response(),
                }
            } else {
                let Ok(requests) = serde_json::from_slice::<Vec<&RawValue>>(&body) else {
                    return RpcResponse::PARSE_ERROR.into_response();
                };

                if requests.is_empty() {
                    return RpcResponse::INVALID_REQUEST.into_response();
                }

                let mut responses = Vec::new();

                for request in requests {
                    // Notifications return none and are skipped.
                    if let Some(response) = self.run_request(state.clone(), request.get()).await {
                        responses.push(response);
                    }
                }

                // All requests were notifications.
                if responses.is_empty() {
                    return ().into_response();
                }

                serde_json::to_string(&responses).unwrap().into_response()
            }
        })
    }
}

/// Utility trait which automates the serde of an RPC methods input and output.
///
/// This trait is sealed to prevent attempts at implementing it manually. This will
/// likely clash with the existing blanket implementations with very unhelpful error
/// messages.
///
/// This trait is automatically implemented for the following methods:
/// ```
/// async fn input_and_context(ctx: RpcContext, input: impl Deserialize) -> Result<impl Serialize, Into<RpcError>>;
/// async fn input_only(input: impl Deserialize) -> Result<impl Serialize, Into<RpcError>>;
/// async fn context_only(ctx: RpcContext) -> Result<impl Serialize, Into<RpcError>>;
/// ```
///
/// The generics allow us to achieve a form of variadic specilization and can be ignored by callers.
/// See [sealed::Sealed] to add more method signatures or more information on how this works.
pub trait IntoRpcMethod<I, O, S>: sealed::Sealed<I, O, S> {
    fn into_method(self) -> Box<dyn RpcMethod>;
}

impl<T, I, O, S> IntoRpcMethod<I, O, S> for T
where
    T: sealed::Sealed<I, O, S>,
{
    fn into_method(self) -> Box<dyn RpcMethod> {
        sealed::Sealed::<I, O, S>::into_method(self)
    }
}

mod sealed {
    use std::marker::PhantomData;

    use crate::jsonrpc::error::RpcError;

    use super::*;

    /// Sealed implementation of [RpcMethod].
    ///
    /// The generics allow for a form of specialization over a methods Input, Output and State
    /// by treating each as a tuple. Varying the tuple length allows us to target a specific method
    /// signature. This same could be achieved with a single generic but it becomes less clear as
    /// each permuation would require a different tuple length.
    ///
    /// By convention, the lack of a type is equivalent to the unit tuple (). So if we want to target functions
    /// with no input params, no input state and an output:
    /// ```
    /// Sealed<I = (), S = (), O = ((), Ouput)>
    /// ```
    pub trait Sealed<I, O, S> {
        fn into_method(self) -> Box<dyn RpcMethod>;
    }

    /// ```
    /// async fn example(RpcContext, impl Deserialize) -> Result<Output, Into<RpcError>>
    /// ```
    impl<F, Input, Output, Error, Fut> Sealed<((), Input), ((), Output), ((), RpcContext)> for F
    where
        F: Fn(RpcContext, Input) -> Fut + Sync + Send + 'static,
        Input: DeserializeOwned + Send + Sync + 'static,
        Output: Serialize + Send + Sync + 'static,
        Error: Into<RpcError> + Send + Sync + 'static,
        Fut: Future<Output = Result<Output, Error>> + Send,
    {
        fn into_method(self) -> Box<dyn RpcMethod> {
            struct Helper<F, Input, Output, Error> {
                f: F,
                _marker: PhantomData<(Input, Output, Error)>,
            }

            #[axum::async_trait]
            impl<F, Input, Output, Error, Fut> RpcMethod for Helper<F, Input, Output, Error>
            where
                F: Fn(RpcContext, Input) -> Fut + Sync + Send,
                Input: DeserializeOwned + Send + Sync,
                Output: Serialize + Send + Sync,
                Error: Into<RpcError> + Send + Sync,
                Fut: Future<Output = Result<Output, Error>> + Send,
            {
                async fn invoke(&self, state: RpcContext, input: Value) -> RpcResult {
                    let input = serde_json::from_value::<Input>(input)
                        .map_err(|_| RpcError::InvalidParams)?;
                    let output = (self.f)(state, input).await.map_err(Into::into)?;
                    serde_json::to_value(output).map_err(|e| RpcError::InternalError(e.into()))
                }
            }

            Box::new(Helper {
                f: self,
                _marker: Default::default(),
            })
        }
    }

    /// ```
    /// async fn example(impl Deserialize) -> Result<Output, Into<RpcError>>
    /// ```
    #[async_trait]
    impl<F, Input, Output, Error, Fut> Sealed<((), Input), ((), Output), ()> for F
    where
        F: Fn(Input) -> Fut + Sync + Send + 'static,
        Input: DeserializeOwned + Sync + Send + 'static,
        Output: Serialize + Sync + Send + 'static,
        Error: Into<RpcError> + Sync + Send + 'static,
        Fut: Future<Output = Result<Output, Error>> + Send,
    {
        fn into_method(self) -> Box<dyn RpcMethod> {
            struct Helper<F, Input, Output, Error> {
                f: F,
                _marker: PhantomData<(Input, Output, Error)>,
            }

            #[axum::async_trait]
            impl<F, Input, Output, Error, Fut> RpcMethod for Helper<F, Input, Output, Error>
            where
                F: Fn(Input) -> Fut + Sync + Send,
                Input: DeserializeOwned + Send + Sync,
                Output: Serialize + Send + Sync,
                Error: Into<RpcError> + Send + Sync,
                Fut: Future<Output = Result<Output, Error>> + Send,
            {
                async fn invoke(&self, _state: RpcContext, input: Value) -> RpcResult {
                    let input = serde_json::from_value::<Input>(input)
                        .map_err(|_| RpcError::InvalidParams)?;
                    let output = (self.f)(input).await.map_err(Into::into)?;
                    serde_json::to_value(output).map_err(|e| RpcError::InternalError(e.into()))
                }
            }

            Box::new(Helper {
                f: self,
                _marker: Default::default(),
            })
        }
    }

    /// ```
    /// async fn example(RpcContext) -> Result<Output, Into<RpcError>>
    /// ```
    #[async_trait]
    impl<F, Output, Error, Fut> Sealed<(), ((), Output), ((), RpcContext)> for F
    where
        F: Fn(RpcContext) -> Fut + Sync + Send + 'static,
        Output: Serialize + Sync + Send + 'static,
        Error: Into<RpcError> + Send + Sync + 'static,
        Fut: Future<Output = Result<Output, Error>> + Send,
    {
        fn into_method(self) -> Box<dyn RpcMethod> {
            struct Helper<F, Output, Error> {
                f: F,
                _marker: PhantomData<(Output, Error)>,
            }

            #[axum::async_trait]
            impl<F, Output, Error, Fut> RpcMethod for Helper<F, Output, Error>
            where
                F: Fn(RpcContext) -> Fut + Sync + Send,
                Output: Serialize + Send + Sync,
                Error: Into<RpcError> + Send + Sync,
                Fut: Future<Output = Result<Output, Error>> + Send,
            {
                async fn invoke(&self, state: RpcContext, input: Value) -> RpcResult {
                    if !input.is_null() {
                        return Err(RpcError::InvalidParams);
                    }
                    let output = (self.f)(state).await.map_err(Into::into)?;
                    serde_json::to_value(output).map_err(|e| RpcError::InternalError(e.into()))
                }
            }

            Box::new(Helper {
                f: self,
                _marker: Default::default(),
            })
        }
    }

    /// ```
    /// async fn example() -> Result<Output, Into<RpcError>>
    /// ```
    #[async_trait]
    impl<F, Output, Error, Fut> Sealed<(), (), ((), Output)> for F
    where
        F: Fn() -> Fut + Sync + Send + 'static,
        Output: Serialize + Sync + Send + 'static,
        Error: Into<RpcError> + Sync + Send + 'static,
        Fut: Future<Output = Result<Output, Error>> + Send,
    {
        fn into_method(self) -> Box<dyn RpcMethod> {
            struct Helper<F, Output, Error> {
                f: F,
                _marker: PhantomData<(Output, Error)>,
            }

            #[axum::async_trait]
            impl<F, Output, Error, Fut> RpcMethod for Helper<F, Output, Error>
            where
                F: Fn() -> Fut + Sync + Send,
                Output: Serialize + Send + Sync,
                Error: Into<RpcError> + Send + Sync,
                Fut: Future<Output = Result<Output, Error>> + Send,
            {
                async fn invoke(&self, _state: RpcContext, input: Value) -> RpcResult {
                    if !input.is_null() {
                        return Err(RpcError::InvalidParams);
                    }
                    let output = (self.f)().await.map_err(Into::into)?;
                    serde_json::to_value(output).map_err(|e| RpcError::InternalError(e.into()))
                }
            }

            Box::new(Helper {
                f: self,
                _marker: Default::default(),
            })
        }
    }

    /// ```
    /// fn example() -> &'static str
    /// ```
    #[async_trait]
    impl<F> Sealed<(), (), ((), (), &'static str)> for F
    where
        F: Fn() -> &'static str + Sync + Send + 'static,
    {
        fn into_method(self) -> Box<dyn RpcMethod> {
            struct Helper<F> {
                f: F,
            }

            #[axum::async_trait]
            impl<F> RpcMethod for Helper<F>
            where
                F: Fn() -> &'static str + Sync + Send,
            {
                async fn invoke(&self, _state: RpcContext, input: Value) -> RpcResult {
                    if !input.is_null() {
                        return Err(RpcError::InvalidParams);
                    }
                    let output = (self.f)();
                    serde_json::to_value(output).map_err(|e| RpcError::InternalError(e.into()))
                }
            }
            Box::new(Helper { f: self })
        }
    }
}

/// Handles invoking an RPC route's methods.
///
/// See [rpc_handler] for more information.
#[async_trait]
pub trait RpcMethodHandler {
    async fn call_method(method: &str, state: RpcContext, params: Value) -> RpcResult;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc::RequestId;
    use serde::Deserialize;
    use serde_json::json;

    async fn spawn_server(router: RpcRouter) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://127.0.0.1:{}", addr.port());

        tokio::spawn(async {
            let router = axum::Router::new()
                .route("/", axum::routing::post(router))
                .with_state(RpcContext::for_tests());
            axum::Server::from_tcp(listener)
                .unwrap()
                .serve(router.into_make_service())
                .await
        });

        url
    }

    mod specification_tests {
        //! Test cases lifted directly from the [RPC specification](https://www.jsonrpc.org/specification).
        use super::*;

        fn spec_router() -> RpcRouter {
            crate::error::generate_rpc_error_subset!(ExampleError:);

            #[derive(Debug, Deserialize, Serialize)]
            struct SubtractInput {
                minuend: i32,
                subtrahend: i32,
            }
            async fn subtract(input: SubtractInput) -> Result<Value, ExampleError> {
                Ok(Value::Number((input.minuend - input.subtrahend).into()))
            }

            #[derive(Debug, Deserialize, Serialize)]
            struct SumInput(Vec<i32>);
            async fn sum(input: SumInput) -> Result<Value, ExampleError> {
                Ok(Value::Number((input.0.iter().sum::<i32>()).into()))
            }

            #[derive(Debug, Deserialize, Serialize)]
            struct GetDataInput;
            #[derive(Debug, Deserialize, Serialize)]
            struct GetDataOutput(Vec<Value>);
            async fn get_data() -> Result<GetDataOutput, ExampleError> {
                Ok(GetDataOutput(vec![
                    Value::String("hello".to_owned()),
                    Value::Number(5.into()),
                ]))
            }

            RpcRouter::builder("vTEST")
                .register("subtract", subtract)
                .register("sum", sum)
                .register("get_data", get_data)
                .build()
        }

        #[tokio::test]
        async fn with_positional_params() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!(
                    {"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 2}
                ))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "result": 19, "id": 2});
            assert_eq!(res, expected);

            let res = client
                .post(url)
                .json(&serde_json::json!(
                    {"jsonrpc": "2.0", "method": "subtract", "params": [23, 42], "id": 2}
                ))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "result": -19, "id": 2});
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn with_named_params() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!(
                    {"jsonrpc": "2.0", "method": "subtract", "params": {"subtrahend": 23, "minuend": 42}, "id": 3}
                ))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "result": 19, "id": 3});
            assert_eq!(res, expected);

            let res = client
                .post(url)
                .json(&serde_json::json!(
                    {"jsonrpc": "2.0", "method": "subtract", "params": {"minuend": 42, "subtrahend": 23}, "id": 4}
                ))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "result": 19, "id": 4});
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn notification() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!(
                    {"jsonrpc": "2.0", "method": "update", "params": [1,2,3,4,5]}
                ))
                .send()
                .await
                .unwrap();

            assert_eq!(res.content_length(), Some(0));

            // --> {"jsonrpc": "2.0", "method": "foobar"}
            let res = client
                .post(url)
                .json(&serde_json::json!(
                    {"jsonrpc": "2.0", "method": "foobar"}
                ))
                .send()
                .await
                .unwrap();

            assert_eq!(res.content_length(), Some(0));
        }

        #[tokio::test]
        async fn non_existent_method() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!(
                    {"jsonrpc": "2.0", "method": "foobar", "id": "1"}
                ))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "1"});
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn invalid_json() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .body(r#"{"jsonrpc": "2.0", "method": "foobar, "params": "bar", "baz]"#)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": null});
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn invalid_request_object() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!({"jsonrpc": "2.0", "method": 1, "params": "bar"}))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null});
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn invalid_json_batch() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .body(
                    r#"[
                    {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"},
                    {"jsonrpc": "2.0", "method"
                 ]"#,
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": null});
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn empty_batch() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!([]))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null});
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn invalid_batch() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!([1]))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!([
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}
            ]);
            assert_eq!(res, expected);

            let res = client
                .post(url.clone())
                .json(&serde_json::json!([1, 2, 3]))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!([
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null},
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null},
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}
            ]);
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn batch() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!(
                    [
                        {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"},
                        {"jsonrpc": "2.0", "method": "notify_hello", "params": [7]},
                        {"jsonrpc": "2.0", "method": "subtract", "params": [42,23], "id": "2"},
                        {"foo": "boo"},
                        {"jsonrpc": "2.0", "method": "foo.get", "params": {"name": "myself"}, "id": "5"},
                        {"jsonrpc": "2.0", "method": "get_data", "id": "9"}
                    ]
                ))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!(
                [
                    {"jsonrpc": "2.0", "result": 7, "id": "1"},
                    {"jsonrpc": "2.0", "result": 19, "id": "2"},
                    {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null},
                    {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "5"},
                    {"jsonrpc": "2.0", "result": ["hello", 5], "id": "9"}
                ]
            );
            pretty_assertions::assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn batch_all_notifications() {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!(
                    [
                        {"jsonrpc": "2.0", "method": "notify_sum", "params": [1,2,4]},
                        {"jsonrpc": "2.0", "method": "notify_hello", "params": [7]}
                    ]
                ))
                .send()
                .await
                .unwrap();

            assert_eq!(res.content_length(), Some(0));
        }
    }

    mod request {
        use super::*;

        #[test]
        fn with_null_id() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "params": [1,2,3],
                "id": null
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!([1, 2, 3]),
                id: Some(RequestId::Null),
            };
            assert_eq!(result, expected);
        }

        #[test]
        fn with_string_id() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "params": [1,2,3],
                "id": "text"
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!([1, 2, 3]),
                id: Some(RequestId::String("text".into())),
            };
            assert_eq!(result, expected);
        }

        #[test]
        fn with_number_id() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "params": [1,2,3],
                "id": 456
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!([1, 2, 3]),
                id: Some(RequestId::Number(456)),
            };
            assert_eq!(result, expected);
        }

        #[test]
        fn notification() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "params": [1,2,3]
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!([1, 2, 3]),
                id: None,
            };
            assert_eq!(result, expected);
        }

        #[test]
        fn jsonrpc_version_missing() {
            let json = json!({
                "method": "sum",
                "params": [1,2,3],
                "id": 456
            });
            RpcRequest::deserialize(json).unwrap_err();
        }

        #[test]
        fn jsonrpc_version_is_not_2() {
            let json = json!({
                "jsonrpc": "1.0",
                "method": "sum",
                "params": [1,2,3],
                "id": 456
            });
            RpcRequest::deserialize(json).unwrap_err();
        }

        #[test]
        fn no_params() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "id": 456
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!(null),
                id: Some(RequestId::Number(456)),
            };
            assert_eq!(result, expected);
        }
    }

    mod response {
        use super::*;

        #[test]
        fn output_is_error() {
            let serialized = serde_json::to_value(&RpcResponse {
                output: Err(RpcError::InvalidParams),
                id: RequestId::Number(1),
            })
            .unwrap();

            let expected = json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": RpcError::InvalidParams.code(),
                    "message": RpcError::InvalidParams.message(),
                },
                "id": 1,
            });

            assert_eq!(serialized, expected);
        }

        #[test]
        fn output_is_ok() {
            let serialized = serde_json::to_value(&RpcResponse {
                output: Ok(Value::String("foobar".to_owned())),
                id: RequestId::Number(1),
            })
            .unwrap();

            let expected = json!({
                "jsonrpc": "2.0",
                "result": "foobar",
                "id": 1,
            });

            assert_eq!(serialized, expected);
        }
    }

    mod panic_handling {
        use super::*;

        fn panic_router() -> RpcRouter {
            fn always_panic() -> &'static str {
                panic!("Oh no!");
            }

            fn always_success() -> &'static str {
                "Success"
            }

            RpcRouter::builder("vTest")
                .register("panic", always_panic)
                .register("success", always_success)
                .build()
        }

        #[tokio::test]
        async fn panic_is_internal_error() {
            let url = spawn_server(panic_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!(
                    {"jsonrpc": "2.0", "method": "panic", "id": 1}
                ))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!({"jsonrpc": "2.0", "error": {"code": -32603, "message": "Internal error"}, "id": 1});
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn panic_in_batch_is_isolated() {
            let url = spawn_server(panic_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!(
                    [
                        {"jsonrpc": "2.0", "method": "panic", "id": 1},
                        {"jsonrpc": "2.0", "method": "success", "id": 2},
                    ]
                ))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();

            let expected = serde_json::json!([
                {"jsonrpc": "2.0", "error": {"code": -32603, "message": "Internal error"}, "id": 1},
                {"jsonrpc": "2.0", "result": "Success", "id": 2},
            ]);
            assert_eq!(res, expected);
        }
    }

    #[tokio::test]
    async fn rejects_non_json_content_header() {
        async fn always_success(_ctx: RpcContext) -> RpcResult {
            Ok(json!("Success"))
        }

        let router = RpcRouter::builder("vTEST")
            .register("success", always_success)
            .build();

        let url = spawn_server(router).await;

        let client = reqwest::Client::new();
        let res = client
            .post(url.clone())
            .body(
                serde_json::json!(
                    {"jsonrpc": "2.0", "method": "any", "id": 1}
                )
                .to_string(),
            )
            .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .send()
            .await
            .unwrap()
            .status();

        assert_eq!(res, reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
