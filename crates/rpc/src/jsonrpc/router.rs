use std::collections::HashMap;

use axum::async_trait;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures::stream::FuturesOrdered;
use futures::{Future, FutureExt, StreamExt};
use http::HeaderValue;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::Value;

use crate::context::RpcContext;
use crate::jsonrpc::error::RpcError;
use crate::jsonrpc::request::{RawParams, RpcRequest};
use crate::jsonrpc::response::{RpcResponse, RpcResult};

#[derive(Clone)]
pub struct RpcRouter {
    context: RpcContext,
    methods: &'static HashMap<&'static str, Box<dyn RpcMethod>>,
    version: &'static str,
}

pub struct RpcRouterBuilder {
    methods: HashMap<&'static str, Box<dyn RpcMethod>>,
    version: &'static str,
}

impl RpcRouterBuilder {
    pub fn register<I, O, S, M: IntoRpcMethod<'static, I, O, S>>(
        mut self,
        method_name: &'static str,
        method: M,
    ) -> Self {
        self.methods
            .insert(method_name, IntoRpcMethod::into_method(method));
        self
    }

    pub fn build(self, context: RpcContext) -> RpcRouter {
        // Intentionally leak the hashmap to give it a static lifetime.
        //
        // Since the router is expected to be long lived, this shouldn't be an issue.
        let methods = Box::new(self.methods);
        let methods = Box::leak(methods);

        RpcRouter {
            context,
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
    async fn run_request<'a>(&self, request: &'a str) -> Option<RpcResponse<'a>> {
        let Ok(request) = serde_json::from_str::<RpcRequest<'_>>(request) else {
            return Some(RpcResponse::INVALID_REQUEST);
        };

        // Ignore notification requests.
        if request.id.is_notification() {
            return None;
        }

        // Also grab the method_name as it is a static str, which is required by the metrics.
        let Some((&method_name, method)) = self.methods.get_key_value(request.method.as_ref())
        else {
            return Some(RpcResponse::method_not_found(request.id));
        };

        metrics::increment_counter!("rpc_method_calls_total", "method" => method_name, "version" => self.version);

        let method = method.invoke(self.context.clone(), request.params);
        let result = std::panic::AssertUnwindSafe(method).catch_unwind().await;

        let output = match result {
            Ok(output) => output,
            Err(_e) => {
                tracing::warn!(method=%request.method, "RPC method panic'd");
                Err(RpcError::InternalError(anyhow::anyhow!("Internal error")))
            }
        };

        if output.is_err() {
            metrics::increment_counter!("rpc_method_calls_failed_total", "method" => method_name, "version" => self.version);
        }

        Some(RpcResponse {
            output,
            id: request.id,
        })
    }
}

// A slight variation on the axum json extractor.
fn is_utf8_encoded_json(headers: http::HeaderMap) -> bool {
    let Some(content_type) = headers.get(http::header::CONTENT_TYPE) else {
        return false;
    };

    let Ok(content_type) = content_type.to_str() else {
        return false;
    };

    let mime = if let Ok(mime) = content_type.parse::<mime::Mime>() {
        mime
    } else {
        return false;
    };

    // Only accept utf8 encoding, which is the default if it missing.
    let valid_charset = mime
        .get_param(mime::CHARSET)
        .map(|x| x == "utf-8")
        .unwrap_or(true);

    // `application/json` or `XXX+json` are allowed.
    let is_json = (mime.type_() == "application" && mime.subtype() == "json")
        || mime.suffix().map_or(false, |name| name == "json");

    is_json && valid_charset
}

#[axum::debug_handler]
pub async fn rpc_handler(
    State(state): State<RpcRouter>,
    headers: http::HeaderMap,
    body: axum::body::Bytes,
) -> impl axum::response::IntoResponse {
    // Only utf8 json content allowed.
    if !is_utf8_encoded_json(headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }

    #[inline]
    /// Helper to scope the responses so we can set the content-type afterwards
    /// instead of dealing with branches / early exits.
    async fn handle(
        state: RpcRouter,
        body: axum::body::Bytes,
    ) -> impl axum::response::IntoResponse {
        // Unfortunately due to this https://github.com/serde-rs/json/issues/497
        // we cannot use an enum with borrowed raw values inside to do a single deserialization
        // for us. Instead we have to distinguish manually between a single request and a batch
        // request which we do by checking the first byte.
        if body.as_ref().first() != Some(&b'[') {
            let Ok(request) = serde_json::from_slice::<&RawValue>(&body) else {
                return RpcResponse::PARSE_ERROR.into_response();
            };

            match state.run_request(request.get()).await {
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

            // TODO Make it configurable
            let concurrency_limit = 10;
            let responses = run_concurrently(concurrency_limit, requests, |request| {
                state.run_request(request.get())
            })
            .await;

            // Notifications return none and are skipped.
            let responses = responses
                .into_iter()
                .filter_map(|option| option)
                .collect::<Vec<RpcResponse>>();

            // All requests were notifications.
            if responses.is_empty() {
                return ().into_response();
            }

            serde_json::to_string(&responses).unwrap().into_response()
        }
    }

    let mut response = handle(state, body).await.into_response();

    use http::header::CONTENT_TYPE;
    static APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
    response
        .headers_mut()
        .insert(CONTENT_TYPE, APPLICATION_JSON.clone());
    response
}

#[axum::async_trait]
pub trait RpcMethod: Send + Sync {
    async fn invoke<'a>(&self, state: RpcContext, input: RawParams<'a>) -> RpcResult;
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
pub trait IntoRpcMethod<'a, I, O, S>: sealed::Sealed<I, O, S> {
    fn into_method(self) -> Box<dyn RpcMethod>;
}

impl<'a, T, I, O, S> IntoRpcMethod<'a, I, O, S> for T
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
    impl<'a, F, Input, Output, Error, Fut> Sealed<((), Input), ((), Output), ((), RpcContext)> for F
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
                async fn invoke<'a>(&self, state: RpcContext, input: RawParams<'a>) -> RpcResult {
                    let input = input.deserialize()?;
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
    impl<'a, F, Input, Output, Error, Fut> Sealed<((), Input), ((), Output), ()> for F
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
                async fn invoke<'a>(&self, _state: RpcContext, input: RawParams<'a>) -> RpcResult {
                    let input = input.deserialize()?;
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
    impl<'a, F, Output, Error, Fut> Sealed<(), ((), Output), ((), RpcContext)> for F
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
                async fn invoke<'a>(&self, state: RpcContext, input: RawParams<'a>) -> RpcResult {
                    if !input.is_empty() {
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
    impl<'a, F, Output, Error, Fut> Sealed<(), (), ((), Output)> for F
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
                async fn invoke<'a>(&self, _state: RpcContext, input: RawParams<'a>) -> RpcResult {
                    if !input.is_empty() {
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
    impl<'a, F> Sealed<(), (), ((), (), &'static str)> for F
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
                async fn invoke<'a>(&self, _state: RpcContext, input: RawParams<'a>) -> RpcResult {
                    if !input.is_empty() {
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
#[async_trait]
pub trait RpcMethodHandler {
    async fn call_method(method: &str, state: RpcContext, params: Value) -> RpcResult;
}

// TODO Doc.
async fn run_concurrently<O, I, F, W, V>(concurrency_limit: usize, inputs: V, work: W) -> Vec<O>
where
    V: IntoIterator<Item = I>,
    W: Fn(I) -> F,
    F: Future<Output = O> + Sized,
{
    // TODO Possible to simplify this?
    let futures = inputs
        .into_iter()
        .map(|i| async { i })
        .collect::<FuturesOrdered<_>>();
    let (result_sender, mut result_receiver) = tokio::sync::mpsc::channel(futures.len());

    futures
        .for_each_concurrent(Some(concurrency_limit), |input| async {
            let result = work(input).await;

            // No reason for this to fail as:
            //  * channel capacity is sized according to the input size,
            //  * a sender is kept alive until completion
            // TODO add a timeout to make sure this doesn't loop?
            result_sender.send(result).await.expect(
                "This channel is expected to be open and to not go over capacity. This is a bug.",
            );
        })
        .await;

    // Necessary to break the receive loop eventually.
    drop(result_sender);

    // TODO Maybe return the receiver? Or a stream of some kind?
    let mut results = Vec::new();
    while let Some(result) = result_receiver.recv().await {
        results.push(result)
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    // TODO Move
    #[tokio::test]
    async fn concurrent_futures() {
        use std::time::{Duration, Instant};
        use tokio::time::sleep;

        let iterations = 10;
        // Needs to be above an unknown threshold for this test to work due to execution overhead.
        let sleep_time = Duration::from_millis(10);
        assert!(iterations > 2); // Needed for the duration assertion to be relevant.

        {
            let start = Instant::now();
            let results = run_concurrently(10, 0..iterations, |i| async move {
                sleep(sleep_time).await;
                i
            })
            .await;

            // Make sure the futures were indeed executed concurrently: total time << sum of the sleep times
            assert!(start.elapsed() < (sleep_time * 2));

            // Make sure the results are complete.
            assert_eq!(results.len(), iterations);
            // Make sure the results are ordered.
            results
                .into_iter()
                .enumerate()
                .for_each(|(expected, result)| {
                    assert_eq!(result, expected);
                });
        }

        // Now do this again with a concurrent limit of 1.
        {
            let start = Instant::now();
            let results = run_concurrently(1, 0..iterations, |i| async move {
                sleep(sleep_time).await;
                i
            })
            .await;

            // Total time should be ~= sum of the sleep times
            let elapsed = start.elapsed();
            dbg!(&elapsed);
            let margin = 2;
            assert!(elapsed > (sleep_time * (iterations - margin).try_into().unwrap()));
            assert!(elapsed < (sleep_time * (iterations + margin).try_into().unwrap()));

            // Make sure the results are complete.
            assert_eq!(results.len(), iterations);
            // Make sure the results are ordered.
            results
                .into_iter()
                .enumerate()
                .for_each(|(expected, result)| {
                    assert_eq!(result, expected);
                });
        }
    }

    async fn spawn_server(router: RpcRouter) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://127.0.0.1:{}", addr.port());

        tokio::spawn(async {
            let router = axum::Router::new()
                .route("/", axum::routing::post(rpc_handler))
                .with_state(router);
            axum::Server::from_tcp(listener)
                .unwrap()
                .serve(router.into_make_service())
                .await
        });

        url
    }

    /// Spawns an RPC server with the given router and queries it with the given request.
    async fn serve_and_query(router: RpcRouter, request: Value) -> Value {
        let url = spawn_server(router).await;

        let client = reqwest::Client::new();
        client
            .post(url.clone())
            .json(&request)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    }

    mod specification_tests {
        //! Test cases lifted directly from the [RPC specification](https://www.jsonrpc.org/specification).
        use super::*;
        use pretty_assertions::assert_eq;
        use rstest::rstest;
        use serde_json::json;

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
                .build(RpcContext::for_tests())
        }

        #[rstest]
        #[case::with_positional_params(
            json!({"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 2}),
            json!({"jsonrpc": "2.0", "result": 19, "id": 2}),
        )]
        #[case::with_positional_params_switched(
            json!({"jsonrpc": "2.0", "method": "subtract", "params": [23, 42], "id": 2}),
            json!({"jsonrpc": "2.0", "result": -19, "id": 2}),
        )]
        #[case::with_named_params(
            json!({"jsonrpc": "2.0", "method": "subtract", "params": {"subtrahend": 23, "minuend": 42}, "id": 3}),
            json!({"jsonrpc": "2.0", "result": 19, "id": 3}),
        )]
        #[case::with_named_params_switched(
            json!({"jsonrpc": "2.0", "method": "subtract", "params": {"minuend": 42, "subtrahend": 23}, "id": 4}),
            json!({"jsonrpc": "2.0", "result": 19, "id": 4}),
        )]
        #[case::non_existent_method(
            json!({"jsonrpc": "2.0", "method": "foobar", "id": "1"}),
            json!({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "1"}),
        )]
        #[case::invalid_request_object(
            json!({"jsonrpc": "2.0", "method": 1, "params": "bar"}),
            json!({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}),
        )]
        #[case::empty_batch(
            json!([]),
            json!({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}),
        )]
        #[case::invalid_batch_single(
            json!([1]),
            json!([{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}]),
        )]
        #[case::invalid_batch_multiple(
            json!([1, 2, 3]),
            json!([
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null},
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null},
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}
            ]),
        )]
        #[case::batch(
            json!([
                {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"},
                {"jsonrpc": "2.0", "method": "notify_hello", "params": [7]},
                {"jsonrpc": "2.0", "method": "subtract", "params": [42,23], "id": "2"},
                {"foo": "boo"},
                {"jsonrpc": "2.0", "method": "foo.get", "params": {"name": "myself"}, "id": "5"},
                {"jsonrpc": "2.0", "method": "get_data", "id": "9"}
            ]),
            json!([
                {"jsonrpc": "2.0", "result": 7, "id": "1"},
                {"jsonrpc": "2.0", "result": 19, "id": "2"},
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null},
                {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "5"},
                {"jsonrpc": "2.0", "result": ["hello", 5], "id": "9"}
            ]),
        )]
        #[tokio::test]
        async fn specification_test(#[case] request: Value, #[case] expected: Value) {
            let response = serve_and_query(spec_router(), request).await;

            assert_eq!(response, expected);
        }

        #[rstest]
        #[case::with_params(json!({"jsonrpc": "2.0", "method": "update", "params": [1,2,3,4,5]}))]
        #[case::without_params(json!({"jsonrpc": "2.0", "method": "foobar"}))]
        #[case::batch(json!([
            {"jsonrpc": "2.0", "method": "notify_sum", "params": [1,2,4]},
            {"jsonrpc": "2.0", "method": "notify_hello", "params": [7]}
        ]))]
        #[tokio::test]
        async fn notifications(#[case] request: Value) {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&request)
                .send()
                .await
                .unwrap();

            assert_eq!(res.content_length(), Some(0));
        }

        #[rstest]
        #[case::single(r#"{"jsonrpc": "2.0", "method": "foobar, "params": "bar", "baz]"#)]
        #[case::batch(
            r#"[
            {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"},
            {"jsonrpc": "2.0", "method"
         ]"#
        )]
        #[tokio::test]
        async fn invalid_json(#[case] request: &'static str) {
            let url = spawn_server(spec_router()).await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .body(request)
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
                .build(RpcContext::for_tests())
        }

        #[tokio::test]
        async fn panic_is_internal_error() {
            let response = serve_and_query(
                panic_router(),
                json!(
                    {"jsonrpc": "2.0", "method": "panic", "id": 1}
                ),
            )
            .await;

            let expected = serde_json::json!({"jsonrpc": "2.0", "error": {"code": -32603, "message": "Internal error"}, "id": 1});
            assert_eq!(response, expected);
        }

        #[tokio::test]
        async fn panic_in_batch_is_isolated() {
            let response = serve_and_query(
                panic_router(),
                json!([
                    {"jsonrpc": "2.0", "method": "panic", "id": 1},
                    {"jsonrpc": "2.0", "method": "success", "id": 2},
                ]),
            )
            .await;

            let expected = serde_json::json!([
                {"jsonrpc": "2.0", "error": {"code": -32603, "message": "Internal error"}, "id": 1},
                {"jsonrpc": "2.0", "result": "Success", "id": 2},
            ]);
            assert_eq!(response, expected);
        }
    }

    #[tokio::test]
    async fn rejects_non_json_content_header() {
        async fn always_success(_ctx: RpcContext) -> RpcResult {
            Ok(json!("Success"))
        }

        let router = RpcRouter::builder("vTEST")
            .register("success", always_success)
            .build(RpcContext::for_tests());

        let url = spawn_server(router).await;

        let client = reqwest::Client::new();
        let res = client
            .post(url.clone())
            .body(
                json!(
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

    #[tokio::test]
    async fn accepts_json_with_charset_utf8() {
        async fn always_success(_ctx: RpcContext) -> RpcResult {
            Ok(json!("Success"))
        }

        let router = RpcRouter::builder("vTEST")
            .register("success", always_success)
            .build(RpcContext::for_tests());

        let url = spawn_server(router).await;

        let expected = json!({"jsonrpc": "2.0", "result": "Success", "id": 1});

        let client = reqwest::Client::new();
        let res = client
            .post(url.clone())
            .body(
                json!(
                    {"jsonrpc": "2.0", "method": "success", "id": 1}
                )
                .to_string(),
            )
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();

        assert_eq!(res, expected);
    }

    #[tokio::test]
    async fn rejects_json_with_charset_utf16() {
        async fn always_success(_ctx: RpcContext) -> RpcResult {
            Ok(json!("Success"))
        }

        let router = RpcRouter::builder("vTEST")
            .register("success", always_success)
            .build(RpcContext::for_tests());

        let url = spawn_server(router).await;

        let client = reqwest::Client::new();
        let res = client
            .post(url.clone())
            .body(
                json!(
                    {"jsonrpc": "2.0", "method": "success", "id": 1}
                )
                .to_string(),
            )
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=utf-16",
            )
            .send()
            .await
            .unwrap()
            .status();

        assert_eq!(res, reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn with_no_params() {
        fn always_success() -> &'static str {
            "Success"
        }

        let router = RpcRouter::builder("vTEST")
            .register("success", always_success)
            .build(RpcContext::for_tests());

        let url = spawn_server(router).await;

        let expected = json!({"jsonrpc": "2.0", "result": "Success", "id": 1});

        let client = reqwest::Client::new();
        let res = client
            .post(url.clone())
            .json(&json!(
                {"jsonrpc": "2.0", "method": "success", "id": 1}
            ))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();

        assert_eq!(res, expected);

        let res = client
            .post(url.clone())
            .json(&json!(
                {"jsonrpc": "2.0", "method": "success", "id": 1, "params": []}
            ))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();

        assert_eq!(res, expected);
    }

    #[tokio::test]
    async fn response_hash_content_type_json() {
        fn always_success() -> &'static str {
            "Success"
        }

        let router = RpcRouter::builder("vTEST")
            .register("success", always_success)
            .build(RpcContext::for_tests());

        let url = spawn_server(router).await;

        let client = reqwest::Client::new();
        let res = client
            .post(url.clone())
            .json(&json!(
                {"jsonrpc": "2.0", "method": "success", "id": 1}
            ))
            .send()
            .await
            .unwrap();

        use reqwest::header::CONTENT_TYPE;
        let content_type = res
            .headers()
            .get(CONTENT_TYPE)
            .expect("content-type header should be set");

        assert_eq!(content_type, "application/json");
    }
}
