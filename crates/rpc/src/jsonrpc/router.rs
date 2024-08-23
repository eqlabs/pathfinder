use std::collections::HashMap;
use std::num::NonZeroUsize;

use axum::async_trait;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures::{Future, FutureExt, StreamExt};
use http::HeaderValue;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use tracing::Instrument;

use crate::context::RpcContext;
use crate::jsonrpc::error::RpcError;
use crate::jsonrpc::request::{RawParams, RpcRequest};
use crate::jsonrpc::response::{RpcResponse, RpcResult};
use crate::RpcVersion;

#[derive(Clone)]
pub struct RpcRouter {
    pub context: RpcContext,
    methods: &'static HashMap<&'static str, Box<dyn RpcMethod>>,
    version: RpcVersion,
}

pub struct RpcRouterBuilder {
    methods: HashMap<&'static str, Box<dyn RpcMethod>>,
    version: RpcVersion,
}

impl RpcRouterBuilder {
    /// Registers an RPC method.
    ///
    /// Panics if the method was already registered.
    pub fn register<I, O, S, M: IntoRpcMethod<'static, I, O, S>>(
        mut self,
        method_name: &'static str,
        method: M,
    ) -> Self {
        if self
            .methods
            .insert(method_name, IntoRpcMethod::into_method(method))
            .is_some()
        {
            panic!("'{method_name}' is already registered");
        }
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

    fn new(version: RpcVersion) -> Self {
        RpcRouterBuilder {
            methods: Default::default(),
            version,
        }
    }
}

impl RpcRouter {
    pub fn builder(version: RpcVersion) -> RpcRouterBuilder {
        RpcRouterBuilder::new(version)
    }

    /// Parses and executes a request. Returns [None] if its a notification.
    async fn run_request(&self, request: &str) -> Option<RpcResponse> {
        tracing::trace!(%request, "Running request");

        let request = match serde_json::from_str::<RpcRequest<'_>>(request) {
            Ok(request) => request,
            Err(e) => {
                return Some(RpcResponse::invalid_request(e.to_string()));
            }
        };

        // Ignore notification requests.
        if request.id.is_notification() {
            return None;
        }

        // Also grab the method_name as it is a static str, which is required by the
        // metrics.
        let Some((&method_name, method)) = self.methods.get_key_value(request.method.as_ref())
        else {
            return Some(RpcResponse::method_not_found(request.id));
        };

        metrics::increment_counter!("rpc_method_calls_total", "method" => method_name, "version" => self.version.to_str());

        let method = method.invoke(self.context.clone(), request.params, self.version);
        let result = std::panic::AssertUnwindSafe(method).catch_unwind().await;

        let output = match result {
            Ok(output) => output,
            Err(e) => {
                tracing::warn!(method=%request.method, backtrace=?e, "RPC method panic'd");
                Err(RpcError::InternalError(anyhow::anyhow!(
                    "RPC method panic'd"
                )))
            }
        };

        if output.is_err() {
            metrics::increment_counter!("rpc_method_calls_failed_total", "method" => method_name, "version" => self.version.to_str());
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

    let mut response = match handle_json_rpc_body(&state, body.as_ref()).await {
        Ok(responses) => match responses {
            RpcResponses::Empty => ().into_response(),
            RpcResponses::Single(response) => response.into_response(),
            RpcResponses::Multiple(responses) => {
                serde_json::to_string(&responses).unwrap().into_response()
            }
        },
        Err(RpcRequestError::ParseError(e)) => RpcResponse::parse_error(e).into_response(),
        Err(RpcRequestError::InvalidRequest(e)) => RpcResponse::invalid_request(e).into_response(),
    };

    use http::header::CONTENT_TYPE;
    static APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
    response
        .headers_mut()
        .insert(CONTENT_TYPE, APPLICATION_JSON.clone());
    response
}

pub(super) enum RpcRequestError {
    ParseError(String),
    InvalidRequest(String),
}

#[derive(Debug)]
pub(super) enum RpcResponses {
    Empty,
    Single(RpcResponse),
    Multiple(Vec<RpcResponse>),
}

impl serde::ser::Serialize for RpcResponses {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Empty => ().serialize(serializer),
            Self::Single(response) => response.serialize(serializer),
            Self::Multiple(responses) => responses.serialize(serializer),
        }
    }
}

/// Helper to scope the responses so we can set the content-type afterwards
/// instead of dealing with branches / early exits.
pub(super) async fn handle_json_rpc_body(
    state: &RpcRouter,
    body: &[u8],
) -> Result<RpcResponses, RpcRequestError> {
    // Unfortunately due to this https://github.com/serde-rs/json/issues/497
    // we cannot use an enum with borrowed raw values inside to do a single
    // deserialization for us. Instead we have to distinguish manually
    // between a single request and a batch request which we do by checking
    // the first byte.
    if body.first() != Some(&b'[') {
        let request = match serde_json::from_slice::<&RawValue>(body) {
            Ok(request) => request,
            Err(e) => {
                return Err(RpcRequestError::ParseError(e.to_string()));
            }
        };

        match state.run_request(request.get()).await {
            Some(response) => Ok(RpcResponses::Single(response)),
            None => Ok(RpcResponses::Empty),
        }
    } else {
        let requests = match serde_json::from_slice::<Vec<&RawValue>>(body) {
            Ok(requests) => requests,
            Err(e) => {
                return Err(RpcRequestError::ParseError(e.to_string()));
            }
        };

        if requests.is_empty() {
            return Err(RpcRequestError::InvalidRequest(
                "A batch request must contain at least one request".to_owned(),
            ));
        }

        let responses = run_concurrently(
            state.context.config.batch_concurrency_limit,
            requests.into_iter().enumerate(),
            |(idx, request)| {
                state
                    .run_request(request.get())
                    .instrument(tracing::debug_span!("batch", idx))
            },
        )
        .await
        .flatten()
        .collect::<Vec<RpcResponse>>();

        // All requests were notifications.
        if responses.is_empty() {
            return Ok(RpcResponses::Empty);
        }

        Ok(RpcResponses::Multiple(responses))
    }
}

#[axum::async_trait]
pub trait RpcMethod: Send + Sync {
    async fn invoke<'a>(
        &self,
        state: RpcContext,
        input: RawParams<'a>,
        version: RpcVersion,
    ) -> RpcResult;
}

/// Utility trait which automates the serde of an RPC methods input and output.
///
/// This trait is sealed to prevent attempts at implementing it manually. This
/// will likely clash with the existing blanket implementations with very
/// unhelpful error messages.
///
/// This trait is automatically implemented for the following methods:
/// ```
/// async fn input_and_context(
///     ctx: RpcContext,
///     input: impl Deserialize,
/// ) -> Result<impl Serialize, Into<RpcError>>;
/// async fn input_only(input: impl Deserialize) -> Result<impl Serialize, Into<RpcError>>;
/// async fn context_only(ctx: RpcContext) -> Result<impl Serialize, Into<RpcError>>;
/// ```
///
/// The generics allow us to achieve a form of variadic specialization and can
/// be ignored by callers. See [sealed::Sealed] to add more method signatures or
/// more information on how this works.
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

    use super::*;
    use crate::dto::serialize::{SerializeForVersion, Serializer};
    use crate::jsonrpc::error::RpcError;
    use crate::RpcVersion;

    /// Sealed implementation of [RpcMethod].
    ///
    /// The generics allow for a form of specialization over a methods Input,
    /// Output and State by treating each as a tuple. Varying the tuple
    /// length allows us to target a specific method signature. This same
    /// could be achieved with a single generic but it becomes less clear as
    /// each permutation would require a different tuple length.
    ///
    /// By convention, the lack of a type is equivalent to the unit tuple (). So
    /// if we want to target functions with no input params, no input state
    /// and an output:
    /// ```rust
    /// Sealed<I = (), S = (), O = ((), Output)>
    /// ```
    pub trait Sealed<I, O, S> {
        fn into_method(self) -> Box<dyn RpcMethod>;
    }

    /// ```
    /// async fn example(RpcContext, impl Deserialize, RpcVersion) -> Result<Output, Into<RpcError>>
    /// ```
    impl<'a, F, Input, Output, Error, Fut>
        Sealed<((), (), Input), ((), (), Output), ((), (), RpcContext)> for F
    where
        F: Fn(RpcContext, Input, RpcVersion) -> Fut + Sync + Send + 'static,
        Input: DeserializeOwned + Send + Sync + 'static,
        Output: SerializeForVersion + Send + Sync + 'static,
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
                F: Fn(RpcContext, Input, RpcVersion) -> Fut + Sync + Send,
                Input: DeserializeOwned + Send + Sync,
                Output: SerializeForVersion + Send + Sync,
                Error: Into<RpcError> + Send + Sync,
                Fut: Future<Output = Result<Output, Error>> + Send,
            {
                async fn invoke<'a>(
                    &self,
                    state: RpcContext,
                    input: RawParams<'a>,
                    version: RpcVersion,
                ) -> RpcResult {
                    let input = input.deserialize()?;
                    (self.f)(state, input, version)
                        .await
                        .map_err(Into::into)?
                        .serialize(Serializer::new(version))
                        .map_err(|e| RpcError::InternalError(e.into()))
                }
            }

            Box::new(Helper {
                f: self,
                _marker: Default::default(),
            })
        }
    }

    /// ```
    /// async fn example(RpcContext, impl Deserialize) -> Result<Output, Into<RpcError>>
    /// ```
    impl<'a, F, Input, Output, Error, Fut> Sealed<((), Input), ((), Output), ((), RpcContext)> for F
    where
        F: Fn(RpcContext, Input) -> Fut + Sync + Send + 'static,
        Input: DeserializeOwned + Send + Sync + 'static,
        Output: SerializeForVersion + Send + Sync + 'static,
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
                Output: SerializeForVersion + Send + Sync,
                Error: Into<RpcError> + Send + Sync,
                Fut: Future<Output = Result<Output, Error>> + Send,
            {
                async fn invoke<'a>(
                    &self,
                    state: RpcContext,
                    input: RawParams<'a>,
                    version: RpcVersion,
                ) -> RpcResult {
                    let input = input.deserialize()?;
                    (self.f)(state, input)
                        .await
                        .map_err(Into::into)?
                        .serialize(Serializer::new(version))
                        .map_err(|e| RpcError::InternalError(e.into()))
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
        Output: SerializeForVersion + Sync + Send + 'static,
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
                Output: SerializeForVersion + Send + Sync,
                Error: Into<RpcError> + Send + Sync,
                Fut: Future<Output = Result<Output, Error>> + Send,
            {
                async fn invoke<'a>(
                    &self,
                    _state: RpcContext,
                    input: RawParams<'a>,
                    version: RpcVersion,
                ) -> RpcResult {
                    let input = input.deserialize()?;
                    (self.f)(input)
                        .await
                        .map_err(Into::into)?
                        .serialize(Serializer::new(version))
                        .map_err(|e| RpcError::InternalError(e.into()))
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
        Output: SerializeForVersion + Sync + Send + 'static,
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
                Output: SerializeForVersion + Send + Sync,
                Error: Into<RpcError> + Send + Sync,
                Fut: Future<Output = Result<Output, Error>> + Send,
            {
                async fn invoke<'a>(
                    &self,
                    state: RpcContext,
                    input: RawParams<'a>,
                    version: RpcVersion,
                ) -> RpcResult {
                    if !input.is_empty() {
                        return Err(RpcError::InvalidParams(
                            "This method takes no inputs".to_owned(),
                        ));
                    }
                    (self.f)(state)
                        .await
                        .map_err(Into::into)?
                        .serialize(Serializer::new(version))
                        .map_err(|e| RpcError::InternalError(e.into()))
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
        Output: SerializeForVersion + Sync + Send + 'static,
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
                Output: SerializeForVersion + Send + Sync,
                Error: Into<RpcError> + Send + Sync,
                Fut: Future<Output = Result<Output, Error>> + Send,
            {
                async fn invoke<'a>(
                    &self,
                    _state: RpcContext,
                    input: RawParams<'a>,
                    version: RpcVersion,
                ) -> RpcResult {
                    if !input.is_empty() {
                        return Err(RpcError::InvalidParams(
                            "This method takes no inputs".to_owned(),
                        ));
                    }
                    (self.f)()
                        .await
                        .map_err(Into::into)?
                        .serialize(Serializer::new(version))
                        .map_err(|e| RpcError::InternalError(e.into()))
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
                async fn invoke<'a>(
                    &self,
                    _state: RpcContext,
                    input: RawParams<'a>,
                    version: RpcVersion,
                ) -> RpcResult {
                    if !input.is_empty() {
                        return Err(RpcError::InvalidParams(
                            "This method takes no inputs".to_owned(),
                        ));
                    }
                    (self.f)()
                        .serialize(Serializer::new(version))
                        .map_err(|e| RpcError::InternalError(e.into()))
                }
            }
            Box::new(Helper { f: self })
        }
    }
}

/// Performs asynchronous work concurrently on an input iterator, returning an
/// `Iterator` with the output of each piece of work.
///
/// ⚠ Execution will be performed out of order. Results are
/// eventually re-ordered.
///
/// Usage example:
/// ```ignore
/// let results = run_concurrently(
///     NonZeroUsize::new(10).unwrap(),
///     0..iterations,
///     |i| async move {
///         sleep(Duration::from_millis(i) as u64).await;
///         i
///     },
/// )
/// .await
/// .collect::<Vec<i>>();
/// ```
async fn run_concurrently<O, I, F, W, V>(
    concurrency_limit: NonZeroUsize,
    input_iter: V,
    work: W,
) -> impl Iterator<Item = O>
where
    V: Iterator<Item = I> + ExactSizeIterator,
    W: Fn(I) -> F,
    F: Future<Output = O> + Sized,
{
    let capacity = input_iter.len();
    let (result_sender, mut result_receiver) = tokio::sync::mpsc::channel(capacity);

    futures::stream::iter(input_iter)
        .enumerate()
        .for_each_concurrent(Some(concurrency_limit.get()), |(index, input)| {
            let result_sender = result_sender.clone();
            let future = work(input);

            async move {
                let result = future.await;

                // No reason for this to fail as:
                //  * channel capacity is sized according to the input size,
                //  * a sender is kept alive until completion
                result_sender.send((index, result)).await.expect(
                    "This channel is expected to be open and to not go over capacity. This is a \
                     bug.",
                );
            }
        })
        .await;

    // Necessary to break the receive loop eventually.
    drop(result_sender);

    // All results should be available immediately at this point.
    let mut indexed_results = Vec::new();
    indexed_results.reserve_exact(capacity);
    while let Some(indexed_result) = result_receiver.recv().await {
        indexed_results.push(indexed_result)
    }

    indexed_results.sort_by(|(index_a, _), (index_b, _)| index_a.cmp(index_b));

    indexed_results.into_iter().map(|(_index, result)| result)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};

    use super::*;

    async fn spawn_server(router: RpcRouter) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://127.0.0.1:{}", addr.port());

        tokio::spawn(async {
            let router = axum::Router::new()
                .route("/", axum::routing::post(rpc_handler))
                .with_state(router);
            axum::serve(listener, router.into_make_service()).await
        });

        url
    }

    /// Spawns an RPC server with the given router and queries it with the given
    /// request.
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
        use pretty_assertions_sorted::assert_eq;
        use rstest::rstest;
        use serde_json::json;

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

            RpcRouter::builder(RpcVersion::default())
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
            json!({"jsonrpc": "2.0", "id": null, 
                "error": {"code": -32600, "message": "Invalid request", "data": {
                    "reason": "invalid type: integer `1`, expected a string at line 1 column 27"
                }}}),
        )]
        #[case::empty_batch(
            json!([]),
            json!({"jsonrpc": "2.0", "id": null, 
                "error": {"code": -32600, "message": "Invalid request", "data": {
                    "reason": "A batch request must contain at least one request"
                }}}),
        )]
        #[case::invalid_batch_single(
            json!([1]),
            json!([{"jsonrpc": "2.0", "id": null, 
                "error": {"code": -32600, "message": "Invalid request", "data": {
                    "reason": "invalid type: integer `1`, expected struct Helper at line 1 column 1"
                }}}
            ]),
        )]
        #[case::invalid_batch_multiple(
            json!([1, 2, 3]),
            json!([
                {"jsonrpc": "2.0", "id": null, 
                    "error": {"code": -32600, "message": "Invalid request", "data": {
                        "reason": "invalid type: integer `1`, expected struct Helper at line 1 column 1"
                    }}},
                {"jsonrpc": "2.0", "id": null, 
                    "error": {"code": -32600, "message": "Invalid request", "data": {
                        "reason": "invalid type: integer `2`, expected struct Helper at line 1 column 1"
                    }}},
                {"jsonrpc": "2.0", "id": null, 
                    "error": {"code": -32600, "message": "Invalid request", "data": {
                        "reason": "invalid type: integer `3`, expected struct Helper at line 1 column 1"
                    }}},
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
                {"jsonrpc": "2.0", "id": null, "error": 
                    {"code": -32600, "message": "Invalid request", "data": {
                        "reason": "missing field `jsonrpc` at line 1 column 13"
                    }}},
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
        #[case::single(
            r#"{"jsonrpc": "2.0", "method": "foobar, "params": "bar", "baz]"#,
            "expected `,` or `}` at line 1 column 40"
        )]
        #[case::batch(
            r#"[
            {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"},
            {"jsonrpc": "2.0", "method"
         ]"#,
            "expected `:` at line 4 column 10"
        )]
        #[tokio::test]
        async fn invalid_json(#[case] request: &'static str, #[case] reason: &'static str) {
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

            let expected = serde_json::json!({"jsonrpc": "2.0", "error": {"code": -32700, "data": {"reason": reason}, "message": "Parse error"}, "id": null});
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

            RpcRouter::builder(Default::default())
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

        let router = RpcRouter::builder(Default::default())
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

        let router = RpcRouter::builder(Default::default())
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

        let router = RpcRouter::builder(Default::default())
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

        let router = RpcRouter::builder(Default::default())
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

        let router = RpcRouter::builder(Default::default())
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

    mod concurrent_futures {
        use std::cmp::max;
        use std::sync::Arc;
        use std::time::Duration;

        use tokio::sync::Notify;
        use tokio::time::timeout;

        use super::*;

        pub enum TaskEvent {
            Start,
            End(usize),
        }

        #[tokio::test]
        async fn concurrent_futures() {
            let iterations = 100;
            let concurrency_limit = iterations / 2;
            let events =
                concurrent_count(iterations, NonZeroUsize::new(concurrency_limit).unwrap()).await;
            assert_eq!(max_concurrency_level(&events), concurrency_limit);

            // The test should have messed up with the execution order, which is important
            // to assess that the results are ordered according to the input
            // order and not the execution order.
            let order_difference = events
                .into_iter()
                .filter_map(|event| {
                    if let TaskEvent::End(index) = event {
                        Some(index)
                    } else {
                        None
                    }
                })
                .enumerate()
                .any(|(execution_index, task_index)| execution_index != task_index);
            assert!(order_difference);
        }

        #[tokio::test]
        async fn sequential_futures() {
            let iterations = 100;
            let concurrency_limit = 1;
            let events =
                concurrent_count(iterations, NonZeroUsize::new(concurrency_limit).unwrap()).await;
            assert_eq!(max_concurrency_level(&events), concurrency_limit);

            // Make sure there isn't a change in the execution order so there is no change
            // in behavior with the introduction of this feature.
            let order_match = events
                .into_iter()
                .filter_map(|event| {
                    if let TaskEvent::End(index) = event {
                        Some(index)
                    } else {
                        None
                    }
                })
                .enumerate()
                .all(|(execution_index, task_index)| execution_index == task_index);
            assert!(order_match);
        }

        async fn concurrent_count(
            iterations: usize,
            concurrency_limit: NonZeroUsize,
        ) -> Vec<TaskEvent> {
            #[derive(Clone)]
            struct State {
                index: usize,
                notify: Arc<Notify>,
            }

            let task_states = (0..iterations)
                .map(|index| State {
                    index,
                    notify: Arc::new(Notify::new()),
                })
                .collect::<Vec<State>>();

            let (event_sender, mut event_receiver) = tokio::sync::mpsc::channel(iterations * 2);
            let (result_sender, result_receiver) = tokio::sync::oneshot::channel();

            // Run the tasks in the background
            tokio::spawn({
                let task_states = task_states.clone();
                async move {
                    let results =
                        run_concurrently(concurrency_limit, task_states.into_iter(), |state| {
                            let event_sender = event_sender.clone();
                            async move {
                                event_sender.send(TaskEvent::Start).await.unwrap();
                                // Wait until allowed to continue.
                                let _start = state.notify.notified().await;
                                event_sender
                                    .send(TaskEvent::End(state.index))
                                    .await
                                    .unwrap();
                                state.index
                            }
                        })
                        .await
                        .collect::<Vec<usize>>();

                    result_sender.send(results).unwrap();
                }
            });

            // N tasks should already have started, N being the `concurrency_limit`.
            let mut events = vec![];
            for _i in 0..concurrency_limit.get() {
                let event = timeout(Duration::from_millis(100), event_receiver.recv())
                    .await
                    .expect("Timeout reached, there's something wrong with the concurrency limit")
                    .expect("The event channel closed early");
                events.push(event);
            }

            // Allow all tasks to continue, descending order to mess up with completion
            // order.
            for i in (0..iterations).rev() {
                task_states[i].notify.notify_one();
            }

            let results = result_receiver.await.unwrap();

            // Make sure the results are complete.
            assert_eq!(results.len(), iterations);
            // Make sure the results are ordered consistently with the input.
            results
                .into_iter()
                .enumerate()
                .for_each(|(expected, result)| {
                    assert_eq!(result, expected);
                });

            // Now retrieve the rest of the events
            while let Some(event) = event_receiver.recv().await {
                events.push(event)
            }

            events
        }

        fn max_concurrency_level(events: &[TaskEvent]) -> usize {
            let mut started_task = 0;
            let mut max_simultaneous = 0;

            for event in events {
                match event {
                    TaskEvent::Start => {
                        started_task += 1;
                        max_simultaneous = max(max_simultaneous, started_task);
                    }
                    TaskEvent::End(_) => {
                        started_task -= 1;
                    }
                }
            }

            max_simultaneous
        }
    }
}
