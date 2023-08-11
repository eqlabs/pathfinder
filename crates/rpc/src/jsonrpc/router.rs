use axum::extract::State;
use axum::headers::ContentType;
use axum::response::IntoResponse;
use axum::{async_trait, TypedHeader};
use futures::Future;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::context::RpcContext;
use crate::jsonrpc::error::RpcError;
use crate::jsonrpc::request::RpcRequest;
use crate::jsonrpc::response::{RpcResponse, RpcResult};

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
#[async_trait]
pub trait RpcMethod<I, O, S>: sealed::Sealed<I, O, S> {
    // TODO: consider an associated type for version for the metrics.
    // TODO: consider another layer of trait for the method handler to return Option<dyn RpcMethod> for method str.
    async fn invoke(
        &self,
        method_name: &'static str,
        version: &'static str,
        ctx: RpcContext,
        params: Value,
    ) -> RpcResult;
}

#[async_trait]
impl<T, I, O, S> RpcMethod<I, O, S> for T
where
    T: sealed::Sealed<I, O, S> + std::marker::Sync,
{
    async fn invoke(
        &self,
        method_name: &'static str,
        version: &'static str,
        ctx: RpcContext,
        params: Value,
    ) -> RpcResult {
        // TODO: is version always required or is it None for root?
        metrics::increment_counter!("rpc_method_calls_total", "method" => method_name, "version" => version);
        let result = <T as sealed::Sealed<I, O, S>>::invoke(&self, ctx, params).await;

        if result.is_err() {
            metrics::increment_counter!("rpc_method_calls_failed_total", "method" => method_name, "version" => version)
        }

        result
    }
}

mod sealed {
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
    #[async_trait]
    pub trait Sealed<I, O, S> {
        // TODO: param parsing error handling for each impl if there is no input required.
        async fn invoke(&self, ctx: RpcContext, params: Value) -> RpcResult;
    }

    /// ```
    /// async fn example(RpcContext, impl Deserialize) -> Result<Output, Into<RpcError>>
    /// ```
    #[async_trait]
    impl<F, Input, Output, Error, Fut> Sealed<((), Input), ((), Output), ((), RpcContext)> for F
    where
        F: Fn(RpcContext, Input) -> Fut + std::marker::Sync,
        Input: DeserializeOwned + std::marker::Send,
        Output: Serialize,
        Error: Into<RpcError>,
        Fut: Future<Output = Result<Output, Error>> + std::marker::Send,
    {
        async fn invoke(&self, ctx: RpcContext, params: Value) -> RpcResult {
            let input: Input =
                serde_json::from_value(params).map_err(|_| RpcError::InvalidParams)?;
            let output = self(ctx, input).await.map_err(Into::into)?;
            serde_json::to_value(&output).map_err(|e| RpcError::InternalError(e.into()))
        }
    }

    /// ```
    /// async fn example(impl Deserialize) -> Result<Output, Into<RpcError>>
    /// ```
    #[async_trait]
    impl<F, Input, Output, Error, Fut> Sealed<((), Input), ((), Output), ()> for F
    where
        F: Fn(Input) -> Fut + std::marker::Sync,
        Input: DeserializeOwned + std::marker::Send,
        Output: Serialize,
        Error: Into<RpcError>,
        Fut: Future<Output = Result<Output, Error>> + std::marker::Send,
    {
        async fn invoke(&self, _ctx: RpcContext, params: Value) -> RpcResult {
            let input: Input =
                serde_json::from_value(params).map_err(|_| RpcError::InvalidParams)?;
            let output = self(input).await.map_err(Into::into)?;
            serde_json::to_value(&output).map_err(|e| RpcError::InternalError(e.into()))
        }
    }

    /// ```
    /// async fn example(RpcContext) -> Result<Output, Into<RpcError>>
    /// ```
    #[async_trait]
    impl<F, Output, Error, Fut> Sealed<(), ((), Output), ((), RpcContext)> for F
    where
        F: Fn(RpcContext) -> Fut + std::marker::Sync,
        Output: Serialize,
        Error: Into<RpcError>,
        Fut: Future<Output = Result<Output, Error>> + std::marker::Send,
    {
        async fn invoke(&self, ctx: RpcContext, _params: Value) -> RpcResult {
            let output = self(ctx).await.map_err(Into::into)?;
            serde_json::to_value(&output).map_err(|e| RpcError::InternalError(e.into()))
        }
    }

    /// ```
    /// async fn example() -> Result<Output, Into<RpcError>>
    /// ```
    #[async_trait]
    impl<F, Output, Error, Fut> Sealed<(), (), ((), Output)> for F
    where
        F: Fn() -> Fut + std::marker::Sync,
        Output: Serialize,
        Error: Into<RpcError>,
        Fut: Future<Output = Result<Output, Error>> + std::marker::Send,
    {
        async fn invoke(&self, _ctx: RpcContext, _params: Value) -> RpcResult {
            let output = self().await.map_err(Into::into)?;
            serde_json::to_value(&output).map_err(|e| RpcError::InternalError(e.into()))
        }
    }

    /// ```
    /// fn example() -> &'static str
    /// ```
    #[async_trait]
    impl<F> Sealed<(), (), ((), (), &'static str)> for F
    where
        F: Fn() -> &'static str + std::marker::Sync,
    {
        async fn invoke(&self, _ctx: RpcContext, _params: Value) -> RpcResult {
            serde_json::to_value(self()).map_err(|e| RpcError::InternalError(e.into()))
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

/// An axum handler for a JSON RPC endpoint.
///
/// Specify the RPC methods by implementing [RpcMethodHandler].
///
/// ```rust
/// let router = axum::Router::new()
///     .route("/", post(rpc_handler::<ExampleHandler>));
/// ```
pub async fn rpc_handler<H: RpcMethodHandler>(
    State(state): State<RpcContext>,
    TypedHeader(content_type): TypedHeader<ContentType>,
    bytes: axum::body::Bytes,
) -> impl IntoResponse {
    // Only allow json content.
    if content_type != ContentType::json() {
        return axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }

    /// Used to parse the outer shell of an JSON RPC request.
    ///
    /// The specification requires differentiating between invalid json and invalid individual requests
    /// within the json. This intermediary type let's us handle this.
    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum RawRequest {
        // This must come first as otherwise a batch request will get parsed as a Value::Array
        Batch(Vec<Value>),
        Single(Value),
    }

    // TODO: what HTTP codes should the rpc errors get?

    let Ok(raw_request) = serde_json::from_slice::<RawRequest>(&bytes) else {
        return RpcResponse::PARSE_ERROR.into_response();
    };

    match raw_request {
        RawRequest::Single(request) => {
            let Ok(request) = serde_json::from_value::<RpcRequest>(request) else {
                return serde_json::to_string(&RpcResponse::INVALID_REQUEST).unwrap().into_response();
            };

            // Ignore notification requests.
            let Some(id) = request.id else {
                // TODO: should this just be closed connection?
                return ().into_response();
            };

            // Use tokio spawn to handle panics. This could be done by catch_unwind but RpcContext
            // contains a mutex which is not unwindsafe and I'm not smart enough to figure it out.
            let result = tokio::spawn(async move {
                H::call_method(&request.method, state, request.params).await
            })
            .await;

            let output = match result {
                Ok(output) => output,
                Err(e) => Err(RpcError::InternalError(anyhow::anyhow!(e))),
            };

            RpcResponse { output, id }.into_response()
        }
        RawRequest::Batch(requests) => {
            // An empty batch is invalid
            if requests.is_empty() {
                return serde_json::to_string(&RpcResponse::INVALID_REQUEST)
                    .unwrap()
                    .into_response();
            }

            let mut responses = Vec::new();

            for request in requests {
                let Ok(request) = serde_json::from_value::<RpcRequest>(request) else {
                    responses.push(RpcResponse::INVALID_REQUEST);
                    continue;
                };

                // Ignore notification requests.
                let Some(id) = request.id else {
                    continue;
                };

                // Use tokio spawn to handle panics. This could be done by catch_unwind but RpcContext
                // contains a mutex which is not unwindsafe and I'm not smart enough to figure it out.
                let state2 = state.clone();
                let result = tokio::spawn(async move {
                    H::call_method(&request.method, state2, request.params).await
                })
                .await;
                let output = match result {
                    Ok(output) => output,
                    Err(e) => Err(RpcError::InternalError(anyhow::anyhow!(e))),
                };
                responses.push(RpcResponse { output, id });
            }

            // All requests were notifications.
            if responses.is_empty() {
                // TODO: should this just be closed connection?
                return ().into_response();
            }

            return serde_json::to_string(&responses).unwrap().into_response();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc::RequestId;
    use serde_json::json;

    async fn spawn_server<H: RpcMethodHandler + 'static>() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://127.0.0.1:{}", addr.port());

        tokio::spawn(async {
            let router = axum::Router::new()
                .route("/", axum::routing::post(rpc_handler::<H>))
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

        struct SpecMethodHandler;
        #[async_trait]
        impl RpcMethodHandler for SpecMethodHandler {
            async fn call_method(method: &str, ctx: RpcContext, params: Value) -> RpcResult {
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

                #[rustfmt::skip]
                let output = match method {
                    "subtract" => subtract.invoke("subtract", "version", ctx, params).await,
                    "sum"      => sum.invoke("sum", "version", ctx, params).await,
                    "get_data" => get_data.invoke("get_data", "version", ctx, params).await,
                    unknown    => Err(RpcError::MethodNotFound {
                        method: unknown.to_owned(),
                    }),
                };

                output
            }
        }

        #[tokio::test]
        async fn with_positional_params() {
            let url = spawn_server::<SpecMethodHandler>().await;

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
            let url = spawn_server::<SpecMethodHandler>().await;

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
            let url = spawn_server::<SpecMethodHandler>().await;

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
            let url = spawn_server::<SpecMethodHandler>().await;

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
            let url = spawn_server::<SpecMethodHandler>().await;

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
            let url = spawn_server::<SpecMethodHandler>().await;

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
            let url = spawn_server::<SpecMethodHandler>().await;

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
            let url = spawn_server::<SpecMethodHandler>().await;

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
            let url = spawn_server::<SpecMethodHandler>().await;

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
            let url = spawn_server::<SpecMethodHandler>().await;

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
            assert_eq!(res, expected);
        }

        #[tokio::test]
        async fn batch_all_notifications() {
            let url = spawn_server::<SpecMethodHandler>().await;

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
                id: Some(RequestId::String("text".to_owned())),
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

        struct PanicHandler;
        #[async_trait]
        impl RpcMethodHandler for PanicHandler {
            async fn call_method(method: &str, _ctx: RpcContext, _params: Value) -> RpcResult {
                match method {
                    "panic" => panic!("Oh no!"),
                    _ => Ok(json!("Success")),
                }
            }
        }

        #[tokio::test]
        async fn panic_is_internal_error() {
            let url = spawn_server::<PanicHandler>().await;

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
            let url = spawn_server::<PanicHandler>().await;

            let client = reqwest::Client::new();
            let res = client
                .post(url.clone())
                .json(&serde_json::json!(
                    [
                        {"jsonrpc": "2.0", "method": "panic", "id": 1},
                        {"jsonrpc": "2.0", "method": "no panic", "id": 2},
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
        struct OnlySuccess;
        #[async_trait]
        impl RpcMethodHandler for OnlySuccess {
            async fn call_method(_method: &str, _ctx: RpcContext, _params: Value) -> RpcResult {
                Ok(json!("Success"))
            }
        }

        let url = spawn_server::<OnlySuccess>().await;

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
