//! Middleware that proxies requests at a specified URI to internal
//! RPC method calls.
use http::{response::Builder, status::StatusCode};
use hyper::{Body, Method, Request, Response};
use jsonrpsee::core::error::GenericTransportError;
use jsonrpsee::core::http_helpers::read_body;
use jsonrpsee::types::error::{reject_too_big_request, ErrorCode, ErrorResponse};
use jsonrpsee::types::Id;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Layer that applies [`RpcVersioningService`] which proxies the requests at specific paths
/// to specific RPC method calls.
///
/// See [`RpcVersioningService`] for more details.
#[derive(Debug, Copy, Clone)]
pub struct RpcVersioningLayer {
    max_request_body_size: u32,
}

impl RpcVersioningLayer {
    pub fn new(max_request_body_size: u32) -> Self {
        Self {
            max_request_body_size,
        }
    }
}

impl<S> Layer<S> for RpcVersioningLayer {
    type Service = RpcVersioningService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcVersioningService::new(inner, self.max_request_body_size)
    }
}

/// Proxy requests on specific paths to the specified RPC method calls.
///
/// # Request
///
/// RPC method names in the request body are prefixed with the path to
/// which the request is being made, for example:
///
/// ```txt
/// /rpc/v0.2
/// {"method": "starknet_chainId"}
/// ```
///
/// becomes
///
/// ```txt
/// /
/// {"method": "v0.2_starknet_chainId"}
/// ```
///
/// # Response
///
/// Responses are not modified.
#[derive(Debug, Clone)]
pub struct RpcVersioningService<S> {
    inner: Arc<Mutex<S>>,
    max_request_body_size: u32,
}

impl<S> RpcVersioningService<S> {
    /// Creates new [`RpcVersioningService`]
    pub fn new(inner: S, max_request_body_size: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            max_request_body_size,
        }
    }
}

impl<S> Service<Request<Body>> for RpcVersioningService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Do not delegate to the inner service to avoid locking
        // This if fine because we don't use more middleware and
        // the internal service of the `jsonrpsee` server just returns
        // `Poll::Ready(Ok(()))`
        Poll::Ready(Ok(()))
    }

    /// Attempts to do as little error handling as possible:
    /// - if has to manage an error condition tries to do it consistently with the inner service,
    /// - otherwise let the inner service do it, so that there are less cases in which we have to
    ///   care for consistency.
    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        let max_request_body_size = self.max_request_body_size;

        let prefixes = if req.method() == Method::POST {
            match req.uri().path() {
                // An empty path "" is treated the same as "/".
                // However for a non-empty path adding a trailing slash
                // makes it a different path from the original,
                // that's why we have to account for those separately.
                "/" | "/rpc/v0.2" | "/rpc/v0.2/" => {
                    Some(&[("starknet_", "v0.2_"), ("pathfinder_", "v0.1_")][..])
                }
                "/rpc/v0.3" | "/rpc/v0.3/" => Some(&[("starknet_", "v0.3_")][..]),
                "/rpc/pathfinder/v0.1" | "/rpc/pathfinder/v0.1/" => {
                    Some(&[("pathfinder_", "v0.1_")][..])
                }
                _ => return Box::pin(std::future::ready(Ok(response::not_found()))),
            }
        } else {
            None
        };

        match prefixes {
            Some(prefixes) => {
                let fut = async move {
                    // Retain the parts to then later recreate the request
                    let (parts, body) = req.into_parts();

                    let (body, is_single) =
                        match read_body(&parts.headers, body, max_request_body_size).await {
                            Ok(x) => x,
                            Err(GenericTransportError::TooLarge) => {
                                return Ok(response::too_large(max_request_body_size))
                            }
                            Err(GenericTransportError::Malformed) => {
                                return Ok(response::malformed())
                            }
                            Err(GenericTransportError::Inner(_)) => return Ok(response::internal()),
                        };

                    let body = if is_single {
                        let mut request: jsonrpsee::types::Request<'_> =
                            serde_json::from_slice(&body).unwrap();
                        prefix_method(&mut request, prefixes);
                        serde_json::to_vec(&request)
                    } else {
                        let mut batch: Vec<jsonrpsee::types::Request<'_>> =
                            serde_json::from_slice(&body).unwrap();
                        batch
                            .iter_mut()
                            .for_each(|request| prefix_method(request, prefixes));
                        serde_json::to_vec(&batch)
                    };

                    let body = match body {
                        Ok(body) => body,
                        Err(_) => return Ok(response::internal()),
                    };

                    let req: Request<Body> = Request::from_parts(parts, body.into());
                    let fut = Self::call_inner(inner, req);
                    let resp = fut.await?;
                    Ok(resp)
                };
                Box::pin(fut)
            }
            None => Self::call_inner(inner, req),
        }
    }
}

fn prefix_method(request: &mut jsonrpsee::types::Request<'_>, prefixes: &[(&str, &str)]) {
    for (old, new) in prefixes {
        if request.method.starts_with(old) {
            let method = new.to_string() + &request.method;
            request.method = method.into();
            break;
        }
    }
}

impl<S> RpcVersioningService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
{
    fn call_inner(
        inner: Arc<Mutex<S>>,
        req: Request<Body>,
    ) -> <Self as Service<Request<Body>>>::Future {
        // Call the inner service and get a future that resolves to the response.
        let guard = inner.lock();
        match guard {
            Ok(mut guard) => {
                let fut = guard.call(req);
                Box::pin(fut)
            }
            Err(_) => Box::pin(std::future::ready(Ok(response::internal()))),
        }
    }
}

/// These responses are 1:1 to what jsonrpsee could have exported
mod response {
    use jsonrpsee::types::ErrorObject;

    use super::*;

    const CONTENT_TYPE: &str = "content-type";
    const TEXT: &str = "text/plain";
    const JSON: &str = "application/json; charset=utf-8";

    pub(super) fn not_found() -> Response<Body> {
        with_canonical_reason(StatusCode::NOT_FOUND)
    }

    pub(super) fn too_large(limit: u32) -> Response<Body> {
        with_error(StatusCode::PAYLOAD_TOO_LARGE, reject_too_big_request(limit))
    }

    pub(super) fn malformed() -> Response<Body> {
        with_error(StatusCode::BAD_REQUEST, ErrorCode::ParseError)
    }

    pub(super) fn internal() -> Response<Body> {
        with_error(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError)
    }

    fn with_error<'a>(code: StatusCode, error: impl Into<ErrorObject<'a>>) -> Response<Body> {
        let body = ErrorResponse::borrowed(error.into(), Id::Null);
        let body = serde_json::to_string(&body)
            .expect("error response is serializable")
            .into();

        Builder::new()
            .status(code)
            .header(CONTENT_TYPE, JSON)
            .body(body)
            .expect("response is properly formed")
    }

    fn with_canonical_reason(code: StatusCode) -> Response<Body> {
        Builder::new()
            .status(code)
            .header(CONTENT_TYPE, TEXT)
            .body(
                code.canonical_reason()
                    .expect("canonical reason is defined")
                    .into(),
            )
            .expect("response is properly formed")
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn api_versions_are_routed_correctly_for_all_methods() {
        use super::super::test_client::TestClientBuilder;
        use super::super::{RpcContext, RpcMetricsLogger, RpcServer};
        use pathfinder_common::test_utils::metrics::{FakeRecorder, RecorderGuard};
        use serde_json::json;

        let recorder = FakeRecorder::default();
        let handle = recorder.handle();
        // Other concurrent tests could be setting their own recorders
        let _guard = RecorderGuard::lock(recorder);

        let context = RpcContext::for_tests();
        let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
            .with_logger(RpcMetricsLogger)
            .run()
            .await
            .unwrap();

        // Common methods for starknet RPC spec v0.2 and v0.3
        let common = [
            "starknet_addDeclareTransaction",
            "starknet_addDeployAccountTransaction",
            "starknet_addInvokeTransaction",
            "starknet_blockHashAndNumber",
            "starknet_blockNumber",
            "starknet_call",
            "starknet_chainId",
            "starknet_getBlockWithTxHashes",
            "starknet_getBlockWithTxs",
            "starknet_getBlockTransactionCount",
            "starknet_getClass",
            "starknet_getClassAt",
            "starknet_getClassHashAt",
            "starknet_getEvents",
            "starknet_getNonce",
            "starknet_getStateUpdate",
            "starknet_getStorageAt",
            "starknet_getTransactionByBlockIdAndIndex",
            "starknet_getTransactionByHash",
            "starknet_getTransactionReceipt",
            "starknet_pendingTransactions",
            "starknet_syncing",
        ]
        .into_iter();
        // Methods available only in starknet RPC spec v0.2
        let v02_only = ["starknet_estimateFee"].into_iter();
        // Methods available in pathfinder RPC spec v0.1
        let pathfinder_only = ["pathfinder_getProof", "pathfinder_version"].into_iter();

        let v02_methods = common.clone().chain(v02_only.clone()).collect::<Vec<_>>();
        let v03_methods = common.clone().collect::<Vec<_>>();
        let pathfinder_methods = pathfinder_only.clone().collect::<Vec<_>>();

        for (paths, version, methods) in vec![
            (
                vec!["", "/", "/rpc/v0.2", "/rpc/v0.2/"],
                "v0.2",
                v02_methods,
            ),
            (vec!["/rpc/v0.3", "/rpc/v0.3/"], "v0.3", v03_methods),
            // rpc/pathfinder/v0.1 methods are also available in the default RPC api version, which is starknet v0.2
            (
                vec![
                    "",
                    "/",
                    "/rpc/v0.2",
                    "/rpc/v0.2/",
                    "/rpc/pathfinder/v0.1",
                    "/rpc/pathfinder/v0.1/",
                ],
                "v0.1",
                pathfinder_methods,
            ),
        ]
        .into_iter()
        {
            for (i, path) in paths.into_iter().map(ToOwned::to_owned).enumerate() {
                let client = TestClientBuilder::default()
                    .address(address)
                    .endpoint(path.clone())
                    .build()
                    .unwrap();

                for method in methods.iter() {
                    let res = client.request::<serde_json::Value>(method, json!([])).await;

                    match res {
                        Err(jsonrpsee::core::Error::Call(
                            jsonrpsee::types::error::CallError::Custom(e),
                        )) if e.code() == jsonrpsee::types::error::METHOD_NOT_FOUND_CODE => {
                            panic!("Unregistered method called, path: {path}, method: {method}")
                        }
                        Ok(_) | Err(_) => {}
                    }

                    let expected_counter = i as u64 + 1;
                    let actual_counter = handle.get_counter_value_by_label(
                        "rpc_method_calls_total",
                        [("method", method), ("version", version)],
                    );
                    assert_eq!(
                        actual_counter, expected_counter,
                        "path: {path}, method: {method}"
                    );
                }
            }
        }
    }
}
