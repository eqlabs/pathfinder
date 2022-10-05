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
pub struct RpcVersioningLayer;

impl<S> Layer<S> for RpcVersioningLayer {
    type Service = RpcVersioningService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcVersioningService::new(inner)
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
/// /v0.1
/// {"method": "starknet_getChainId"}
/// ```
///
/// becomes
///
/// ```txt
/// /
/// {"method": "v0.1_starknet_getChainId"}
/// ```
///
/// # Response
///
/// Responses are not modified.
#[derive(Debug, Clone)]
pub struct RpcVersioningService<S> {
    inner: Arc<Mutex<S>>,
}

impl<S> RpcVersioningService<S> {
    /// Creates new [`RpcVersioningService`]
    pub fn new(inner: S) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
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

        let modify = req.method() == Method::POST;

        if modify {
            // FIXME these prefixes need to be tightly-knit to
            // the internal names of the rpc methods
            let prefix = match req.uri().path() {
                "/" | "/v0.1" => "v0.1_starknet_",
                "/v0.2" => "v0.2_starknet_",
                _ => return Box::pin(std::future::ready(Ok(response::not_found()))),
            };

            // FIXME take it from the tower service
            // or pass the value both to the server builder
            // and the middleware ctor
            let max_request_body_size = 1024 * 1024;

            let fut = async move {
                // Retain the parts to then later recreate the request
                let (parts, body) = req.into_parts();

                let (body, _is_single) =
                    match read_body(&parts.headers, body, max_request_body_size).await {
                        Ok(x) => x,
                        Err(GenericTransportError::TooLarge) => {
                            return Ok(response::too_large(max_request_body_size))
                        }
                        Err(GenericTransportError::Malformed) => return Ok(response::malformed()),
                        Err(GenericTransportError::Inner(_)) => return Ok(response::internal()),
                    };

                /*
                    Mutex + Smarter (serde based) swap is roughly a 8% penalty
                    fn prefix_method<'a>(request: &mut jsonrpsee::types::Request<'a>, prefix: &str) {
                        let mut method = prefix.to_string();
                        method.add_assign(&request.method);
                        request.method = method.into();
                    }

                    let body = if is_single {
                        let mut request: jsonrpsee::types::Request<'_> =
                            serde_json::from_slice(&body).unwrap();
                        prefix_method(&mut request, version_prefix);
                        serde_json::to_vec(&request).expect("TODO")
                    } else {
                        let mut batch: Vec<jsonrpsee::types::Request<'_>> =
                            serde_json::from_slice(&body).unwrap();
                        batch
                            .iter_mut()
                            .for_each(|request| prefix_method(request, version_prefix));
                        serde_json::to_vec(&batch).expect("TODO")
                    };
                */

                // Mutex + Stupid swap is roughly a 5% penalty
                let body = match String::from_utf8(body) {
                    Ok(body) => body,
                    // Ultimately we expect JSON which is UTF-8 so an early conversion should not fail
                    Err(_) => return Ok(response::malformed()),
                };
                let body = body.replace("starknet_", prefix);

                let req: Request<Body> = Request::from_parts(parts, body.into());
                let fut = {
                    // Why cannot there be a non &mut service alternative
                    let mut guard = inner.lock().expect("TODO");
                    guard.call(req)
                };
                let resp = fut.await?;
                Ok(resp)
            };

            Box::pin(fut)
        } else {
            // Call the inner service and get a future that resolves to the response.
            let fut = {
                let mut guard = inner.lock().expect("TODO");
                guard.call(req)
            };
            Box::pin(fut)
        }
    }
}
