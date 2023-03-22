//! Middleware that proxies requests at a specified URI to internal
//! RPC method calls.
use hyper::{Body, Request, Response};
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
        todo!()
    }

    fn call(&mut self, _: Request<Body>) -> Self::Future {
        todo!()
    }
}
