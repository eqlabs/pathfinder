///! A drop-in replacement for `jsonrpsee::http_client::HttpClient` meant only for testing the RPC API,
///! which is supposed to provide better error reporting, especially wrt serde errors.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jsonrpsee::core::client::{ClientT, IdKind, RequestIdManager};
use jsonrpsee::core::{Error, TEN_MB_SIZE_BYTES};
use jsonrpsee::types::error::CallError;
use jsonrpsee::types::{ErrorResponse, ParamsSer, RequestSer, Response};
use serde::de::DeserializeOwned;

/// Convenience function to save on boilerplate in the tests
pub fn client(addr: SocketAddr) -> TestClient {
    TestClientBuilder::default()
        .request_timeout(Duration::from_secs(120))
        .build(addr)
        .expect("Failed to create test HTTP-RPC client")
}

/// Test Http Client Builder.
#[derive(Debug)]
pub struct TestClientBuilder {
    max_request_body_size: u32,
    request_timeout: Duration,
    max_concurrent_requests: usize,
    id_kind: IdKind,
}

#[allow(dead_code)]
impl TestClientBuilder {
    /// Sets the maximum size of a request body in bytes (default is 10 MiB).
    pub fn max_request_body_size(mut self, size: u32) -> Self {
        self.max_request_body_size = size;
        self
    }

    /// Set request timeout (default is 60 seconds).
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set max concurrent requests.
    pub fn max_concurrent_requests(mut self, max: usize) -> Self {
        self.max_concurrent_requests = max;
        self
    }

    /// Configure the data type of the request object ID (default is number).
    pub fn id_format(mut self, id_kind: IdKind) -> Self {
        self.id_kind = id_kind;
        self
    }

    /// Build the HTTP client with target to connect to.
    pub fn build(self, target: std::net::SocketAddr) -> Result<TestClient, Error> {
        let transport = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .build()
            .map_err(|e| Error::Transport(e.into()))?;

        Ok(TestClient {
            transport,
            target: reqwest::Url::parse(&format!("http://{target}")).unwrap(),
            id_manager: Arc::new(RequestIdManager::new(
                self.max_concurrent_requests,
                self.id_kind,
            )),
        })
    }
}

impl Default for TestClientBuilder {
    fn default() -> Self {
        Self {
            max_request_body_size: TEN_MB_SIZE_BYTES,
            request_timeout: Duration::from_secs(120),
            max_concurrent_requests: 256,
            id_kind: IdKind::Number,
        }
    }
}

/// JSON-RPC HTTP Client that provides functionality to perform method calls.
#[derive(Debug, Clone)]
pub struct TestClient {
    /// HTTP transport client.
    transport: reqwest::Client,
    /// Url to which requests will be sent.
    target: reqwest::Url,
    /// Request ID manager.
    id_manager: Arc<RequestIdManager>,
}

#[async_trait]
impl ClientT for TestClient {
    async fn notification<'a>(&self, _: &'a str, _: Option<ParamsSer<'a>>) -> Result<(), Error> {
        unimplemented!()
    }

    /// Perform a request towards the server.
    ///
    /// The difference from [`jsonrpsee::http_client::HttpClient::request`] is that
    /// this method reports the core reason for response `R` serde error,
    /// while the former just ignores it.
    async fn request<'a, R>(
        &self,
        method: &'a str,
        params: Option<ParamsSer<'a>>,
    ) -> Result<R, Error>
    where
        R: DeserializeOwned,
    {
        let guard = self.id_manager.next_request_id()?;
        let id = guard.inner();
        let request = RequestSer::new(&id, method, params);
        let request = serde_json::to_vec(&request).map_err(Error::ParseError)?;

        const CONTENT_TYPE_JSON: &str = "application/json";

        let body = match self
            .transport
            .post(self.target.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static(CONTENT_TYPE_JSON),
            )
            .header(
                reqwest::header::ACCEPT,
                reqwest::header::HeaderValue::from_static(CONTENT_TYPE_JSON),
            )
            .body(request)
            .send()
            .await
        {
            Ok(response) => match response.bytes().await {
                Ok(body) => body,
                Err(error) => return Err(Error::Transport(error.into())),
            },
            Err(error) => {
                if error.is_timeout() {
                    return Err(Error::RequestTimeout);
                } else {
                    return Err(Error::Transport(error.into()));
                }
            }
        };

        let json_rpc_response: Response<'_, R> = match serde_json::from_slice(&body) {
            Ok(response) => response,
            Err(error) => {
                let json_rpc_error_response: ErrorResponse<'_> = match serde_json::from_slice(&body)
                {
                    Ok(error_response) => error_response,
                    Err(_) =>
                    // We failed to deserialize into `ErrorResponse`.
                    //
                    // So, if there is no valid
                    // 1. JSON-RPC [response object](https://www.jsonrpc.org/specification#response_object) in the reply,
                    // 2. or [JSON-RPC error response object](https://www.jsonrpc.org/specification#error_object) in the reply,
                    // 3. it's got to be an RPC API serialization error on our (server) side.
                    //
                    // This (3) error is simply ignored by `jsonrpsee::http_client::HttpClient`
                    // so we used to end up with a `ParseError` which resulted from trying to deserialize
                    // a response `R` from our API that had some serialization bug into
                    // a `jsonrpsee::types::ErrorResponse` which will always fail with a
                    // misleading "no such field >error<" message.
                    //
                    // We could also use a `ParseError` here but it would not be as informative.
                    {
                        return Err(Error::Custom(format!(
                            "Error deserializing {}, {error}",
                            std::any::type_name::<R>()
                        )))
                    }
                };
                return Err(Error::Call(CallError::Custom(
                    json_rpc_error_response.error_object().clone().into_owned(),
                )));
            }
        };

        if json_rpc_response.id == id {
            Ok(json_rpc_response.result)
        } else {
            Err(Error::InvalidRequestId)
        }
    }

    async fn batch_request<'a, R>(
        &self,
        _: Vec<(&'a str, Option<ParamsSer<'a>>)>,
    ) -> Result<Vec<R>, Error>
    where
        R: DeserializeOwned + Default + Clone,
    {
        unimplemented!()
    }
}
