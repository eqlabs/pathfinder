///! A drop-in replacement for `jsonrpsee::http_client::HttpClient` meant only for testing the RPC API,
///! which is supposed to provide better error reporting, especially wrt serde errors.
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use jsonrpsee::core::Error;
use jsonrpsee::types::error::CallError;
use jsonrpsee::types::{ErrorResponse, Id, ParamsSer, RequestSer, Response};
use serde::de::DeserializeOwned;

/// Create an RPC [`TestClient`] with a timeout of 120 seconds.
pub fn client(addr: SocketAddr) -> TestClient {
    TestClientBuilder::default()
        .with_request_timeout(Duration::from_secs(120))
        .build(addr)
        .expect("Failed to create test HTTP-RPC client")
}

/// Test Http Client Builder.
#[derive(Debug)]
pub struct TestClientBuilder<'a> {
    request_timeout: Duration,
    path: Option<&'a str>,
}

#[allow(dead_code)]
impl<'a> TestClientBuilder<'a> {
    /// Set request timeout (default is 120 seconds).
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set path (default is none).
    pub fn with_path(mut self, path: &'a str) -> Self {
        self.path = Some(path);
        self
    }

    /// Build the HTTP client with target to connect to.
    pub fn build(self, addr: SocketAddr) -> Result<TestClient, Error> {
        let transport = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .build()
            .map_err(|e| Error::Transport(e.into()))?;

        let path = self.path.unwrap_or_default();

        Ok(TestClient {
            transport,
            target: reqwest::Url::parse(&format!("http://{addr}{path}")).unwrap(),
            current_id: AtomicU64::new(0),
        })
    }
}

impl Default for TestClientBuilder<'_> {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(120),
            path: None,
        }
    }
}

/// JSON-RPC HTTP Client that provides functionality to perform method calls.
#[derive(Debug)]
pub struct TestClient {
    /// HTTP transport client.
    transport: reqwest::Client,
    /// Url to which requests will be sent.
    target: reqwest::Url,
    /// Tracks consecutive expected request IDs.
    current_id: AtomicU64,
}

impl TestClient {
    /// Perform a request towards the server.
    ///
    /// The difference from [`jsonrpsee::http_client::HttpClient::request`] is that
    /// this method reports the core reason for response `R` serde error,
    /// while the former just ignores it.
    ///
    /// TODO get rid of the ParamsSer ugliness
    pub async fn request<'a, R>(
        &self,
        method: &'a str,
        params: Option<ParamsSer<'a>>,
    ) -> Result<R, Error>
    where
        R: DeserializeOwned,
    {
        let id = Id::Number(
            self.current_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
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
            Ok(response) => {
                let status = response.status();

                if status.is_success() {
                    match response.bytes().await {
                        Ok(body) => body,
                        Err(error) => return Err(Error::Transport(error.into())),
                    }
                } else {
                    // Normal clients would just return the HTTP body content, but we really wanna return
                    // the convenient error type, so let's just return some exotic variant with some
                    // informative content
                    return Err(Error::Custom(format!(
                        "TestClient: Server replied with HTTP status {status}",
                    )));
                }
            }
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
                            "TestClient: Error deserializing {}, {error}",
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
}
