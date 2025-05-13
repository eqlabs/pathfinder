//! Provides a builder API for creating and sending Sequencer REST requests.
//!
//! This builder utilises a type state builder pattern with generics to only
//! allow valid operations at each stage of the build process. Each stage is
//! consumed to generate the next stage and the final stage executes the query.
//!
//! Here is an overview of the four builder stages.
//!
//!   1. [Init](stage::Init) which provides the entry point of the
//!      [builder](Request).
//!   2. [Method](stage::Method) where you select the REST API method.
//!   3. [Params](stage::Params) where you select the retry behavior.
//!   4. [Final](stage::Final) where you select the REST operation type, which
//!      is then executed.
use pathfinder_common::{BlockId, ClassHash, TransactionHash};
use reqwest::StatusCode;
use starknet_gateway_types::error::SequencerError;

use crate::metrics::{with_metrics, BlockTag, RequestMetadata};
use crate::IS_PRE_0_14_0;

const X_THROTTLING_BYPASS: &str = "X-Throttling-Bypass";

/// A Sequencer Request builder.
pub struct Request<'a, S: RequestState> {
    state: S,
    primary_url: reqwest::Url,
    secondary_url: reqwest::Url,
    api_key: Option<String>,
    client: &'a reqwest::Client,
}

pub mod stage {
    use crate::metrics::RequestMetadata;

    /// Provides the [builder](super::Request::builder) entry-point.
    #[allow(dead_code)]
    pub struct Init;

    /// Select the Sequencer API method to call:
    /// - [add_transaction](super::Request::add_transaction)
    /// - [get_block](super::Request::get_block)
    /// - [get_class_by_hash](super::Request::get_class_by_hash)
    /// - [get_transaction_status](super::Request::get_transaction_status)
    /// - [get_state_update](super::Request::get_state_update)
    /// - [get_contract_addresses](super::Request::get_contract_addresses)
    pub struct Method;

    /// Specify the request parameters:
    /// - [block](super::Request::block)
    /// - [class_hash](super::Request::class_hash)
    /// - [optional_token](super::Request::optional_token)
    /// - [transaction_hash](super::Request::transaction_hash)
    /// - [param](super::Request::param) (allows adding custom (name, value)
    ///   parameter)
    /// - [block_tag](super::Request::block_tag) (allows specifying the block
    ///   tag, either `latest` or `pending`)
    ///
    /// and then specify the [retry behavior](super::Request::retry).
    pub struct Params {
        pub meta: RequestMetadata,
    }

    /// Specify the REST operation send the request:
    /// - [get](super::Request::get)
    /// - [get_as_bytes](super::Request::get_as_bytes)
    /// - [post_with_json](super::Request::post_with_json)
    pub struct Final {
        pub meta: RequestMetadata,
        pub retry: bool,
    }

    impl super::RequestState for Init {}
    impl super::RequestState for Method {}
    impl super::RequestState for Params {}
    impl super::RequestState for Final {}
}

impl<'a> Request<'a, stage::Init> {
    /// Initialize a [Request] builder.
    pub fn builder(
        client: &'a reqwest::Client,
        primary_url: reqwest::Url,
        secondary_url: reqwest::Url,
        api_key: Option<String>,
    ) -> Request<'a, stage::Method> {
        Request {
            primary_url,
            secondary_url,
            client,
            api_key,
            state: stage::Method,
        }
    }
}

/// Helper macros used in [`stage::Method`]
mod request_macros {
    /// Generates the const `METHODS` slice. At least one item is required.
    macro_rules! method_names {
        () => {
            compile_error!("At least one method has to be defined");
        };
        ($($x:ident),+ $(,)?) => {
            pub const METHODS: &'static [&'static str] = &[$(stringify!($x)),+];
        };
    }

    /// Generates methods with names from the list.
    ///
    /// Each generated method delegates the call to `method`.
    macro_rules! method_defs {
        ($($x:ident),+ $(,)?) => {
            $(request_macros::method!($x);)+
        };
    }

    /// Generates one method with `name`.
    ///
    /// The generated method delegates the call to `method`.
    macro_rules! method {
        ($name:ident) => {
            pub fn $name(self) -> Request<'a, stage::Params> {
                self.method(stringify!($name))
            }
        };
    }

    /// Generates methods with names from the list and a const slice `METHODS`
    /// which then can be used to register metrics per method.
    macro_rules! methods {
        () => {
            method_names!();
        };
        ($($x:ident),+ $(,)?) => {
            request_macros::method_names!($($x),+);
            $(request_macros::method_defs!($x);)+
        };
    }

    pub(super) use {method, method_defs, method_names, methods};
}

impl<'a> Request<'a, stage::Method> {
    request_macros::methods!(
        add_transaction,
        get_block,
        get_class_by_hash,
        get_compiled_class_by_class_hash,
        get_transaction_status,
        get_state_update,
        get_contract_addresses,
        get_block_traces,
        get_transaction_trace,
        get_signature,
        get_public_key,
    );

    /// Appends the given method to the request url.
    fn method(mut self, method: &'static str) -> Request<'a, stage::Params> {
        self.primary_url
            .path_segments_mut()
            .expect("Primary URL is valid")
            .push(method);

        self.secondary_url
            .path_segments_mut()
            .expect("Secondary URL is valid")
            .push(method);

        Request {
            primary_url: self.primary_url,
            secondary_url: self.secondary_url,
            client: self.client,
            api_key: self.api_key,
            state: stage::Params {
                meta: RequestMetadata::new(method),
            },
        }
    }
}

impl<'a> Request<'a, stage::Params> {
    pub fn block<B: Into<BlockId>>(self, block: B) -> Self {
        use std::borrow::Cow;

        let block: BlockId = block.into();
        let (name, value, tag) = match block {
            BlockId::Number(number) => (
                "blockNumber",
                Cow::from(number.get().to_string()),
                BlockTag::None,
            ),
            BlockId::Hash(hash) => ("blockHash", hash.0.to_hex_str(), BlockTag::None),
            // These have to use "blockNumber", "blockHash" does not accept tags.
            BlockId::Latest => ("blockNumber", Cow::from("latest"), BlockTag::Latest),
            BlockId::Pending => ("blockNumber", Cow::from("pending"), BlockTag::Pending),
        };

        self.block_tag(tag).param(name, &value)
    }

    pub fn class_hash(self, class_hash: ClassHash) -> Self {
        self.param("classHash", &class_hash.0.to_hex_str())
    }

    pub fn optional_token(self, token: Option<&str>) -> Self {
        match token {
            Some(token) => self.param("token", token),
            None => self,
        }
    }

    pub fn transaction_hash(self, hash: TransactionHash) -> Self {
        self.param("transactionHash", &hash.0.to_hex_str())
    }

    pub fn param(mut self, name: &str, value: &str) -> Self {
        self.primary_url.query_pairs_mut().append_pair(name, value);
        self
    }

    pub fn block_tag(mut self, tag: BlockTag) -> Self {
        self.state.meta.tag = tag;
        self
    }

    /// Sets the request retry behavior.
    pub fn retry(self, retry: bool) -> Request<'a, stage::Final> {
        Request {
            primary_url: self.primary_url,
            secondary_url: self.secondary_url,
            client: self.client,
            api_key: self.api_key,
            state: stage::Final {
                meta: self.state.meta,
                retry,
            },
        }
    }
}

impl Request<'_, stage::Final> {
    /// Sends the Sequencer request as a REST `GET` operation and parses the
    /// response into `T`.
    pub async fn get<T>(self) -> Result<T, SequencerError>
    where
        T: serde::de::DeserializeOwned,
    {
        // TODO remove this workaround once mainnet is on 0.14.0
        async fn send_request_and_probe_0_14_0<T: serde::de::DeserializeOwned>(
            primary_url: reqwest::Url,
            secondary_url: reqwest::Url,
            api_key: Option<String>,
            client: &reqwest::Client,
            meta: RequestMetadata,
        ) -> Result<T, SequencerError> {
            // The flag could in theory be set multiple times, but as it's only ever
            // set to false the multiple stores don't cause any problems.
            let is_pre_0_14_0 = IS_PRE_0_14_0.load(std::sync::atomic::Ordering::Relaxed);
            match send_request(primary_url, api_key.clone(), client, meta).await {
                Err(SequencerError::ReqwestError(e))
                    if e.status() == Some(StatusCode::NOT_FOUND) && is_pre_0_14_0 =>
                {
                    let result = send_request(secondary_url, api_key, client, meta).await;
                    if result.is_ok() {
                        // The old URL was not found, and we got a successful reply from the new
                        // one, which gives us enough confidence to start using the new URL
                        // for the next requests.
                        IS_PRE_0_14_0.store(false, std::sync::atomic::Ordering::Relaxed);
                        tracing::info!("Feeder gateway URL updated to Starknet 0.14.0");
                    }

                    result
                }
                r => r,
            }
        }

        async fn send_request<T: serde::de::DeserializeOwned>(
            url: reqwest::Url,
            api_key: Option<String>,
            client: &reqwest::Client,
            meta: RequestMetadata,
        ) -> Result<T, SequencerError> {
            with_metrics(meta, async move {
                tracing::trace!(%url, "Fetching data from feeder gateway");
                let request = client.get(url);
                let request = match api_key {
                    Some(api_key) => request.header(X_THROTTLING_BYPASS, api_key),
                    None => request,
                };
                let response = request.send().await?;
                parse::<T>(response).await
            })
            .await
        }

        match self.state.retry {
            false => {
                send_request_and_probe_0_14_0(
                    self.primary_url,
                    self.secondary_url,
                    self.api_key,
                    self.client,
                    self.state.meta,
                )
                .await
            }
            true => {
                retry0(
                    || async {
                        let primary_url = self.primary_url.clone();
                        let secondary_url = self.secondary_url.clone();
                        let api_key = self.api_key.clone();
                        send_request_and_probe_0_14_0(
                            primary_url,
                            secondary_url,
                            api_key,
                            self.client,
                            self.state.meta,
                        )
                        .await
                    },
                    retry_condition,
                )
                .await
            }
        }
    }

    /// Sends the Sequencer request as a REST `GET` operation and returns the
    /// response's bytes.
    pub async fn get_as_bytes(self) -> Result<bytes::Bytes, SequencerError> {
        // TODO remove this workaround once mainnet is on 0.14.0
        async fn get_as_bytes_inner_and_probe_0_14_0(
            primary_url: reqwest::Url,
            secondary_url: reqwest::Url,
            api_key: Option<String>,
            client: &reqwest::Client,
            meta: RequestMetadata,
        ) -> Result<bytes::Bytes, SequencerError> {
            // The flag could in theory be set multiple times, but as it's only ever
            // set to false the multiple stores don't cause any problems.
            let is_pre_0_14_0 = IS_PRE_0_14_0.load(std::sync::atomic::Ordering::Relaxed);
            match get_as_bytes_inner(primary_url, api_key.clone(), client, meta).await {
                Err(SequencerError::ReqwestError(e))
                    if e.status() == Some(StatusCode::NOT_FOUND) && is_pre_0_14_0 =>
                {
                    let result = get_as_bytes_inner(secondary_url, api_key, client, meta).await;
                    if result.is_ok() {
                        // The old URL was not found, and we got a successful reply from the new
                        // one, which gives us enough confidence to start using the new URL
                        // for the next requests.
                        IS_PRE_0_14_0.store(false, std::sync::atomic::Ordering::Relaxed);
                        tracing::info!("Feeder gateway URL updated to Starknet 0.14.0");
                    }

                    result
                }
                r => r,
            }
        }

        async fn get_as_bytes_inner(
            url: reqwest::Url,
            api_key: Option<String>,
            client: &reqwest::Client,
            meta: RequestMetadata,
        ) -> Result<bytes::Bytes, SequencerError> {
            with_metrics(meta, async {
                tracing::trace!(%url, "Fetching binary data from feeder gateway");
                let request = client.get(url);
                let request = match api_key {
                    Some(api_key) => request.header(X_THROTTLING_BYPASS, api_key),
                    None => request,
                };
                let response = request.send().await?;
                let response = parse_raw(response).await?;
                let bytes = response.bytes().await?;
                Ok(bytes)
            })
            .await
        }

        match self.state.retry {
            false => {
                get_as_bytes_inner_and_probe_0_14_0(
                    self.primary_url,
                    self.secondary_url,
                    self.api_key,
                    self.client,
                    self.state.meta,
                )
                .await
            }
            true => {
                retry0(
                    || async {
                        let primary_url = self.primary_url.clone();
                        let secondary_url = self.secondary_url.clone();
                        let api_key = self.api_key.clone();
                        get_as_bytes_inner_and_probe_0_14_0(
                            primary_url,
                            secondary_url,
                            api_key,
                            self.client,
                            self.state.meta,
                        )
                        .await
                    },
                    retry_condition,
                )
                .await
            }
        }
    }

    /// Sends the Sequencer request as a REST `POST` operation, in addition to
    /// the specified JSON body. The response is parsed as type `T`.
    ///
    /// Can specify an optional timeout which will override the client's
    /// timeout.
    pub async fn post_with_json<T, J>(
        self,
        json: &J,
        timeout: Option<std::time::Duration>,
    ) -> Result<T, SequencerError>
    where
        T: serde::de::DeserializeOwned,
        J: serde::Serialize + ?Sized,
    {
        async fn post_with_json_inner<T, J>(
            url: reqwest::Url,
            api_key: Option<String>,
            client: &reqwest::Client,
            meta: RequestMetadata,
            json: &J,
            timeout: Option<std::time::Duration>,
        ) -> Result<T, SequencerError>
        where
            T: serde::de::DeserializeOwned,
            J: serde::Serialize + ?Sized,
        {
            with_metrics(meta, async {
                let request = client.post(url);
                let request = match api_key {
                    Some(api_key) => request.header(X_THROTTLING_BYPASS, api_key),
                    None => request,
                };
                let request = match timeout {
                    Some(timeout) => request.timeout(timeout),
                    None => request,
                };
                let response = request.json(json).send().await?;
                parse::<T>(response).await
            })
            .await
        }

        match self.state.retry {
            false => {
                post_with_json_inner(
                    self.primary_url,
                    self.api_key,
                    self.client,
                    self.state.meta,
                    json,
                    timeout,
                )
                .await
            }
            true => {
                retry0(
                    || async {
                        tracing::trace!(url=%self.primary_url, "Posting data to gateway");
                        let url = self.primary_url.clone();
                        let api_key = self.api_key.clone();
                        post_with_json_inner(
                            url,
                            api_key,
                            self.client,
                            self.state.meta,
                            json,
                            timeout,
                        )
                        .await
                    },
                    retry_condition,
                )
                .await
            }
        }
    }
}

async fn parse<T>(response: reqwest::Response) -> Result<T, SequencerError>
where
    T: ::serde::de::DeserializeOwned,
{
    let response = parse_raw(response).await?;
    // Attempt to deserialize the actual data we are looking for
    let response = response.json::<T>().await?;
    Ok(response)
}

/// Helper function which allows skipping deserialization when required.
async fn parse_raw(response: reqwest::Response) -> Result<reqwest::Response, SequencerError> {
    use starknet_gateway_types::error::StarknetError;

    // Starknet specific errors end with a 400 or 500 status code
    // but the body contains a JSON object with the error description
    if response.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR
        || response.status() == reqwest::StatusCode::BAD_REQUEST
    {
        let error = match response.json::<StarknetError>().await {
            Ok(e) => SequencerError::StarknetError(e),
            Err(e) if e.is_decode() => SequencerError::InvalidStarknetErrorVariant,
            Err(e) => SequencerError::ReqwestError(e),
        };
        return Err(error);
    }
    // Status codes 401..499 and 501..599 are mapped to
    // SequencerError::TransportError
    response.error_for_status_ref().map(|_| ())?;
    Ok(response)
}

pub trait RequestState {}

/// Wrapper function to allow retrying sequencer queries in an exponential
/// manner.
async fn retry0<T, Fut, FutureFactory, Ret>(
    future_factory: FutureFactory,
    retry_condition: Ret,
) -> Result<T, SequencerError>
where
    Fut: futures::Future<Output = Result<T, SequencerError>>,
    FutureFactory: FnMut() -> Fut,
    Ret: FnMut(&SequencerError) -> bool,
{
    use std::num::NonZeroU64;

    use pathfinder_retry::Retry;

    Retry::exponential(future_factory, NonZeroU64::new(2).unwrap())
        .factor(NonZeroU64::new(1).unwrap())
        .max_delay(std::time::Duration::from_secs(10))
        .when(retry_condition)
        .await
}

/// Determines if an error is retryable or not.
fn retry_condition(e: &SequencerError) -> bool {
    use reqwest::StatusCode;
    use tracing::{debug, error, info, warn};

    match e {
        SequencerError::ReqwestError(e) => {
            if e.is_timeout() {
                info!(reason=%e, "Request failed, retrying. Fetching the response or parts of it timed out. Try increasing request timeout by using the `--gateway.request-timeout` CLI option.");
                return true;
            }

            if e.is_body() || e.is_connect() {
                info!(reason=%e, "Request failed, retrying");
            } else if e.is_status() {
                match e.status().expect("status related error") {
                    StatusCode::NOT_FOUND
                    | StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::BAD_GATEWAY
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT => {
                        debug!(reason=%e, "Request failed, retrying");
                    }
                    StatusCode::INTERNAL_SERVER_ERROR => {
                        error!(reason=%e, "Request failed, retrying");
                    }
                    _ => warn!(reason=%e, "Request failed, retrying"),
                }
            } else if e.is_decode() {
                error!(reason=%e, "Request failed, retrying");
            } else {
                warn!(reason=%e, "Request failed, retrying");
            }

            true
        }
        SequencerError::StarknetError(_) => false,
        SequencerError::InvalidStarknetErrorVariant => {
            error!(reason=%e, "Request failed, retrying");
            true
        }
    }
}

#[cfg(test)]
mod tests {
    mod retry {
        use std::collections::VecDeque;
        use std::convert::Infallible;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        use assert_matches::assert_matches;
        use pretty_assertions_sorted::assert_eq;
        use tokio::sync::Mutex;
        use tokio::task::JoinHandle;
        use warp::http::response::Builder;
        use warp::http::StatusCode;
        use warp::Filter;

        use crate::builder::{retry0, retry_condition};

        // A test helper
        fn status_queue_server(
            statuses: VecDeque<(StatusCode, &'static str)>,
        ) -> (JoinHandle<()>, SocketAddr) {
            use std::cell::RefCell;

            let statuses = Arc::new(Mutex::new(RefCell::new(statuses)));
            let any = warp::any().then(move || {
                let s = statuses.clone();
                async move {
                    let s = s.lock().await;
                    let s = s.borrow_mut().pop_front().unwrap();
                    Builder::new().status(s.0).body(s.1)
                }
            });

            let (addr, run_srv) = warp::serve(any).bind_ephemeral(([127, 0, 0, 1], 0));
            let server_handle = tokio::spawn(run_srv);
            (server_handle, addr)
        }

        // A test helper
        fn slow_server() -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
            let any = warp::any().then(|| async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Result::<_, Infallible>::Ok(Builder::new().status(200).body(""))
            });
            let (addr, run_srv) = warp::serve(any).bind_ephemeral(([127, 0, 0, 1], 0));
            let server_handle = tokio::spawn(run_srv);
            (server_handle, addr)
        }

        #[test_log::test(tokio::test)]
        async fn stop_on_ok() {
            use crate::builder;

            tokio::time::pause();

            let statuses = VecDeque::from([
                (StatusCode::TOO_MANY_REQUESTS, ""),
                (StatusCode::BAD_GATEWAY, ""),
                (StatusCode::SERVICE_UNAVAILABLE, ""),
                (StatusCode::GATEWAY_TIMEOUT, ""),
                (StatusCode::OK, r#""Finally!""#),
                (StatusCode::TOO_MANY_REQUESTS, ""),
                (StatusCode::BAD_GATEWAY, ""),
                (StatusCode::SERVICE_UNAVAILABLE, ""),
            ]);

            let (_jh, addr) = status_queue_server(statuses);
            let result = retry0(
                || async {
                    let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                    url.set_port(Some(addr.port())).unwrap();
                    let response = reqwest::get(url).await?;
                    builder::parse::<String>(response).await
                },
                retry_condition,
            )
            .await
            .unwrap();
            assert_eq!(result, "Finally!");
        }

        #[test_log::test(tokio::test)]
        async fn stop_on_fatal() {
            use starknet_gateway_types::error::{KnownStarknetErrorCode, SequencerError};

            use crate::builder;

            tokio::time::pause();

            let statuses = VecDeque::from([
                (StatusCode::TOO_MANY_REQUESTS, ""),
                (StatusCode::BAD_GATEWAY, ""),
                (StatusCode::SERVICE_UNAVAILABLE, ""),
                (StatusCode::GATEWAY_TIMEOUT, ""),
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"code":"StarknetErrorCode.BLOCK_NOT_FOUND","message":""}"#,
                ),
                (StatusCode::TOO_MANY_REQUESTS, ""),
                (StatusCode::BAD_GATEWAY, ""),
                (StatusCode::SERVICE_UNAVAILABLE, ""),
            ]);

            let (_jh, addr) = status_queue_server(statuses);
            let error = retry0(
                || async {
                    let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                    url.set_port(Some(addr.port())).unwrap();
                    let response = reqwest::get(url).await?;
                    builder::parse::<String>(response).await
                },
                retry_condition,
            )
            .await
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(se) => assert_eq!(se.code, KnownStarknetErrorCode::BlockNotFound.into())
            );
        }

        #[tokio::test(flavor = "current_thread")]
        async fn request_timeout() {
            use std::sync::atomic::{AtomicUsize, Ordering};

            use crate::builder;

            tokio::time::pause();

            let (_jh, addr) = slow_server();
            static CNT: AtomicUsize = AtomicUsize::new(0);

            let fut = retry0(
                || async {
                    let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                    url.set_port(Some(addr.port())).unwrap();

                    let client = reqwest::Client::builder().build().unwrap();

                    CNT.fetch_add(1, Ordering::Relaxed);

                    // This is the same as using Client::builder().timeout()
                    let response = client
                        .get(url)
                        .timeout(Duration::from_millis(1))
                        .send()
                        .await?;
                    builder::parse::<String>(response).await
                },
                retry_condition,
            );

            // The retry loops forever, so wrap it in a timeout and check the counter.
            // 4 retries = 2 + 4 + 8 + 10 = 24 seconds
            // 5 retries = 2 + 4 + 8 + 10 + 10 = 34 seconds
            tokio::time::timeout(Duration::from_secs(30), fut)
                .await
                .unwrap_err();

            // 5th try should have timedout if this is really exponential backoff
            assert_eq!(CNT.load(Ordering::Relaxed), 5);
        }
    }

    mod invalid_starknet_error_variant {
        use gateway_test_utils::GATEWAY_TIMEOUT;
        use warp::http::response::Builder;
        use warp::Filter;

        use crate::{Client, GatewayApi};

        fn server() -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
            let any = warp::any().then(|| async { Builder::new().status(500).body("whatever") });
            let (addr, run_srv) = warp::serve(any).bind_ephemeral(([127, 0, 0, 1], 0));
            let server_handle = tokio::spawn(run_srv);
            (server_handle, addr)
        }

        #[tokio::test]
        async fn causes_short_reply() {
            let (_jh, addr) = server();
            let mut url = reqwest::Url::parse("http://localhost/").unwrap();
            url.set_port(Some(addr.port())).unwrap();
            let client = Client::with_base_url(url, GATEWAY_TIMEOUT)
                .unwrap()
                .disable_retry_for_tests();
            let error = client
                .block_header(pathfinder_common::BlockId::Latest)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "error decoding response body: invalid error variant"
            );
        }
    }

    mod api_key_is_set_when_configured {
        use fake::{Fake, Faker};
        use gateway_test_utils::GATEWAY_TIMEOUT;
        use httpmock::prelude::*;
        use httpmock::Mock;
        use serde_json::json;

        use crate::Client;

        async fn setup_with_fake_api_key(server: &MockServer) -> (Mock<'_>, Client) {
            let api_key = Faker.fake::<String>();

            let mock = server.mock(|when, then| {
                when.any_request().header("X-Throttling-Bypass", &api_key);
                then.status(200).json_body(json!({}));
            });

            let client = Client::with_base_url(server.base_url().parse().unwrap(), GATEWAY_TIMEOUT)
                .unwrap()
                .with_api_key(Some(api_key.clone()));

            (mock, client)
        }

        #[tokio::test]
        async fn get() -> anyhow::Result<()> {
            let server = MockServer::start_async().await;
            let (mock, client) = setup_with_fake_api_key(&server).await;

            let _: serde_json::Value = client
                .clone()
                .gateway_request()
                .method("")
                .retry(false)
                .get()
                .await?;

            let _: serde_json::Value = client
                .clone()
                .feeder_gateway_request()
                .method("")
                .retry(false)
                .get()
                .await?;

            mock.assert_hits(2);

            Ok(())
        }

        #[tokio::test]
        async fn get_as_bytes() -> anyhow::Result<()> {
            let server = MockServer::start_async().await;
            let (mock, client) = setup_with_fake_api_key(&server).await;

            let _: bytes::Bytes = client
                .clone()
                .gateway_request()
                .method("")
                .retry(false)
                .get_as_bytes()
                .await?;

            let _: bytes::Bytes = client
                .clone()
                .feeder_gateway_request()
                .method("")
                .retry(false)
                .get_as_bytes()
                .await?;

            mock.assert_hits(2);

            Ok(())
        }

        #[tokio::test]
        async fn post_with_json() -> anyhow::Result<()> {
            let server = MockServer::start_async().await;
            let (mock, client) = setup_with_fake_api_key(&server).await;

            let _: serde_json::Value = client
                .clone()
                .gateway_request()
                .method("")
                .retry(false)
                .post_with_json(&json!({}), None)
                .await?;

            let _: serde_json::Value = client
                .clone()
                .feeder_gateway_request()
                .method("")
                .retry(false)
                .post_with_json(&json!({}), None)
                .await?;

            mock.assert_hits(2);

            Ok(())
        }
    }
}
