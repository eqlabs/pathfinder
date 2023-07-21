//! Starknet L2 sequencer client.
use pathfinder_common::{
    BlockId, BlockNumber, CallParam, CasmHash, Chain, ClassHash, ContractAddress,
    ContractAddressSalt, Fee, StateUpdate, TransactionHash, TransactionNonce,
    TransactionSignatureElem, TransactionVersion,
};
use reqwest::Url;
use starknet_gateway_types::{
    error::SequencerError,
    reply,
    request::add_transaction::{
        AddTransaction, ContractDefinition, Declare, DeployAccount, InvokeFunction,
    },
};
use std::{fmt::Debug, result::Result, time::Duration};

mod builder;
mod metrics;

#[allow(unused_variables)]
#[mockall::automock]
#[async_trait::async_trait]
pub trait GatewayApi: Sync {
    async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
        unimplemented!();
    }

    async fn block_without_retry(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingBlock, SequencerError> {
        unimplemented!()
    }

    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError> {
        unimplemented!();
    }

    async fn pending_class_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        unimplemented!();
    }

    async fn pending_casm_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        unimplemented!();
    }

    async fn transaction(
        &self,
        transaction_hash: TransactionHash,
    ) -> Result<reply::Transaction, SequencerError> {
        unimplemented!();
    }

    async fn state_update(&self, block: BlockId) -> Result<StateUpdate, SequencerError> {
        unimplemented!();
    }

    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError> {
        unimplemented!();
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_invoke_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address: ContractAddress,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
        unimplemented!();
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_declare_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_definition: ContractDefinition,
        sender_address: ContractAddress,
        compiled_class_hash: Option<CasmHash>,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeclareResponse, SequencerError> {
        unimplemented!();
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_deploy_account(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address_salt: ContractAddressSalt,
        class_hash: ClassHash,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::DeployAccountResponse, SequencerError> {
        unimplemented!();
    }
}

#[async_trait::async_trait]
impl<T: GatewayApi + Sync + Send> GatewayApi for std::sync::Arc<T> {
    async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
        self.as_ref().block(block).await
    }

    async fn block_without_retry(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingBlock, SequencerError> {
        self.as_ref().block_without_retry(block).await
    }

    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError> {
        self.as_ref().class_by_hash(class_hash).await
    }

    async fn pending_class_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        self.as_ref().pending_class_by_hash(class_hash).await
    }

    async fn pending_casm_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        self.as_ref().pending_casm_by_hash(class_hash).await
    }

    async fn transaction(
        &self,
        transaction_hash: TransactionHash,
    ) -> Result<reply::Transaction, SequencerError> {
        self.as_ref().transaction(transaction_hash).await
    }

    async fn state_update(&self, block: BlockId) -> Result<StateUpdate, SequencerError> {
        self.as_ref().state_update(block).await
    }

    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError> {
        self.as_ref().eth_contract_addresses().await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_invoke_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address: ContractAddress,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
        self.as_ref()
            .add_invoke_transaction(
                version,
                max_fee,
                signature,
                nonce,
                contract_address,
                calldata,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_declare_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_definition: ContractDefinition,
        sender_address: ContractAddress,
        compiled_class_hash: Option<CasmHash>,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeclareResponse, SequencerError> {
        self.as_ref()
            .add_declare_transaction(
                version,
                max_fee,
                signature,
                nonce,
                contract_definition,
                sender_address,
                compiled_class_hash,
                token,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_deploy_account(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address_salt: ContractAddressSalt,
        class_hash: ClassHash,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::DeployAccountResponse, SequencerError> {
        self.as_ref()
            .add_deploy_account(
                version,
                max_fee,
                signature,
                nonce,
                contract_address_salt,
                class_hash,
                calldata,
            )
            .await
    }
}

/// Starknet sequencer client using REST API.
///
/// Retry is performed on __all__ types of errors __except for__
/// [Starknet specific errors](starknet_gateway_types::error::StarknetError).
///
/// Initial backoff time is 30 seconds and saturates at 10 minutes:
///
/// `backoff [secs] = min((2 ^ N) * 15, 600) [secs]`
///
/// where `N` is the consecutive retry iteration number `{1, 2, ...}`.
#[derive(Debug, Clone)]
pub struct Client {
    /// This client is internally refcounted
    inner: reqwest::Client,
    /// Starknet gateway URL.
    gateway: Url,
    /// Starknet feeder gateway URL.
    feeder_gateway: Url,
    /// Whether __read only__ requests should be retried, defaults to __true__ for production.
    /// Use [disable_retry_for_tests](Client::disable_retry_for_tests) to disable retry logic for all __read only__ requests when testing.
    retry: bool,
}

impl Client {
    /// Creates a [Client] for [Chain::Mainnet].
    pub fn mainnet() -> Self {
        Self::with_base_url(Url::parse("https://alpha-mainnet.starknet.io/").unwrap()).unwrap()
    }

    /// Creates a [Client] for [Chain::Testnet].
    pub fn testnet() -> Self {
        Self::with_base_url(Url::parse("https://alpha4.starknet.io/").unwrap()).unwrap()
    }

    /// Creates a [Client] for [Chain::Testnet2].
    pub fn testnet2() -> Self {
        Self::with_base_url(Url::parse("https://alpha4-2.starknet.io/").unwrap()).unwrap()
    }

    /// Creates a [Client] for [Chain::Integration].
    pub fn integration() -> Self {
        Self::with_base_url(Url::parse("https://external.integration.starknet.io").unwrap())
            .unwrap()
    }

    /// Creates a [Client] with a shared feeder gateway and gateway base url.
    pub fn with_base_url(base: Url) -> anyhow::Result<Self> {
        let gateway = base.join("gateway")?;
        let feeder_gateway = base.join("feeder_gateway")?;
        Self::with_urls(gateway, feeder_gateway)
    }

    /// Create a Sequencer client for the given [Url]s.
    pub fn with_urls(gateway: Url, feeder_gateway: Url) -> anyhow::Result<Self> {
        metrics::register();

        Ok(Self {
            inner: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .user_agent(pathfinder_common::consts::USER_AGENT)
                .build()?,
            gateway,
            feeder_gateway,
            retry: true,
        })
    }

    /// Use this method to disable retry logic for all __non write__ requests when testing.
    pub fn disable_retry_for_tests(self) -> Self {
        Self {
            retry: false,
            ..self
        }
    }

    fn gateway_request(&self) -> builder::Request<'_, builder::stage::Method> {
        builder::Request::builder(&self.inner, self.gateway.clone())
    }

    fn feeder_gateway_request(&self) -> builder::Request<'_, builder::stage::Method> {
        builder::Request::builder(&self.inner, self.feeder_gateway.clone())
    }

    async fn block_with_retry_behaviour(
        &self,
        block: BlockId,
        retry: bool,
    ) -> Result<reply::MaybePendingBlock, SequencerError> {
        self.feeder_gateway_request()
            .get_block()
            .with_block(block)
            .with_retry(retry)
            .get()
            .await
    }

    /// Returns the [network chain](Chain) this client is operating on.
    pub async fn chain(&self) -> anyhow::Result<Chain> {
        use pathfinder_common::consts::{
            INTEGRATION_GENESIS_HASH, MAINNET_GENESIS_HASH, TESTNET2_GENESIS_HASH,
            TESTNET_GENESIS_HASH,
        };
        // unwrap is safe as `block_hash` is always present for non-pending blocks.
        let genesis_hash = self
            .block(BlockNumber::GENESIS.into())
            .await?
            .as_block()
            .expect("Genesis block should not be pending")
            .block_hash;

        match genesis_hash {
            testnet if testnet == TESTNET_GENESIS_HASH => Ok(Chain::Testnet),
            testnet2 if testnet2 == TESTNET2_GENESIS_HASH => Ok(Chain::Testnet2),
            mainnet if mainnet == MAINNET_GENESIS_HASH => Ok(Chain::Mainnet),
            integration if integration == INTEGRATION_GENESIS_HASH => Ok(Chain::Integration),
            other => Err(anyhow::anyhow!("Unknown genesis block hash: {}", other.0)),
        }
    }
}

#[async_trait::async_trait]
impl GatewayApi for Client {
    #[tracing::instrument(skip(self))]
    async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
        self.block_with_retry_behaviour(block, self.retry).await
    }

    #[tracing::instrument(skip(self))]
    async fn block_without_retry(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingBlock, SequencerError> {
        self.block_with_retry_behaviour(block, false).await
    }

    /// Gets class for a particular class hash.
    #[tracing::instrument(skip(self))]
    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError> {
        self.feeder_gateway_request()
            .get_class_by_hash()
            .with_class_hash(class_hash)
            .with_retry(self.retry)
            .get_as_bytes()
            .await
    }

    /// Gets class for a particular class hash.
    #[tracing::instrument(skip(self))]
    async fn pending_class_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        self.feeder_gateway_request()
            .get_class_by_hash()
            .with_class_hash(class_hash)
            .with_block(BlockId::Pending)
            .with_retry(self.retry)
            .get_as_bytes()
            .await
    }

    /// Gets CASM for a particular class hash.
    #[tracing::instrument(skip(self))]
    async fn pending_casm_by_hash(
        &self,
        class_hash: ClassHash,
    ) -> Result<bytes::Bytes, SequencerError> {
        self.feeder_gateway_request()
            .get_compiled_class_by_class_hash()
            .with_class_hash(class_hash)
            .with_block(BlockId::Pending)
            .with_retry(self.retry)
            .get_as_bytes()
            .await
    }

    /// Gets transaction by hash.
    #[tracing::instrument(skip(self))]
    async fn transaction(
        &self,
        transaction_hash: TransactionHash,
    ) -> Result<reply::Transaction, SequencerError> {
        self.feeder_gateway_request()
            .get_transaction()
            .with_transaction_hash(transaction_hash)
            .with_retry(self.retry)
            .get()
            .await
    }

    #[tracing::instrument(skip(self))]
    async fn state_update(&self, block: BlockId) -> Result<StateUpdate, SequencerError> {
        let state_update: reply::StateUpdate = self
            .feeder_gateway_request()
            .get_state_update()
            .with_block(block)
            .with_retry(self.retry)
            .get()
            .await?;

        Ok(state_update.into())
    }

    /// Gets addresses of the Ethereum contracts crucial to Starknet operation.
    #[tracing::instrument(skip(self))]
    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError> {
        self.feeder_gateway_request()
            .get_contract_addresses()
            .with_retry(self.retry)
            .get()
            .await
    }

    /// Adds a transaction invoking a contract.
    #[tracing::instrument(skip(self))]
    async fn add_invoke_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        sender_address: ContractAddress,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
        let req = AddTransaction::Invoke(InvokeFunction {
            sender_address,
            calldata,
            max_fee,
            version,
            signature,
            nonce,
        });

        // Note that we don't do retries here.
        // This method is used to proxy an add transaction operation from the JSON-RPC
        // API to the sequencer. Retries should be implemented in the JSON-RPC
        // client instead.
        self.gateway_request()
            .add_transaction()
            .with_retry(false)
            .post_with_json(&req)
            .await
    }

    /// Adds a transaction declaring a class.
    #[tracing::instrument(skip(self))]
    async fn add_declare_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_definition: ContractDefinition,
        sender_address: ContractAddress,
        compiled_class_hash: Option<CasmHash>,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeclareResponse, SequencerError> {
        let req = AddTransaction::Declare(Declare {
            contract_class: contract_definition,
            sender_address,
            max_fee,
            signature,
            nonce,
            version,
            compiled_class_hash,
        });

        // Note that we don't do retries here.
        // This method is used to proxy an add transaction operation from the JSON-RPC
        // API to the sequencer. Retries should be implemented in the JSON-RPC
        // client instead.
        self.gateway_request()
            .add_transaction()
            // mainnet requires a token (but testnet does not so its optional).
            .with_optional_token(token.as_deref())
            .with_retry(false)
            .post_with_json(&req)
            .await
    }

    #[tracing::instrument(skip(self))]
    async fn add_deploy_account(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: TransactionNonce,
        contract_address_salt: ContractAddressSalt,
        class_hash: ClassHash,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::DeployAccountResponse, SequencerError> {
        let req = AddTransaction::DeployAccount(DeployAccount {
            version,
            max_fee,
            signature,
            nonce,
            class_hash,
            contract_address_salt,
            constructor_calldata: calldata,
        });

        // Note that we don't do retries here.
        // This method is used to proxy an add transaction operation from the JSON-RPC
        // API to the sequencer. Retries should be implemented in the JSON-RPC
        // client instead.

        self.gateway_request()
            .add_transaction()
            .with_retry(false)
            .post_with_json(&req)
            .await
    }
}

pub mod test_utils {
    use super::Client;
    use starknet_gateway_types::error::KnownStarknetErrorCode;

    /// Helper funtion which allows for easy creation of a response tuple
    /// that contains a [StarknetError](starknet_gateway_types::error::StarknetError) for a given [KnownStarknetErrorCode].
    ///
    /// The response tuple can then be used by the [setup] function.
    ///
    /// The `message` field is always an empty string.
    /// The HTTP status code for this response is always `500` (`Internal Server Error`).
    pub fn response_from(code: KnownStarknetErrorCode) -> (String, u16) {
        use starknet_gateway_types::error::StarknetError;

        let e = StarknetError {
            code: code.into(),
            message: "".to_string(),
        };
        (serde_json::to_string(&e).unwrap(), 500)
    }

    /// # Usage
    ///
    /// Use to initialize a [Client] test case. The function does one of the following things:
    ///
    /// 1. if `SEQUENCER_TESTS_LIVE_API` environment variable is set:
    ///    - creates a [Client] instance which connects to the Goerli
    ///      sequencer API
    ///
    /// 2. otherwise:
    ///    - initializes a local mock server instance with the given expected
    ///      url paths & queries and respective fixtures for replies
    ///    - creates a [Client] instance which connects to the mock server
    ///
    pub fn setup<S1, S2, const N: usize>(
        url_paths_queries_and_response_fixtures: [(S1, (S2, u16)); N],
    ) -> (Option<tokio::task::JoinHandle<()>>, Client)
    where
        S1: std::convert::AsRef<str>
            + std::fmt::Display
            + std::fmt::Debug
            + std::cmp::PartialEq
            + Send
            + Sync
            + Clone
            + 'static,
        S2: std::string::ToString + Send + Sync + Clone + 'static,
    {
        if std::env::var_os("SEQUENCER_TESTS_LIVE_API").is_some() {
            (None, Client::testnet())
        } else if std::env::var_os("SEQUENCER_TESTS_LIVE_API_INTEGRATION").is_some() {
            (None, Client::integration())
        } else {
            use warp::Filter;
            let opt_query_raw = warp::query::raw()
                .map(Some)
                .or_else(|_| async { Ok::<(Option<String>,), std::convert::Infallible>((None,)) });
            let path = warp::any().and(warp::path::full()).and(opt_query_raw).map(
                move |full_path: warp::path::FullPath, raw_query: Option<String>| {
                    let actual_full_path_and_query = match raw_query {
                        Some(some_raw_query) => {
                            format!("{}?{}", full_path.as_str(), some_raw_query.as_str())
                        }
                        None => full_path.as_str().to_owned(),
                    };

                    match url_paths_queries_and_response_fixtures
                        .iter()
                        .find(|x| x.0.as_ref() == actual_full_path_and_query)
                    {
                        Some((_, (body, status))) => http::response::Builder::new()
                            .status(*status)
                            .body(body.to_string()),
                        None => panic!(
                            "Actual url path and query {} not found in the expected {:?}",
                            actual_full_path_and_query,
                            url_paths_queries_and_response_fixtures
                                .iter()
                                .map(|(expected_path, _)| expected_path)
                                .collect::<Vec<_>>()
                        ),
                    }
                },
            );

            let (addr, serve_fut) = warp::serve(path).bind_ephemeral(([127, 0, 0, 1], 0));
            let server_handle = tokio::spawn(serve_fut);
            let client =
                Client::with_base_url(reqwest::Url::parse(&format!("http://{addr}")).unwrap())
                    .unwrap();
            (Some(server_handle), client)
        }
    }

    /// # Usage
    ///
    /// Use to initialize a [Client] test case. The function does one of the following things:
    /// - initializes a local mock server instance with the given expected
    ///   url paths & queries and respective fixtures for replies
    /// - creates a [Client] instance which connects to the mock server
    /// - replies for a particular path & query are consumed one at a time until exhausted
    ///
    /// # Panics
    ///
    /// Panics if replies for a particular path & query have been exhausted and the
    /// client still attempts to query the very same path.
    ///
    pub fn setup_with_varied_responses<const M: usize, const N: usize>(
        url_paths_queries_and_response_fixtures: [(String, [(String, u16); M]); N],
    ) -> (Option<tokio::task::JoinHandle<()>>, Client) {
        let url_paths_queries_and_response_fixtures = url_paths_queries_and_response_fixtures
            .into_iter()
            .map(|x| {
                (
                    x.0.clone(),
                    x.1.into_iter().collect::<std::collections::VecDeque<_>>(),
                )
            })
            .collect::<Vec<_>>();
        use std::sync::{Arc, Mutex};

        let url_paths_queries_and_response_fixtures =
            Arc::new(Mutex::new(url_paths_queries_and_response_fixtures));

        use warp::Filter;
        let opt_query_raw = warp::query::raw()
            .map(Some)
            .or_else(|_| async { Ok::<(Option<String>,), std::convert::Infallible>((None,)) });
        let path = warp::any().and(warp::path::full()).and(opt_query_raw).map(
            move |full_path: warp::path::FullPath, raw_query: Option<String>| {
                let actual_full_path_and_query = match raw_query {
                    Some(some_raw_query) => {
                        format!("{}?{}", full_path.as_str(), some_raw_query.as_str())
                    }
                    None => full_path.as_str().to_owned(),
                };

                let mut url_paths_queries_and_response_fixtures =
                    url_paths_queries_and_response_fixtures.lock().unwrap();

                match url_paths_queries_and_response_fixtures
                    .iter_mut()
                    .find(|x| x.0 == actual_full_path_and_query)
                {
                    Some((_, responses)) => {
                        let (body, status) =
                            responses.pop_front().expect("more responses for this path");
                        http::response::Builder::new().status(status).body(body)
                    }
                    None => panic!(
                        "Actual url path and query {} not found in the expected {:?}",
                        actual_full_path_and_query,
                        url_paths_queries_and_response_fixtures
                            .iter()
                            .map(|(expected_path, _)| expected_path)
                            .collect::<Vec<_>>()
                    ),
                }
            },
        );

        let (addr, serve_fut) = warp::serve(path).bind_ephemeral(([127, 0, 0, 1], 0));
        let server_handle = tokio::spawn(serve_fut);
        let client = Client::with_base_url(reqwest::Url::parse(&format!("http://{addr}")).unwrap())
            .unwrap()
            .disable_retry_for_tests();
        (Some(server_handle), client)
    }
}

#[cfg(test)]
mod tests {
    use super::{test_utils::*, *};
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockHash, BlockNumber, StarknetVersion};
    use stark_hash::Felt;
    use starknet_gateway_test_fixtures::{testnet::*, *};
    use starknet_gateway_types::error::KnownStarknetErrorCode;
    use starknet_gateway_types::request::{BlockHashOrTag, BlockNumberOrTag};

    pub const GENESIS_BLOCK_NUMBER: BlockNumberOrTag =
        BlockNumberOrTag::Number(BlockNumber::GENESIS);
    pub const INVALID_BLOCK_NUMBER: BlockNumberOrTag = BlockNumberOrTag::Number(BlockNumber::MAX);
    pub const GENESIS_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(block_hash!(
        "07d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"
    ));
    pub const INVALID_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(block_hash!(
        "06d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"
    ));

    #[test_log::test(tokio::test)]
    async fn client_user_agent() {
        use pathfinder_common::{consts::VERGEN_GIT_DESCRIBE, BlockTimestamp};
        use starknet_gateway_types::reply::{Block, Status};
        use std::convert::Infallible;
        use warp::Filter;

        let filter = warp::header::optional("user-agent").and_then(
            |user_agent: Option<String>| async move {
                let user_agent = user_agent.expect("user-agent set");
                let (name, version) = user_agent.split_once('/').unwrap();

                assert_eq!(name, "starknet-pathfinder");
                assert_eq!(version, VERGEN_GIT_DESCRIBE);

                Ok::<_, Infallible>(warp::reply::json(&Block {
                    block_hash: BlockHash(Felt::ZERO),
                    block_number: BlockNumber::GENESIS,
                    gas_price: None,
                    parent_block_hash: BlockHash(Felt::ZERO),
                    sequencer_address: None,
                    state_commitment: pathfinder_common::StateCommitment(Felt::ZERO),
                    status: Status::NotReceived,
                    timestamp: BlockTimestamp::new_or_panic(0),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: StarknetVersion::default(),
                }))
            },
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (addr, run_srv) =
            warp::serve(filter).bind_with_graceful_shutdown(([127, 0, 0, 1], 0), async {
                shutdown_rx.await.ok();
            });
        let server_handle = tokio::spawn(run_srv);

        let url = format!("http://{addr}");
        let url = Url::parse(&url).unwrap();
        let client = Client::with_base_url(url).unwrap();

        let _ = client.block(BlockId::Latest).await;
        shutdown_tx.send(()).unwrap();
        server_handle.await.unwrap();
    }

    mod block_matches_by_hash_on {
        use super::*;

        #[tokio::test]
        async fn genesis() {
            let (_jh, client) = setup([
                (
                    format!("/feeder_gateway/get_block?blockHash={GENESIS_BLOCK_HASH}"),
                    (v0_9_0::block::GENESIS, 200),
                ),
                (
                    format!("/feeder_gateway/get_block?blockNumber={GENESIS_BLOCK_NUMBER}"),
                    (v0_9_0::block::GENESIS, 200),
                ),
            ]);
            let by_hash = client
                .block(BlockId::from(GENESIS_BLOCK_HASH))
                .await
                .unwrap();
            let by_number = client
                .block(BlockId::from(GENESIS_BLOCK_NUMBER))
                .await
                .unwrap();
            assert_eq!(by_hash, by_number);
        }

        #[tokio::test]
        async fn specific_block() {
            let (_jh, client) = setup([
                (
                    "/feeder_gateway/get_block?blockHash=0x40ffdbd9abbc4fc64652c50db94a29bce65c183316f304a95df624de708e746",
                    (v0_9_0::block::NUMBER_231579, 200)
                ),
                (
                    "/feeder_gateway/get_block?blockNumber=231579",
                    (v0_9_0::block::NUMBER_231579, 200)
                ),
            ]);
            let by_hash = client
                .block(
                    block_hash!("040ffdbd9abbc4fc64652c50db94a29bce65c183316f304a95df624de708e746")
                        .into(),
                )
                .await
                .unwrap();
            let by_number = client
                .block(BlockNumber::new_or_panic(231579).into())
                .await
                .unwrap();
            assert_eq!(by_hash, by_number);
        }
    }

    mod block {
        use super::*;
        use pathfinder_common::BlockId;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn latest() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_block?blockNumber=latest",
                (v0_9_0::block::NUMBER_231579, 200),
            )]);
            client.block(BlockId::Latest).await.unwrap();
        }

        #[tokio::test]
        async fn pending() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_block?blockNumber=pending",
                (v0_9_0::block::PENDING, 200),
            )]);
            client.block(BlockId::Pending).await.unwrap();
        }

        #[test_log::test(tokio::test)]
        async fn invalid_hash() {
            let (_jh, client) = setup([(
                format!("/feeder_gateway/get_block?blockHash={INVALID_BLOCK_HASH}"),
                response_from(KnownStarknetErrorCode::BlockNotFound),
            )]);
            let error = client
                .block(BlockId::from(INVALID_BLOCK_HASH))
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, KnownStarknetErrorCode::BlockNotFound.into())
            );
        }

        #[test_log::test(tokio::test)]
        async fn invalid_number() {
            let (_jh, client) = setup([(
                format!("/feeder_gateway/get_block?blockNumber={INVALID_BLOCK_NUMBER}"),
                response_from(KnownStarknetErrorCode::BlockNotFound),
            )]);
            let error = client
                .block(BlockId::from(INVALID_BLOCK_NUMBER))
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, KnownStarknetErrorCode::BlockNotFound.into())
            );
        }

        #[tokio::test]
        async fn with_starknet_version_added_in_0_9_1() {
            use starknet_gateway_types::reply::MaybePendingBlock;
            let (_jh, client) = setup([
                (
                    // block 300k on testnet in case of a live api test
                    "/feeder_gateway/get_block?blockNumber=300000",
                    (integration::block::NUMBER_192844, 200),
                ),
                (
                    "/feeder_gateway/get_block?blockNumber=pending",
                    (integration::block::PENDING, 200),
                ),
            ]);

            let expected_version = StarknetVersion::new(0, 9, 1);

            let version = client
                .block(BlockNumber::new_or_panic(300000).into())
                .await
                .unwrap()
                .as_block()
                .expect("should not had been a pending block")
                .starknet_version;
            assert_eq!(version, expected_version);

            let block = client.block(BlockId::Pending).await.unwrap();
            assert_matches!(block, MaybePendingBlock::Pending(_));
        }
    }

    mod class_by_hash {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test_log::test(tokio::test)]
        async fn invalid_class_hash() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_class_by_hash?classHash={}",
                    INVALID_CLASS_HASH.0.to_hex_str()
                ),
                response_from(KnownStarknetErrorCode::UndeclaredClass),
            )]);
            let error = client.class_by_hash(INVALID_CLASS_HASH).await.unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, KnownStarknetErrorCode::UndeclaredClass.into())
            );
        }

        #[tokio::test]
        async fn success() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_class_by_hash?classHash={}",
                    VALID_CLASS_HASH.0.to_hex_str()
                ),
                (r#"{"hello":"world"}"#, 200),
            )]);
            let bytes = client.class_by_hash(VALID_CLASS_HASH).await.unwrap();
            serde_json::from_slice::<serde_json::value::Value>(&bytes).unwrap();
        }
    }

    mod transaction {
        use super::{reply::Status, *};
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn declare() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_transaction?transactionHash=0x587d93f2339b7f2beda040187dbfcb9e076ce4a21eb8d15ae64819718817fbe",
                (v0_9_0::transaction::INVOKE, 200)
            )]);
            assert_eq!(
                client
                    .transaction(transaction_hash!(
                        "0587d93f2339b7f2beda040187dbfcb9e076ce4a21eb8d15ae64819718817fbe"
                    ))
                    .await
                    .unwrap()
                    .status,
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn deploy() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_transaction?transactionHash=0x3d7623443283d9a0cec946492db78b06d57642a551745ddfac8d3f1f4fcc2a8",
                (v0_9_0::transaction::DEPLOY, 200)
            )]);
            assert_eq!(
                client
                    .transaction(transaction_hash!(
                        "03d7623443283d9a0cec946492db78b06d57642a551745ddfac8d3f1f4fcc2a8"
                    ))
                    .await
                    .unwrap()
                    .status,
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn invoke() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_transaction?transactionHash=0x587d93f2339b7f2beda040187dbfcb9e076ce4a21eb8d15ae64819718817fbe",
                (v0_9_0::transaction::INVOKE, 200)
            )]);
            assert_eq!(
                client
                    .transaction(transaction_hash!(
                        "0587d93f2339b7f2beda040187dbfcb9e076ce4a21eb8d15ae64819718817fbe"
                    ))
                    .await
                    .unwrap()
                    .status,
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_transaction?transactionHash={}",
                    INVALID_TX_HASH.0.to_hex_str()
                ),
                (r#"{"status": "NOT_RECEIVED"}"#, 200),
            )]);
            assert_eq!(
                client.transaction(INVALID_TX_HASH).await.unwrap().status,
                Status::NotReceived,
            );
        }
    }

    mod state_update_matches_by_hash_on {
        use super::*;

        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn genesis() {
            let (_jh, client) = setup([
                (
                    "/feeder_gateway/get_state_update?blockNumber=0".to_string(),
                    (v0_11_0::state_update::GENESIS, 200),
                ),
                (
                    format!("/feeder_gateway/get_state_update?blockHash={GENESIS_BLOCK_HASH}"),
                    (v0_11_0::state_update::GENESIS, 200),
                ),
            ]);
            let by_number = client
                .state_update(BlockId::from(GENESIS_BLOCK_NUMBER))
                .await
                .unwrap();
            let by_hash = client
                .state_update(BlockId::from(GENESIS_BLOCK_HASH))
                .await
                .unwrap();

            assert_eq!(by_number, by_hash);
        }

        #[tokio::test]
        async fn specific_block() {
            let (_jh, client) = setup([
                (
                    "/feeder_gateway/get_state_update?blockNumber=315700",
                    (v0_11_0::state_update::NUMBER_315700, 200)
                ),
                (
                    "/feeder_gateway/get_state_update?blockHash=0x17e4297ba605d22babb8c4e59a965b00e0487cd1e3ff63f99dbc7fe33e4fd03",
                    (v0_11_0::state_update::NUMBER_315700, 200)
                ),
            ]);
            let by_number = client
                .state_update(BlockNumber::new_or_panic(315700).into())
                .await
                .unwrap();
            let by_hash = client
                .state_update(
                    block_hash!("017e4297ba605d22babb8c4e59a965b00e0487cd1e3ff63f99dbc7fe33e4fd03")
                        .into(),
                )
                .await
                .unwrap();

            assert_eq!(by_number, by_hash);
        }
    }

    mod state_update {
        use super::*;

        #[test_log::test(tokio::test)]
        async fn invalid_number() {
            let (_jh, client) = setup([(
                format!("/feeder_gateway/get_state_update?blockNumber={INVALID_BLOCK_NUMBER}"),
                response_from(KnownStarknetErrorCode::BlockNotFound),
            )]);
            let error = client
                .state_update(BlockId::from(INVALID_BLOCK_NUMBER))
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, KnownStarknetErrorCode::BlockNotFound.into())
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            let (_jh, client) = setup([(
                format!("/feeder_gateway/get_state_update?blockHash={INVALID_BLOCK_HASH}"),
                response_from(KnownStarknetErrorCode::BlockNotFound),
            )]);
            let error = client
                .state_update(BlockId::from(INVALID_BLOCK_HASH))
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, KnownStarknetErrorCode::BlockNotFound.into())
            );
        }

        #[tokio::test]
        async fn latest() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_state_update?blockNumber=latest",
                (v0_11_0::state_update::NUMBER_315700, 200),
            )]);
            client.state_update(BlockId::Latest).await.unwrap();
        }

        #[tokio::test]
        async fn pending() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_state_update?blockNumber=pending",
                (v0_11_0::state_update::PENDING, 200),
            )]);
            client.state_update(BlockId::Pending).await.unwrap();
        }
    }

    #[tokio::test]
    async fn eth_contract_addresses() {
        let (_jh, client) = setup([(
            "/feeder_gateway/get_contract_addresses",
            (
                r#"{"Starknet":"0xde29d060d45901fb19ed6c6e959eb22d8626708e","GpsStatementVerifier":"0xab43ba48c9edf4c2c4bb01237348d1d7b28ef168"}"#,
                200,
            ),
        )]);
        client.eth_contract_addresses().await.unwrap();
    }

    mod add_transaction {
        use super::*;
        use pathfinder_common::ContractAddress;
        use starknet_gateway_types::request::{
            add_transaction::CairoContractDefinition,
            contract::{EntryPointType, SelectorAndOffset},
        };
        use std::collections::HashMap;

        mod invoke {
            use super::*;

            fn inputs() -> (
                TransactionVersion,
                Fee,
                Vec<TransactionSignatureElem>,
                TransactionNonce,
                ContractAddress,
                Vec<CallParam>,
            ) {
                (
                    TransactionVersion::ONE,
                    fee!("4F388496839"),
                    vec![
                        transaction_signature_elem!(
                            "0x07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                        ),
                        transaction_signature_elem!(
                            "0x071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                        ),
                    ],
                    transaction_nonce!("0x1"),
                    contract_address!(
                        "0x023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd"
                    ),
                    vec![
                        call_param!("0x1"),
                        call_param!(
                            "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
                        ),
                        call_param!(
                            "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                        ),
                        CallParam(Felt::ZERO),
                        call_param!("0x1"),
                        call_param!("0x1"),
                        call_param!("0x2b"),
                        CallParam(Felt::ZERO),
                    ],
                )
            }

            #[tokio::test]
            async fn v0_is_deprecated() {
                let (_jh, client) = setup([(
                    "/gateway/add_transaction",
                    response_from(KnownStarknetErrorCode::DeprecatedTransaction),
                )]);
                let (_, fee, sig, nonce, addr, call) = inputs();
                let error = client
                    .add_invoke_transaction(TransactionVersion::ZERO, fee, sig, nonce, addr, call)
                    .await
                    .unwrap_err();
                assert_matches!(
                    error,
                    SequencerError::StarknetError(e) => assert_eq!(e.code, KnownStarknetErrorCode::DeprecatedTransaction.into())
                );
            }

            #[tokio::test]
            async fn successful() {
                let (_jh, client) = setup([(
                    "/gateway/add_transaction",
                    (
                        r#"{"code":"TRANSACTION_RECEIVED","transaction_hash":"0x0389DD0629F42176CC8B6C43ACEFC0713D0064ECDFC0470E0FC179F53421A38B"}"#,
                        200,
                    ),
                )]);
                // test with values dumped from `starknet invoke` for a test contract
                let (ver, fee, sig, nonce, addr, call) = inputs();
                client
                    .add_invoke_transaction(ver, fee, sig, nonce, addr, call)
                    .await
                    .unwrap();
            }
        }

        mod declare {
            use starknet_gateway_types::request::{
                add_transaction::SierraContractDefinition, contract::SelectorAndFunctionIndex,
            };

            use super::*;

            #[tokio::test]
            async fn v0_is_deprecated() {
                let (_jh, client) = setup([(
                    "/gateway/add_transaction",
                    response_from(KnownStarknetErrorCode::DeprecatedTransaction),
                )]);

                let error = client
                    .add_declare_transaction(
                        TransactionVersion::ZERO,
                        Fee(Felt::ZERO),
                        vec![],
                        TransactionNonce(Felt::ZERO),
                        ContractDefinition::Cairo(cairo_contract_class_from_fixture()),
                        contract_address!("0x1"),
                        None,
                        None,
                    )
                    .await
                    .unwrap_err();
                assert_matches!(
                    error,
                    SequencerError::StarknetError(e) => assert_eq!(e.code, KnownStarknetErrorCode::DeprecatedTransaction.into())
                );
            }

            #[tokio::test]
            async fn successful_v1() {
                let (_jh, client) = setup([(
                    "/gateway/add_transaction",
                    (
                        r#"{"code": "TRANSACTION_RECEIVED",
                            "transaction_hash": "0x77ccba4df42cf0f74a8eb59a96d7880fae371edca5d000ca5f9985652c8a8ed",
                            "class_hash": "0x711941b11a8236b8cca42b664e19342ac7300abb1dc44957763cb65877c2708"}"#,
                        200,
                    ),
                )]);

                client
                    .add_declare_transaction(
                        TransactionVersion::ONE,
                        fee!("0xFFFF"),
                        vec![],
                        TransactionNonce(Felt::ZERO),
                        ContractDefinition::Cairo(cairo_contract_class_from_fixture()),
                        contract_address!("0x1"),
                        None,
                        None,
                    )
                    .await
                    .unwrap();
            }

            fn sierra_contract_class_from_fixture() -> SierraContractDefinition {
                let sierra_class =
                    starknet_gateway_test_fixtures::class_definitions::CAIRO_1_0_0_ALPHA6_SIERRA;
                let mut sierra_class =
                    serde_json::from_slice::<serde_json::Value>(sierra_class).unwrap();
                let sierra_program = sierra_class.get_mut("sierra_program").unwrap().take();
                let sierra_program = serde_json::from_value::<Vec<Felt>>(sierra_program).unwrap();
                let mut gzip_encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                serde_json::to_writer(&mut gzip_encoder, &sierra_program).unwrap();
                let sierra_program = gzip_encoder.finish().unwrap();
                let sierra_program = base64::encode(sierra_program);

                let mut entry_points = sierra_class.get_mut("entry_points_by_type").unwrap().take();

                let mut entry_points_by_type: HashMap<
                    EntryPointType,
                    Vec<SelectorAndFunctionIndex>,
                > = Default::default();
                entry_points_by_type.insert(
                    EntryPointType::Constructor,
                    serde_json::from_value::<Vec<SelectorAndFunctionIndex>>(
                        entry_points.get_mut("CONSTRUCTOR").unwrap().take(),
                    )
                    .unwrap(),
                );
                entry_points_by_type.insert(
                    EntryPointType::External,
                    serde_json::from_value::<Vec<SelectorAndFunctionIndex>>(
                        entry_points.get_mut("EXTERNAL").unwrap().take(),
                    )
                    .unwrap(),
                );
                entry_points_by_type.insert(
                    EntryPointType::L1Handler,
                    serde_json::from_value::<Vec<SelectorAndFunctionIndex>>(
                        entry_points.get_mut("L1_HANDLER").unwrap().take(),
                    )
                    .unwrap(),
                );

                SierraContractDefinition {
                    sierra_program,
                    contract_class_version: "0.1.0".into(),
                    abi: "trust the contract developer".into(),
                    entry_points_by_type,
                }
            }

            #[tokio::test]
            async fn successful_v2() {
                let (_jh, client) = setup([(
                    "/gateway/add_transaction",
                    (
                        r#"{"code": "TRANSACTION_RECEIVED",
                            "transaction_hash": "0x77ccba4df42cf0f74a8eb59a96d7880fae371edca5d000ca5f9985652c8a8ed",
                            "class_hash": "0x711941b11a8236b8cca42b664e19342ac7300abb1dc44957763cb65877c2708"}"#,
                        200,
                    ),
                )]);

                client
                    .add_declare_transaction(
                        TransactionVersion::TWO,
                        fee!("0xffff"),
                        vec![],
                        TransactionNonce(Felt::ZERO),
                        ContractDefinition::Sierra(sierra_contract_class_from_fixture()),
                        contract_address!("0x1"),
                        Some(casm_hash!(
                            "0x5bcd45099caf3dca6c0c0f6697698c90eebf02851acbbaf911186b173472fcc"
                        )),
                        None,
                    )
                    .await
                    .unwrap();
            }
        }

        #[tokio::test]
        async fn test_deploy_account() {
            use starknet_gateway_types::request::add_transaction::AddTransaction;
            let (_jh, client) = setup([(
                "/gateway/add_transaction",
                (v0_10_1::add_transaction::DEPLOY_ACCOUNT_RESPONSE, 200),
            )]);

            let json =
                starknet_gateway_test_fixtures::v0_10_1::add_transaction::DEPLOY_ACCOUNT_REQUEST;
            let req: AddTransaction = serde_json::from_str(json).expect("Request parsed from JSON");
            let req = match req {
                AddTransaction::DeployAccount(deploy_account) => Some(deploy_account),
                _ => None,
            };
            let req = req.expect("Request matched as DEPLOY_ACCOUNT");

            let res = client
                .add_deploy_account(
                    req.version,
                    req.max_fee,
                    req.signature,
                    req.nonce,
                    req.contract_address_salt,
                    req.class_hash,
                    req.constructor_calldata,
                )
                .await
                .expect("DEPLOY_ACCOUNT response");

            let expected = reply::add_transaction::DeployAccountResponse {
                code: "TRANSACTION_RECEIVED".to_string(),
                transaction_hash: transaction_hash!(
                    "06dac1655b34e52a449cfe961188f7cc2b1496bcd36706cedf4935567be29d5b"
                ),
                address: contract_address!(
                    "04e574ea2abd76d3105b3d29de28af0c5a28b889aa465903080167f6b48b1acc"
                ),
            };

            assert_eq!(res, expected);
        }

        /// Return a contract definition that was dumped from a `starknet deploy`.
        fn cairo_contract_class_from_fixture() -> CairoContractDefinition {
            let json = starknet_gateway_test_fixtures::class_definitions::CONTRACT_DEFINITION;
            let json: serde_json::Value = serde_json::from_slice(json).unwrap();
            let program = &json["program"];

            // Program is expected to be a gzip-compressed then base64 encoded representation of the JSON.
            let mut gzip_encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            serde_json::to_writer(&mut gzip_encoder, program).unwrap();
            let compressed_program = gzip_encoder.finish().unwrap();
            let program = base64::encode(compressed_program);

            let entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndOffset>> =
                HashMap::from([
                    (EntryPointType::Constructor, vec![]),
                    (
                        EntryPointType::External,
                        vec![
                            SelectorAndOffset {
                                offset: byte_code_offset!("0x3a"),
                                selector: entry_point!("0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"),
                            },
                            SelectorAndOffset {
                                offset: byte_code_offset!("0x5b"),
                                selector: entry_point!("039e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695"),
                            },
                        ],
                    ),
                    (EntryPointType::L1Handler, vec![]),
                ]);
            CairoContractDefinition {
                program,
                entry_points_by_type,
                abi: Some(json["contract_definition"]["abi"].clone()),
            }
        }

        mod deploy_token {
            use super::*;
            use http::StatusCode;
            use std::collections::HashMap;
            use warp::{http::Response, Filter};

            const EXPECTED_TOKEN: &str = "magic token value";
            const EXPECTED_ERROR_MESSAGE: &str = "error message";

            fn test_server() -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
                fn token_check(params: HashMap<String, String>) -> impl warp::Reply {
                    match params.get("token") {
                        Some(token) if token == EXPECTED_TOKEN => Response::builder().status(StatusCode::OK).body(serde_json::to_vec(&serde_json::json!({
                            "code": "TRANSACTION_ACCEPTED",
                            "transaction_hash": "0x57ed4b4c76a1ca0ba044a654dd3ee2d0d3e550343d739350a22aacdd524110d",
                            "class_hash":"0x3926aea98213ec34fe9783d803237d221c54c52344422e1f4942a5b340fa6ad"
                        })).unwrap()),
                        _ => Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(serde_json::to_vec(&serde_json::json!({
                            "code": "StarknetErrorCode.NON_PERMITTED_CONTRACT",
                            "message": EXPECTED_ERROR_MESSAGE,
                        })).unwrap())
                    }
                }

                let route = warp::any()
                    .and(warp::query::<HashMap<String, String>>())
                    .map(token_check);
                let (addr, run_srv) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
                let server_handle = tokio::spawn(run_srv);
                (server_handle, addr)
            }

            #[test_log::test(tokio::test)]
            async fn test_token_is_passed_to_sequencer_api() {
                let (_jh, addr) = test_server();
                let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                url.set_port(Some(addr.port())).unwrap();
                let client = Client::with_base_url(url).unwrap();

                client
                    .add_declare_transaction(
                        TransactionVersion::ZERO,
                        Fee::ZERO,
                        vec![],
                        TransactionNonce::ZERO,
                        ContractDefinition::Cairo(CairoContractDefinition {
                            program: "".to_owned(),
                            entry_points_by_type: HashMap::new(),
                            abi: None,
                        }),
                        ContractAddress::new_or_panic(Felt::ZERO),
                        None,
                        Some(EXPECTED_TOKEN.to_owned()),
                    )
                    .await
                    .unwrap();
            }

            #[test_log::test(tokio::test)]
            async fn test_deploy_fails_with_no_token() {
                let (_jh, addr) = test_server();
                let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                url.set_port(Some(addr.port())).unwrap();
                let client = Client::with_base_url(url).unwrap();

                let err = client
                    .add_declare_transaction(
                        TransactionVersion::ZERO,
                        Fee::ZERO,
                        vec![],
                        TransactionNonce::ZERO,
                        ContractDefinition::Cairo(CairoContractDefinition {
                            program: "".to_owned(),
                            entry_points_by_type: HashMap::new(),
                            abi: None,
                        }),
                        ContractAddress::new_or_panic(Felt::ZERO),
                        None,
                        None,
                    )
                    .await
                    .unwrap_err();

                assert_matches!(err, SequencerError::StarknetError(se) => {
                        assert_eq!(se.code, KnownStarknetErrorCode::NotPermittedContract.into());
                        assert_eq!(se.message, EXPECTED_ERROR_MESSAGE);
                });
            }
        }
    }

    mod chain {
        use crate::Client;
        use pathfinder_common::Chain;

        #[derive(Copy, Clone, PartialEq, Eq)]
        /// Used by [setup_server] to determine which block to return.
        enum TargetChain {
            Testnet,
            Mainnet,
            Invalid,
        }

        /// Creates a [starknet_gateway_client::Client] where the endpoint is either the real feeder gateway,
        /// or a local warp server. A local server is created if:
        /// - SEQUENCER_TESTS_LIVE_API is not set, __or__
        /// - `target == TargetChain::Invalid`
        ///
        /// The local server only supports the `feeder_gateway/get_block?blockNumber=0` queries.
        fn setup_server(target: TargetChain) -> (Option<tokio::task::JoinHandle<()>>, Client) {
            use warp::http::{Response, StatusCode};
            use warp::Filter;

            // `TargetChain::Invalid` always uses the local server setup as the Sequencer
            // won't return an invalid genesis block.
            if std::env::var_os("SEQUENCER_TESTS_LIVE_API").is_some()
                && target != TargetChain::Invalid
            {
                match target {
                    TargetChain::Mainnet => (None, Client::mainnet().disable_retry_for_tests()),
                    TargetChain::Testnet => (None, Client::testnet().disable_retry_for_tests()),
                    // Escaped above already
                    TargetChain::Invalid => unreachable!(),
                }
            } else {
                #[derive(serde::Deserialize, serde::Serialize)]
                #[serde(deny_unknown_fields)]
                struct Params {
                    #[serde(rename = "blockNumber")]
                    block_number: u64,
                }

                let filter = warp::get()
                    .and(warp::path("feeder_gateway"))
                    .and(warp::path("get_block"))
                    .and(warp::query::<Params>())
                    .map(move |params: Params| match params.block_number {
                        0 => {
                            const GOERLI_GENESIS: &str = starknet_gateway_test_fixtures::v0_9_0::block::GENESIS;

                            let data = match target {
                                TargetChain::Testnet => GOERLI_GENESIS.to_owned(),
                                // This is a bit of a cheat, but we don't currently have a mainnet fixture and I'm hesitant to introduce one
                                // since it requires re-organising all the fixtures.
                                TargetChain::Mainnet => GOERLI_GENESIS.replace(
                                    r#""block_hash": "0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"#,
                                    r#""block_hash": "0x047C3637B57C2B079B93C61539950C17E868A28F46CDEF28F88521067F21E943"#,
                                ),
                                TargetChain::Invalid => GOERLI_GENESIS.replace(
                                    r#"block_hash": "0x7d328"#,
                                    r#"block_hash": "0x11111"#,
                                ),
                            };
                            Response::new(data)
                        }
                        _ => Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body("Only supports genesis block request".to_owned())
                            .unwrap(),
                    });

                let (addr, serve_fut) = warp::serve(filter).bind_ephemeral(([127, 0, 0, 1], 0));
                let server_handle = tokio::spawn(serve_fut);
                let client =
                    Client::with_base_url(reqwest::Url::parse(&format!("http://{addr}")).unwrap())
                        .unwrap()
                        .disable_retry_for_tests();

                (Some(server_handle), client)
            }
        }

        #[tokio::test]
        async fn testnet() {
            let (_server_handle, sequencer) = setup_server(TargetChain::Testnet);
            let chain = sequencer.chain().await.unwrap();
            assert_eq!(chain, Chain::Testnet);
        }

        #[tokio::test]
        async fn mainnet() {
            let (_server_handle, sequencer) = setup_server(TargetChain::Mainnet);
            let chain = sequencer.chain().await.unwrap();
            assert_eq!(chain, Chain::Mainnet);
        }

        #[tokio::test]
        async fn invalid() {
            let (_server_handle, sequencer) = setup_server(TargetChain::Invalid);
            sequencer.chain().await.unwrap_err();
        }
    }
}
