//! StarkNet L2 sequencer client.
use pathfinder_common::{
    BlockId, CallParam, CasmHash, Chain, ClassHash, ContractAddress, ContractAddressSalt,
    EntryPoint, Fee, SierraHash, StarknetBlockNumber, StarknetTransactionHash, StorageAddress,
    StorageValue, TransactionNonce, TransactionSignatureElem, TransactionVersion,
};
use reqwest::Url;
use starknet_gateway_types::{
    error::SequencerError,
    reply,
    request::{
        add_transaction::{
            AddTransaction, ContractDefinition, Declare, DeployAccount, InvokeFunction,
        },
        BlockHashOrTag,
    },
};
use std::{fmt::Debug, result::Result, time::Duration};

mod builder;
mod metrics;

#[cfg_attr(feature = "test-utils", mockall::automock)]
#[async_trait::async_trait]
pub trait ClientApi {
    async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError>;

    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError>;

    async fn compiled_class(&self, class_hash: SierraHash) -> Result<bytes::Bytes, SequencerError>;

    async fn storage(
        &self,
        contract_addr: ContractAddress,
        key: StorageAddress,
        block_hash: BlockHashOrTag,
    ) -> Result<StorageValue, SequencerError>;

    async fn transaction(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> Result<reply::Transaction, SequencerError>;

    async fn state_update(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingStateUpdate, SequencerError>;

    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError>;

    #[allow(clippy::too_many_arguments)]
    async fn add_invoke_transaction(
        &self,
        version: TransactionVersion,
        max_fee: Fee,
        signature: Vec<TransactionSignatureElem>,
        nonce: Option<TransactionNonce>,
        contract_address: ContractAddress,
        entry_point_selector: Option<EntryPoint>,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError>;

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
    ) -> Result<reply::add_transaction::DeclareResponse, SequencerError>;

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
    ) -> Result<reply::add_transaction::DeployAccountResponse, SequencerError>;
}

/// StarkNet sequencer client using REST API.
///
/// Retry is performed on __all__ types of errors __except for__
/// [StarkNet specific errors](starknet_gateway_types::error::StarknetError).
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
    /// StarkNet gateway URL.
    gateway: Url,
    /// StarkNet feeder gateway URL.
    feeder_gateway: Url,
}

impl Client {
    #[cfg(not(test))]
    const RETRY: builder::Retry = builder::Retry::Enabled;
    #[cfg(test)]
    const RETRY: builder::Retry = builder::Retry::Disabled;

    /// Creates a new Sequencer client for the given chain.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new(chain: Chain) -> anyhow::Result<Self> {
        match chain {
            Chain::Mainnet => Ok(Self::mainnet()),
            Chain::Testnet => Ok(Self::testnet()),
            Chain::Testnet2 => Ok(Self::testnet2()),
            Chain::Integration => Ok(Self::integration()),
            Chain::Custom => panic!("Not supported for Chain::Custom"),
        }
    }

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
        })
    }

    fn gateway_request(&self) -> builder::Request<'_, builder::stage::Method> {
        builder::Request::builder(&self.inner, self.gateway.clone())
    }

    fn feeder_gateway_request(&self) -> builder::Request<'_, builder::stage::Method> {
        builder::Request::builder(&self.inner, self.feeder_gateway.clone())
    }

    /// Returns the [network chain](Chain) this client is operating on.
    pub async fn chain(&self) -> anyhow::Result<Chain> {
        use pathfinder_common::consts::{
            INTEGRATION_GENESIS_HASH, MAINNET_GENESIS_HASH, TESTNET2_GENESIS_HASH,
            TESTNET_GENESIS_HASH,
        };
        // unwrap is safe as `block_hash` is always present for non-pending blocks.
        let genesis_hash = self
            .block(StarknetBlockNumber::GENESIS.into())
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
impl ClientApi for Client {
    #[tracing::instrument(skip(self))]
    async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
        self.feeder_gateway_request()
            .get_block()
            .with_block(block)
            .with_retry(Self::RETRY)
            .get()
            .await
    }

    #[tracing::instrument(skip(self))]
    async fn compiled_class(&self, hash: SierraHash) -> Result<bytes::Bytes, SequencerError> {
        self.feeder_gateway_request()
            .get_compiled_class_by_class_hash()
            // Let's not introduce an equivalent of `with_class_hash` for `SierraHash`
            // which is conceptually the same thing here
            .with_class_hash(ClassHash(hash.0))
            .with_retry(Self::RETRY)
            .get_as_bytes()
            .await
    }

    /// Gets class for a particular class hash.
    #[tracing::instrument(skip(self))]
    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError> {
        self.feeder_gateway_request()
            .get_class_by_hash()
            .with_class_hash(class_hash)
            .with_retry(Self::RETRY)
            .get_as_bytes()
            .await
    }

    /// Gets storage value associated with a `key` for a prticular contract.
    #[tracing::instrument(skip(self))]
    async fn storage(
        &self,
        contract_addr: ContractAddress,
        key: StorageAddress,
        block_hash: BlockHashOrTag,
    ) -> Result<StorageValue, SequencerError> {
        self.feeder_gateway_request()
            .get_storage_at()
            .with_contract_address(contract_addr)
            .with_storage_address(key)
            .with_block(block_hash)
            .with_retry(Self::RETRY)
            .get()
            .await
    }

    /// Gets transaction by hash.
    #[tracing::instrument(skip(self))]
    async fn transaction(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> Result<reply::Transaction, SequencerError> {
        self.feeder_gateway_request()
            .get_transaction()
            .with_transaction_hash(transaction_hash)
            .with_retry(Self::RETRY)
            .get()
            .await
    }

    #[tracing::instrument(skip(self))]
    async fn state_update(
        &self,
        block: BlockId,
    ) -> Result<reply::MaybePendingStateUpdate, SequencerError> {
        self.feeder_gateway_request()
            .get_state_update()
            .with_block(block)
            .with_retry(Self::RETRY)
            .get()
            .await
    }

    /// Gets addresses of the Ethereum contracts crucial to Starknet operation.
    #[tracing::instrument(skip(self))]
    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError> {
        self.feeder_gateway_request()
            .get_contract_addresses()
            .with_retry(Self::RETRY)
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
        nonce: Option<TransactionNonce>,
        contract_address: ContractAddress,
        entry_point_selector: Option<EntryPoint>,
        calldata: Vec<CallParam>,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
        let req = AddTransaction::Invoke(InvokeFunction {
            contract_address,
            entry_point_selector,
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
            .with_retry(builder::Retry::Disabled)
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
            .with_retry(builder::Retry::Disabled)
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
            .with_retry(builder::Retry::Disabled)
            .post_with_json(&req)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use pathfinder_common::{Chain, StarknetBlockHash, StarknetBlockNumber};
    use stark_hash::Felt;
    use starknet_gateway_test_fixtures::{testnet::*, *};
    use starknet_gateway_types::error::StarknetErrorCode;
    use starknet_gateway_types::request::Tag;
    use std::collections::VecDeque;

    /// Helper funtion which allows for easy creation of a response tuple
    /// that contains a [StarknetError] for a given [StarknetErrorCode].
    ///
    /// The response tuple can then be used by the [setup] function.
    ///
    /// The `message` field is always an empty string.
    /// The HTTP status code for this response is always `500` (`Internal Server Error`).
    fn response_from(code: StarknetErrorCode) -> (String, u16) {
        use starknet_gateway_types::error::StarknetError;

        let e = StarknetError {
            code,
            message: "".to_string(),
        };
        (serde_json::to_string(&e).unwrap(), 500)
    }

    /// # Usage
    ///
    /// Use to initialize a [sequencer::Client] test case. The function does one of the following things:
    ///
    /// 1. if `SEQUENCER_TESTS_LIVE_API` environment variable is set:
    ///    - creates a [sequencer::Client] instance which connects to the Goerli
    ///      sequencer API
    ///
    /// 2. otherwise:
    ///    - initializes a local mock server instance with the given expected
    ///      url paths & queries and respective fixtures for replies
    ///    - creates a [sequencer::Client] instance which connects to the mock server
    ///
    fn setup<S1, S2, const N: usize>(
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
            (None, Client::new(Chain::Testnet).unwrap())
        } else if std::env::var_os("SEQUENCER_TESTS_LIVE_API_INTEGRATION").is_some() {
            (None, Client::new(Chain::Integration).unwrap())
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
    /// Use to initialize a [sequencer::Client] test case. The function does one of the following things:
    /// - initializes a local mock server instance with the given expected
    ///   url paths & queries and respective fixtures for replies
    /// - creates a [sequencer::Client] instance which connects to the mock server
    /// - replies for a particular path & query are consumed one at a time until exhausted
    ///
    /// # Panics
    ///
    /// Panics if replies for a particular path & query have been exhausted and the
    /// client still attempts to query the very same path.
    ///
    fn setup_with_varied_responses<const M: usize, const N: usize>(
        url_paths_queries_and_response_fixtures: [(String, [(String, u16); M]); N],
    ) -> (Option<tokio::task::JoinHandle<()>>, Client) {
        let url_paths_queries_and_response_fixtures = url_paths_queries_and_response_fixtures
            .into_iter()
            .map(|x| (x.0.clone(), x.1.into_iter().collect::<VecDeque<_>>()))
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
        let client =
            Client::with_base_url(reqwest::Url::parse(&format!("http://{addr}")).unwrap()).unwrap();
        (Some(server_handle), client)
    }

    #[test_log::test(tokio::test)]
    async fn client_user_agent() {
        use pathfinder_common::{
            consts::VERGEN_GIT_SEMVER_LIGHTWEIGHT, test_utils::metrics::RecorderGuard,
            StarknetBlockTimestamp,
        };
        use starknet_gateway_types::reply::{Block, Status};
        use std::convert::Infallible;
        use warp::Filter;

        let _guard = RecorderGuard::lock_as_noop();
        let filter = warp::header::optional("user-agent").and_then(
            |user_agent: Option<String>| async move {
                let user_agent = user_agent.expect("user-agent set");
                let (name, version) = user_agent.split_once('/').unwrap();

                assert_eq!(name, "starknet-pathfinder");
                assert_eq!(version, VERGEN_GIT_SEMVER_LIGHTWEIGHT);

                Ok::<_, Infallible>(warp::reply::json(&Block {
                    block_hash: StarknetBlockHash(Felt::ZERO),
                    block_number: StarknetBlockNumber::GENESIS,
                    gas_price: None,
                    parent_block_hash: StarknetBlockHash(Felt::ZERO),
                    sequencer_address: None,
                    state_commitment: pathfinder_common::StateCommitment(Felt::ZERO),
                    status: Status::NotReceived,
                    timestamp: StarknetBlockTimestamp::new_or_panic(0),
                    transaction_receipts: vec![],
                    transactions: vec![],
                    starknet_version: None,
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
        use pathfinder_common::{felt, test_utils::metrics::RecorderGuard};

        #[tokio::test]
        async fn genesis() {
            let _guard = RecorderGuard::lock_as_noop();
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
            let _guard = RecorderGuard::lock_as_noop();
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
                    StarknetBlockHash(felt!(
                        "040ffdbd9abbc4fc64652c50db94a29bce65c183316f304a95df624de708e746"
                    ))
                    .into(),
                )
                .await
                .unwrap();
            let by_number = client
                .block(StarknetBlockNumber::new_or_panic(231579).into())
                .await
                .unwrap();
            assert_eq!(by_hash, by_number);
        }
    }

    mod block {
        use super::*;
        use pathfinder_common::{test_utils::metrics::RecorderGuard, BlockId};
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn latest() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([(
                "/feeder_gateway/get_block?blockNumber=latest",
                (v0_9_0::block::NUMBER_231579, 200),
            )]);
            client.block(BlockId::Latest).await.unwrap();
        }

        #[tokio::test]
        async fn pending() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([(
                "/feeder_gateway/get_block?blockNumber=pending",
                (v0_9_0::block::PENDING, 200),
            )]);
            client.block(BlockId::Pending).await.unwrap();
        }

        #[test_log::test(tokio::test)]
        async fn invalid_hash() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([(
                format!("/feeder_gateway/get_block?blockHash={INVALID_BLOCK_HASH}"),
                response_from(StarknetErrorCode::BlockNotFound),
            )]);
            let error = client
                .block(BlockId::from(INVALID_BLOCK_HASH))
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[test_log::test(tokio::test)]
        async fn invalid_number() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([(
                format!("/feeder_gateway/get_block?blockNumber={INVALID_BLOCK_NUMBER}"),
                response_from(StarknetErrorCode::BlockNotFound),
            )]);
            let error = client
                .block(BlockId::from(INVALID_BLOCK_NUMBER))
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn with_starknet_version_added_in_0_9_1() {
            let _guard = RecorderGuard::lock_as_noop();
            use starknet_gateway_types::reply::MaybePendingBlock;
            let (_jh, client) = setup([
                // TODO move these fixtures to v0_9_1
                (
                    "/feeder_gateway/get_block?blockNumber=192844",
                    (integration::block::NUMBER_192844, 200),
                ),
                (
                    "/feeder_gateway/get_block?blockNumber=pending",
                    (integration::block::PENDING, 200),
                ),
            ]);

            let expected_version = "0.9.1";

            let block = client
                .block(StarknetBlockNumber::new_or_panic(192844).into())
                .await
                .unwrap();
            assert_eq!(
                block
                    .as_block()
                    .expect("should not had been a pending block")
                    .starknet_version
                    .as_deref(),
                Some(expected_version)
            );

            let block = client.block(BlockId::Pending).await.unwrap();

            match block {
                MaybePendingBlock::Pending(p) => {
                    assert_eq!(p.starknet_version.as_deref(), Some(expected_version))
                }
                MaybePendingBlock::Block(_) => panic!("should not had been a ready block"),
            }
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
                response_from(StarknetErrorCode::UndeclaredClass),
            )]);
            let error = client.class_by_hash(INVALID_CLASS_HASH).await.unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::UndeclaredClass)
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

    mod compiled_class {
        use super::*;
        use pathfinder_common::{felt, version_check};
        use pretty_assertions::assert_eq;

        #[test_log::test(tokio::test)]
        async fn invalid_hash() {
            const INVALID_HASH: SierraHash = SierraHash(felt!("0xaaaaa"));
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_compiled_class_by_class_hash?classHash={}",
                    INVALID_HASH.0.to_hex_str()
                ),
                response_from(StarknetErrorCode::UndeclaredClass),
            )]);
            let error = client.compiled_class(INVALID_HASH).await.unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::UndeclaredClass)
            );
        }

        #[tokio::test]
        async fn success() {
            version_check!(
                Testnet < 0 - 11 - 0,
                "Update class 2 hash (sierra) for testnet, current value is from integration"
            );

            const VALID_HASH: SierraHash = SierraHash(felt!(
                "0x4e70b19333ae94bd958625f7b61ce9eec631653597e68645e13780061b2136c"
            ));
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_compiled_class_by_class_hash?classHash={}",
                    VALID_HASH.0.to_hex_str()
                ),
                (r#"{"fake":"fixture"}"#, 200),
            )]);
            let bytes = client.compiled_class(VALID_HASH).await.unwrap();
            serde_json::from_slice::<serde_json::value::Value>(&bytes).unwrap();
        }
    }

    mod storage {
        use super::*;
        use pathfinder_common::felt;
        use pretty_assertions::assert_eq;
        use starknet_gateway_test_fixtures::testnet::VALID_KEY_DEC;

        #[test_log::test(tokio::test)]
        async fn invalid_contract_address() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key={}&blockNumber=latest",
                    INVALID_CONTRACT_ADDR.get().to_hex_str(),
                    VALID_KEY_DEC
                ),
                (r#""0x0""#, 200),
            )]);
            let result = client
                .storage(
                    INVALID_CONTRACT_ADDR,
                    VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
            assert_eq!(result, StorageValue(Felt::ZERO));
        }

        #[tokio::test]
        async fn invalid_key() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key=0&blockNumber=latest",
                    VALID_CONTRACT_ADDR.get().to_hex_str()
                ),
                (r#""0x0""#, 200),
            )]);
            let result = client
                .storage(
                    VALID_CONTRACT_ADDR,
                    StorageAddress::new_or_panic(Felt::ZERO),
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
            assert_eq!(result, StorageValue(Felt::ZERO));
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key={}&blockHash={}",
                    VALID_CONTRACT_ADDR.get().to_hex_str(),
                    VALID_KEY_DEC,
                    INVALID_BLOCK_HASH
                ),
                response_from(StarknetErrorCode::BlockNotFound),
            )]);
            let error = client
                .storage(VALID_CONTRACT_ADDR, VALID_KEY, INVALID_BLOCK_HASH)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn latest_invoke_block() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key={}&blockHash={}",
                    VALID_CONTRACT_ADDR.get().to_hex_str(),
                    VALID_KEY_DEC,
                    INVOKE_CONTRACT_BLOCK_HASH
                ),
                (r#""0x1e240""#, 200),
            )]);
            let result = client
                .storage(VALID_CONTRACT_ADDR, VALID_KEY, INVOKE_CONTRACT_BLOCK_HASH)
                .await
                .unwrap();
            assert_eq!(result, StorageValue(felt!("0x1e240")));
        }

        #[tokio::test]
        async fn latest_block() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key={}&blockNumber=latest",
                    VALID_CONTRACT_ADDR.get().to_hex_str(),
                    VALID_KEY_DEC,
                ),
                (r#""0x1e240""#, 200),
            )]);
            let result = client
                .storage(
                    VALID_CONTRACT_ADDR,
                    VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
            assert_eq!(result, StorageValue(felt!("0x1e240")));
        }

        #[tokio::test]
        async fn pending_block() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key={}&blockNumber=pending",
                    VALID_CONTRACT_ADDR.get().to_hex_str(),
                    VALID_KEY_DEC
                ),
                (r#""0x1e240""#, 200),
            )]);
            let result = client
                .storage(
                    VALID_CONTRACT_ADDR,
                    VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Pending),
                )
                .await
                .unwrap();
            assert_eq!(result, StorageValue(felt!("0x1e240")));
        }
    }

    mod transaction {
        use super::{reply::Status, *};
        use pathfinder_common::felt;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn declare() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_transaction?transactionHash=0x587d93f2339b7f2beda040187dbfcb9e076ce4a21eb8d15ae64819718817fbe",
                (v0_9_0::transaction::INVOKE, 200)
            )]);
            assert_eq!(
                client
                    .transaction(StarknetTransactionHash(felt!(
                        "0587d93f2339b7f2beda040187dbfcb9e076ce4a21eb8d15ae64819718817fbe"
                    )))
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
                    .transaction(StarknetTransactionHash(felt!(
                        "03d7623443283d9a0cec946492db78b06d57642a551745ddfac8d3f1f4fcc2a8"
                    )))
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
                    .transaction(StarknetTransactionHash(felt!(
                        "0587d93f2339b7f2beda040187dbfcb9e076ce4a21eb8d15ae64819718817fbe"
                    )))
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
        use super::{
            reply::state_update::{DeployedContract, StorageDiff},
            *,
        };
        use pathfinder_common::{
            felt, test_utils::metrics::RecorderGuard, ContractAddress, StateCommitment,
        };
        use pretty_assertions::assert_eq;
        use starknet_gateway_types::reply::MaybePendingStateUpdate;
        use std::collections::{BTreeSet, HashMap};

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct OrderedStateDiff {
            pub storage_diffs: HashMap<ContractAddress, BTreeSet<StorageDiff>>,
            pub deployed_contracts: BTreeSet<DeployedContract>,
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct OrderedStateUpdate {
            pub block_hash: StarknetBlockHash,
            pub new_root: StateCommitment,
            pub old_root: StateCommitment,
            pub state_diff: OrderedStateDiff,
        }

        impl From<MaybePendingStateUpdate> for OrderedStateUpdate {
            fn from(s: MaybePendingStateUpdate) -> Self {
                match s {
                    MaybePendingStateUpdate::StateUpdate(s) => Self {
                        block_hash: s.block_hash,
                        new_root: s.new_root,
                        old_root: s.old_root,
                        state_diff: OrderedStateDiff {
                            storage_diffs: s
                                .state_diff
                                .storage_diffs
                                .into_iter()
                                .map(|(addr, diffs)| (addr, diffs.into_iter().collect()))
                                .collect(),
                            deployed_contracts: s
                                .state_diff
                                .deployed_contracts
                                .into_iter()
                                .collect(),
                        },
                    },
                    MaybePendingStateUpdate::Pending(_) => unreachable!(),
                }
            }
        }

        #[tokio::test]
        async fn genesis() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([
                (
                    "/feeder_gateway/get_state_update?blockNumber=0".to_string(),
                    (v0_9_1::state_update::GENESIS, 200),
                ),
                (
                    format!("/feeder_gateway/get_state_update?blockHash={GENESIS_BLOCK_HASH}"),
                    (v0_9_1::state_update::GENESIS, 200),
                ),
            ]);
            let by_number: OrderedStateUpdate = client
                .state_update(BlockId::from(GENESIS_BLOCK_NUMBER))
                .await
                .unwrap()
                .into();
            let by_hash: OrderedStateUpdate = client
                .state_update(BlockId::from(GENESIS_BLOCK_HASH))
                .await
                .unwrap()
                .into();

            assert_eq!(by_number, by_hash);
        }

        #[tokio::test]
        async fn specific_block() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([
                (
                    "/feeder_gateway/get_state_update?blockNumber=315700",
                    (v0_9_1::state_update::NUMBER_315700, 200)
                ),
                (
                    "/feeder_gateway/get_state_update?blockHash=0x17e4297ba605d22babb8c4e59a965b00e0487cd1e3ff63f99dbc7fe33e4fd03",
                    (v0_9_1::state_update::NUMBER_315700, 200)
                ),
            ]);
            let by_number: OrderedStateUpdate = client
                .state_update(StarknetBlockNumber::new_or_panic(315700).into())
                .await
                .unwrap()
                .into();
            let by_hash: OrderedStateUpdate = client
                .state_update(
                    StarknetBlockHash(felt!(
                        "017e4297ba605d22babb8c4e59a965b00e0487cd1e3ff63f99dbc7fe33e4fd03"
                    ))
                    .into(),
                )
                .await
                .unwrap()
                .into();

            assert_eq!(by_number, by_hash);
        }
    }

    mod state_update {
        use super::*;
        use pathfinder_common::test_utils::metrics::RecorderGuard;

        #[test_log::test(tokio::test)]
        async fn invalid_number() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([(
                format!("/feeder_gateway/get_state_update?blockNumber={INVALID_BLOCK_NUMBER}"),
                response_from(StarknetErrorCode::BlockNotFound),
            )]);
            let error = client
                .state_update(BlockId::from(INVALID_BLOCK_NUMBER))
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([(
                format!("/feeder_gateway/get_state_update?blockHash={INVALID_BLOCK_HASH}"),
                response_from(StarknetErrorCode::BlockNotFound),
            )]);
            let error = client
                .state_update(BlockId::from(INVALID_BLOCK_HASH))
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn latest() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([(
                "/feeder_gateway/get_state_update?blockNumber=latest",
                (v0_9_1::state_update::NUMBER_315700, 200),
            )]);
            client.state_update(BlockId::Latest).await.unwrap();
        }

        #[tokio::test]
        async fn pending() {
            let _guard = RecorderGuard::lock_as_noop();
            let (_jh, client) = setup([(
                "/feeder_gateway/get_state_update?blockNumber=pending",
                (v0_9_1::state_update::PENDING, 200),
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
        use pathfinder_common::{felt, ByteCodeOffset, ContractAddress};
        use starknet_gateway_types::request::{
            add_transaction::CairoContractDefinition,
            contract::{EntryPointType, SelectorAndOffset},
        };
        use std::collections::HashMap;

        #[tokio::test]
        async fn invalid_entry_point_selector() {
            // test with values dumped from `starknet invoke` for a test contract,
            // except for an invalid entry point value
            let (_jh, client) = setup([(
                "/gateway/add_transaction",
                response_from(StarknetErrorCode::UnsupportedSelectorForFee),
            )]);
            let error = client
                .add_invoke_transaction(
                    TransactionVersion::ZERO,
                    Fee(5444010076217u128.to_be_bytes().into()),
                    vec![
                        TransactionSignatureElem(felt!(
                            "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                        )),
                        TransactionSignatureElem(felt!(
                            "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                        )),
                    ],
                    None,
                    ContractAddress::new_or_panic(felt!(
                        "023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd"
                    )),
                    Some(EntryPoint(Felt::ZERO)),
                    vec![
                        CallParam(felt!("0x1")),
                        CallParam(felt!(
                            "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
                        )),
                        CallParam(felt!(
                            "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                        )),
                        CallParam(Felt::ZERO),
                        CallParam(felt!("0x1")),
                        CallParam(felt!("0x1")),
                        CallParam(felt!("0x2b")),
                        CallParam(Felt::ZERO),
                    ],
                )
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::UnsupportedSelectorForFee)
            );
        }

        #[tokio::test]
        async fn invoke_function() {
            let (_jh, client) = setup([(
                "/gateway/add_transaction",
                (
                    r#"{"code":"TRANSACTION_RECEIVED","transaction_hash":"0x0389DD0629F42176CC8B6C43ACEFC0713D0064ECDFC0470E0FC179F53421A38B"}"#,
                    200,
                ),
            )]);
            // test with values dumped from `starknet invoke` for a test contract
            client
                .add_invoke_transaction(
                    TransactionVersion::ZERO,
                    Fee(5444010076217u128.to_be_bytes().into()),
                    vec![
                        TransactionSignatureElem(felt!(
                            "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                        )),
                        TransactionSignatureElem(felt!(
                            "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                        )),
                    ],
                    None,
                    ContractAddress::new_or_panic(felt!(
                        "023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd"
                    )),
                    Some(EntryPoint(felt!(
                        "015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
                    ))),
                    vec![
                        CallParam(felt!("0x1")),
                        CallParam(felt!(
                            "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
                        )),
                        CallParam(felt!(
                            "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                        )),
                        CallParam(Felt::ZERO),
                        CallParam(felt!("0x1")),
                        CallParam(felt!("0x1")),
                        CallParam(felt!("0x2b")),
                        CallParam(Felt::ZERO),
                    ],
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn declare_class() {
            let contract_class = get_contract_class_from_fixture();

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
                    TransactionVersion::ZERO,
                    Fee(0u128.to_be_bytes().into()),
                    vec![],
                    TransactionNonce(Felt::ZERO),
                    ContractDefinition::Cairo(contract_class),
                    // actual address dumped from a `starknet declare` call
                    ContractAddress::new_or_panic(felt!("0x1")),
                    None,
                    None,
                )
                .await
                .unwrap();
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
                transaction_hash: StarknetTransactionHash(pathfinder_common::felt!(
                    "06dac1655b34e52a449cfe961188f7cc2b1496bcd36706cedf4935567be29d5b"
                )),
                address: ContractAddress::new_or_panic(pathfinder_common::felt!(
                    "04e574ea2abd76d3105b3d29de28af0c5a28b889aa465903080167f6b48b1acc"
                )),
            };

            assert_eq!(res, expected);
        }

        /// Return a contract definition that was dumped from a `starknet deploy`.
        fn get_contract_class_from_fixture() -> CairoContractDefinition {
            let json = zstd::decode_all(
                starknet_gateway_test_fixtures::zstd_compressed_contracts::CONTRACT_DEFINITION,
            )
            .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
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
                                offset: ByteCodeOffset(felt!("0x3a")),
                                selector: EntryPoint(felt!(
                                                "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320")
                                ),
                            },
                            SelectorAndOffset {
                                offset: ByteCodeOffset(felt!("0x5b")),
                                selector: EntryPoint(felt!(
                                                "039e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695"
                                        )),
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
                        Fee(0u128.to_be_bytes().into()),
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
                        Fee(0u128.to_be_bytes().into()),
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
                        assert_eq!(se.code, StarknetErrorCode::NotPermittedContract);
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
                    TargetChain::Mainnet => (None, Client::new(Chain::Mainnet).unwrap()),
                    TargetChain::Testnet => (None, Client::new(Chain::Testnet).unwrap()),
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
                        .unwrap();

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

    mod metrics {
        use super::*;
        use futures::stream::StreamExt;
        use pathfinder_common::BlockId;
        use pretty_assertions::assert_eq;
        use std::future::Future;

        #[tokio::test]
        async fn all_counter_types_including_tags() {
            use super::ClientApi;

            with_method(
                "get_block",
                |client, x| async move {
                    let _ = client.block(x).await;
                },
                (v0_9_0::block::GENESIS.to_owned(), 200),
            )
            .await;
            with_method(
                "get_state_update",
                |client, x| async move {
                    let _ = client.state_update(x).await;
                },
                (v0_9_1::state_update::GENESIS.to_owned(), 200),
            )
            .await;
        }

        async fn with_method<F, Fut, T>(method_name: &'static str, f: F, response: (String, u16))
        where
            F: Fn(Client, BlockId) -> Fut,
            Fut: Future<Output = T>,
        {
            use pathfinder_common::test_utils::metrics::{FakeRecorder, RecorderGuard};

            let recorder = FakeRecorder::new(&["get_block", "get_state_update"]);
            let handle = recorder.handle();
            let _guard = RecorderGuard::lock(recorder);

            let responses = [
                // Any valid fixture
                response,
                // 1 StarkNet error
                response_from(StarknetErrorCode::BlockNotFound),
                // 2 decode errors
                (r#"{"not":"valid"}"#.to_owned(), 200),
                (r#"{"not":"valid, again"}"#.to_owned(), 200),
                // 3 of rate limiting
                ("you're being rate limited".to_owned(), 429),
                ("".to_owned(), 429),
                ("".to_owned(), 429),
            ];

            let (_jh, client) = setup_with_varied_responses([
                (
                    format!("/feeder_gateway/{method_name}?blockNumber=123"),
                    responses.clone(),
                ),
                (
                    format!("/feeder_gateway/{method_name}?blockNumber=latest"),
                    responses.clone(),
                ),
                (
                    format!("/feeder_gateway/{method_name}?blockNumber=pending"),
                    responses,
                ),
            ]);
            [BlockId::Number(StarknetBlockNumber::new_or_panic(123)); 7]
                .into_iter()
                .chain([BlockId::Latest; 7].into_iter())
                .chain([BlockId::Pending; 7].into_iter())
                .map(|x| f(client.clone(), x))
                .collect::<futures::stream::FuturesUnordered<_>>()
                .collect::<Vec<_>>()
                .await;

            // IMPORTANT
            //
            // We're not using any crate::sequencer::metrics consts here, because this is public API
            // and we'd like to catch if/when it changed (apparently due to a bug)
            [
                ("gateway_requests_total", None, None, 21),
                ("gateway_requests_total", Some("latest"), None, 7),
                ("gateway_requests_total", Some("pending"), None, 7),
                ("gateway_requests_failed_total", None, None, 18),
                ("gateway_requests_failed_total", Some("latest"), None, 6),
                ("gateway_requests_failed_total", Some("pending"), None, 6),
                ("gateway_requests_failed_total", None, Some("starknet"), 3),
                (
                    "gateway_requests_failed_total",
                    Some("latest"),
                    Some("starknet"),
                    1,
                ),
                (
                    "gateway_requests_failed_total",
                    Some("pending"),
                    Some("starknet"),
                    1,
                ),
                ("gateway_requests_failed_total", None, Some("decode"), 6),
                (
                    "gateway_requests_failed_total",
                    Some("latest"),
                    Some("decode"),
                    2,
                ),
                (
                    "gateway_requests_failed_total",
                    Some("pending"),
                    Some("decode"),
                    2,
                ),
                (
                    "gateway_requests_failed_total",
                    None,
                    Some("rate_limiting"),
                    9,
                ),
                (
                    "gateway_requests_failed_total",
                    Some("latest"),
                    Some("rate_limiting"),
                    3,
                ),
                (
                    "gateway_requests_failed_total",
                    Some("pending"),
                    Some("rate_limiting"),
                    3,
                ),
            ]
            .into_iter()
            .for_each(|(counter_name, tag, failure_reason, expected_count)| {
                match (tag, failure_reason) {
                    (None, None) => assert_eq!(
                        handle.get_counter_value(counter_name, method_name),
                        expected_count,
                        "counter: {counter_name}, method: {method_name}"
                    ),
                    (None, Some(reason)) => assert_eq!(
                        handle.get_counter_value_by_label(
                            counter_name,
                            [("method", method_name), ("reason", reason)]
                        ),
                        expected_count,
                        "counter: {counter_name}, method: {method_name}, reason: {reason}"
                    ),
                    (Some(tag), None) => assert_eq!(
                        handle.get_counter_value_by_label(
                            counter_name,
                            [("method", method_name), ("tag", tag)]
                        ),
                        expected_count,
                        "counter: {counter_name}, method: {method_name}, tag: {tag}"
                    ),
                    (Some(tag), Some(reason)) => assert_eq!(
                        handle.get_counter_value_by_label(
                            counter_name,
                            [("method", method_name), ("tag", tag), ("reason", reason)]
                        ),
                        expected_count,
                        "counter: {counter_name}, method: {method_name}, tag: {tag}, reason: {reason}"
                    ),
                }
            });
        }
    }

    mod version_check {
        // Ensures the versions in the pathfinder_common::version_check! macro are kept in sync with reality.
        //
        // The tests are kept here to prevent crate dependency cycles while keeping the macro widely available.
        use pathfinder_common::version_check;

        use crate::{Client, ClientApi};
        use anyhow::Context;
        use pathfinder_common::BlockId;

        async fn get_latest_version(client: &Client) -> anyhow::Result<(u64, u64, u64)> {
            let version = client
                .block(BlockId::Latest)
                .await?
                .as_block()
                .context("Latest gateway block was of type pending")?
                .starknet_version
                .context("Latest gateway block has no version")?;

            let mut split = version.split('.');
            let major = split
                .next()
                .context("Version string is empty")?
                .parse::<u64>()
                .context("Parsing major component")?;
            let minor = split
                .next()
                .context("Version string is missing minor component")?
                .parse::<u64>()
                .context("Parsing minor component")?;
            let patch = split
                .next()
                .context("Version string is missing patch component")?
                .parse::<u64>()
                .context("Parsing patch component")?;

            Ok((major, minor, patch))
        }

        #[tokio::test]
        async fn integration() {
            let actual = get_latest_version(&Client::integration()).await.unwrap();
            assert_eq!(
                actual,
                (0, 11, 0),
                "Integration gateway version has changed, update version_check"
            );
        }

        #[tokio::test]
        async fn mainnet() {
            version_check!(Mainnet == 0 - 10 - 3);
            let actual = get_latest_version(&Client::mainnet()).await.unwrap();
            assert_eq!(
                actual,
                (0, 10, 3),
                "Mainnet gateway version has changed, update version_check"
            );
        }

        #[tokio::test]
        async fn testnet() {
            version_check!(Testnet == 0 - 10 - 3);
            let actual = get_latest_version(&Client::testnet()).await.unwrap();
            assert_eq!(
                actual,
                (0, 10, 3),
                "Testnet gateway version has changed, update version_check"
            );
        }

        #[tokio::test]
        async fn testnet2() {
            version_check!(Testnet2 == 0 - 10 - 3);
            let actual = get_latest_version(&Client::testnet2()).await.unwrap();
            assert_eq!(
                actual,
                (0, 10, 3),
                "Testnet gateway version has changed, update version_check"
            );
        }
    }
}
