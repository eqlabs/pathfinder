//! StarkNet L2 sequencer client.
pub mod error;
pub mod reply;
pub mod request;

use self::{
    error::StarknetError,
    request::{add_transaction::ContractDefinition, Call},
};
use crate::{
    core::{
        CallSignatureElem, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt, Fee,
        StarknetTransactionHash, StorageAddress, StorageValue, TransactionNonce,
        TransactionVersion,
    },
    ethereum::Chain,
    rpc::types::{BlockHashOrTag, BlockNumberOrTag, Tag},
    sequencer::error::SequencerError,
};
use reqwest::Url;
use std::{borrow::Cow, fmt::Debug, future::Future, result::Result, time::Duration};

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait ClientApi {
    async fn block_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<reply::Block, SequencerError>;

    async fn block_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Block, SequencerError>;

    async fn call(
        &self,
        payload: request::Call,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Call, SequencerError>;

    async fn full_contract(
        &self,
        contract_addr: ContractAddress,
    ) -> Result<bytes::Bytes, SequencerError>;

    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError>;

    async fn class_hash(
        &self,
        contract_address: ContractAddress,
    ) -> Result<ClassHash, SequencerError>;

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

    async fn transaction_status(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> Result<reply::TransactionStatus, SequencerError>;

    async fn state_update_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::StateUpdate, SequencerError>;

    async fn state_update_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<reply::StateUpdate, SequencerError>;

    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError>;

    async fn add_invoke_transaction(
        &self,
        function_invocation: Call,
        max_fee: Fee,
        version: TransactionVersion,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError>;

    #[allow(clippy::too_many_arguments)]
    async fn add_declare_transaction(
        &self,
        contract_definition: ContractDefinition,
        sender_address: ContractAddress,
        max_fee: Fee,
        signature: Vec<CallSignatureElem>,
        nonce: TransactionNonce,
        version: TransactionVersion,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeclareResponse, SequencerError>;

    async fn add_deploy_transaction(
        &self,
        contract_address_salt: ContractAddressSalt,
        constructor_calldata: Vec<ConstructorParam>,
        contract_definition: ContractDefinition,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeployResponse, SequencerError>;
}

/// StarkNet sequencer client using REST API.
///
/// Retry is performed on __all__ types of errors __except for__
/// [StarkNet specific errors](crate::sequencer::error::StarknetError).
///
/// Initial backoff time is 30 seconds and saturates at 1 hour:
///
/// `backoff [secs] = min((2 ^ N) * 15, 3600) [secs]`
///
/// where `N` is the consecutive retry iteration number `{1, 2, ...}`.
#[derive(Debug, Clone)]
pub struct Client {
    /// This client is internally refcounted
    inner: reqwest::Client,
    /// StarkNet sequencer URL.
    sequencer_url: Url,
}

/// Helper function which simplifies the handling of optional block hashes in queries.
fn block_hash_str(hash: BlockHashOrTag) -> (&'static str, Cow<'static, str>) {
    match hash {
        BlockHashOrTag::Hash(h) => ("blockHash", h.0.to_hex_str()),
        BlockHashOrTag::Tag(Tag::Latest) => ("blockNumber", Cow::from("latest")),
        BlockHashOrTag::Tag(Tag::Pending) => ("blockNumber", Cow::from("pending")),
    }
}

/// Helper function which simplifies the handling of optional block numbers in queries.
fn block_number_str(number: BlockNumberOrTag) -> Cow<'static, str> {
    match number {
        BlockNumberOrTag::Number(n) => Cow::from(n.0.to_string()),
        BlockNumberOrTag::Tag(Tag::Latest) => Cow::from("latest"),
        BlockNumberOrTag::Tag(Tag::Pending) => Cow::from("pending"),
    }
}

/// __Mandatory__ function to parse every sequencer query response and deserialize
/// to expected output type.
async fn parse<T>(resp: reqwest::Response) -> Result<T, SequencerError>
where
    T: ::serde::de::DeserializeOwned,
{
    let resp = parse_raw(resp).await?;
    // Attempt to deserialize the actual data we are looking for
    let resp = resp.json::<T>().await?;
    Ok(resp)
}

/// Helper function which allows skipping deserialization when required.
async fn parse_raw(resp: reqwest::Response) -> Result<reqwest::Response, SequencerError> {
    // Starknet specific errors end with a 500 status code
    // but the body contains a JSON object with the error description
    if resp.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        let starknet_error = resp.json::<StarknetError>().await?;
        return Err(SequencerError::StarknetError(starknet_error));
    }
    // Status codes <400;499> and <501;599> are mapped to SequencerError::TransportError
    resp.error_for_status_ref().map(|_| ())?;
    Ok(resp)
}

/// Wrapper function to allow retrying sequencer queries in an exponential manner.
///
/// Does not retry in tests.
async fn retry<T, Fut, FutureFactory>(future_factory: FutureFactory) -> Result<T, SequencerError>
where
    Fut: Future<Output = Result<T, SequencerError>>,
    FutureFactory: FnMut() -> Fut,
{
    if cfg!(test) {
        retry0(future_factory, |_| false).await
    } else {
        retry0(future_factory, retry_condition).await
    }
}

/// Wrapper function to allow retrying sequencer queries in an exponential manner.
async fn retry0<T, Fut, FutureFactory, Ret>(
    future_factory: FutureFactory,
    retry_condition: Ret,
) -> Result<T, SequencerError>
where
    Fut: Future<Output = Result<T, SequencerError>>,
    FutureFactory: FnMut() -> Fut,
    Ret: FnMut(&SequencerError) -> bool,
{
    use crate::retry::Retry;
    use std::num::NonZeroU64;

    Retry::exponential(future_factory, NonZeroU64::new(2).unwrap())
        .factor(NonZeroU64::new(15).unwrap())
        .max_delay(Duration::from_secs(60 * 60))
        .when(retry_condition)
        .await
}

/// Determines if an error is retryable or not.
fn retry_condition(e: &SequencerError) -> bool {
    use reqwest::StatusCode;
    use tracing::{debug, error, info, warn};

    match e {
        SequencerError::ReqwestError(e) => {
            if e.is_body() || e.is_connect() || e.is_timeout() {
                info!(reason=%e, "Request failed, retrying");
            } else if e.is_status() {
                match e.status() {
                    Some(
                        StatusCode::NOT_FOUND
                        | StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT,
                    ) => {
                        debug!(reason=%e, "Request failed, retrying");
                    }
                    Some(StatusCode::INTERNAL_SERVER_ERROR) => {
                        error!(reason=%e, "Request failed, retrying");
                    }
                    Some(_) => warn!(reason=%e, "Request failed, retrying"),
                    None => unreachable!(),
                }
            } else if e.is_decode() {
                error!(reason=%e, "Request failed, retrying");
            } else {
                warn!(reason=%e, "Request failed, retrying");
            }

            true
        }
        SequencerError::StarknetError(_) => false,
    }
}

impl Client {
    /// Creates a new Sequencer client for the given chain.
    pub fn new(chain: Chain) -> reqwest::Result<Self> {
        let url = match chain {
            Chain::Mainnet => Url::parse("https://alpha-mainnet.starknet.io/").unwrap(),
            Chain::Goerli => Url::parse("https://alpha4.starknet.io/").unwrap(),
        };

        Self::with_url(url)
    }

    #[cfg(test)]
    pub(crate) fn integration() -> reqwest::Result<Self> {
        let integration_url = Url::parse("https://external.integration.starknet.io").unwrap();

        Self::with_url(integration_url)
    }

    /// Create a Sequencer client for the given [Url].
    fn with_url(url: Url) -> reqwest::Result<Self> {
        Ok(Self {
            inner: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .user_agent(crate::consts::USER_AGENT)
                .build()?,
            sequencer_url: url,
        })
    }

    /// Helper function that constructs a URL for particular query.
    fn build_query(&self, path_segments: &[&str], params: &[(&str, &str)]) -> Url {
        let mut query_url = self.sequencer_url.clone();
        query_url
            .path_segments_mut()
            .expect("Base URL is valid")
            .extend(path_segments);
        query_url.query_pairs_mut().extend_pairs(params);
        tracing::trace!(%query_url);
        query_url
    }
}

#[async_trait::async_trait]
impl ClientApi for Client {
    /// Gets block by number.
    #[tracing::instrument(skip(self))]
    async fn block_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<reply::Block, SequencerError> {
        let number = block_number_str(block_number);
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(
                    &["feeder_gateway", "get_block"],
                    &[("blockNumber", &number)],
                ))
                .send()
                .await?;
            parse::<reply::Block>(resp).await
        })
        .await
    }

    /// Get block by hash.
    #[tracing::instrument(skip(self))]
    async fn block_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Block, SequencerError> {
        let (tag, hash) = block_hash_str(block_hash);
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(&["feeder_gateway", "get_block"], &[(tag, &hash)]))
                .send()
                .await?;
            parse::<reply::Block>(resp).await
        })
        .await
    }

    /// Performs a `call` on contract's function. Call result is not stored in L2, as opposed to `invoke`.
    #[tracing::instrument(skip(self))]
    async fn call(
        &self,
        payload: request::Call,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Call, SequencerError> {
        let (tag, hash) = block_hash_str(block_hash);
        retry(|| async {
            let resp = self
                .inner
                .post(self.build_query(&["feeder_gateway", "call_contract"], &[(tag, &hash)]))
                .json(&payload)
                .send()
                .await?;
            parse(resp).await
        })
        .await
    }

    /// Gets full contract definition.
    #[tracing::instrument(skip(self))]
    async fn full_contract(
        &self,
        contract_addr: ContractAddress,
    ) -> Result<bytes::Bytes, SequencerError> {
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(
                    &["feeder_gateway", "get_full_contract"],
                    &[("contractAddress", &contract_addr.0.to_hex_str())],
                ))
                .send()
                .await?;
            let resp = parse_raw(resp).await?;
            let resp = resp.bytes().await?;
            Ok(resp)
        })
        .await
    }

    /// Gets class for a particular class hash.
    #[tracing::instrument(skip(self))]
    async fn class_by_hash(&self, class_hash: ClassHash) -> Result<bytes::Bytes, SequencerError> {
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(
                    &["feeder_gateway", "get_class_by_hash"],
                    &[("classHash", &class_hash.0.to_hex_str())],
                ))
                .send()
                .await?;
            let resp = parse_raw(resp).await?;
            let resp = resp.bytes().await?;
            Ok(resp)
        })
        .await
    }

    /// Gets class hash for a particular contract address.
    #[tracing::instrument(skip(self))]
    async fn class_hash(
        &self,
        contract_address: ContractAddress,
    ) -> Result<ClassHash, SequencerError> {
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(
                    &["feeder_gateway", "get_class_hash_at"],
                    &[("contractAddress", &contract_address.0.to_hex_str())],
                ))
                .send()
                .await?;
            parse(resp).await
        })
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
        use crate::rpc::serde::starkhash_to_dec_str;

        let (tag, hash) = block_hash_str(block_hash);
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(
                    &["feeder_gateway", "get_storage_at"],
                    &[
                        ("contractAddress", &contract_addr.0.to_hex_str()),
                        ("key", &starkhash_to_dec_str(&key.0)),
                        (tag, &hash),
                    ],
                ))
                .send()
                .await?;
            parse::<StorageValue>(resp).await
        })
        .await
    }

    /// Gets transaction by hash.
    #[tracing::instrument(skip(self))]
    async fn transaction(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> Result<reply::Transaction, SequencerError> {
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(
                    &["feeder_gateway", "get_transaction"],
                    &[("transactionHash", &transaction_hash.0.to_hex_str())],
                ))
                .send()
                .await?;
            parse(resp).await
        })
        .await
    }

    /// Gets transaction status by transaction hash.
    #[tracing::instrument(skip(self))]
    async fn transaction_status(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> Result<reply::TransactionStatus, SequencerError> {
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(
                    &["feeder_gateway", "get_transaction_status"],
                    &[("transactionHash", &transaction_hash.0.to_hex_str())],
                ))
                .send()
                .await?;
            parse(resp).await
        })
        .await
    }

    /// Gets state update for a particular block hash.
    #[tracing::instrument(skip(self))]
    async fn state_update_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::StateUpdate, SequencerError> {
        let (tag, hash) = block_hash_str(block_hash);
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(&["feeder_gateway", "get_state_update"], &[(tag, &hash)]))
                .send()
                .await?;
            parse(resp).await
        })
        .await
    }

    /// Gets state update for a particular block number.
    #[tracing::instrument(skip(self))]
    async fn state_update_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<reply::StateUpdate, SequencerError> {
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(
                    &["feeder_gateway", "get_state_update"],
                    &[("blockNumber", &block_number_str(block_number))],
                ))
                .send()
                .await?;
            parse(resp).await
        })
        .await
    }

    /// Gets addresses of the Ethereum contracts crucial to Starknet operation.
    #[tracing::instrument(skip(self))]
    async fn eth_contract_addresses(&self) -> Result<reply::EthContractAddresses, SequencerError> {
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(&["feeder_gateway", "get_contract_addresses"], &[]))
                .send()
                .await?;
            parse(resp).await
        })
        .await
    }

    /// Adds a transaction invoking a contract.
    #[tracing::instrument(skip(self))]
    async fn add_invoke_transaction(
        &self,
        call: Call,
        max_fee: Fee,
        version: TransactionVersion,
    ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
        let req = request::add_transaction::AddTransaction::Invoke(
            request::add_transaction::InvokeFunction {
                contract_address: call.contract_address,
                entry_point_selector: call.entry_point_selector,
                calldata: call.calldata,
                max_fee,
                version,
                signature: call.signature,
            },
        );

        // Note that we don't do retries here.
        // This method is used to proxy an add transaction operation from the JSON-RPC
        // API to the sequencer. Retries should be implemented in the JSON-RPC
        // client instead.
        let resp = self
            .inner
            .post(self.build_query(&["gateway", "add_transaction"], &[]))
            .json(&req)
            .send()
            .await?;
        parse(resp).await
    }

    /// Adds a transaction declaring a class.
    #[tracing::instrument(skip(self))]
    async fn add_declare_transaction(
        &self,
        contract_definition: ContractDefinition,
        sender_address: ContractAddress,
        max_fee: Fee,
        signature: Vec<CallSignatureElem>,
        nonce: TransactionNonce,
        version: TransactionVersion,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeclareResponse, SequencerError> {
        let req =
            request::add_transaction::AddTransaction::Declare(request::add_transaction::Declare {
                contract_class: contract_definition,
                sender_address,
                max_fee,
                signature,
                nonce,
                version,
            });
        let mut url = self.build_query(&["gateway", "add_transaction"], &[]);
        // this is an optional token currently required on mainnet
        if let Some(token) = token {
            url.query_pairs_mut().append_pair("token", &token);
        }
        // Note that we don't do retries here.
        // This method is used to proxy an add transaction operation from the JSON-RPC
        // API to the sequencer. Retries should be implemented in the JSON-RPC
        // client instead.
        let resp = self.inner.post(url).json(&req).send().await?;
        parse(resp).await
    }

    /// Deploys a contract.
    #[tracing::instrument(skip(self, contract_definition))]
    async fn add_deploy_transaction(
        &self,
        contract_address_salt: ContractAddressSalt,
        constructor_calldata: Vec<ConstructorParam>,
        contract_definition: ContractDefinition,
        token: Option<String>,
    ) -> Result<reply::add_transaction::DeployResponse, SequencerError> {
        let req =
            request::add_transaction::AddTransaction::Deploy(request::add_transaction::Deploy {
                contract_address_salt,
                contract_definition,
                constructor_calldata,
            });
        let mut url = self.build_query(&["gateway", "add_transaction"], &[]);
        // this is an optional token currently required on mainnet
        if let Some(token) = token {
            url.query_pairs_mut().append_pair("token", &token);
        }
        // Note that we don't do retries here.
        // This method is used to proxy an add transaction operation from the JSON-RPC
        // API to the sequencer. Retries should be implemented in the JSON-RPC
        // client instead.
        let resp = self.inner.post(url).json(&req).send().await?;
        parse(resp).await
    }
}

#[cfg(test)]
pub mod test_utils {
    use crate::{
        core::{
            CallParam, ContractAddress, EntryPoint, StarknetBlockHash, StarknetBlockNumber,
            StarknetTransactionHash, StarknetTransactionIndex, StorageAddress, StorageValue,
        },
        rpc::types::{BlockHashOrTag, BlockNumberOrTag},
    };
    use stark_hash::{HexParseError, StarkHash};

    macro_rules! impl_from_hex_str {
        ($type:ty) => {
            impl $type {
                pub fn from_hex_str(s: &str) -> std::result::Result<Self, HexParseError> {
                    Ok(Self(StarkHash::from_hex_str(s)?))
                }
            }
        };
    }

    impl_from_hex_str!(CallParam);
    impl_from_hex_str!(ContractAddress);
    impl_from_hex_str!(EntryPoint);
    impl_from_hex_str!(StarknetBlockHash);
    impl_from_hex_str!(StarknetTransactionHash);
    impl_from_hex_str!(StorageAddress);
    impl_from_hex_str!(StorageValue);

    lazy_static::lazy_static! {
        pub static ref GENESIS_BLOCK_NUMBER: BlockNumberOrTag = BlockNumberOrTag::Number(StarknetBlockNumber(0u64));
        pub static ref INVALID_BLOCK_NUMBER: BlockNumberOrTag = BlockNumberOrTag::Number(StarknetBlockNumber(u64::MAX));
        pub static ref GENESIS_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash::from_hex_str("0x07d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b").unwrap());
        pub static ref INVALID_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash::from_hex_str("0x06d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b").unwrap());
        pub static ref PRE_DEPLOY_CONTRACT_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash::from_hex_str("0x05ef884a311df4339c8df791ce19bf305d7cf299416666b167bc56dd2d1f435f").unwrap());
        pub static ref INVOKE_CONTRACT_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash::from_hex_str("0x03871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27").unwrap());
        pub static ref VALID_TX_HASH: StarknetTransactionHash = StarknetTransactionHash::from_hex_str("0x0493d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24").unwrap();
        pub static ref INVALID_TX_HASH: StarknetTransactionHash = StarknetTransactionHash::from_hex_str("0x0393d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24").unwrap();
        pub static ref VALID_CONTRACT_ADDR: ContractAddress = ContractAddress::from_hex_str("0x06fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39").unwrap();
        pub static ref INVALID_CONTRACT_ADDR: ContractAddress = ContractAddress::from_hex_str("0x05fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39").unwrap();
        pub static ref VALID_ENTRY_POINT: EntryPoint = EntryPoint::from_hex_str("0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320").unwrap();
        pub static ref INVALID_ENTRY_POINT: EntryPoint = EntryPoint(StarkHash::ZERO);
        pub static ref INVALID_TX_INDEX: StarknetTransactionIndex = StarknetTransactionIndex(u64::MAX);
        pub static ref VALID_KEY: StorageAddress = StorageAddress::from_hex_str("0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091").unwrap();
        pub static ref VALID_KEY_DEC: String = crate::rpc::serde::starkhash_to_dec_str(&VALID_KEY.0);
        pub static ref VALID_CALL_DATA: Vec<CallParam> = vec![CallParam::from_hex_str("0x4d2").unwrap()];
    }
}

#[cfg(test)]
mod tests {
    use super::{error::StarknetErrorCode, test_utils::*, *};
    use crate::core::{StarknetBlockHash, StarknetBlockNumber};
    use assert_matches::assert_matches;
    use stark_hash::StarkHash;

    impl std::fmt::Display for crate::core::ContractAddress {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut buf = [0u8; 2 + 64];
            let s = self.0.as_hex_str(&mut buf);
            f.write_str(s)
        }
    }

    impl std::fmt::Display for crate::core::StarknetTransactionHash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut buf = [0u8; 2 + 64];
            let s = self.0.as_hex_str(&mut buf);
            f.write_str(s)
        }
    }

    /// Helper macro which creates a successful response tuple
    /// which can then be used by the [setup] function.
    ///
    /// The macro takes the name of the fixture file.
    /// The fixture file should be a text file containing valid UTF8 characters.
    ///
    /// The HTTP status code value of the tuple is `200` (`OK`).
    macro_rules! response {
        ($file_name:literal) => {
            (
                include_str!(concat!("../fixtures/sequencer/", $file_name)),
                200,
            )
        };
    }

    impl StarknetErrorCode {
        /// Helper funtion which allows for easy creation of a response tuple
        /// that contains a [StarknetError] for a given [StarknetErrorCode].
        ///
        /// The response tuple can then be used by the [setup] function.
        ///
        /// The `message` field is always an empty string.
        /// The HTTP status code for this response is always `500` (`Internal Server Error`).
        fn into_response(self) -> (String, u16) {
            let e = StarknetError {
                code: self,
                message: "".to_string(),
            };
            (serde_json::to_string(&e).unwrap(), 500)
        }
    }

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
            (None, Client::new(Chain::Goerli).unwrap())
        } else {
            use warp::Filter;
            let path = warp::any()
                .and(warp::path::full())
                .and(warp::query::raw())
                .map(move |full_path: warp::path::FullPath, raw_query| {
                    let actual_full_path_and_query =
                        format!("{}?{}", full_path.as_str(), raw_query);

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
                });

            let (addr, serve_fut) = warp::serve(path).bind_ephemeral(([127, 0, 0, 1], 0));
            let server_handle = tokio::spawn(serve_fut);
            let client =
                Client::with_url(reqwest::Url::parse(&format!("http://{}", addr)).unwrap())
                    .unwrap();
            (Some(server_handle), client)
        }
    }

    #[test_log::test(tokio::test)]
    async fn client_user_agent() {
        use crate::core::StarknetBlockTimestamp;
        use crate::sequencer::reply::{Block, Status};
        use std::convert::Infallible;
        use warp::Filter;

        let filter = warp::header::optional("user-agent").and_then(
            |user_agent: Option<String>| async move {
                let user_agent = user_agent.expect("user-agent set");
                let (name, version) = user_agent.split_once('/').unwrap();

                assert_eq!(name, "starknet-pathfinder");
                assert_eq!(version, env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT"));

                Ok::<_, Infallible>(warp::reply::json(&Block {
                    block_hash: None,
                    block_number: None,
                    gas_price: None,
                    parent_block_hash: StarknetBlockHash(StarkHash::ZERO),
                    sequencer_address: None,
                    state_root: None,
                    status: Status::NotReceived,
                    timestamp: StarknetBlockTimestamp(0),
                    transaction_receipts: vec![],
                    transactions: vec![],
                }))
            },
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (addr, run_srv) =
            warp::serve(filter).bind_with_graceful_shutdown(([127, 0, 0, 1], 0), async {
                shutdown_rx.await.ok();
            });
        let server_handle = tokio::spawn(run_srv);

        let url = format!("http://{}", addr);
        let url = Url::parse(&url).unwrap();
        let client = Client::with_url(url).unwrap();

        let _ = client.block_by_hash(BlockHashOrTag::Tag(Tag::Latest)).await;
        shutdown_tx.send(()).unwrap();
        server_handle.await.unwrap();
    }

    mod block_by_number_matches_by_hash_on {
        use super::*;

        #[tokio::test]
        async fn genesis() {
            let (_jh, client) = setup([
                (
                    format!(
                        "/feeder_gateway/get_block?blockHash={}",
                        *GENESIS_BLOCK_HASH
                    ),
                    response!("genesis_block.json"),
                ),
                (
                    format!(
                        "/feeder_gateway/get_block?blockNumber={}",
                        *GENESIS_BLOCK_NUMBER
                    ),
                    response!("genesis_block.json"),
                ),
            ]);
            let by_hash = client.block_by_hash(*GENESIS_BLOCK_HASH).await.unwrap();
            let by_number = client.block_by_number(*GENESIS_BLOCK_NUMBER).await.unwrap();
            assert_eq!(by_hash, by_number);
        }

        #[tokio::test]
        async fn specific_block() {
            let (_jh, client) = setup([
                (
                    "/feeder_gateway/get_block?blockHash=0x7448f26fd6604a4b93008915e26bd226c39d8b4e2a6bdd99b0c923a9d6970e0",
                    response!("block_200k.json")
                ),
                (
                    "/feeder_gateway/get_block?blockNumber=200000",
                    response!("block_200k.json")
                ),
            ]);
            let by_hash = client
                .block_by_hash(BlockHashOrTag::Hash(
                    StarknetBlockHash::from_hex_str(
                        "0x7448f26fd6604a4b93008915e26bd226c39d8b4e2a6bdd99b0c923a9d6970e0",
                    )
                    .unwrap(),
                ))
                .await
                .unwrap();
            let by_number = client
                .block_by_number(BlockNumberOrTag::Number(StarknetBlockNumber(200000)))
                .await
                .unwrap();
            assert_eq!(by_hash, by_number);
        }
    }

    mod block_by_hash {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn latest() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_block?blockNumber=latest",
                response!("block_200k.json"),
            )]);
            client
                .block_by_hash(BlockHashOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_block?blockNumber=pending",
                response!("pending_block.json"),
            )]);
            client
                .block_by_hash(BlockHashOrTag::Tag(Tag::Pending))
                .await
                .unwrap();
        }

        #[test_log::test(tokio::test)]
        async fn invalid() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_block?blockHash={}",
                    *INVALID_BLOCK_HASH
                ),
                StarknetErrorCode::BlockNotFound.into_response(),
            )]);
            let error = client.block_by_hash(*INVALID_BLOCK_HASH).await.unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }
    }

    mod block_by_number {
        use super::*;

        #[tokio::test]
        async fn latest() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_block?blockNumber=latest",
                response!("block_200k.json"),
            )]);
            client
                .block_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_block?blockNumber=pending",
                response!("pending_block.json"),
            )]);
            client
                .block_by_number(BlockNumberOrTag::Tag(Tag::Pending))
                .await
                .unwrap();
        }

        #[test_log::test(tokio::test)]
        async fn invalid() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_block?blockNumber={}",
                    *INVALID_BLOCK_NUMBER
                ),
                StarknetErrorCode::BlockNotFound.into_response(),
            )]);
            let error = client
                .block_by_number(*INVALID_BLOCK_NUMBER)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn contains_receipts_without_status_field() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_block?blockNumber=1716",
                response!("block_1716.json"),
            )]);
            client
                .block_by_number(BlockNumberOrTag::Number(StarknetBlockNumber(1716)))
                .await
                .unwrap();
        }
    }

    mod call {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn invalid_entry_point() {
            let (_jh, client) = setup([(
                "/feeder_gateway/call_contract?blockNumber=latest",
                StarknetErrorCode::EntryPointNotFound.into_response(),
            )]);
            let error = client
                .call(
                    request::Call {
                        calldata: VALID_CALL_DATA.clone(),
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *INVALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::EntryPointNotFound)
            );
        }

        #[tokio::test]
        async fn invalid_contract_address() {
            let (_jh, client) = setup([(
                "/feeder_gateway/call_contract?blockNumber=latest",
                StarknetErrorCode::UninitializedContract.into_response(),
            )]);
            let error = client
                .call(
                    request::Call {
                        calldata: VALID_CALL_DATA.clone(),
                        contract_address: *INVALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::UninitializedContract)
            );
        }

        #[tokio::test]
        async fn invalid_call_data() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/call_contract?blockHash={}",
                    *INVOKE_CONTRACT_BLOCK_HASH
                ),
                StarknetErrorCode::TransactionFailed.into_response(),
            )]);
            let error = client
                .call(
                    request::Call {
                        calldata: vec![],
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    *INVOKE_CONTRACT_BLOCK_HASH,
                )
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::TransactionFailed)
            );
        }

        #[tokio::test]
        async fn uninitialized_contract() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/call_contract?blockHash={}",
                    *GENESIS_BLOCK_HASH
                ),
                StarknetErrorCode::UninitializedContract.into_response(),
            )]);
            let error = client
                .call(
                    request::Call {
                        calldata: vec![],
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    *GENESIS_BLOCK_HASH,
                )
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::UninitializedContract)
            );
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/call_contract?blockHash={}",
                    *INVALID_BLOCK_HASH
                ),
                StarknetErrorCode::BlockNotFound.into_response(),
            )]);
            let error = client
                .call(
                    request::Call {
                        calldata: VALID_CALL_DATA.clone(),
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    *INVALID_BLOCK_HASH,
                )
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
                    "/feeder_gateway/call_contract?blockHash={}",
                    *INVOKE_CONTRACT_BLOCK_HASH
                ),
                (r#"{"result":[]}"#, 200),
            )]);
            client
                .call(
                    request::Call {
                        calldata: VALID_CALL_DATA.clone(),
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    *INVOKE_CONTRACT_BLOCK_HASH,
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn latest_block() {
            let (_jh, client) = setup([(
                "/feeder_gateway/call_contract?blockNumber=latest",
                (r#"{"result":[]}"#, 200),
            )]);
            client
                .call(
                    request::Call {
                        calldata: VALID_CALL_DATA.clone(),
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending_block() {
            let (_jh, client) = setup([(
                "/feeder_gateway/call_contract?blockNumber=pending",
                (r#"{"result":[]}"#, 200),
            )]);
            client
                .call(
                    request::Call {
                        calldata: VALID_CALL_DATA.clone(),
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Tag(Tag::Pending),
                )
                .await
                .unwrap();
        }
    }

    mod full_contract {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test_log::test(tokio::test)]
        async fn invalid_contract_address() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_full_contract?contractAddress={}",
                    *INVALID_CONTRACT_ADDR
                ),
                StarknetErrorCode::UninitializedContract.into_response(),
            )]);
            let error = client
                .full_contract(*INVALID_CONTRACT_ADDR)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::UninitializedContract)
            );
        }

        #[tokio::test]
        async fn success() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_full_contract?contractAddress={}",
                    *VALID_CONTRACT_ADDR
                ),
                (r#"{"hello":"world"}"#, 200),
            )]);
            let bytes = client.full_contract(*VALID_CONTRACT_ADDR).await.unwrap();
            serde_json::from_slice::<serde_json::value::Value>(&bytes).unwrap();
        }
    }

    mod storage {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test_log::test(tokio::test)]
        async fn invalid_contract_address() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key={}&blockNumber=latest",
                    *INVALID_CONTRACT_ADDR, *VALID_KEY_DEC
                ),
                (r#""0x0""#, 200),
            )]);
            let result = client
                .storage(
                    *INVALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
            assert_eq!(result, StorageValue(StarkHash::ZERO));
        }

        #[tokio::test]
        async fn invalid_key() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key=0&blockNumber=latest",
                    *VALID_CONTRACT_ADDR
                ),
                (r#""0x0""#, 200),
            )]);
            let result = client
                .storage(
                    *VALID_CONTRACT_ADDR,
                    StorageAddress(StarkHash::ZERO),
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
            assert_eq!(result, StorageValue(StarkHash::ZERO));
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key={}&blockHash={}",
                    *VALID_CONTRACT_ADDR, *VALID_KEY_DEC, *INVALID_BLOCK_HASH
                ),
                StarknetErrorCode::BlockNotFound.into_response(),
            )]);
            let error = client
                .storage(*VALID_CONTRACT_ADDR, *VALID_KEY, *INVALID_BLOCK_HASH)
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
                    *VALID_CONTRACT_ADDR, *VALID_KEY_DEC, *INVOKE_CONTRACT_BLOCK_HASH
                ),
                (r#""0x1e240""#, 200),
            )]);
            let result = client
                .storage(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    *INVOKE_CONTRACT_BLOCK_HASH,
                )
                .await
                .unwrap();
            assert_eq!(
                result,
                StorageValue(StarkHash::from_hex_str("0x1e240").unwrap())
            );
        }

        #[tokio::test]
        async fn latest_block() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key={}&blockNumber=latest",
                    *VALID_CONTRACT_ADDR, *VALID_KEY_DEC,
                ),
                (r#""0x1e240""#, 200),
            )]);
            let result = client
                .storage(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
            assert_eq!(
                result,
                StorageValue(StarkHash::from_hex_str("0x1e240").unwrap())
            );
        }

        #[tokio::test]
        async fn pending_block() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_storage_at?contractAddress={}&key={}&blockNumber=pending",
                    *VALID_CONTRACT_ADDR, *VALID_KEY_DEC
                ),
                (r#""0x1e240""#, 200),
            )]);
            let result = client
                .storage(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Pending),
                )
                .await
                .unwrap();
            assert_eq!(
                result,
                StorageValue(StarkHash::from_hex_str("0x1e240").unwrap())
            );
        }
    }

    mod transaction {
        use super::{reply::Status, *};
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn accepted() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_transaction?transactionHash={}",
                    *VALID_TX_HASH
                ),
                response!("valid_tx.json"),
            )]);
            assert_eq!(
                client.transaction(*VALID_TX_HASH).await.unwrap().status,
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_transaction?transactionHash={}",
                    *INVALID_TX_HASH
                ),
                (r#"{"status": "NOT_RECEIVED"}"#, 200),
            )]);
            assert_eq!(
                client.transaction(*INVALID_TX_HASH).await.unwrap().status,
                Status::NotReceived,
            );
        }
    }

    mod transaction_status {
        use super::{reply::Status, *};

        #[tokio::test]
        async fn accepted() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_transaction_status?transactionHash={}",
                    *VALID_TX_HASH
                ),
                response!("valid_tx_status.json"),
            )]);
            assert_eq!(
                client
                    .transaction_status(*VALID_TX_HASH)
                    .await
                    .unwrap()
                    .tx_status,
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_transaction_status?transactionHash={}",
                    *INVALID_TX_HASH
                ),
                (r#"{"tx_status": "NOT_RECEIVED"}"#, 200),
            )]);
            assert_eq!(
                client
                    .transaction_status(*INVALID_TX_HASH)
                    .await
                    .unwrap()
                    .tx_status,
                Status::NotReceived
            );
        }
    }

    mod state_update_by_number_matches_by_hash_on {
        use super::{
            reply::{
                state_update::{Contract, StorageDiff},
                StateUpdate,
            },
            *,
        };
        use crate::core::{ContractAddress, GlobalRoot};
        use pretty_assertions::assert_eq;
        use std::collections::{BTreeSet, HashMap};

        #[derive(Clone, Debug, PartialEq)]
        pub struct OrderedStateDiff {
            pub storage_diffs: HashMap<ContractAddress, BTreeSet<StorageDiff>>,
            pub deployed_contracts: BTreeSet<Contract>,
        }

        #[derive(Clone, Debug, PartialEq)]
        pub struct OrderedStateUpdate {
            pub new_root: GlobalRoot,
            pub old_root: GlobalRoot,
            pub state_diff: OrderedStateDiff,
        }

        impl From<StateUpdate> for OrderedStateUpdate {
            fn from(s: StateUpdate) -> Self {
                Self {
                    new_root: s.new_root,
                    old_root: s.old_root,
                    state_diff: OrderedStateDiff {
                        storage_diffs: s
                            .state_diff
                            .storage_diffs
                            .into_iter()
                            .map(|(addr, diffs)| (addr, diffs.into_iter().collect()))
                            .collect(),
                        deployed_contracts: s.state_diff.deployed_contracts.into_iter().collect(),
                    },
                }
            }
        }

        #[tokio::test]
        async fn genesis() {
            let (_jh, client) = setup([
                (
                    "/feeder_gateway/get_state_update?blockNumber=0".to_string(),
                    response!("genesis_state_update.json"),
                ),
                (
                    format!(
                        "/feeder_gateway/get_state_update?blockHash={}",
                        *GENESIS_BLOCK_HASH
                    ),
                    response!("genesis_state_update.json"),
                ),
            ]);
            let by_number: OrderedStateUpdate = client
                .state_update_by_number(*GENESIS_BLOCK_NUMBER)
                .await
                .unwrap()
                .into();
            let by_hash: OrderedStateUpdate = client
                .state_update_by_hash(*GENESIS_BLOCK_HASH)
                .await
                .unwrap()
                .into();

            assert_eq!(by_number, by_hash);
        }

        #[tokio::test]
        async fn specific_block() {
            let (_jh, client) = setup([
                (
                    "/feeder_gateway/get_state_update?blockNumber=200000",
                    response!("state_update_200k.json"),
                ),
                (
                    "/feeder_gateway/get_state_update?blockHash=0x7448f26fd6604a4b93008915e26bd226c39d8b4e2a6bdd99b0c923a9d6970e0",
                    response!("state_update_200k.json"),
                ),
            ]);
            let by_number: OrderedStateUpdate = client
                .state_update_by_number(BlockNumberOrTag::Number(StarknetBlockNumber(200000)))
                .await
                .unwrap()
                .into();
            let by_hash: OrderedStateUpdate = client
                .state_update_by_hash(BlockHashOrTag::Hash(
                    StarknetBlockHash::from_hex_str(
                        "0x7448f26fd6604a4b93008915e26bd226c39d8b4e2a6bdd99b0c923a9d6970e0",
                    )
                    .unwrap(),
                ))
                .await
                .unwrap()
                .into();

            assert_eq!(by_number, by_hash);
        }
    }

    mod state_update_by_number {
        use super::*;

        #[test_log::test(tokio::test)]
        async fn invalid_number() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_state_update?blockNumber={}",
                    *INVALID_BLOCK_NUMBER
                ),
                StarknetErrorCode::BlockNotFound.into_response(),
            )]);
            let error = client
                .state_update_by_number(*INVALID_BLOCK_NUMBER)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn latest() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_state_update?blockNumber=latest",
                response!("state_update_200k.json"),
            )]);
            client
                .state_update_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_state_update?blockNumber=pending",
                response!("pending_state_update.json"),
            )]);
            client
                .state_update_by_number(BlockNumberOrTag::Tag(Tag::Pending))
                .await
                .unwrap();
        }
    }

    mod state_update_by_hash {
        use super::*;

        #[tokio::test]
        async fn invalid_hash() {
            let (_jh, client) = setup([(
                format!(
                    "/feeder_gateway/get_state_update?blockHash={}",
                    *INVALID_BLOCK_HASH
                ),
                StarknetErrorCode::BlockNotFound.into_response(),
            )]);
            let error = client
                .state_update_by_hash(*INVALID_BLOCK_HASH)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn latest() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_state_update?blockNumber=latest",
                response!("state_update_200k.json"),
            )]);
            client
                .state_update_by_hash(BlockHashOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            let (_jh, client) = setup([(
                "/feeder_gateway/get_state_update?blockNumber=pending",
                response!("pending_state_update.json"),
            )]);
            client
                .state_update_by_hash(BlockHashOrTag::Tag(Tag::Pending))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn eth_contract_addresses() {
        let (_jh, client) = setup([(
            "/feeder_gateway/get_contract_addresses?",
            (
                r#"{"Starknet":"0xde29d060d45901fb19ed6c6e959eb22d8626708e","GpsStatementVerifier":"0xab43ba48c9edf4c2c4bb01237348d1d7b28ef168"}"#,
                200,
            ),
        )]);
        client.eth_contract_addresses().await.unwrap();
    }

    mod add_transaction {
        use std::collections::HashMap;

        use super::*;
        use crate::{
            core::{ByteCodeOffset, CallParam, CallSignatureElem, EntryPoint},
            sequencer::request::contract::{EntryPointType, SelectorAndOffset},
        };

        use web3::types::H256;

        #[tokio::test]
        async fn invalid_entry_point_selector() {
            // test with values dumped from `starknet invoke` for a test contract,
            // except for an invalid entry point value
            let (_jh, client) = setup([(
                "/gateway/add_transaction?",
                StarknetErrorCode::UnsupportedSelectorForFee.into_response(),
            )]);
            let  error = client
                .add_invoke_transaction(
                    Call {
                        contract_address: ContractAddress(
                            StarkHash::from_hex_str(
                                "0x23371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd",
                            )
                            .unwrap(),
                        ),
                        calldata: vec![
                            CallParam(StarkHash::from_hex_str("0x1").unwrap()),
                            CallParam(
                                StarkHash::from_hex_str(
                                    "0x677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1",
                                )
                                .unwrap(),
                            ),
                            CallParam(
                                StarkHash::from_hex_str(
                                    "0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
                                )
                                .unwrap(),
                            ),
                            CallParam(StarkHash::ZERO),
                            CallParam(StarkHash::from_hex_str("0x1").unwrap()),
                            CallParam(StarkHash::from_hex_str("0x1").unwrap()),
                            CallParam(StarkHash::from_hex_str("0x2b").unwrap()),
                            CallParam(StarkHash::ZERO),
                        ],
                        entry_point_selector: EntryPoint(StarkHash::ZERO),
                        signature: vec![
                            CallSignatureElem(
                                StarkHash::from_hex_str(
                                    "0x7dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                                )
                                .unwrap(),
                            ),
                            CallSignatureElem(
                                StarkHash::from_hex_str(
                                    "0x71456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                                )
                                .unwrap(),
                            ),
                        ],
                    },
                    Fee(5444010076217u128.to_be_bytes().into()),
                    TransactionVersion(H256::zero()),
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
                "/gateway/add_transaction?",
                (
                    r#"{"code":"TRANSACTION_RECEIVED","transaction_hash":"0x0389DD0629F42176CC8B6C43ACEFC0713D0064ECDFC0470E0FC179F53421A38B"}"#,
                    200,
                ),
            )]);
            // test with values dumped from `starknet invoke` for a test contract
            client
                .add_invoke_transaction(
                    Call {
                        contract_address: ContractAddress(
                            StarkHash::from_hex_str(
                                "0x23371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd",
                            )
                            .unwrap(),
                        ),
                        calldata: vec![
                            CallParam(StarkHash::from_hex_str("0x1").unwrap()),
                            CallParam(
                                StarkHash::from_hex_str(
                                    "0x677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1",
                                )
                                .unwrap(),
                            ),
                            CallParam(
                                StarkHash::from_hex_str(
                                    "0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
                                )
                                .unwrap(),
                            ),
                            CallParam(StarkHash::ZERO),
                            CallParam(StarkHash::from_hex_str("0x1").unwrap()),
                            CallParam(StarkHash::from_hex_str("0x1").unwrap()),
                            CallParam(StarkHash::from_hex_str("0x2b").unwrap()),
                            CallParam(StarkHash::ZERO),
                        ],
                        entry_point_selector: EntryPoint(
                            StarkHash::from_hex_str(
                                "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
                            )
                            .unwrap(),
                        ),
                        signature: vec![
                            CallSignatureElem(
                                StarkHash::from_hex_str(
                                    "0x7dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5",
                                )
                                .unwrap(),
                            ),
                            CallSignatureElem(
                                StarkHash::from_hex_str(
                                    "0x71456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8",
                                )
                                .unwrap(),
                            ),
                        ],
                    },
                    Fee(5444010076217u128.to_be_bytes().into()),
                    TransactionVersion(H256::zero()),
                )
                .await
                .unwrap();
        }

        #[test]
        fn test_program_is_valid_compressed_json() {
            use flate2::write::GzDecoder;
            use std::io::Write;

            let json = include_bytes!("../resources/deploy_transaction.json");
            let json: serde_json::Value = serde_json::from_slice(json).unwrap();
            let program = json["contract_definition"]["program"].as_str().unwrap();
            let gzipped_program = base64::decode(program).unwrap();

            let mut decoder = GzDecoder::new(Vec::new());
            decoder.write_all(&gzipped_program).unwrap();
            let json = decoder.finish().unwrap();

            let _contract: serde_json::Value = serde_json::from_slice(&json).unwrap();
        }

        #[tokio::test]
        async fn declare_class() {
            let contract_class = get_contract_class_from_fixture();

            let (_jh, client) = setup([(
                "/gateway/add_transaction?",
                (
                    r#"{"code": "TRANSACTION_RECEIVED",
                        "transaction_hash": "0x77ccba4df42cf0f74a8eb59a96d7880fae371edca5d000ca5f9985652c8a8ed",
                        "class_hash": "0x711941b11a8236b8cca42b664e19342ac7300abb1dc44957763cb65877c2708"}"#,
                    200,
                ),
            )]);

            client
                .add_declare_transaction(
                    contract_class,
                    // actual address dumped from a `starknet declare` call
                    ContractAddress(StarkHash::from_hex_str("0x1").unwrap()),
                    Fee(0u128.to_be_bytes().into()),
                    vec![],
                    TransactionNonce(StarkHash::ZERO),
                    TransactionVersion(H256::zero()),
                    None,
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn deploy_contract() {
            let contract_definition = get_contract_class_from_fixture();

            let (_jh, client) = setup([(
                "/gateway/add_transaction?",
                (
                    r#"{"code":"TRANSACTION_RECEIVED","transaction_hash":"0x057ED4B4C76A1CA0BA044A654DD3EE2D0D3E550343D739350A22AACDD524110D",
                    "address":"0x03926AEA98213EC34FE9783D803237D221C54C52344422E1F4942A5B340FA6AD"}"#,
                    200,
                ),
            )]);
            client
                .add_deploy_transaction(
                    ContractAddressSalt(
                        StarkHash::from_hex_str(
                            "0x5864b5e296c05028ac2bbc4a4c1378f56a3489d13e581f21d566bb94580f76d",
                        )
                        .unwrap(),
                    ),
                    vec![],
                    contract_definition,
                    None,
                )
                .await
                .unwrap();
        }

        /// Return a contract definition that was dumped from a `starknet deploy`.
        fn get_contract_class_from_fixture() -> ContractDefinition {
            let json = include_bytes!("../resources/deploy_transaction.json");
            let json: serde_json::Value = serde_json::from_slice(json).unwrap();
            let program = json["contract_definition"]["program"].as_str().unwrap();
            let entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndOffset>> =
                        HashMap::from([
                            (EntryPointType::Constructor, vec![]),
                            (
                                EntryPointType::External,
                                vec![
                                    SelectorAndOffset {
                                        offset: ByteCodeOffset(StarkHash::from_hex_str("0x3a").unwrap()),
                                        selector: EntryPoint(StarkHash::from_hex_str(
                                                "0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
                                            )
                                            .unwrap()
                                        ),
                                    },
                                    SelectorAndOffset{
                                        offset: ByteCodeOffset(StarkHash::from_hex_str("0x5b").unwrap()),
                                        selector: EntryPoint(StarkHash::from_hex_str(
                                                "0x39e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695",
                                            )
                                            .unwrap()
                                        ),
                                    },
                                ],
                            ),
                            (EntryPointType::L1Handler, vec![]),
                        ]);
            ContractDefinition {
                abi: serde_json::json!([
                    {
                        "inputs": [
                            {
                                "name": "amount",
                                "type": "felt"
                            }
                        ],
                        "name": "increase_balance",
                        "outputs": [],
                        "type": "function"
                    },
                    {
                        "inputs": [],
                        "name": "get_balance",
                        "outputs": [
                            {
                                "name": "res",
                                "type": "felt"
                            }
                        ],
                        "stateMutability": "view",
                        "type": "function"
                    }
                ]),
                program: program.to_owned(),
                entry_points_by_type,
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
                            "address":"0x3926aea98213ec34fe9783d803237d221c54c52344422e1f4942a5b340fa6ad"
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
                let client = Client::with_url(url).unwrap();

                client
                    .add_deploy_transaction(
                        ContractAddressSalt(StarkHash::ZERO),
                        vec![],
                        ContractDefinition {
                            abi: serde_json::json!([]),
                            program: "".to_owned(),
                            entry_points_by_type: HashMap::new(),
                        },
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
                let client = Client::with_url(url).unwrap();

                let err = client
                    .add_deploy_transaction(
                        ContractAddressSalt(StarkHash::ZERO),
                        vec![],
                        ContractDefinition {
                            abi: serde_json::json!([]),
                            program: "".to_owned(),
                            entry_points_by_type: HashMap::new(),
                        },
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

    mod retry {
        use super::{SequencerError, StarknetErrorCode};
        use assert_matches::assert_matches;
        use http::{response::Builder, StatusCode};
        use pretty_assertions::assert_eq;
        use std::{
            collections::VecDeque, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration,
        };
        use tokio::{sync::Mutex, task::JoinHandle};
        use warp::Filter;

        // A test helper
        fn status_queue_server(
            statuses: VecDeque<(StatusCode, &'static str)>,
        ) -> (JoinHandle<()>, SocketAddr) {
            use std::cell::RefCell;

            let statuses = Arc::new(Mutex::new(RefCell::new(statuses)));
            let any = warp::any().and_then(move || {
                let s = statuses.clone();
                async move {
                    let s = s.lock().await;
                    let s = s.borrow_mut().pop_front().unwrap();
                    Result::<_, Infallible>::Ok(Builder::new().status(s.0).body(s.1))
                }
            });

            let (addr, run_srv) = warp::serve(any).bind_ephemeral(([127, 0, 0, 1], 0));
            let server_handle = tokio::spawn(run_srv);
            (server_handle, addr)
        }

        // A test helper
        fn slow_server() -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
            async fn slow() -> Result<impl warp::Reply, Infallible> {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(Builder::new().status(200).body(""))
            }

            let any = warp::any().and_then(slow);
            let (addr, run_srv) = warp::serve(any).bind_ephemeral(([127, 0, 0, 1], 0));
            let server_handle = tokio::spawn(run_srv);
            (server_handle, addr)
        }

        #[test_log::test(tokio::test)]
        async fn stop_on_ok() {
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
            let result = super::retry0(
                || async {
                    let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                    url.set_port(Some(addr.port())).unwrap();
                    let resp = reqwest::get(url).await?;
                    super::parse::<String>(resp).await
                },
                super::retry_condition,
            )
            .await
            .unwrap();
            assert_eq!(result, "Finally!");
        }

        #[test_log::test(tokio::test)]
        async fn stop_on_fatal() {
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
            let error = super::retry0(
                || async {
                    let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                    url.set_port(Some(addr.port())).unwrap();
                    let resp = reqwest::get(url).await?;
                    super::parse::<String>(resp).await
                },
                super::retry_condition,
            )
            .await
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(se) => assert_eq!(se.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test(flavor = "current_thread", start_paused = true)]
        async fn request_timeout() {
            use std::sync::atomic::{AtomicUsize, Ordering};

            let (_jh, addr) = slow_server();
            static CNT: AtomicUsize = AtomicUsize::new(0);

            let fut = super::retry0(
                || async {
                    let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                    url.set_port(Some(addr.port())).unwrap();

                    let client = reqwest::Client::builder().build().unwrap();

                    CNT.fetch_add(1, Ordering::Relaxed);

                    // This is the same as using Client::builder().timeout()
                    let resp = client
                        .get(url)
                        .timeout(Duration::from_millis(1))
                        .send()
                        .await?;
                    super::parse::<String>(resp).await
                },
                super::retry_condition,
            );

            // The retry loops forever, so wrap it in a timeout and check the counter.
            tokio::time::timeout(Duration::from_millis(250), fut)
                .await
                .unwrap_err();
            // 4th try should have timedout if this is really exponential backoff
            assert_eq!(CNT.load(Ordering::Relaxed), 4);
        }
    }
}
