//! StarkNet L2 sequencer client.
pub mod error;
pub mod reply;
pub mod request;

use self::error::StarknetError;
use crate::{
    core::{ContractAddress, StarknetTransactionHash, StorageAddress, StorageValue},
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
        BlockHashOrTag::Hash(h) => ("blockHash", Cow::from(h.0.to_hex_str())),
        BlockHashOrTag::Tag(Tag::Latest) => ("blockNumber", Cow::from("null")),
        BlockHashOrTag::Tag(Tag::Pending) => ("blockNumber", Cow::from("pending")),
    }
}

/// Helper function which simplifies the handling of optional block numbers in queries.
fn block_number_str(number: BlockNumberOrTag) -> Cow<'static, str> {
    match number {
        BlockNumberOrTag::Number(n) => Cow::from(n.0.to_string()),
        BlockNumberOrTag::Tag(Tag::Latest) => Cow::from("null"),
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
async fn retry<T, Fut, FutureFactory>(future_factory: FutureFactory) -> Result<T, SequencerError>
where
    Fut: Future<Output = Result<T, SequencerError>>,
    FutureFactory: FnMut() -> Fut,
{
    use crate::retry::Retry;
    use reqwest::StatusCode;
    use std::num::NonZeroU64;
    use tracing::{debug, error, info, warn};

    Retry::exponential(future_factory, NonZeroU64::new(2).unwrap())
        .factor(NonZeroU64::new(15).unwrap())
        .max_delay(Duration::from_secs(60 * 60))
        .when(|e| match e {
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
        })
        .await
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

    /// Create a Sequencer client for the given [Url].
    fn with_url(url: Url) -> reqwest::Result<Self> {
        // Resolves to "pathfinder/<version_info>"
        const USER_AGENT: &str = concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT")
        );

        Ok(Self {
            inner: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .user_agent(USER_AGENT)
                .build()?,
            sequencer_url: url,
        })
    }

    /// Helper function that constructs a URL for particular query.
    fn build_query(&self, path_segment: &str, params: &[(&str, &str)]) -> Url {
        let mut query_url = self.sequencer_url.clone();
        query_url
            .path_segments_mut()
            .expect("Base URL is valid")
            .extend(&["feeder_gateway", path_segment]);
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
                .get(self.build_query("get_block", &[("blockNumber", &number)]))
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
                .get(self.build_query("get_block", &[(tag, &hash)]))
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
                .post(self.build_query("call_contract", &[(tag, &hash)]))
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
                    "get_full_contract",
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
                    "get_storage_at",
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
                    "get_transaction",
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
                    "get_transaction_status",
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
                .get(self.build_query("get_state_update", &[(tag, &hash)]))
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
                    "get_state_update",
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
                .get(self.build_query("get_contract_addresses", &[]))
                .send()
                .await?;
            parse(resp).await
        })
        .await
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
    use pedersen::{HexParseError, StarkHash};

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
        pub static ref DEPLOY_CONTRACT_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash::from_hex_str("0x07177acba67cb659e336abb3a158c8d29770b87b1b62e2bfa94cd376b72d34c5").unwrap());
        pub static ref INVOKE_CONTRACT_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash::from_hex_str("0x03871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27").unwrap());
        pub static ref VALID_TX_HASH: StarknetTransactionHash = StarknetTransactionHash::from_hex_str("0x0493d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24").unwrap();
        pub static ref INVALID_TX_HASH: StarknetTransactionHash = StarknetTransactionHash::from_hex_str("0x0393d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24").unwrap();
        pub static ref VALID_CONTRACT_ADDR: ContractAddress = ContractAddress::from_hex_str("0x06fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39").unwrap();
        pub static ref INVALID_CONTRACT_ADDR: ContractAddress = ContractAddress::from_hex_str("0x05fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39").unwrap();
        pub static ref VALID_ENTRY_POINT: EntryPoint = EntryPoint::from_hex_str("0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320").unwrap();
        pub static ref INVALID_ENTRY_POINT: EntryPoint = EntryPoint(StarkHash::ZERO);
        pub static ref VALID_TX_INDEX: StarknetTransactionIndex = StarknetTransactionIndex(0u64);
        pub static ref INVALID_TX_INDEX: StarknetTransactionIndex = StarknetTransactionIndex(u64::MAX);
        pub static ref VALID_KEY: StorageAddress = StorageAddress::from_hex_str("0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091").unwrap();
        pub static ref INVALID_KEY: StorageAddress = StorageAddress::from_hex_str("0x0106F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091").unwrap();
        pub static ref ZERO_KEY: StorageAddress = StorageAddress(StarkHash::ZERO);
        pub static ref VALID_CALL_DATA: Vec<CallParam> = vec![CallParam::from_hex_str("0x4d2").unwrap()];
    }
}

#[cfg(test)]
mod tests {
    use super::{error::StarknetErrorCode, test_utils::*, *};
    use crate::core::{StarknetBlockHash, StarknetBlockNumber};
    use assert_matches::assert_matches;
    use pedersen::StarkHash;

    /// Convenience wrapper
    fn client() -> Client {
        Client::new(Chain::Goerli).unwrap()
    }

    #[tokio::test]
    async fn client_user_agent() {
        use std::convert::Infallible;

        use warp::Filter;

        let filter = warp::header::optional("user-agent").and_then(
            |user_agent: Option<String>| async move {
                let user_agent = user_agent.expect("user-agent set");
                let (name, version) = user_agent.split_once('/').unwrap();

                assert_eq!(name, "pathfinder");
                assert_eq!(version, env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT"));

                Result::<_, Infallible>::Ok("")
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
            let by_hash = client().block_by_hash(*GENESIS_BLOCK_HASH).await.unwrap();
            let by_number = client()
                .block_by_number(*GENESIS_BLOCK_NUMBER)
                .await
                .unwrap();
            assert_eq!(by_hash, by_number);
        }

        #[tokio::test]
        async fn specific_block() {
            let by_hash = client()
                .block_by_hash(BlockHashOrTag::Hash(
                    StarknetBlockHash::from_hex_str(
                        "0x07187d565e5563658f2b88a9000c6eb84692dcd90a8ab7d8fe75d768205d9b66",
                    )
                    .unwrap(),
                ))
                .await
                .unwrap();
            let by_number = client()
                .block_by_number(BlockNumberOrTag::Number(StarknetBlockNumber(50000)))
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
            client()
                .block_by_hash(BlockHashOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            client()
                .block_by_hash(BlockHashOrTag::Tag(Tag::Pending))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn block_without_block_hash_field() {
            client()
                .block_by_hash(BlockHashOrTag::Hash(
                    StarknetBlockHash::from_hex_str(
                        "01cf37f162c3fa3b57c1c4324c240b0c8c65bb5a15e039817a3023b9890e94d1",
                    )
                    .unwrap(),
                ))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid() {
            // Invalid block hash
            let error = client()
                .block_by_hash(*INVALID_BLOCK_HASH)
                .await
                .unwrap_err();
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
            client()
                .block_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            client()
                .block_by_number(BlockNumberOrTag::Tag(Tag::Pending))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid() {
            let error = client()
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
            client()
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
            let error = client()
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
            let error = client()
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
            let error = client()
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
            let error = client()
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
            let error = client()
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
            client()
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
            client()
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
            client()
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

        #[tokio::test]
        async fn invalid_contract_address() {
            let error = client()
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
            let bytes = client().full_contract(*VALID_CONTRACT_ADDR).await.unwrap();
            // Fast sanity check
            // TODO replace with something more meaningful once we figure out the structure to deserialize to
            assert_eq!(bytes.len(), 53032);
        }
    }

    mod storage {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn invalid_contract_address() {
            let result = client()
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
            let result = client()
                .storage(
                    *VALID_CONTRACT_ADDR,
                    *ZERO_KEY,
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
            assert_eq!(result, StorageValue(StarkHash::ZERO));
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let error = client()
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
            client()
                .storage(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    *INVOKE_CONTRACT_BLOCK_HASH,
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn latest_block() {
            client()
                .storage(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending_block() {
            client()
                .storage(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Pending),
                )
                .await
                .unwrap();
        }
    }

    mod transaction {
        use super::{reply::Status, *};
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn accepted() {
            assert_eq!(
                client().transaction(*VALID_TX_HASH).await.unwrap().status,
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            assert_eq!(
                client().transaction(*INVALID_TX_HASH).await.unwrap().status,
                Status::NotReceived,
            );
        }
    }

    mod transaction_status {
        use super::{reply::Status, *};

        #[tokio::test]
        async fn accepted() {
            assert_eq!(
                client()
                    .transaction_status(*VALID_TX_HASH)
                    .await
                    .unwrap()
                    .tx_status,
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            assert_eq!(
                client()
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
            let by_number: OrderedStateUpdate = Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
                .state_update_by_number(*GENESIS_BLOCK_NUMBER)
                .await
                .unwrap()
                .into();

            let by_hash: OrderedStateUpdate = Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
                .state_update_by_hash(*GENESIS_BLOCK_HASH)
                .await
                .unwrap()
                .into();

            assert_eq!(by_number, by_hash);
        }

        #[tokio::test]
        async fn specific_block() {
            let by_number: OrderedStateUpdate = Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
                .state_update_by_number(BlockNumberOrTag::Number(StarknetBlockNumber(10000)))
                .await
                .unwrap()
                .into();

            let by_hash: OrderedStateUpdate = Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
                .state_update_by_hash(BlockHashOrTag::Hash(
                    StarknetBlockHash::from_hex_str(
                        "0x59fc9ede727664c12a5cc72252d1c1dd7d84f9182644f9b39f405d33bedcc99",
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

        #[tokio::test]
        async fn invalid_number() {
            let error = Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
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
            Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
                .state_update_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
                .state_update_by_number(BlockNumberOrTag::Tag(Tag::Pending))
                .await
                .unwrap();
        }
    }

    mod state_update_by_hash {
        use super::*;

        #[tokio::test]
        async fn invalid_hash() {
            let error = Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
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
            Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
                .state_update_by_hash(BlockHashOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            Client::new(crate::ethereum::Chain::Goerli)
                .unwrap()
                .state_update_by_hash(BlockHashOrTag::Tag(Tag::Pending))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn eth_contract_addresses() {
        client().eth_contract_addresses().await.unwrap();
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
        use tracing_test::traced_test;
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

        #[tokio::test]
        #[traced_test]
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
            let result = super::retry(|| async {
                let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                url.set_port(Some(addr.port())).unwrap();
                let resp = reqwest::get(url).await?;
                super::parse::<String>(resp).await
            })
            .await
            .unwrap();
            assert_eq!(result, "Finally!");
        }

        #[tokio::test]
        #[traced_test]
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
            let error = super::retry(|| async {
                let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                url.set_port(Some(addr.port())).unwrap();
                let resp = reqwest::get(url).await?;
                super::parse::<String>(resp).await
            })
            .await
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(se) => assert_eq!(se.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        #[traced_test]
        async fn request_timeout() {
            use std::sync::atomic::{AtomicUsize, Ordering};

            let (_jh, addr) = slow_server();
            static CNT: AtomicUsize = AtomicUsize::new(0);

            let fut = super::retry(|| async {
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
            });

            // The retry loops forever, so wrap it in a timeout and check the counter.
            tokio::time::timeout(Duration::from_millis(250), fut)
                .await
                .unwrap_err();
            // 4th try should have timedout if this is really exponential backoff
            assert_eq!(CNT.load(Ordering::Relaxed), 4);
        }
    }
}
