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

/// StarkNet sequencer client using REST API.
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
///
/// Initial backoff time is 2 seconds. Retrying stops after approximately 4 minutes in total.
async fn retry<T, Fut, FutureFactory>(future_factory: FutureFactory) -> Result<T, SequencerError>
where
    Fut: Future<Output = Result<T, SequencerError>>,
    FutureFactory: FnMut() -> Fut,
{
    use crate::retry::Retry;
    use reqwest::StatusCode;
    use std::num::{NonZeroU64, NonZeroUsize};

    Retry::exponential(future_factory, NonZeroU64::new(2).unwrap())
        // Max number of retries of 7 gives a total accumulated timeout of 4 minutes and 15 seconds (2^8-1)
        .max_num_retries(NonZeroUsize::new(7).unwrap())
        .when(|e| match e {
            SequencerError::TransportError(te) if te.is_timeout() => {
                tracing::debug!("Retrying due to timeout");
                true
            }
            SequencerError::TransportError(te) => match te.status() {
                Some(
                    status @ (StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::REQUEST_TIMEOUT
                    | StatusCode::BAD_GATEWAY
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT),
                ) => {
                    tracing::debug!("Retrying due to: {status}");
                    true
                }
                Some(_) | None => false,
            },
            _ => false,
        })
        .await
}

impl Client {
    /// Creates a new Sequencer client for the given chain.
    pub fn new(chain: Chain) -> reqwest::Result<Self> {
        let sequencer_url = match chain {
            Chain::Mainnet => Url::parse("https://alpha-mainnet.starknet.io/").unwrap(),
            Chain::Goerli => Url::parse("https://alpha4.starknet.io/").unwrap(),
        };
        Ok(Self {
            inner: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()?,
            sequencer_url,
        })
    }

    /// Gets block by number.
    #[tracing::instrument(skip(self))]
    pub async fn block_by_number(
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

    /// Gets block by number with the specified timeout.
    #[tracing::instrument(skip(self))]
    pub async fn block_by_number_with_timeout(
        &self,
        block_number: BlockNumberOrTag,
        timeout: Duration,
    ) -> Result<reply::Block, SequencerError> {
        let number = block_number_str(block_number);
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query("get_block", &[("blockNumber", &number)]))
                .timeout(timeout)
                .send()
                .await?;
            parse::<reply::Block>(resp).await
        })
        .await
    }

    /// Get block by hash.
    #[tracing::instrument(skip(self))]
    pub async fn block_by_hash(
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
    pub async fn call(
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
    pub async fn full_contract(
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
    pub async fn storage(
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
    pub async fn transaction(
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
    pub async fn transaction_status(
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
    pub async fn state_update_by_hash(
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
    pub async fn state_update_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<reply::StateUpdate, SequencerError> {
        retry(|| async {
            let resp = self
                .inner
                .get(self.build_query(
                    "get_state_update",
                    &[("block_number", &block_number_str(block_number))],
                ))
                .send()
                .await?;
            parse(resp).await
        })
        .await
    }

    /// Gets addresses of the Ethereum contracts crucial to Starknet operation.
    #[tracing::instrument(skip(self))]
    pub async fn eth_contract_addresses(
        &self,
    ) -> Result<reply::EthContractAddresses, SequencerError> {
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
    use reqwest::StatusCode;

    /// Convenience wrapper
    fn client() -> Client {
        Client::new(Chain::Goerli).unwrap()
    }

    /// Convenience macro to allow retrying the test if rate limiting kicks in.
    ///
    /// Necessary until we resign from testing the client on a live API.
    ///
    /// Unfortunately __we cannot just use a wrapper function that takes the future as an argument__,
    /// as this would mean that we would reuse the same client instance after each sleep which
    /// is insufficient to break out of http 429 (the client needs to be destroyed as it does
    /// employ pooling internally).
    /// So __the following code does not actually yield desired results__, not to mention the obvious
    /// convenience pf using `Rc<SequencerError>`due to the fact that some of its variants are not clonable:
    /// ```
    /// /// Helper wrapper to allow retrying the test if rate limiting kicks in.
    ///
    /// /// Necessary until we resign from testing the client on a live API.
    ///
    /// /// __`Rc`__ is used to work around most inner error types being not clonable.
    /// async fn retry_on_spurious_err<Out, Fut>(f: Fut) -> Result<Out, Rc<SequencerError>>
    /// where
    ///     Out: Clone,
    ///     Fut: Future<Output = Result<Out, Rc<SequencerError>>>,
    /// {
    ///     let mut sleep_time_ms = 8000;
    ///     const MAX_SLEEP_TIME_MS: u64 = 128000;
    ///     let clonable = f.shared();
    ///     loop {
    ///         match clonable.clone().await {
    ///             Ok(r) => return Ok(r),
    ///             Err(e) => match &*e {
    ///                 SequencerError::TransportError(ee)
    ///                     if ee.status() == Some(StatusCode::TOO_MANY_REQUESTS) =>
    ///                 {
    ///                     if sleep_time_ms > MAX_SLEEP_TIME_MS {
    ///                         return Err(e);
    ///                     }
    ///                     // Give the api some slack and then retry
    ///                     tokio::time::sleep(Duration::from_millis(sleep_time_ms)).await;
    ///                     sleep_time_ms *= 2;
    ///                 }
    ///                 _ => return Err(e),
    ///             },
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// By the way we would still have to use a convenience macro to avoid some boilerplate code pleasures:
    ///
    /// ```
    /// /// Convenience macro, frees the user of remembering to add `async {}` and `map_err(Rc::new)` to the mix.
    /// macro_rules! retry_on_rate_limiting {
    ///     ($wrapped_call:expr) => {
    ///         retry_on_spurious_err(async { ($wrapped_call).await.map_err(Rc::new) })
    ///     };
    /// }
    /// ```
    macro_rules! retry_on_rate_limiting {
        ($wrapped_call:expr) => {{
            let mut sleep_time_ms = 8000;
            const MAX_SLEEP_TIME_MS: u64 = 128000;
            loop {
                match ($wrapped_call) {
                    Ok(r) => break Ok(r),
                    Err(e) => match &e {
                        SequencerError::TransportError(ee)
                            if ee.status() == Some(StatusCode::TOO_MANY_REQUESTS) =>
                        {
                            if sleep_time_ms > MAX_SLEEP_TIME_MS {
                                break Err(e);
                            }
                            // Give the api some slack and then retry
                            eprintln!(
                                "Got HTTP 429, retrying after {} seconds...",
                                sleep_time_ms / 1000
                            );
                            tokio::time::sleep(Duration::from_millis(sleep_time_ms)).await;
                            sleep_time_ms *= 2;
                        }
                        _ => break Err(e),
                    },
                }
            }
        }};
    }

    mod block_by_number_matches_by_hash_on {
        use super::*;

        #[tokio::test]
        async fn genesis() {
            let by_hash =
                retry_on_rate_limiting!(client().block_by_hash(*GENESIS_BLOCK_HASH).await).unwrap();
            let by_number =
                retry_on_rate_limiting!(client().block_by_number(*GENESIS_BLOCK_NUMBER).await)
                    .unwrap();
            assert_eq!(by_hash, by_number);
        }

        #[tokio::test]
        async fn specific_block() {
            let by_hash = retry_on_rate_limiting!(
                client()
                    .block_by_hash(BlockHashOrTag::Hash(
                        StarknetBlockHash::from_hex_str(
                            "0x07187d565e5563658f2b88a9000c6eb84692dcd90a8ab7d8fe75d768205d9b66"
                        )
                        .unwrap()
                    ))
                    .await
            )
            .unwrap();
            let by_number = retry_on_rate_limiting!(
                client()
                    .block_by_number(BlockNumberOrTag::Number(StarknetBlockNumber(50000)))
                    .await
            )
            .unwrap();
            assert_eq!(by_hash, by_number);
        }
    }

    mod block_by_hash {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn latest() {
            retry_on_rate_limiting!(
                client()
                    .block_by_hash(BlockHashOrTag::Tag(Tag::Latest))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            retry_on_rate_limiting!(
                client()
                    .block_by_hash(BlockHashOrTag::Tag(Tag::Pending))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn block_without_block_hash_field() {
            retry_on_rate_limiting!(
                client()
                    .block_by_hash(BlockHashOrTag::Hash(
                        StarknetBlockHash::from_hex_str(
                            "01cf37f162c3fa3b57c1c4324c240b0c8c65bb5a15e039817a3023b9890e94d1",
                        )
                        .unwrap(),
                    ))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn invalid() {
            // Invalid block hash
            let error = retry_on_rate_limiting!(client().block_by_hash(*INVALID_BLOCK_HASH).await)
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
            retry_on_rate_limiting!(
                client()
                    .block_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            retry_on_rate_limiting!(
                client()
                    .block_by_number(BlockNumberOrTag::Tag(Tag::Pending))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn invalid() {
            let error =
                retry_on_rate_limiting!(client().block_by_number(*INVALID_BLOCK_NUMBER).await)
                    .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn contains_receipts_without_status_field() {
            retry_on_rate_limiting!(
                client()
                    .block_by_number(BlockNumberOrTag::Number(StarknetBlockNumber(1716)))
                    .await
            )
            .unwrap();
        }
    }

    mod block_by_number_with_timeout {
        use super::*;

        #[tokio::test]
        async fn latest() {
            retry_on_rate_limiting!(
                client()
                    .block_by_number_with_timeout(
                        BlockNumberOrTag::Tag(Tag::Latest),
                        Duration::from_secs(120)
                    )
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            retry_on_rate_limiting!(
                client()
                    .block_by_number_with_timeout(
                        BlockNumberOrTag::Tag(Tag::Pending),
                        Duration::from_secs(120)
                    )
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn invalid() {
            let error = retry_on_rate_limiting!(
                client()
                    .block_by_number_with_timeout(*INVALID_BLOCK_NUMBER, Duration::from_secs(120))
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn contains_receipts_without_status_field() {
            retry_on_rate_limiting!(
                client()
                    .block_by_number_with_timeout(
                        BlockNumberOrTag::Number(StarknetBlockNumber(1716)),
                        Duration::from_secs(120)
                    )
                    .await
            )
            .unwrap();
        }
    }

    mod call {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn invalid_entry_point() {
            let error = retry_on_rate_limiting!(
                client()
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
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::EntryPointNotFound)
            );
        }

        #[tokio::test]
        async fn invalid_contract_address() {
            let error = retry_on_rate_limiting!(
                client()
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
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::UninitializedContract)
            );
        }

        #[tokio::test]
        async fn invalid_call_data() {
            let error = retry_on_rate_limiting!(
                client()
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
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::TransactionFailed)
            );
        }

        #[tokio::test]
        async fn uninitialized_contract() {
            let error = retry_on_rate_limiting!(
                client()
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
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::UninitializedContract)
            );
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let error = retry_on_rate_limiting!(
                client()
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
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn latest_invoke_block() {
            retry_on_rate_limiting!(
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
            )
            .unwrap();
        }

        #[tokio::test]
        async fn latest_block() {
            retry_on_rate_limiting!(
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
            )
            .unwrap();
        }

        #[tokio::test]
        async fn pending_block() {
            retry_on_rate_limiting!(
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
            )
            .unwrap();
        }
    }

    mod full_contract {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn invalid_contract_address() {
            let error =
                retry_on_rate_limiting!(client().full_contract(*INVALID_CONTRACT_ADDR).await)
                    .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::UninitializedContract)
            );
        }

        #[tokio::test]
        async fn success() {
            let bytes = retry_on_rate_limiting!(client().full_contract(*VALID_CONTRACT_ADDR).await)
                .unwrap();
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
            let result = retry_on_rate_limiting!(
                client()
                    .storage(
                        *INVALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Tag(Tag::Latest),
                    )
                    .await
            )
            .unwrap();
            assert_eq!(result, StorageValue(StarkHash::ZERO));
        }

        #[tokio::test]
        async fn invalid_key() {
            let result = retry_on_rate_limiting!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        *ZERO_KEY,
                        BlockHashOrTag::Tag(Tag::Latest),
                    )
                    .await
            )
            .unwrap();
            assert_eq!(result, StorageValue(StarkHash::ZERO));
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let error = retry_on_rate_limiting!(
                client()
                    .storage(*VALID_CONTRACT_ADDR, *VALID_KEY, *INVALID_BLOCK_HASH,)
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn latest_invoke_block() {
            retry_on_rate_limiting!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        *INVOKE_CONTRACT_BLOCK_HASH,
                    )
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn latest_block() {
            retry_on_rate_limiting!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Tag(Tag::Latest),
                    )
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn pending_block() {
            retry_on_rate_limiting!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Tag(Tag::Pending),
                    )
                    .await
            )
            .unwrap();
        }
    }

    mod transaction {
        use super::{reply::Status, *};
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn accepted() {
            assert_eq!(
                retry_on_rate_limiting!(client().transaction(*VALID_TX_HASH).await)
                    .unwrap()
                    .status,
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            assert_eq!(
                retry_on_rate_limiting!(client().transaction(*INVALID_TX_HASH).await)
                    .unwrap()
                    .status,
                Status::NotReceived,
            );
        }
    }

    mod transaction_status {
        use super::{reply::Status, *};

        #[tokio::test]
        async fn accepted() {
            assert_eq!(
                retry_on_rate_limiting!(client().transaction_status(*VALID_TX_HASH).await)
                    .unwrap()
                    .tx_status,
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            assert_eq!(
                retry_on_rate_limiting!(client().transaction_status(*INVALID_TX_HASH).await)
                    .unwrap()
                    .tx_status,
                Status::NotReceived
            );
        }
    }

    mod state_update_by_number_matches_by_hash_on {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        #[ignore = "Wait until integration is stabilized and there's a goerli deployment."]
        async fn genesis() {
            let by_number = retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_number(*GENESIS_BLOCK_NUMBER,)
                    .await
            )
            .unwrap();

            let by_hash = retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_hash(*GENESIS_BLOCK_HASH)
                    .await
            )
            .unwrap();

            assert_eq!(by_number, by_hash);
        }

        #[tokio::test]
        #[ignore = "Wait until integration is stabilized and there's a goerli deployment."]
        async fn specific_block() {
            let by_number = retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_number(BlockNumberOrTag::Number(StarknetBlockNumber(1000)))
                    .await
            )
            .unwrap();

            let by_hash = retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_hash(BlockHashOrTag::Hash(
                        StarknetBlockHash::from_hex_str("TODO").unwrap()
                    ))
                    .await
            )
            .unwrap();

            assert_eq!(by_number, by_hash);
        }
    }

    mod state_update_by_number {
        use super::*;

        #[tokio::test]
        #[ignore = "Wait until integration is stabilized and there's a goerli deployment."]
        async fn invalid_number() {
            let error = retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_number(*INVALID_BLOCK_NUMBER,)
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn latest() {
            retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_number(BlockNumberOrTag::Tag(Tag::Pending))
                    .await
            )
            .unwrap();
        }
    }

    mod state_update_by_hash {
        use super::*;

        #[tokio::test]
        async fn invalid_hash() {
            let error = retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_hash(*INVALID_BLOCK_HASH)
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn latest() {
            retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_hash(BlockHashOrTag::Tag(Tag::Latest))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn pending() {
            retry_on_rate_limiting!(
                Client::new(crate::ethereum::Chain::Goerli)
                    .unwrap()
                    .state_update_by_hash(BlockHashOrTag::Tag(Tag::Pending))
                    .await
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn eth_contract_addresses() {
        retry_on_rate_limiting!(client().eth_contract_addresses().await).unwrap();
    }

    mod retry {
        use super::{SequencerError, StarknetErrorCode};
        use assert_matches::assert_matches;
        use http::StatusCode;
        use pretty_assertions::assert_eq;

        async fn run_retry(
            statuses: Vec<(StatusCode, &'static str)>,
        ) -> Result<String, SequencerError> {
            use http::response::Builder;
            use std::{
                cell::RefCell,
                sync::{Arc, Mutex},
            };
            use warp::Filter;

            let statuses = Arc::new(Mutex::new(RefCell::new(statuses)));
            let any = warp::any().map(move || {
                let s = statuses.clone();
                let s = s.lock().unwrap();
                let s = s.borrow_mut().pop().unwrap();
                Builder::new().status(s.0).body(s.1)
            });

            let (addr, run_srv) = warp::serve(any).bind_ephemeral(([127, 0, 0, 1], 0));
            let _jh = tokio::spawn(run_srv);

            // super::retry is the UUT here
            let result = super::retry(|| async {
                let mut url = reqwest::Url::parse("http://localhost/").unwrap();
                url.set_port(Some(addr.port())).unwrap();
                let resp = reqwest::get(url).await.unwrap();
                super::parse::<String>(resp).await
            })
            .await;
            result
        }

        #[tokio::test]
        async fn stop_on_ok() {
            let ends_with_ok = vec![
                (StatusCode::OK, r#""Finally!""#),
                (StatusCode::REQUEST_TIMEOUT, ""),
                (StatusCode::GATEWAY_TIMEOUT, ""),
                (StatusCode::SERVICE_UNAVAILABLE, ""),
                (StatusCode::BAD_GATEWAY, ""),
                (StatusCode::TOO_MANY_REQUESTS, ""),
            ];

            let result = run_retry(ends_with_ok).await.unwrap();
            assert_eq!(result, "Finally!");
        }

        #[tokio::test]
        async fn stop_on_fatal() {
            let ends_with_ok = vec![
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"code":"StarknetErrorCode.BLOCK_NOT_FOUND","message":""}"#,
                ),
                (StatusCode::REQUEST_TIMEOUT, ""),
                (StatusCode::GATEWAY_TIMEOUT, ""),
                (StatusCode::SERVICE_UNAVAILABLE, ""),
                (StatusCode::BAD_GATEWAY, ""),
                (StatusCode::TOO_MANY_REQUESTS, ""),
            ];

            let error = run_retry(ends_with_ok).await.unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(se) => assert_eq!(se.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn stop_on_max_retry_count() {
            let ends_with_ok = vec![
                (StatusCode::SERVICE_UNAVAILABLE, ""),
                (StatusCode::REQUEST_TIMEOUT, ""),
                (StatusCode::GATEWAY_TIMEOUT, ""),
                (StatusCode::BAD_GATEWAY, ""),
                (StatusCode::TOO_MANY_REQUESTS, ""),
                (StatusCode::TOO_MANY_REQUESTS, ""),
                (StatusCode::TOO_MANY_REQUESTS, ""),
                (StatusCode::TOO_MANY_REQUESTS, ""),
            ];

            let error = run_retry(ends_with_ok).await.unwrap_err();
            assert_matches!(
                error,
                SequencerError::TransportError(te) => assert_eq!(te.status(), Some(StatusCode::SERVICE_UNAVAILABLE))
            );
        }
    }
}
