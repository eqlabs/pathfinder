//! StarkNet L2 sequencer client.
pub mod error;
pub mod reply;
pub mod request;

use self::error::StarknetError;
use crate::{
    core::{
        ByteCodeWord, ContractAddress, ContractCode, StarknetTransactionHash, StorageAddress,
        StorageValue,
    },
    rpc::types::{BlockHashOrTag, BlockNumberOrTag, Tag},
    sequencer::error::SequencerError,
};
use reqwest::Url;
use std::{borrow::Cow, fmt::Debug, result::Result, time::Duration};

/// StarkNet sequencer client using REST API.
#[derive(Debug)]
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
    let resp = resp.text().await?;
    // Attempt to deserialize the actual data we are looking for
    let resp = serde_json::from_str::<T>(resp.as_str())?;
    Ok(resp)
}

/// Helper function which allows skipping deserialization when required.
async fn parse_raw(resp: reqwest::Response) -> Result<reqwest::Response, SequencerError> {
    // Starknet specific errors end with a 500 status code
    // but the body contains a JSON object with the error description
    if resp.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        let resp = resp.text().await?;
        let starknet_error = serde_json::from_str::<StarknetError>(resp.as_str())?;
        return Err(SequencerError::StarknetError(starknet_error));
    }
    // Status codes <400;499> and <501;599> are mapped to SequencerError::TransportError
    resp.error_for_status_ref().map(|_| ())?;
    Ok(resp)
}

impl Client {
    /// Creates a new sequencer client for the Goerli testnet.
    pub fn goerli() -> reqwest::Result<Self> {
        // Unwrap is safe here as this is a valid URL string.
        Self::new(Url::parse("https://alpha4.starknet.io/").unwrap())
    }

    /// Creates a new sequencer client for the mainnet.
    pub fn main() -> reqwest::Result<Self> {
        // Unwrap is safe here as this is a valid URL string.
        Self::new(Url::parse("https://alpha-mainnet.starknet.io/").unwrap())
    }

    /// Creates a new sequencer client, `sequencer_url` needs to be a valid _base URL_.
    fn new(sequencer_url: Url) -> reqwest::Result<Self> {
        debug_assert!(!sequencer_url.cannot_be_a_base());
        Ok(Self {
            inner: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()?,
            sequencer_url,
        })
    }

    /// Gets block by number.
    pub async fn block_by_number(
        &self,
        block_number: BlockNumberOrTag,
    ) -> Result<reply::Block, SequencerError> {
        let number = block_number_str(block_number);
        let resp = self
            .inner
            .get(self.build_query("get_block", &[("blockNumber", &number)]))
            .send()
            .await?;
        parse::<reply::Block>(resp).await
    }

    /// Gets block by number with the specified timeout.
    pub async fn block_by_number_with_timeout(
        &self,
        block_number: BlockNumberOrTag,
        timeout: Duration,
    ) -> Result<reply::Block, SequencerError> {
        let number = block_number_str(block_number);
        let resp = self
            .inner
            .get(self.build_query("get_block", &[("blockNumber", &number)]))
            .timeout(timeout)
            .send()
            .await?;
        parse::<reply::Block>(resp).await
    }

    /// Get block by hash.
    pub async fn block_by_hash(
        &self,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Block, SequencerError> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = self
            .inner
            .get(self.build_query("get_block", &[(tag, &hash)]))
            .send()
            .await?;
        parse::<reply::Block>(resp).await
    }

    /// Performs a `call` on contract's function. Call result is not stored in L2, as opposed to `invoke`.
    pub async fn call(
        &self,
        payload: request::Call,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Call, SequencerError> {
        let (tag, hash) = block_hash_str(block_hash);
        let url = self.build_query("call_contract", &[(tag, &hash)]);
        let resp = self.inner.post(url).json(&payload).send().await?;
        parse(resp).await
    }

    /// Gets contract's code and ABI.
    pub async fn code(
        &self,
        contract_addr: ContractAddress,
        block_hash: BlockHashOrTag,
    ) -> Result<ContractCode, SequencerError> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = self
            .inner
            .get(self.build_query(
                "get_code",
                &[
                    ("contractAddress", &contract_addr.0.to_hex_str()),
                    (tag, &hash),
                ],
            ))
            .send()
            .await?;
        let code = parse::<reply::Code>(resp).await?;

        Ok(ContractCode {
            bytecode: code.bytecode.into_iter().map(ByteCodeWord).collect(),
            abi: code.abi.to_string(),
        })
    }

    /// Gets full contract definition.
    pub async fn full_contract(
        &self,
        contract_addr: ContractAddress,
    ) -> Result<bytes::Bytes, SequencerError> {
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
    }

    /// Gets storage value associated with a `key` for a prticular contract.
    pub async fn storage(
        &self,
        contract_addr: ContractAddress,
        key: StorageAddress,
        block_hash: BlockHashOrTag,
    ) -> Result<StorageValue, SequencerError> {
        use crate::rpc::serde::starkhash_to_dec_str;

        let (tag, hash) = block_hash_str(block_hash);
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
    }

    /// Gets transaction by hash.
    pub async fn transaction(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> Result<reply::Transaction, SequencerError> {
        let resp = self
            .inner
            .get(self.build_query(
                "get_transaction",
                &[("transactionHash", &transaction_hash.0.to_hex_str())],
            ))
            .send()
            .await?;
        parse(resp).await
    }

    /// Gets transaction status by transaction hash.
    pub async fn transaction_status(
        &self,
        transaction_hash: StarknetTransactionHash,
    ) -> Result<reply::TransactionStatus, SequencerError> {
        let resp = self
            .inner
            .get(self.build_query(
                "get_transaction_status",
                &[("transactionHash", &transaction_hash.0.to_hex_str())],
            ))
            .send()
            .await?;
        parse(resp).await
    }

    /// Helper function that constructs a URL for particular query.
    fn build_query(&self, path_segment: &str, params: &[(&str, &str)]) -> Url {
        let mut query_url = self.sequencer_url.clone();
        query_url
            .path_segments_mut()
            .expect("Base URL is valid")
            .extend(&["feeder_gateway", path_segment]);
        query_url.query_pairs_mut().extend_pairs(params);
        query_url
    }
}

#[cfg(test)]
pub mod test_utils {
    use crate::{
        core::{
            CallParam, ContractAddress, EntryPoint, StarknetBlockHash, StarknetBlockNumber,
            StarknetTransactionHash, StarknetTransactionIndex, StorageAddress,
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
        Client::goerli().unwrap()
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

    #[tokio::test]
    #[ignore = "Currently gives 502/503"]
    async fn genesis_block() {
        let by_hash =
            retry_on_rate_limiting!(client().block_by_hash(*GENESIS_BLOCK_HASH).await).unwrap();
        let by_number =
            retry_on_rate_limiting!(client().block_by_number(*GENESIS_BLOCK_NUMBER).await).unwrap();
        assert_eq!(by_hash, by_number);
    }

    #[tokio::test]
    // Temporary replacement for the `genesis_block` test, which essentially does the same
    async fn block_number_matches_block_hash() {
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
        #[ignore = "Currently gives 502/503"]
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
        #[ignore = "Currently gives 502/503"]
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
        #[ignore = "Currently gives 502/503"]
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

    mod code {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn invalid_contract_address() {
            let result = retry_on_rate_limiting!(
                client()
                    .code(*INVALID_CONTRACT_ADDR, BlockHashOrTag::Tag(Tag::Latest))
                    .await
            )
            .unwrap();
            assert_eq!(
                result,
                ContractCode {
                    abi: String::new(),
                    bytecode: Vec::new(),
                }
            );
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let error = retry_on_rate_limiting!(
                client()
                    .code(*VALID_CONTRACT_ADDR, *INVALID_BLOCK_HASH,)
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
                    .code(*VALID_CONTRACT_ADDR, *INVOKE_CONTRACT_BLOCK_HASH,)
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn latest_block() {
            retry_on_rate_limiting!(
                client()
                    .code(*VALID_CONTRACT_ADDR, BlockHashOrTag::Tag(Tag::Latest))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn pending_block() {
            retry_on_rate_limiting!(
                client()
                    .code(*VALID_CONTRACT_ADDR, BlockHashOrTag::Tag(Tag::Pending))
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
}
