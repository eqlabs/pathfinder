//! StarkNet L2 sequencer client.
pub mod error;
pub mod reply;
pub mod request;

use crate::{
    rpc::types::{relaxed, BlockHashOrTag, BlockNumberOrTag, Tag},
    sequencer::error::SequencerError,
};
use reqwest::Url;
use std::{borrow::Cow, fmt::Debug, result::Result, time::Duration};
use web3::types::{H256, U256};

use self::error::StarknetError;

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
        BlockHashOrTag::Hash(h) => ("blockHash", Cow::from(format!("0x{:x}", h))),
        BlockHashOrTag::Tag(Tag::Latest) => ("blockId", Cow::from("null")),
        BlockHashOrTag::Tag(Tag::Pending) => ("blockId", Cow::from("pending")),
    }
}

/// __Mandatory__ function to parse every sequencer query response.
async fn parse<T>(resp: reqwest::Response) -> Result<T, SequencerError>
where
    T: serde::de::DeserializeOwned,
{
    // Starknet specific errors end with a 500 status code
    // but the body contains a JSON object with the error description
    if resp.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        let resp = resp.text().await?;
        let starknet_error = serde_json::from_str::<StarknetError>(resp.as_str())?;
        return Err(SequencerError::StarknetError(starknet_error));
    }
    // Status codes <400;499> and <501;599> are mapped to SequencerError::TransportError
    resp.error_for_status_ref().map(|_| ())?;
    let resp = resp.text().await?;
    // Attempt to deserialize the actual data we are looking for
    let deserialized = serde_json::from_str::<T>(resp.as_str())?;
    Ok(deserialized)
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
        let block_hash = match block_number {
            BlockNumberOrTag::Number(n) => {
                let resp = self
                    .inner
                    .get(self.build_query("get_block_hash_by_id", &[("blockId", &n.to_string())]))
                    .send()
                    .await?;
                let block_hash: relaxed::H256 = parse(resp).await?;
                BlockHashOrTag::Hash(*block_hash)
            }
            BlockNumberOrTag::Tag(tag) => BlockHashOrTag::Tag(tag),
        };
        self.block_by_hash(block_hash).await
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
        contract_addr: H256,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Code, SequencerError> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = self
            .inner
            .get(self.build_query(
                "get_code",
                &[
                    ("contractAddress", format!("{:x}", contract_addr).as_str()),
                    (tag, &hash),
                ],
            ))
            .send()
            .await?;
        parse(resp).await
    }

    /// Gets storage value associated with a `key` for a prticular contract.
    pub async fn storage(
        &self,
        contract_addr: H256,
        key: U256,
        block_hash: BlockHashOrTag,
    ) -> Result<H256, SequencerError> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = self
            .inner
            .get(self.build_query(
                "get_storage_at",
                &[
                    ("contractAddress", format!("{:x}", contract_addr).as_str()),
                    ("key", key.to_string().as_str()),
                    (tag, &hash),
                ],
            ))
            .send()
            .await?;
        let value: relaxed::H256 = parse(resp).await?;
        Ok(*value)
    }

    /// Gets transaction by hash.
    pub async fn transaction(
        &self,
        transaction_hash: H256,
    ) -> Result<reply::Transaction, SequencerError> {
        let resp = self
            .inner
            .get(self.build_query(
                "get_transaction",
                &[(
                    "transactionHash",
                    format!("{:#x}", transaction_hash).as_str(),
                )],
            ))
            .send()
            .await?;
        parse(resp).await
    }

    /// Gets transaction status by transaction hash.
    pub async fn transaction_status(
        &self,
        transaction_hash: H256,
    ) -> Result<reply::TransactionStatus, SequencerError> {
        let resp = self
            .inner
            .get(self.build_query(
                "get_transaction_status",
                &[(
                    "transactionHash",
                    format!("{:#x}", transaction_hash).as_str(),
                )],
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
mod tests {
    use super::{error::StarknetErrorCode, *};
    use assert_matches::assert_matches;
    use reqwest::StatusCode;
    use std::str::FromStr;
    use web3::types::U256;

    lazy_static::lazy_static! {
        static ref GENESIS_BLOCK_HASH: H256 = H256::from_str("0x07d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b").unwrap();
        static ref INVALID_BLOCK_HASH: H256 = H256::from_str("0x13d8d8bb5716cd3f16e54e3a6ff1a50542461d9022e5f4dec7a4b064041ab8d7").unwrap();
        static ref UNKNOWN_BLOCK_HASH: H256 = H256::from_str("0x03c85a69453e63fd475424ecc70438bd855cd76e6f0d5dec0d0dd56e0f7a771c").unwrap();
        static ref CONTRACT_BLOCK_HASH: H256 = H256::from_str("0x03871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27").unwrap();
        static ref VALID_TX_HASH: H256 = H256::from_str("0x0493d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24").unwrap();
        static ref INVALID_TX_HASH: H256 = H256::from_str("0x1493d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24").unwrap();
        static ref UNKNOWN_TX_HASH: H256 = H256::from_str("0x015e4bb72df94be3044139fea2116c4d54add05cf9ef8f35aea114b5cea94713").unwrap();
        static ref VALID_CONTRACT_ADDR: H256 = H256::from_str("0x06fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39").unwrap();
        static ref INVALID_CONTRACT_ADDR: H256 = H256::from_str("0x16fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39").unwrap();
        static ref UNKNOWN_CONTRACT_ADDR: H256 = H256::from_str("0x0739636829ad5205d81af792a922a40e35c0ec7a72f4859843ee2e2a0d6f0af0").unwrap();
        static ref VALID_ENTRY_POINT: H256 = H256::from_str("0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320").unwrap();
    }

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

    mod block_by_hash {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        #[ignore = "Currently gives 502"]
        async fn genesis() {
            retry_on_rate_limiting!(
                client()
                    .block_by_hash(BlockHashOrTag::Hash(*GENESIS_BLOCK_HASH))
                    .await
            )
            .unwrap();
        }

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
        #[ignore = "Currently gives 502"]
        async fn block_without_block_hash_field() {
            retry_on_rate_limiting!(
                client()
                    .block_by_hash(BlockHashOrTag::Hash(
                        H256::from_str(
                            "01cf37f162c3fa3b57c1c4324c240b0c8c65bb5a15e039817a3023b9890e94d1",
                        )
                        .unwrap(),
                    ))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn unknown() {
            // Use valid hash from mainnet
            let error = retry_on_rate_limiting!(
                client()
                    .block_by_hash(BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH))
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn invalid() {
            // Invalid block hash
            let error = retry_on_rate_limiting!(
                client()
                    .block_by_hash(BlockHashOrTag::Hash(*INVALID_BLOCK_HASH))
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeBlockHash)
            );
        }
    }

    mod block_by_number {
        use super::*;

        #[tokio::test]
        async fn genesis() {
            retry_on_rate_limiting!(client().block_by_number(BlockNumberOrTag::Number(0)).await)
                .unwrap();
        }

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
            let error = retry_on_rate_limiting!(
                client()
                    .block_by_number(BlockNumberOrTag::Number(u64::MAX))
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::MalformedRequest)
            );
        }

        #[tokio::test]
        #[ignore = "Currently gives 502"]
        async fn contains_receipts_without_status_field() {
            retry_on_rate_limiting!(
                client()
                    .block_by_number(BlockNumberOrTag::Number(1716))
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
                            calldata: vec![U256::from(1234u64)],
                            contract_address: *VALID_CONTRACT_ADDR,
                            entry_point_selector: H256::zero(),
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
                            calldata: vec![U256::from(1234u64)],
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
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeContractAddress)
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
                        BlockHashOrTag::Hash(*CONTRACT_BLOCK_HASH),
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
                        BlockHashOrTag::Hash(*GENESIS_BLOCK_HASH),
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
                            calldata: vec![U256::from(1234u64)],
                            contract_address: *VALID_CONTRACT_ADDR,
                            entry_point_selector: *VALID_ENTRY_POINT,
                            signature: vec![],
                        },
                        BlockHashOrTag::Hash(*INVALID_BLOCK_HASH),
                    )
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeBlockHash)
            );
        }

        #[tokio::test]
        async fn unknown_block_hash() {
            let error = retry_on_rate_limiting!(
                client()
                    .call(
                        request::Call {
                            calldata: vec![U256::from(1234u64)],
                            contract_address: *VALID_CONTRACT_ADDR,
                            entry_point_selector: *VALID_ENTRY_POINT,
                            signature: vec![],
                        },
                        BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH),
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
                            calldata: vec![U256::from(1234u64)],
                            contract_address: *VALID_CONTRACT_ADDR,
                            entry_point_selector: *VALID_ENTRY_POINT,
                            signature: vec![],
                        },
                        BlockHashOrTag::Hash(*CONTRACT_BLOCK_HASH),
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
                            calldata: vec![U256::from(1234u64)],
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
                            calldata: vec![U256::from(1234u64)],
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
            let error = retry_on_rate_limiting!(
                client()
                    .code(*INVALID_CONTRACT_ADDR, BlockHashOrTag::Tag(Tag::Latest))
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeContractAddress)
            );
        }

        #[tokio::test]
        async fn unknown_contract_address() {
            retry_on_rate_limiting!(
                client()
                    .code(*UNKNOWN_CONTRACT_ADDR, BlockHashOrTag::Tag(Tag::Latest))
                    .await
            )
            .unwrap();
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let error = retry_on_rate_limiting!(
                client()
                    .code(
                        *VALID_CONTRACT_ADDR,
                        BlockHashOrTag::Hash(*INVALID_BLOCK_HASH),
                    )
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeBlockHash)
            );
        }

        #[tokio::test]
        async fn unknown_block_hash() {
            let error = retry_on_rate_limiting!(
                client()
                    .code(
                        *VALID_CONTRACT_ADDR,
                        BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH),
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
                    .code(
                        *VALID_CONTRACT_ADDR,
                        BlockHashOrTag::Hash(*CONTRACT_BLOCK_HASH),
                    )
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

    mod storage {
        use super::*;
        use pretty_assertions::assert_eq;

        lazy_static::lazy_static! {
            static ref VALID_KEY: U256 = U256::from_str_radix("916907772491729262376534102982219947830828984996257231353398618781993312401", 10).unwrap();
        }

        #[tokio::test]
        async fn invalid_contract_address() {
            let error = retry_on_rate_limiting!(
                client()
                    .storage(
                        *INVALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Tag(Tag::Latest),
                    )
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeContractAddress)
            );
        }

        #[tokio::test]
        async fn invalid_key() {
            let error = retry_on_rate_limiting!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        U256::max_value(),
                        BlockHashOrTag::Tag(Tag::Latest),
                    )
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeStorageKey)
            );
        }

        #[tokio::test]
        async fn unknown_block_hash() {
            let error = retry_on_rate_limiting!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH),
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
        async fn invalid_block_hash() {
            let error = retry_on_rate_limiting!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Hash(*INVALID_BLOCK_HASH),
                    )
                    .await
            )
            .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeBlockHash)
            );
        }

        #[tokio::test]
        async fn latest_invoke_block() {
            retry_on_rate_limiting!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Hash(*CONTRACT_BLOCK_HASH),
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
            let error =
                retry_on_rate_limiting!(client().transaction(*INVALID_TX_HASH).await).unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeTransactionHash)
            );
        }

        #[tokio::test]
        async fn unknown_hash() {
            assert_eq!(
                retry_on_rate_limiting!(client().transaction(*UNKNOWN_TX_HASH).await)
                    .unwrap()
                    .status,
                Status::NotReceived
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
            let error =
                retry_on_rate_limiting!(client().transaction_status(*INVALID_TX_HASH).await)
                    .unwrap_err();
            assert_matches!(
                error,
                SequencerError::StarknetError(e) => assert_eq!(e.code, StarknetErrorCode::OutOfRangeTransactionHash)
            );
        }

        #[tokio::test]
        async fn unknown_hash() {
            assert_eq!(
                retry_on_rate_limiting!(client().transaction_status(*UNKNOWN_TX_HASH).await)
                    .unwrap()
                    .tx_status,
                Status::NotReceived
            );
        }
    }
}
