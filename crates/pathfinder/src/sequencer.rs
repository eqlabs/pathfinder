//! StarkNet L2 sequencer client.
pub mod reply;
pub mod request;

use self::reply::BlockReply;
use crate::{
    rpc::types::{BlockHashOrTag, BlockNumberOrTag, Tag},
    serde::from_relaxed_hex_str,
};
use anyhow::Result;
use reqwest::Url;
use serde_json::{from_value, Value};
use std::{borrow::Cow, convert::TryInto, fmt::Debug};
use web3::types::{H256, U256};

/// StarkNet sequencer client using REST API.
#[derive(Debug)]
pub struct Client {
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

impl Client {
    /// Creates a new sequencer client, `sequencer_url` needs to be a valid _base URL_.
    pub fn new(sequencer_url: Url) -> Self {
        debug_assert!(!sequencer_url.cannot_be_a_base());
        Self { sequencer_url }
    }

    /// Gets block by number.
    pub async fn block_by_number(&self, block_number: BlockNumberOrTag) -> Result<reply::Block> {
        let block_hash = match block_number {
            BlockNumberOrTag::Number(n) => {
                let resp = reqwest::get(
                    self.build_query("get_block_hash_by_id", &[("blockId", &n.to_string())]),
                )
                .await
                .unwrap();
                let resp = resp.text().await?;

                if let Ok(e) = serde_json::from_str::<self::reply::starknet::Error>(resp.as_str()) {
                    return Err(e.into());
                }

                let resp = resp
                    .strip_prefix('\"')
                    .ok_or(anyhow::anyhow!("quoted hash string expected"))?;
                let resp = resp
                    .strip_suffix('\"')
                    .ok_or(anyhow::anyhow!("quoted hash string expected"))?;
                let block_hash = crate::serde::from_relaxed_hex_str::<
                    H256,
                    { H256::len_bytes() },
                    { H256::len_bytes() * 2 },
                >(resp)?;
                BlockHashOrTag::Hash(block_hash)
            }
            BlockNumberOrTag::Tag(tag) => BlockHashOrTag::Tag(tag),
        };
        self.block_by_hash(block_hash).await
    }

    /// Get block by hash.
    pub async fn block_by_hash(&self, block_hash: BlockHashOrTag) -> Result<reply::Block> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = reqwest::get(self.build_query("get_block", &[(tag, &hash)])).await?;
        let resp = resp.text().await?;
        serde_json::from_str::<BlockReply>(resp.as_str())?.try_into()
    }

    /// Performs a `call` on contract's function. Call result is not stored in L2, as opposed to `invoke`.
    pub async fn call(
        &self,
        payload: request::Call,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Call> {
        let (tag, hash) = block_hash_str(block_hash);
        let url = self.build_query("call_contract", &[(tag, &hash)]);
        let client = reqwest::Client::new();
        let resp = client.post(url).json(&payload).send().await?;
        let resp = resp.text().await?;
        serde_json::from_str::<reply::CallReply>(resp.as_str())?.try_into()
    }

    /// Gets contract's code and ABI.
    pub async fn code(
        &self,
        contract_addr: H256,
        block_hash: BlockHashOrTag,
    ) -> Result<reply::Code> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = reqwest::get(self.build_query(
            "get_code",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                (tag, &hash),
            ],
        ))
        .await?;
        let resp = resp.text().await?;
        serde_json::from_str::<reply::CodeReply>(resp.as_str())?.try_into()
    }

    /// Gets storage value associated with a `key` for a prticular contract.
    pub async fn storage(
        &self,
        contract_addr: H256,
        key: U256,
        block_hash: BlockHashOrTag,
    ) -> Result<H256> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = reqwest::get(self.build_query(
            "get_storage_at",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("key", key.to_string().as_str()),
                (tag, &hash),
            ],
        ))
        .await?;
        let resp = resp.text().await?;
        let json_val: Value = serde_json::from_str(resp.as_str())?;

        if let Value::String(s) = json_val {
            let value =
                from_relaxed_hex_str::<H256, { H256::len_bytes() }, { H256::len_bytes() * 2 }>(
                    s.as_str(),
                )?;
            Ok(value)
        } else {
            let error = from_value::<reply::starknet::Error>(json_val)?;
            Err(anyhow::Error::new(error))
        }
    }

    /// Gets transaction by hash.
    pub async fn transaction(&self, transaction_hash: H256) -> Result<reply::Transaction> {
        let resp = reqwest::get(self.build_query(
            "get_transaction",
            &[(
                "transactionHash",
                format!("{:#x}", transaction_hash).as_str(),
            )],
        ))
        .await?;
        let resp = resp.text().await?;
        serde_json::from_str::<reply::TransactionReply>(resp.as_str())?.try_into()
    }

    /// Gets transaction status by transaction hash.
    pub async fn transaction_status(
        &self,
        transaction_hash: H256,
    ) -> Result<reply::TransactionStatus> {
        let resp = reqwest::get(self.build_query(
            "get_transaction_status",
            &[(
                "transactionHash",
                format!("{:#x}", transaction_hash).as_str(),
            )],
        ))
        .await?;
        let resp = resp.text().await?;
        serde_json::from_str::<reply::TransactionStatusReply>(resp.as_str())?.try_into()
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
    use super::{
        reply::{
            starknet::{Error, ErrorCode},
            transaction::Status,
        },
        *,
    };
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

    // Alpha4 network client factory helper
    fn client() -> Client {
        const URL: &str = "https://alpha4.starknet.io/";
        Client::new(Url::parse(URL).unwrap())
    }

    mod block_by_hash {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        #[ignore = "currently causes HTTP 504"]
        async fn genesis() {
            client()
                .block_by_hash(BlockHashOrTag::Hash(*GENESIS_BLOCK_HASH))
                .await
                .unwrap();
        }

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
        #[ignore = "currently causes HTTP 504"]
        async fn block_without_block_hash_field() {
            client()
                .block_by_hash(BlockHashOrTag::Hash(
                    H256::from_str(
                        "01cf37f162c3fa3b57c1c4324c240b0c8c65bb5a15e039817a3023b9890e94d1",
                    )
                    .unwrap(),
                ))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn unknown() {
            // Use valid hash from mainnet
            assert_eq!(
                client()
                    .block_by_hash(BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH))
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::BlockNotFound
            );
        }

        #[tokio::test]
        async fn invalid() {
            // Invalid block hash
            assert_eq!(
                client()
                    .block_by_hash(BlockHashOrTag::Hash(*INVALID_BLOCK_HASH))
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeBlockHash
            );
        }
    }

    mod block_by_number {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn genesis() {
            client()
                .block_by_number(BlockNumberOrTag::Number(0))
                .await
                .unwrap();
        }

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
            assert_eq!(
                client()
                    .block_by_number(BlockNumberOrTag::Number(u64::MAX))
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::MalformedRequest
            );
        }
    }

    mod call {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn invalid_entry_point() {
            assert_eq!(
                client()
                    .call(
                        request::Call {
                            calldata: vec![U256::from(1234)],
                            contract_address: *VALID_CONTRACT_ADDR,
                            entry_point_selector: H256::zero(),
                            signature: vec![],
                        },
                        BlockHashOrTag::Tag(Tag::Latest),
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::EntryPointNotFound
            );
        }

        #[tokio::test]
        async fn invalid_contract_address() {
            assert_eq!(
                client()
                    .call(
                        request::Call {
                            calldata: vec![U256::from(1234)],
                            contract_address: *INVALID_CONTRACT_ADDR,
                            entry_point_selector: *VALID_ENTRY_POINT,
                            signature: vec![],
                        },
                        BlockHashOrTag::Tag(Tag::Latest),
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeContractAddress
            );
        }

        #[tokio::test]
        async fn invalid_call_data() {
            assert_eq!(
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
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::TransactionFailed
            );
        }

        #[tokio::test]
        async fn uninitialized_contract() {
            assert_eq!(
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
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::UninitializedContract
            );
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            assert_eq!(
                client()
                    .call(
                        request::Call {
                            calldata: vec![U256::from(1234)],
                            contract_address: *VALID_CONTRACT_ADDR,
                            entry_point_selector: *VALID_ENTRY_POINT,
                            signature: vec![],
                        },
                        BlockHashOrTag::Hash(*INVALID_BLOCK_HASH),
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeBlockHash
            );
        }

        #[tokio::test]
        async fn unknown_block_hash() {
            assert_eq!(
                client()
                    .call(
                        request::Call {
                            calldata: vec![U256::from(1234)],
                            contract_address: *VALID_CONTRACT_ADDR,
                            entry_point_selector: *VALID_ENTRY_POINT,
                            signature: vec![],
                        },
                        BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH),
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::BlockNotFound
            );
        }

        #[tokio::test]
        async fn latest_invoke_block() {
            client()
                .call(
                    request::Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Hash(*CONTRACT_BLOCK_HASH),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn latest_block() {
            client()
                .call(
                    request::Call {
                        calldata: vec![U256::from(1234)],
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
                        calldata: vec![U256::from(1234)],
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

    mod code {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn invalid_contract_address() {
            assert_eq!(
                client()
                    .code(*INVALID_CONTRACT_ADDR, BlockHashOrTag::Tag(Tag::Latest))
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeContractAddress
            );
        }

        #[tokio::test]
        async fn unknown_contract_address() {
            // Returns empty code and abi
            client()
                .code(*UNKNOWN_CONTRACT_ADDR, BlockHashOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            assert_eq!(
                client()
                    .code(
                        *VALID_CONTRACT_ADDR,
                        BlockHashOrTag::Hash(*INVALID_BLOCK_HASH)
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeBlockHash
            );
        }

        #[tokio::test]
        async fn unknown_block_hash() {
            assert_eq!(
                client()
                    .code(
                        *VALID_CONTRACT_ADDR,
                        BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH)
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::BlockNotFound
            );
        }

        #[tokio::test]
        async fn latest_invoke_block() {
            client()
                .code(
                    *VALID_CONTRACT_ADDR,
                    BlockHashOrTag::Hash(*CONTRACT_BLOCK_HASH),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn latest_block() {
            client()
                .code(*VALID_CONTRACT_ADDR, BlockHashOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn pending_block() {
            client()
                .code(*VALID_CONTRACT_ADDR, BlockHashOrTag::Tag(Tag::Pending))
                .await
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
            assert_eq!(
                client()
                    .storage(
                        *INVALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Tag(Tag::Latest)
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeContractAddress
            );
        }

        #[tokio::test]
        async fn invalid_key() {
            assert_eq!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        U256::max_value(),
                        BlockHashOrTag::Tag(Tag::Latest)
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeStorageKey
            );
        }

        #[tokio::test]
        async fn unknown_block_hash() {
            assert_eq!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH)
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::BlockNotFound
            );
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            assert_eq!(
                client()
                    .storage(
                        *VALID_CONTRACT_ADDR,
                        *VALID_KEY,
                        BlockHashOrTag::Hash(*INVALID_BLOCK_HASH)
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeBlockHash
            );
        }

        #[tokio::test]
        async fn latest_invoke_block() {
            client()
                .storage(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Hash(*CONTRACT_BLOCK_HASH),
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
        use super::*;
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
                client()
                    .transaction(*INVALID_TX_HASH)
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeTransactionHash
            );
        }

        #[tokio::test]
        async fn unknown_hash() {
            assert_eq!(
                client().transaction(*UNKNOWN_TX_HASH).await.unwrap().status,
                Status::NotReceived
            );
        }
    }

    mod transaction_status {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn accepted() {
            assert_eq!(
                client()
                    .transaction_status(*VALID_TX_HASH)
                    .await
                    .unwrap()
                    .tx_status
                    .unwrap(),
                Status::AcceptedOnL1
            );
        }

        #[tokio::test]
        async fn invalid_hash() {
            assert_eq!(
                client()
                    .transaction_status(*INVALID_TX_HASH)
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeTransactionHash
            );
        }

        #[tokio::test]
        async fn unknown_hash() {
            assert_eq!(
                client()
                    .transaction_status(*UNKNOWN_TX_HASH)
                    .await
                    .unwrap()
                    .tx_status
                    .unwrap(),
                Status::NotReceived
            );
        }
    }
}
