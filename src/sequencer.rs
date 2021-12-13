//! StarkNet L2 sequencer client.
pub mod reply;
pub mod request;

use self::reply::BlockReply;
use crate::serde::from_relaxed_hex_str;
use anyhow::Result;
use reqwest::Url;
use serde_json::{from_value, Value};
use std::{convert::TryInto, fmt::Debug};
use web3::types::{H256, U256};

/// StarkNet sequencer client using REST API.
#[derive(Debug)]
pub struct Client {
    /// StarkNet sequencer URL.
    sequencer_url: Url,
}

/// Helper function which simplifies the handling of optional block hashes in queries.
fn block_hash_str(hash: Option<H256>) -> (String, String) {
    hash.map(|h| ("blockHash".to_string(), format!("0x{:x}", h)))
        .unwrap_or_else(|| ("blockId".to_string(), "null".to_string()))
}

impl Client {
    /// Creates a new sequencer client, `sequencer_url` needs to be a valid _base URL_.
    pub fn new(sequencer_url: Url) -> Self {
        debug_assert!(!sequencer_url.cannot_be_a_base());
        Self { sequencer_url }
    }

    /// Gets block by hash.
    pub async fn block(&self, block_hash: H256) -> Result<reply::Block> {
        self.get_block(Some(block_hash)).await
    }

    /// Gets block by number.
    pub async fn block_by_number(&self, block_number: u64) -> Result<reply::Block> {
        let resp = reqwest::get(self.build_query(
            "get_block_hash_by_id",
            &[("blockId", &block_number.to_string())],
        ))
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

        self.get_block(Some(block_hash)).await
    }

    /// Gets latest block.
    pub async fn latest_block(&self) -> Result<reply::Block> {
        self.get_block(None).await
    }

    /// Helper function to wrap block query. `None` as `block_id` means latest block available.
    async fn get_block(&self, block_hash: Option<H256>) -> Result<reply::Block> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = reqwest::get(self.build_query("get_block", &[(&tag, &hash)])).await?;
        let resp = resp.text().await?;
        serde_json::from_str::<BlockReply>(resp.as_str())?.try_into()
    }

    /// Performs a `call` on contract's function. Call result is not stored in L2, as opposed to `invoke`.
    pub async fn call(
        &self,
        payload: request::Call,
        block_hash: Option<H256>,
    ) -> Result<reply::Call> {
        let (tag, hash) = block_hash_str(block_hash);
        let url = self.build_query("call_contract", &[(&tag, &hash)]);
        let client = reqwest::Client::new();
        let resp = client.post(url).json(&payload).send().await?;
        let resp = resp.text().await?;
        serde_json::from_str::<reply::CallReply>(resp.as_str())?.try_into()
    }

    /// Gets contract's code and ABI.
    pub async fn code(&self, contract_addr: H256, block_hash: Option<H256>) -> Result<reply::Code> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = reqwest::get(self.build_query(
            "get_code",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                (&tag, &hash),
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
        block_hash: Option<H256>,
    ) -> Result<H256> {
        let (tag, hash) = block_hash_str(block_hash);
        let resp = reqwest::get(self.build_query(
            "get_storage_at",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("key", key.to_string().as_str()),
                (&tag, &hash),
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
        static ref UNKNOWN_BLOCK_HASH: H256 = H256::from_str("0x017adea6567a9f605d5011ac915bdda56dc1db37e17a7057b3dd7fa99c4ba30b").unwrap();
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

    mod block {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn genesis() {
            client().block(*GENESIS_BLOCK_HASH).await.unwrap();
        }

        #[tokio::test]
        async fn latest() {
            client().latest_block().await.unwrap();
        }

        #[tokio::test]
        async fn block_without_block_hash_field() {
            client()
                .block(
                    H256::from_str(
                        "01cf37f162c3fa3b57c1c4324c240b0c8c65bb5a15e039817a3023b9890e94d1",
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn unknown() {
            // Use valid hash from mainnet
            assert_eq!(
                client()
                    .block(*UNKNOWN_BLOCK_HASH)
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
                    .block(*INVALID_BLOCK_HASH)
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
            client().block_by_number(0).await.unwrap();
        }

        #[tokio::test]
        async fn invalid() {
            assert_eq!(
                client()
                    .block_by_number(u64::MAX)
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
                        None,
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
                        None,
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
                        Some(*CONTRACT_BLOCK_HASH),
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
                        Some(*GENESIS_BLOCK_HASH),
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
                        Some(*INVALID_BLOCK_HASH),
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
                        Some(*UNKNOWN_BLOCK_HASH),
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::BlockNotFound
            );
        }

        #[tokio::test]
        async fn success() {
            client()
                .call(
                    request::Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    Some(*CONTRACT_BLOCK_HASH),
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
                    .code(*INVALID_CONTRACT_ADDR, None)
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeContractAddress
            );
        }

        #[tokio::test]
        async fn unknown_contract_address() {
            // Returns empty code and abi
            client().code(*UNKNOWN_CONTRACT_ADDR, None).await.unwrap();
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            assert_eq!(
                client()
                    .code(*VALID_CONTRACT_ADDR, Some(*INVALID_BLOCK_HASH))
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
                    .code(*VALID_CONTRACT_ADDR, Some(*UNKNOWN_BLOCK_HASH))
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::BlockNotFound
            );
        }

        #[tokio::test]
        async fn success() {
            client()
                .code(*VALID_CONTRACT_ADDR, Some(*CONTRACT_BLOCK_HASH))
                .await
                .map_err(|e| e.downcast::<Error>().unwrap().code)
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
                    .storage(*INVALID_CONTRACT_ADDR, *VALID_KEY, None)
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
                    .storage(*VALID_CONTRACT_ADDR, U256::max_value(), None)
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
                    .storage(*VALID_CONTRACT_ADDR, *VALID_KEY, Some(*UNKNOWN_BLOCK_HASH))
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
                    .storage(*VALID_CONTRACT_ADDR, *VALID_KEY, Some(*INVALID_BLOCK_HASH))
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::OutOfRangeBlockHash
            );
        }

        #[tokio::test]
        async fn success() {
            client()
                .storage(*VALID_CONTRACT_ADDR, *VALID_KEY, Some(*CONTRACT_BLOCK_HASH))
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
