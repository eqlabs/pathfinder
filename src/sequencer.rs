//! StarkNet L2 sequencer client.
pub mod reply;
pub mod request;
mod serde;

use self::reply::BlockReply;
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

/// Helper function which simplifies the handling of optional block IDs in queries.
fn block_id_str(block: Option<U256>) -> String {
    block
        .map(|b| b.to_string())
        .unwrap_or_else(|| "null".to_string())
}

impl Client {
    /// Creates a new sequencer client, `sequencer_url` needs to be a valid _base URL_.
    pub fn new(sequencer_url: Url) -> Self {
        debug_assert!(!sequencer_url.cannot_be_a_base());
        Self { sequencer_url }
    }

    /// Gets block by id.
    pub async fn block(&self, block_id: U256) -> Result<reply::Block> {
        self.get_block(Some(block_id)).await
    }

    /// Gets latest block.
    pub async fn latest_block(&self) -> Result<reply::Block> {
        self.get_block(None).await
    }

    /// Helper function to wrap block query. `None` as `block_id` means latest block available.
    async fn get_block(&self, block_id: Option<U256>) -> Result<reply::Block> {
        let block_id = block_id_str(block_id);
        let resp =
            reqwest::get(self.build_query("get_block", &[("blockId", block_id.as_str())])).await?;
        let resp = resp.text().await?;
        serde_json::from_str::<BlockReply>(resp.as_str())?.try_into()
    }

    /// Performs a `call` on contract's function. Call result is not stored in L2, as opposed to `invoke`.
    pub async fn call(
        &self,
        payload: request::Call,
        block_id: Option<U256>,
    ) -> Result<reply::Call> {
        let block_id = block_id_str(block_id);
        let url = self.build_query("call_contract", &[("blockId", block_id.as_str())]);
        let client = reqwest::Client::new();
        let resp = client.post(url).json(&payload).send().await?;
        let resp = resp.text().await?;
        serde_json::from_str::<reply::CallReply>(resp.as_str())?.try_into()
    }

    /// Gets contract's code and ABI.
    pub async fn code(&self, contract_addr: H256, block_id: Option<U256>) -> Result<reply::Code> {
        let block_id = block_id_str(block_id);
        let resp = reqwest::get(self.build_query(
            "get_code",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("blockId", block_id.as_str()),
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
        block_id: Option<U256>,
    ) -> Result<H256> {
        let block_id = block_id_str(block_id);
        let resp = reqwest::get(self.build_query(
            "get_storage_at",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("key", key.to_string().as_str()),
                ("blockId", block_id.as_str()),
            ],
        ))
        .await?;
        let resp = resp.text().await?;
        let json_val: Value = serde_json::from_str(resp.as_str())?;

        if let Value::String(s) = json_val {
            let value = serde::from_relaxed_hex_str::<
                H256,
                { H256::len_bytes() },
                { H256::len_bytes() * 2 },
            >(s.as_str())?;
            Ok(value)
        } else {
            let error = from_value::<reply::starknet::Error>(json_val)?;
            Err(anyhow::Error::new(error))
        }
    }

    /// Gets transaction by id.
    pub async fn transaction(&self, transaction_id: U256) -> Result<reply::Transaction> {
        let resp = reqwest::get(self.build_query(
            "get_transaction",
            &[("transactionId", transaction_id.to_string().as_str())],
        ))
        .await?;
        let resp = resp.text().await?;
        let resp = serde_json::from_str(resp.as_str())?;
        Ok(resp)
    }

    /// Gets transaction status by transaction id.
    pub async fn transaction_status(
        &self,
        transaction_id: U256,
    ) -> Result<reply::TransactionStatus> {
        let resp = reqwest::get(self.build_query(
            "get_transaction_status",
            &[("transactionId", transaction_id.to_string().as_str())],
        ))
        .await?;
        let resp = resp.text().await?;
        let resp = serde_json::from_str(resp.as_str())?;
        Ok(resp)
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
// Suppress `unwrap_or_else(|_| panic!("failed...")` when using `failed_in!()`
#[allow(clippy::expect_fun_call)]
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
        static ref VALID_CONTRACT_ADDR: H256 = H256::from_str("0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc").unwrap();
        static ref INVALID_CONTRACT_ADDR: H256 = H256::from_str("0x14eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc").unwrap();
    }

    // Alpha2 network client factory helper
    fn client() -> Client {
        const URL: &str = "https://alpha2.starknet.io/";
        Client::new(Url::parse(URL).unwrap())
    }

    mod block {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn genesis() {
            client().block(U256::zero()).await.unwrap();
        }

        #[tokio::test]
        async fn latest() {
            client().latest_block().await.unwrap();
        }

        #[tokio::test]
        async fn contains_l1_l2_msg() {
            client().block(U256::from(20056)).await.unwrap();
        }

        #[tokio::test]
        async fn without_l1_l2_msg() {
            client().block(U256::from(43740)).await.unwrap();
        }

        #[tokio::test]
        async fn not_found() {
            assert_eq!(
                client()
                    .block(U256::max_value())
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::BlockNotFound
            );
        }
    }

    mod call {
        use super::*;
        use pretty_assertions::assert_eq;

        lazy_static::lazy_static! {
            static ref VALID_ENTRY_POINT: H256 = H256::from_str("0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320").unwrap();
        }

        #[tokio::test]
        async fn invalid_entry_point() {
            assert_eq!(
                client()
                    .call(
                        request::Call {
                            calldata: vec![],
                            contract_address: *VALID_CONTRACT_ADDR,
                            entry_point_selector: H256::zero(),
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
        async fn transaction_failed() {
            assert_eq!(
                client()
                    .call(
                        request::Call {
                            calldata: vec![],
                            contract_address: *VALID_CONTRACT_ADDR,
                            entry_point_selector: *VALID_ENTRY_POINT,
                        },
                        Some(U256::from(15947)),
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
                        },
                        Some(U256::from(10000)),
                    )
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::UninitializedContract
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
                    },
                    Some(U256::from(15947)),
                )
                .await
                .unwrap();
        }
    }

    mod code {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn invalid_contract() {
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
        async fn invalid_block() {
            assert_eq!(
                client()
                    .code(*VALID_CONTRACT_ADDR, Some(U256::max_value()))
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::BlockNotFound
            );
        }

        #[tokio::test]
        async fn success() {
            client()
                .code(*VALID_CONTRACT_ADDR, Some(U256::from(15947)))
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
        async fn invalid_contract() {
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
        async fn invalid_block() {
            assert_eq!(
                client()
                    .storage(*VALID_CONTRACT_ADDR, *VALID_KEY, Some(U256::max_value()))
                    .await
                    .map_err(|e| e.downcast::<Error>().unwrap().code)
                    .unwrap_err(),
                ErrorCode::BlockNotFound
            );
        }

        #[tokio::test]
        async fn success() {
            client()
                .storage(*VALID_CONTRACT_ADDR, *VALID_KEY, Some(U256::from(15947)))
                .await
                .unwrap();
        }
    }

    mod transaction {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn first() {
            assert_eq!(
                client().transaction(U256::zero()).await.unwrap().status,
                Status::AcceptedOnChain
            );
        }

        #[tokio::test]
        async fn rejected() {
            assert_eq!(
                client()
                    .transaction(U256::from(162531))
                    .await
                    .unwrap()
                    .status,
                Status::Rejected
            );
        }

        #[tokio::test]
        async fn contains_l1_l2_msg() {
            assert_eq!(
                client()
                    .transaction(U256::from(162531))
                    .await
                    .unwrap()
                    .status,
                Status::Rejected
            );
        }

        #[tokio::test]
        async fn not_received() {
            assert_eq!(
                client().transaction(u128::MAX.into()).await.unwrap().status,
                Status::NotReceived
            );
        }
    }

    mod transaction_status {
        use super::*;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn first() {
            assert_eq!(
                client()
                    .transaction_status(U256::zero())
                    .await
                    .unwrap()
                    .tx_status
                    .unwrap(),
                Status::AcceptedOnChain
            );
        }

        #[tokio::test]
        async fn rejected() {
            assert_eq!(
                client()
                    .transaction_status(U256::from(162531))
                    .await
                    .unwrap()
                    .tx_status
                    .unwrap(),
                Status::Rejected
            );
        }

        #[tokio::test]
        async fn contains_l1_l2_msg() {
            assert_eq!(
                client()
                    .transaction_status(U256::from(162531))
                    .await
                    .unwrap()
                    .tx_status
                    .unwrap(),
                Status::Rejected
            );
        }

        #[tokio::test]
        async fn not_received() {
            assert_eq!(
                client()
                    .transaction_status(U256::max_value())
                    .await
                    .unwrap()
                    .tx_status
                    .unwrap(),
                Status::NotReceived
            );
        }
    }
}
