//! StarkNet L2 sequencer client.
pub mod reply;
pub mod request;
mod serde;

use self::reply::IntoResult;
use anyhow::Result;
use reqwest::Url;
use serde_json::{from_value, Value};
use std::fmt::Debug;
use web3::types::{H256, U256};

/// StarkNet sequencer client using REST API.
#[derive(Debug)]
pub struct Client {
    /// StarkNet sequencer URL.
    sequencer_url: Url,
}

/// Helper enum which simplifies the handling of optional block IDs in queries.
enum BlockId {
    Valid(String),
    Null,
}

impl BlockId {
    /// Constructor, internally converts `block_id` to String if it is `Some()`.
    fn new(block_id: Option<U256>) -> Self {
        match block_id {
            Some(value) => Self::Valid(value.to_string()),
            None => Self::Null,
        }
    }
    /// Returns string slice representing block id or `"null"` if there was none specified.
    fn as_str(&self) -> &str {
        match self {
            Self::Valid(s) => s.as_str(),
            Self::Null => "null",
        }
    }
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
        let block_id = BlockId::new(block_id);
        let resp =
            reqwest::get(self.build_query("get_block", &[("blockId", block_id.as_str())])).await?;
        let resp_txt = resp.text().await?;
        let resp_struct = serde_json::from_str::<reply::BlockReply>(resp_txt.as_str())?;
        let resp_inner = resp_struct.into_result()?;
        Ok(resp_inner)
    }

    /// Performs a `call` on contract's function. Call result is not stored in L2, as opposed to `invoke`.
    pub async fn call(&self, payload: request::Call, block_id: Option<U256>) -> Result<Vec<H256>> {
        let block_id = BlockId::new(block_id);
        let url = self.build_query("call_contract", &[("blockId", block_id.as_str())]);
        let client = reqwest::Client::new();
        let resp = client.post(url).json(&payload).send().await?;
        let resp_txt = resp.text().await?;
        let resp_struct = serde_json::from_str::<reply::CallReply>(resp_txt.as_str())?;
        let resp_inner = resp_struct.into_result()?;
        Ok(resp_inner)
    }

    /// Gets contract's code and ABI.
    pub async fn code(&self, contract_addr: H256, block_id: Option<U256>) -> Result<reply::Code> {
        let block_id = BlockId::new(block_id);
        let resp = reqwest::get(self.build_query(
            "get_code",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("blockId", block_id.as_str()),
            ],
        ))
        .await?;
        let resp_txt = resp.text().await?;
        let resp_struct = serde_json::from_str::<reply::CodeReply>(resp_txt.as_str())?;
        let resp_inner = resp_struct.into_result()?;
        Ok(resp_inner)
    }

    /// Gets storage value associated with a `key` for a prticular contract.
    pub async fn storage(
        &self,
        contract_addr: H256,
        key: U256,
        block_id: Option<U256>,
    ) -> Result<H256> {
        let block_id = BlockId::new(block_id);
        let resp = reqwest::get(self.build_query(
            "get_storage_at",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("key", key.to_string().as_str()),
                ("blockId", block_id.as_str()),
            ],
        ))
        .await?;
        let resp_txt = resp.text().await?;
        let json_val: Value = serde_json::from_str(resp_txt.as_str())?;

        if let Value::String(s) = json_val {
            let value = serde::from_relaxed_hex_str::<
                H256,
                { H256::len_bytes() },
                { H256::len_bytes() * 2 },
            >(s.as_str())?;
            Ok(value)
        } else {
            let error = from_value::<reply::StarknetError>(json_val)?;
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
        let resp_txt = resp.text().await?;
        let resp_struct = serde_json::from_str(resp_txt.as_str())?;
        Ok(resp_struct)
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
        let resp_txt = resp.text().await?;
        let resp_struct = serde_json::from_str(resp_txt.as_str())?;
        Ok(resp_struct)
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
        reply::{starknet_error::Code, transaction::Status, StarknetError},
        *,
    };
    use pretty_assertions::assert_eq;
    use std::str::FromStr;
    use web3::types::U256;

    // Helper macro for meaningful `expect()`s
    macro_rules! failed_in {
        ($line:ident) => {
            format!("failed in line {}", $line).as_str()
        };
    }

    // Alpha2 network client factory helper
    fn client() -> Client {
        const URL: &str = "https://alpha2.starknet.io/";
        Client::new(Url::parse(URL).unwrap())
    }

    #[tokio::test]
    async fn latest_block() {
        client()
            .latest_block()
            .await
            .expect("Correctly deserialized reply");
    }

    #[tokio::test]
    async fn block() {
        let input_vs_expect_ok = [
            // The genesis block, previous_block_id is -1
            (U256::zero(), true, line!()),
            // This block contains a txn which includes a L1 to L2 message
            (U256::from(20056), true, line!()),
            // This block does not contain any txns which include a L1 to L2 message
            (U256::from(43740), true, line!()),
            // Causes BlockNotFound
            (U256::max_value(), false, line!()),
        ];
        let client = client();

        for (input, expect_ok, line) in input_vs_expect_ok {
            let actual = client
                .block(input)
                .await
                .map_err(|e| e.downcast::<StarknetError>().unwrap().code);
            if expect_ok {
                actual.expect(failed_in!(line));
            } else {
                assert_eq!(actual.expect_err(failed_in!(line)), Code::BlockNotFound);
            }
        }
    }

    #[tokio::test]
    async fn call() {
        let invalid_entry_point = H256::zero();
        let valid_entry_point =
            H256::from_str("0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320")
                .unwrap();

        let inputs_vs_exp_error = [
            // (block_id, entry_point, calldata, expected_error, line)
            (
                None,
                invalid_entry_point,
                vec![],
                Some(Code::EntryPointNotFound),
                line!(),
            ),
            (
                Some(U256::from(15947)),
                invalid_entry_point,
                vec![U256::from(12)],
                Some(Code::EntryPointNotFound),
                line!(),
            ),
            (
                Some(U256::from(15947)),
                valid_entry_point,
                vec![],
                Some(Code::TransactionFailed),
                line!(),
            ),
            (
                Some(U256::from(10000)),
                valid_entry_point,
                vec![U256::from(34)],
                Some(Code::UninitializedContract),
                line!(),
            ),
            (
                Some(U256::from(15947)),
                valid_entry_point,
                vec![U256::from(56)],
                None, // Success
                line!(),
            ),
        ];
        let client = client();

        for (block_id, entry_point_selector, calldata, exp_error, line) in inputs_vs_exp_error {
            let actual = client
                .call(
                    request::Call {
                        calldata,
                        contract_address: H256::from_str(
                            "0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc",
                        )
                        .unwrap(),
                        entry_point_selector,
                    },
                    block_id,
                )
                .await
                .map_err(|e| e.downcast::<StarknetError>().unwrap().code);
            if let Some(expected_error) = exp_error {
                assert_eq!(actual.expect_err(failed_in!(line)), expected_error);
            } else {
                actual.expect(failed_in!(line));
            }
        }
    }

    #[tokio::test]
    async fn code() {
        let valid_contract =
            H256::from_str("0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc")
                .unwrap();
        let invalid_contract =
            H256::from_str("0x14eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc")
                .unwrap();
        let inputs_vs_exp_error = [
            // (contract_addr, block_id, expected_error, line)
            (
                invalid_contract,
                None,
                Some(Code::OutOfRangeContractAddress),
                line!(),
            ),
            (
                valid_contract,
                Some(U256::max_value()),
                Some(Code::BlockNotFound),
                line!(),
            ),
            // Success
            (valid_contract, Some(U256::from(15947)), None, line!()),
        ];
        let client = client();

        for (contract_addr, block_id, exp_error, line) in inputs_vs_exp_error {
            let actual = client
                .code(contract_addr, block_id)
                .await
                .map_err(|e| e.downcast::<StarknetError>().unwrap().code);
            if let Some(expected_error) = exp_error {
                assert_eq!(actual.expect_err(failed_in!(line)), expected_error);
            } else {
                actual.expect(failed_in!(line));
            }
        }
    }

    #[tokio::test]
    async fn storage() {
        let valid_contract =
            H256::from_str("0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc")
                .unwrap();
        let invalid_contract =
            H256::from_str("0x14eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc")
                .unwrap();
        let valid_key = U256::from_str_radix(
            "916907772491729262376534102982219947830828984996257231353398618781993312401",
            10,
        )
        .unwrap();
        let inputs_vs_exp_error = [
            // (contract_addr, key, block_id, expected_error, line)
            (valid_contract, valid_key, None, None, line!()),
            (
                invalid_contract,
                valid_key,
                None,
                Some(Code::OutOfRangeContractAddress),
                line!(),
            ),
            (
                valid_contract,
                U256::max_value(),
                None,
                Some(Code::OutOfRangeStorageKey),
                line!(),
            ),
            (
                valid_contract,
                valid_key,
                Some(U256::max_value()),
                Some(Code::BlockNotFound),
                line!(),
            ),
            (
                // Success
                valid_contract,
                valid_key,
                Some(U256::from(15946)),
                None,
                line!(),
            ),
        ];
        let client = client();

        for (contract_addr, key, block_id, exp_error, line) in inputs_vs_exp_error {
            let actual = client
                .storage(contract_addr, key, block_id)
                .await
                .map_err(|e| e.downcast::<StarknetError>().unwrap().code);
            if let Some(expected_error) = exp_error {
                assert_eq!(actual.expect_err(failed_in!(line)), expected_error);
            } else {
                actual.expect(failed_in!(line));
            }
        }
    }

    #[tokio::test]
    async fn transaction_and_transaction_status() {
        let input_vs_txn_status = [
            (U256::zero(), Status::AcceptedOnChain, line!()),
            (U256::from(162531), Status::Rejected, line!()),
            // Txn containing a L1 to L2 message
            (U256::from(186764), Status::AcceptedOnChain, line!()),
            (u128::MAX.into(), Status::NotReceived, line!()),
        ];
        let client = client();

        for (txn_id, txn_status, line) in input_vs_txn_status {
            assert_eq!(
                client
                    .transaction(txn_id)
                    .await
                    .expect(failed_in!(line))
                    .status,
                txn_status
            );
            assert_eq!(
                client
                    .transaction_status(txn_id)
                    .await
                    .expect(failed_in!(line))
                    .tx_status
                    .expect(failed_in!(line)),
                txn_status
            );
        }
    }
}
