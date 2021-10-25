//! StarkNet L2 sequencer client.
pub mod reply;
pub mod request;
mod serde;

use anyhow::Result;
use reqwest::Url;
use std::fmt::Debug;
use web3::types::{H256, U256};

/// StarkNet sequencer client using REST API.
#[derive(Debug)]
pub struct Client {
    /// StarkNet sequencer URL.
    sequencer_url: Url,
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
        let id_string = if let Some(id) = block_id {
            id.to_string()
        } else {
            "null".to_owned()
        };
        let resp =
            reqwest::get(self.build_query("get_block", &[("blockId", id_string.as_str())])).await?;
        let resp_txt = resp.text().await?;
        let block = serde_json::from_str(resp_txt.as_str())?;
        Ok(block)
    }

    /// Performs a `call` on contract's function. Call result is not stored in L2, as opposed to `invoke`.
    pub async fn call(&self, payload: request::Call) -> Result<reply::Call> {
        let url = self.build_query("call_contract", &[("blockId", "null")]);
        let client = reqwest::Client::new();
        let resp = client.post(url).json(&payload).send().await?;
        let resp_txt = resp.text().await?;
        let resp_struct = serde_json::from_str(resp_txt.as_str())?;
        Ok(resp_struct)
    }

    /// Gets contract's code and ABI.
    pub async fn code(&self, contract_addr: H256) -> Result<reply::Code> {
        let resp = reqwest::get(self.build_query(
            "get_code",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("blockId", "null"),
            ],
        ))
        .await?;
        let resp_txt = resp.text().await?;
        let resp_struct = serde_json::from_str(resp_txt.as_str())?;
        Ok(resp_struct)
    }

    /// Gets storage value associated with a `key` for a prticular contract.
    pub async fn storage(&self, contract_addr: H256, key: U256) -> Result<H256> {
        let resp = reqwest::get(self.build_query(
            "get_storage_at",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("key", key.to_string().as_str()),
                ("blockId", "null"),
            ],
        ))
        .await?;
        let resp_txt = resp.text().await?;
        let resp_str = resp_txt.as_str();
        // API returns a quoted string literal, ie. "\"0x123\"".
        let msg = "Expected a double-quoted, 0x-prefixed hex string";
        let no_prefix = resp_str.strip_prefix('"').ok_or(anyhow::anyhow!(msg))?;
        let unquoted = no_prefix.strip_suffix('"').ok_or(anyhow::anyhow!(msg))?;

        let value =
            serde::from_relaxed_hex_str::<H256, { H256::len_bytes() }, { H256::len_bytes() * 2 }>(
                unquoted,
            )?;
        Ok(value)
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
mod tests {
    use super::*;
    use std::str::FromStr;
    use web3::types::U256;

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
        // The genesis block, previous_block_id is -1
        client()
            .block(U256::zero())
            .await
            .expect("Correctly deserialized reply");
        // This block contains a txn which includes a L1 to L2 message
        client()
            .block(U256::from(20056))
            .await
            .expect("Correctly deserialized reply");
        // A quite recent block
        client()
            .block(U256::from(43740))
            .await
            .expect("Correctly deserialized reply");
    }

    #[tokio::test]
    async fn call() {
        client()
            .call(request::Call {
                calldata: vec![],
                contract_address: H256::from_str(
                    "0x0399d3cf2405e997b1cda8c45f5ba919a6499f3d3b00998d5a91d6d9bcbc9128",
                )
                .unwrap(),
                entry_point_selector: H256::from_str(
                    "0x039e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695",
                )
                .unwrap(),
            })
            .await
            .expect("Correctly deserialized reply");
    }

    #[tokio::test]
    async fn code() {
        client()
            .code(
                H256::from_str(
                    "0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc",
                )
                .unwrap(),
            )
            .await
            .expect("Correctly deserialized reply");
    }

    #[tokio::test]
    async fn storage() {
        client()
            .storage(
                H256::from_str(
                    "0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc",
                )
                .unwrap(),
                U256::from_str_radix(
                    "916907772491729262376534102982219947830828984996257231353398618781993312401",
                    10,
                )
                .unwrap(),
            )
            .await
            .expect("Correctly deserialized reply");
    }

    #[tokio::test]
    async fn transaction() {
        // The first txn
        client()
            .transaction(U256::zero())
            .await
            .expect("Correctly deserialized reply");
        // An example of a rejected txn
        client()
            .transaction(U256::from(162531))
            .await
            .expect("Correctly deserialized reply");
        // Txn containing a L1 to L2 message
        client()
            .transaction(U256::from(186764))
            .await
            .expect("Correctly deserialized reply");
        // A quite recent txn
        client()
            .transaction(U256::from(276839))
            .await
            .expect("Correctly deserialized reply");
    }

    #[tokio::test]
    async fn transaction_status() {
        // The first txn
        client()
            .transaction_status(U256::zero())
            .await
            .expect("Correctly deserialized reply");
        // An example of a rejected txn
        client()
            .transaction_status(U256::from(162531))
            .await
            .expect("Correctly deserialized reply");
        // Txn containing a L1 to L2 message
        client()
            .transaction_status(U256::from(186764))
            .await
            .expect("Correctly deserialized reply");
        // A quite recent txn
        client()
            .transaction_status(U256::from(276839))
            .await
            .expect("Correctly deserialized reply");
    }
}
