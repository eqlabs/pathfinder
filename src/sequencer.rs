//! StarkNet L2 sequencer client.

use reqwest::{Result, Url};
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
    pub async fn block(&self, block_id: U256) -> Result<String> {
        self.get_block(Some(block_id)).await
    }

    /// Gets latest block.
    pub async fn latest_block(&self) -> Result<String> {
        self.get_block(None).await
    }

    /// Helper function to wrap block query. `None` as `block_id` means latest block available.
    async fn get_block(&self, block_id: Option<U256>) -> Result<String> {
        let id_string = if let Some(id) = block_id {
            id.to_string()
        } else {
            "null".to_owned()
        };
        let resp =
            reqwest::get(self.build_query("get_block", &[("blockId", id_string.as_str())])).await?;
        resp.text().await
    }

    /// Placeholder for calling an L2 contract's function.
    /// So far __unimplemented__, will panic if called.
    pub async fn call(&self) {
        todo!()
    }

    /// Gets contract's code and ABI.
    pub async fn code(&self, contract_addr: H256) -> Result<String> {
        let resp = reqwest::get(self.build_query(
            "get_code",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("blockId", "null"),
            ],
        ))
        .await?;
        resp.text().await
    }

    /// Gets storage value associated with a `key` for a prticular contract.  
    pub async fn storage(&self, contract_addr: H256, key: U256) -> Result<String> {
        let resp = reqwest::get(self.build_query(
            "get_storage_at",
            &[
                ("contractAddress", format!("{:x}", contract_addr).as_str()),
                ("key", key.to_string().as_str()),
                ("blockId", "null"),
            ],
        ))
        .await?;
        resp.text().await
    }

    /// Gets transaction by id.
    pub async fn transaction(&self, transaction_id: U256) -> Result<String> {
        let resp = reqwest::get(self.build_query(
            "get_transaction",
            &[("transactionId", transaction_id.to_string().as_str())],
        ))
        .await?;
        resp.text().await
    }

    /// Gets transaction status by transaction id.
    pub async fn transaction_status(&self, transaction_id: U256) -> Result<String> {
        let resp = reqwest::get(self.build_query(
            "get_transaction_status",
            &[("transactionId", transaction_id.to_string().as_str())],
        ))
        .await?;
        resp.text().await
    }

    /// Helper function that constructs a URL for particular query.
    fn build_query(&self, path_segment: &str, params: &[(&str, &str)]) -> Url {
        let mut query_url = self.sequencer_url.clone();
        query_url
            .path_segments_mut()
            .expect("Base URL is valid.")
            .extend(&["feeder_gateway", path_segment]);
        query_url.query_pairs_mut().extend_pairs(params);
        query_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;
    use web3::types::U256;

    fn client() -> Client {
        const URL: &str = "https://alpha2.starknet.io/";
        Client::new(Url::parse(URL).unwrap())
    }

    #[tokio::test]
    async fn block_by_id_and_latest() {
        let client = client();
        let result = client.block(U256::from(15611)).await;
        assert!(result.unwrap().contains(
            r#""state_root": "00b3517b9e7018f034b110d111971f5f8d654194b1869bcfb81dc3d4c416c649""#
        ));
        let result = client.latest_block().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn code() {
        let reply = client()
            .code(
                H256::from_str(
                    "0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc",
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(reply.contains(r#""bytecode": [4612671182993063932, 4612671187288031229,"#));
        assert!(reply.contains(
            r#"2345108766317314046], "abi": [{"inputs": [{"name": "amount", "type": "felt"}],"#
        ));
    }

    #[tokio::test]
    async fn storage() {
        let reply = client()
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
            .unwrap();
        assert_eq!(reply.as_str(), "19752");
    }

    #[tokio::test]
    async fn transaction() {
        let reply = client().transaction(U256::from(146566)).await.unwrap();
        assert!(reply.contains(r#""contract_address": "0x4eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc""#));
    }

    #[tokio::test]
    async fn transaction_status() {
        let reply = client()
            .transaction_status(U256::from(146566))
            .await
            .unwrap();
        assert!(reply.contains(r#""block_id": 15946"#));
    }
}
