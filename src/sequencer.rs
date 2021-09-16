//! StarkNet L2 sequencer client.
mod deserialize;
pub mod reply;
pub mod request;

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
    pub async fn storage(&self, contract_addr: H256, key: U256) -> Result<U256> {
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
        let value = U256::from_dec_str(resp_txt.as_str())?;
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
    use web3::types::{H160, U256};

    fn client() -> Client {
        const URL: &str = "https://alpha2.starknet.io/";
        Client::new(Url::parse(URL).unwrap())
    }

    #[tokio::test]
    async fn block_by_id_and_latest() {
        let client = client();
        let result = client.block(U256::from(17187)).await.unwrap();
        assert_eq!(result.status, reply::transaction::Status::AcceptedOnChain);
        assert_eq!(result.timestamp, 1631895149);
        assert_eq!(
            result.transaction_receipts[&U256::from(161202)],
            reply::transaction::Receipt {
                common: reply::transaction::Common {
                    block_id: U256::from(17187),
                    block_number: U256::from(17187),
                    status: reply::transaction::Status::AcceptedOnChain,
                    transaction_id: U256::from(161202),
                    transaction_index: 0
                },
                l2_to_l1_messages: vec![reply::transaction::L2ToL1Message {
                    from_address: H256::from_str(
                        "0x05cd364aae22ede8706f6952ddf22126a31cea3a22250fe7a799eb56ff7b3022"
                    )
                    .unwrap(),
                    payload: vec![U256::from(12), U256::from(34)],
                    to_address: H160::from_str("0xdae8e8de8d2382af5fdfad4b3daeb623bfe1e7af")
                        .unwrap()
                }]
            }
        );
        assert_eq!(
            result.state_root,
            H256::from_str("00e49982d00a200d840bb0799506ba6085074aa18fe8a103cfe80276b0a6a7c1")
                .unwrap()
        );
        let result = client.latest_block().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn call() {
        let reply = client()
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
            .unwrap();
        assert_eq!(
            reply,
            reply::Call {
                result: vec![U256::from(9999)]
            }
        );
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
        assert_eq!(
            reply.abi,
            vec![
                reply::code::Abi {
                    inputs: vec![reply::code::abi::Input {
                        name: "amount".to_owned(),
                        r#type: "felt".to_owned()
                    }],
                    outputs: vec![],
                    name: "increase_balance".to_owned(),
                    state_mutability: None,
                    r#type: "function".to_owned(),
                },
                reply::code::Abi {
                    inputs: vec![],
                    outputs: vec![reply::code::abi::Output {
                        name: "res".to_owned(),
                        r#type: "felt".to_owned()
                    }],
                    name: "get_balance".to_owned(),
                    state_mutability: Some("view".to_owned()),
                    r#type: "function".to_owned(),
                }
            ]
        );
        assert_eq!(reply.bytecode[0], U256::from(4612671182993063932u64));
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
        assert_eq!(reply, U256::from(19752));
    }

    #[tokio::test]
    async fn transaction() {
        let reply = client().transaction(U256::from(146566)).await.unwrap();
        assert_eq!(
            reply,
            reply::Transaction {
                source: reply::transaction::Source {
                    contract_address: H256::from_str(
                        "0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc"
                    )
                    .unwrap(),
                    r#type: reply::transaction::Type::Deploy
                },
                common: reply::transaction::Common {
                    block_id: U256::from(15946),
                    transaction_index: 7,
                    block_number: U256::from(15946),
                    status: reply::transaction::Status::AcceptedOnChain,
                    transaction_id: U256::from(146566),
                }
            }
        );
    }

    #[tokio::test]
    async fn transaction_status() {
        let reply = client()
            .transaction_status(U256::from(146566))
            .await
            .unwrap();
        assert_eq!(
            reply,
            reply::TransactionStatus {
                block_id: U256::from(15946),
                tx_status: reply::transaction::Status::AcceptedOnChain,
            }
        );
    }
}
