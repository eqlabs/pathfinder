use web3::types::{BlockNumber, H256};
pub mod contract;

pub enum BlockId {
    Latest,
    Earliest,
    Number(u64),
    Hash(H256),
}

impl From<BlockId> for web3::types::BlockId {
    fn from(id: BlockId) -> Self {
        type W3 = web3::types::BlockId;
        match id {
            BlockId::Latest => W3::Number(BlockNumber::Latest),
            BlockId::Earliest => W3::Number(BlockNumber::Earliest),
            BlockId::Number(x) => W3::Number(BlockNumber::Number(x.into())),
            BlockId::Hash(x) => W3::Hash(x),
        }
    }
}

#[cfg(test)]
mod test {
    use web3::transports::WebSocket;
    use web3::Web3;
    /// A test helper utility.
    pub async fn create_test_websocket() -> Web3<WebSocket> {
        let url = std::env::var("STARKNET_ETHEREUM_WEBSOCKET_URL").expect(
            "Ethereum websocket URL environment var not set (STARKNET_ETHEREUM_WEBSOCKET_URL)",
        );

        let ws = WebSocket::new(&url).await.unwrap();
        web3::Web3::new(ws)
    }
}
