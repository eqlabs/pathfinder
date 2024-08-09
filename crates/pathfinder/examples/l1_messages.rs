use alloy::{
    eips::BlockId, primitives::{address, U256}, providers::{Provider, ProviderBuilder, WsConnect}, rpc::types::{BlockTransactionsKind, Log}, sol
};
use anyhow::Context;
use futures::StreamExt;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    StarknetCoreContract,
    "examples/core_contract_abi.json"
);

impl StarknetCoreContract::LogMessageToL2 {
    fn message_hash(&self) -> U256 {
        let mut hash = alloy::primitives::Keccak256::new();

        // This is an ethereum address: pad the 160 bits to 32 bytes to match a felt.
        hash.update([0u8; 12]);
        hash.update(self.fromAddress);
        hash.update(self.toAddress.to_be_bytes::<32>());
        hash.update(self.nonce.to_be_bytes::<32>());
        hash.update(self.selector.to_be_bytes::<32>());

        // Pad the u64 to 32 bytes to match a felt.
        hash.update([0u8; 24]);
        hash.update((self.payload.len() as u64).to_be_bytes());

        for elem in &self.payload {
            hash.update(elem.to_be_bytes::<32>());
        }

        hash.finalize().into()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // SEPOLIA
    let core_contract_address = address!("E2Bb56ee936fd6433DC0F6e7e3b8365C906AA057");
    // MAINNET
    // let core_contract_address = address!("c662c410C0ECf747543f5bA90660f6ABeBD9C8c4");

    // FIXME: Replace with actual L1 provider Websocket URL
    let ws = WsConnect::new("wss://");
    let provider = ProviderBuilder::new().on_ws(ws).await?;

    let finalized_block = provider.get_block(BlockId::finalized(), BlockTransactionsKind:: Hashes).await?.context("Finalized block not found")?;
    let finalized_block_hash = finalized_block.header.hash.context("Finalized block hash not found")?;

    let core_contract = StarknetCoreContract::new(core_contract_address, provider.clone());
    let finalized_l2_block_number = core_contract.stateBlockNumber().block(finalized_block_hash.into()).call().await?._0;
    let finalized_l2_block_hash = core_contract.stateBlockHash().block(finalized_block_hash.into()).call().await?._0;
    println!("L1 confirmed L2 block number: {finalized_l2_block_number} hash: {finalized_l2_block_hash:#x}");

    let l2_messages_filter = core_contract.LogMessageToL2_filter().filter.from_block(finalized_block.header.number.unwrap() - 100000);
    let logs = provider.get_logs(&l2_messages_filter).await?;
    for log in logs {
        let log: Log<StarknetCoreContract::LogMessageToL2> = log.log_decode()?;

        let l1_block_number = log.block_number.context("Block number not found")?;
        let tx_hash = log.transaction_hash.context("Transaction hash not found")?;

        let from_address = log.data().fromAddress;
        let to_address = log.data().toAddress;
        let nonce = log.data().nonce;
        let selector = log.data().selector;
        let payload = &log.data().payload;

        let message_hash = log.data().message_hash();

        println!("L1->L2 message block {l1_block_number}, tx {tx_hash}, from {from_address}, to {to_address:#x}, nonce {nonce}, selector {selector:#x}, message hash {message_hash:#x}, payload {payload:?}");
    }

    let l2_messages_filter = core_contract.LogMessageToL2_filter().filter;
    let mut logs = provider.subscribe_logs(&l2_messages_filter).await?.into_stream();

    while let Some(log) = logs.next().await {
        let log: Log<StarknetCoreContract::LogMessageToL2> = log.log_decode()?;

        let l1_block_number = log.block_number.context("Block number not found")?;
        let tx_hash = log.transaction_hash.context("Transaction hash not found")?;

        let from_address = log.data().fromAddress;
        let to_address = log.data().toAddress;
        let nonce = log.data().nonce;
        let selector = log.data().selector;
        let payload = &log.data().payload;

        let message_hash = log.data().message_hash();

        println!("L1->L2 message block {l1_block_number}, tx {tx_hash}, from {from_address}, to {to_address:#x}, nonce {nonce}, selector {selector:#x}, message hash {message_hash:#x}, payload {payload:?}");
    }

    Ok(())
}
