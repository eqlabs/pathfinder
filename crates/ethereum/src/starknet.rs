alloy::sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    StarknetCoreContract,
    "abi/starknet_core_contract.json"
);

impl StarknetCoreContract::LogMessageToL2 {
    pub fn message_hash(&self) -> alloy::primitives::U256 {
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
