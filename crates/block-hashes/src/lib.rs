use pathfinder_common::{BlockHash, BlockNumber, Chain};

mod sepolia;

#[derive(Clone)]
pub struct BlockHashDb {
    chain: Chain,
}

impl BlockHashDb {
    pub fn new(chain: Chain) -> Self {
        Self { chain }
    }

    pub fn block_hash(&self, block_number: BlockNumber) -> Option<BlockHash> {
        match self.chain {
            Chain::SepoliaTestnet => sepolia::block_hash(block_number),
            _ => None,
        }
    }
}
