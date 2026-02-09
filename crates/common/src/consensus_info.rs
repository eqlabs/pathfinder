use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{BlockNumber, ContractAddress, ProposalCommitment};

#[derive(Default, Debug, Clone)]
pub struct ConsensusInfo {
    /// Highest decided height and value.
    pub highest_decision: Option<Decision>,
    /// Track the number of times peer scores were changed.
    pub peer_score_change_counter: u64,
    /// Track the state of cached proposals and finalized blocks.
    pub cached: BTreeMap<u64, CachedAtHeight>,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Deserialize)]
pub struct Decision {
    pub height: BlockNumber,
    pub round: u32,
    pub value: ProposalCommitment,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CachedAtHeight {
    pub proposals: Vec<ProposalParts>,
    pub blocks: Vec<FinalizedBlock>,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Deserialize)]
pub struct ProposalParts {
    pub round: u32,
    pub proposer: ContractAddress,
    pub parts_len: usize,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Deserialize)]
pub struct FinalizedBlock {
    pub round: u32,
    pub is_decided: bool,
}
