use crate::prelude::*;

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Receipt {
    pub actual_fee: Option<Fee>,
    pub events: Vec<crate::event::Event>,
    pub execution_resources: Option<ExecutionResources>,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub execution_status: ExecutionStatus,
    pub transaction_hash: TransactionHash,
    pub transaction_index: TransactionIndex,
}

#[derive(Clone, Debug, PartialEq)]
pub struct L2ToL1Message {
    pub from_address: ContractAddress,
    pub payload: Vec<L2ToL1MessagePayloadElem>,
    pub to_address: EthereumAddress,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExecutionResources {
    pub builtin_instance_counter: BuiltinCounters,
    pub n_steps: u64,
    pub n_memory_holes: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BuiltinCounters {
    pub output_builtin: u64,
    pub pedersen_builtin: u64,
    pub range_check_builtin: u64,
    pub ecdsa_builtin: u64,
    pub bitwise_builtin: u64,
    pub ec_op_builtin: u64,
    pub keccak_builtin: u64,
    pub poseidon_builtin: u64,
    pub segment_arena_builtin: u64,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub enum ExecutionStatus {
    // This must be the default as pre v0.12.1 receipts did not contain this value and
    // were always success as reverted did not exist.
    #[default]
    Succeeded,
    Reverted {
        reason: String,
    },
}
