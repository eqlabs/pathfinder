use crate::prelude::*;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub actual_fee: Fee,
    pub execution_resources: ExecutionResources,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub execution_status: ExecutionStatus,
    pub transaction_hash: TransactionHash,
    pub transaction_index: TransactionIndex,
}

impl Receipt {
    pub fn is_reverted(&self) -> bool {
        matches!(self.execution_status, ExecutionStatus::Reverted { .. })
    }

    pub fn revert_reason(&self) -> Option<&str> {
        match &self.execution_status {
            ExecutionStatus::Succeeded => None,
            ExecutionStatus::Reverted { reason } => Some(reason.as_str()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2ToL1Message {
    pub from_address: ContractAddress,
    pub payload: Vec<L2ToL1MessagePayloadElem>,
    // This is purposefully not EthereumAddress even though this
    // represents an Ethereum address normally. Starknet allows this value
    // to be Felt sized; so technically callers can send a message to a garbage
    // address.
    pub to_address: ContractAddress,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionResources {
    pub builtins: BuiltinCounters,
    pub n_steps: u64,
    pub n_memory_holes: u64,
    pub data_availability: ExecutionDataAvailability,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionDataAvailability {
    pub l1_gas: u128,
    pub l1_data_gas: u128,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuiltinCounters {
    pub output: u64,
    pub pedersen: u64,
    pub range_check: u64,
    pub ecdsa: u64,
    pub bitwise: u64,
    pub ec_op: u64,
    pub keccak: u64,
    pub poseidon: u64,
    pub segment_arena: u64,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    // This must be the default as pre v0.12.1 receipts did not contain this value and
    // were always success as reverted did not exist.
    #[default]
    Succeeded,
    Reverted {
        reason: String,
    },
}
