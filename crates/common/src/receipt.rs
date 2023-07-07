use crate::prelude::*;

pub struct Receipt {
    pub actual_fee: Option<Fee>,
    pub events: Vec<crate::event::Event>,
    pub execution_resources: Option<ExecutionResources>,
    pub l1_to_l2_consumed_message: Option<L1ToL2Message>,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub transaction_hash: TransactionHash,
    pub transaction_index: TransactionIndex,
}

pub struct L1ToL2Message {
    pub from_address: EthereumAddress,
    pub payload: Vec<L1ToL2MessagePayloadElem>,
    pub selector: EntryPoint,
    pub to_address: ContractAddress,
    pub nonce: Option<L1ToL2MessageNonce>,
}

pub struct L2ToL1Message {
    pub from_address: ContractAddress,
    pub payload: Vec<L2ToL1MessagePayloadElem>,
    pub to_address: EthereumAddress,
}

pub struct ExecutionResources {
    pub builtin_instance_counter: BuiltinInstanceCounter,
    pub n_steps: u64,
    pub n_memory_holes: u64,
}

pub enum BuiltinInstanceCounter {
    Normal {
        bitwise_builtin: u64,
        ecdsa_builtin: u64,
        ec_op_builtin: u64,
        output_builtin: u64,
        pedersen_builtin: u64,
        range_check_builtin: u64,
    },
    Empty,
}
