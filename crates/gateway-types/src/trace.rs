use pathfinder_common::{ContractAddress, TransactionHash};
use pathfinder_crypto::Felt;
use serde::Deserialize;

use crate::reply::transaction::ExecutionResources;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionTrace {
    pub revert_error: Option<String>,
    pub validate_invocation: Option<FunctionInvocation>,
    pub function_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    pub signature: Vec<Felt>,
    // This is present for get_block_traces but not for an individual transaction's
    // trace in get_transaction_trace.
    pub transaction_hash: Option<TransactionHash>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockTrace {
    pub traces: Vec<TransactionTrace>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum CallType {
    #[serde(rename = "CALL")]
    Call,
    #[serde(rename = "DELEGATE")]
    Delegate,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub order: i64,
    pub data: Vec<Felt>,
    pub keys: Vec<Felt>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize)]
pub struct FunctionInvocation {
    pub calldata: Vec<Felt>,
    pub contract_address: ContractAddress,
    #[serde(default)]
    pub selector: Option<Felt>,
    #[serde(default)]
    pub call_type: Option<CallType>,
    #[serde(default)]
    pub caller_address: Felt,
    #[serde(default)]
    pub internal_calls: Vec<FunctionInvocation>,
    #[serde(default)]
    pub class_hash: Option<Felt>,
    #[serde(default)]
    pub entry_point_type: Option<EntryPointType>,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default)]
    pub messages: Vec<MsgToL1>,
    #[serde(default)]
    pub result: Vec<Felt>,
    pub execution_resources: ExecutionResources,
    #[serde(default)]
    pub failed: bool,
    #[serde(default)]
    pub gas_consumed: Option<u128>,
    #[serde(default)]
    pub cairo_native: bool,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum EntryPointType {
    #[serde(rename = "CONSTRUCTOR")]
    Constructor,
    #[serde(rename = "EXTERNAL")]
    External,
    #[serde(rename = "L1_HANDLER")]
    L1Handler,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MsgToL1 {
    pub order: usize,
    pub payload: Vec<Felt>,
    pub to_address: Felt,
}

#[cfg(test)]
mod tests {
    use super::*;

    mod block {
        use starknet_gateway_test_fixtures::traces::{TESTNET_889_517, TESTNET_GENESIS};
        use starknet_gateway_test_fixtures::v0_13_4::traces::SEPOLIA_TESTNET_30000;

        use super::*;

        #[test]
        fn parse_genesis() {
            serde_json::from_slice::<BlockTrace>(TESTNET_GENESIS).unwrap();
        }

        #[test]
        fn parse_889_517() {
            // The latest block trace on testnet at the time.
            serde_json::from_slice::<BlockTrace>(TESTNET_889_517).unwrap();
        }

        #[test]
        fn parse_sepolia_testnet_30000_starknet_0_13_4() {
            serde_json::from_str::<BlockTrace>(SEPOLIA_TESTNET_30000).unwrap();
        }
    }

    mod transactions {
        use starknet_gateway_test_fixtures::traces::{
            SEPOLIA_TESTNET_TX_0X6A4A,
            TESTNET_TX_0_0,
            TESTNET_TX_899_517_0,
        };

        use super::*;

        #[test]
        fn parse_genesis() {
            serde_json::from_slice::<TransactionTrace>(TESTNET_TX_0_0).unwrap();
        }

        #[test]
        fn parse_889_517() {
            // The latest block trace on testnet at the time.
            serde_json::from_slice::<TransactionTrace>(TESTNET_TX_899_517_0).unwrap();
        }

        #[test]
        fn parse_0x6a4a() {
            serde_json::from_slice::<TransactionTrace>(SEPOLIA_TESTNET_TX_0X6A4A).unwrap();
        }
    }
}
