//! Structures used for serializing requests to Starkware's sequencer REST API.
use crate::{
    core::{CallParam, CallSignatureElem, ContractAddress, EntryPoint, Fee},
    rpc::{
        serde::{CallParamAsDecimalStr, CallSignatureElemAsDecimalStr},
        types::request as rpc,
    },
};
use serde::Serialize;
use std::convert::From;

/// Used to serialize payload for [ClientApi::call](crate::sequencer::ClientApi::call).
#[serde_with::serde_as]
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Call {
    pub contract_address: ContractAddress,
    #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
    pub calldata: Vec<CallParam>,
    pub entry_point_selector: EntryPoint,
    #[serde_as(as = "Vec<CallSignatureElemAsDecimalStr>")]
    pub signature: Vec<CallSignatureElem>,
}

impl From<rpc::Call> for Call {
    fn from(call: rpc::Call) -> Self {
        Call {
            contract_address: call.contract_address,
            calldata: call.calldata,
            entry_point_selector: call.entry_point_selector,
            // For the time being the RPC API does not use signatures here and we can pass
            // empty signature to the sequencer API safely
            signature: vec![],
        }
    }
}

pub mod contract {
    use std::fmt;

    use crate::core::{ByteCodeOffset, EntryPoint};

    #[derive(Copy, Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Hash, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
        #[serde(rename = "CONSTRUCTOR")]
        Constructor,
    }

    impl fmt::Display for EntryPointType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use EntryPointType::*;
            f.pad(match self {
                External => "EXTERNAL",
                L1Handler => "L1_HANDLER",
                Constructor => "CONSTRUCTOR",
            })
        }
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct SelectorAndOffset {
        pub selector: EntryPoint,
        pub offset: ByteCodeOffset,
    }
}

pub mod add_transaction {
    use std::collections::HashMap;

    use crate::core::{ConstructorParam, ContractAddressSalt, TransactionVersion};
    use crate::rpc::serde::{
        CallParamAsDecimalStr, CallSignatureElemAsDecimalStr, FeeAsHexStr,
        TransactionVersionAsHexStr,
    };

    use serde_with::serde_as;

    use super::contract::{EntryPointType, SelectorAndOffset};
    use super::{CallParam, CallSignatureElem, ContractAddress, EntryPoint, Fee};

    /// Definition of a contract.
    ///
    /// This is somewhat different compared to the contract definition we're using
    /// for contract hash calculation. The actual program contents are not relevant
    /// for us, and they are sent as a gzip + base64 encoded string via the API.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct ContractDefinition {
        pub abi: serde_json::Value,
        // gzip + base64 encoded JSON of the compiled contract JSON
        pub program: String,
        pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndOffset>>,
    }

    /// Contract deployment transaction details.
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct Deploy {
        pub contract_address_salt: ContractAddressSalt,
        pub contract_definition: ContractDefinition,
        pub constructor_calldata: Vec<ConstructorParam>,
    }

    /// Invoke contract transaction details.
    #[serde_as]
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct InvokeFunction {
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        /// Transaction version
        /// starknet.py just sets it to 0.
        /// starknet-cli either sets it to 0 (TRANSACTION_VERSION in constants.py) for invoke
        /// and offsets it with 2**128 (QUERY_VERSION_BASE in constants.py) for calls
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        #[serde_as(as = "Vec<CallSignatureElemAsDecimalStr>")]
        pub signature: Vec<CallSignatureElem>,
    }

    /// Add transaction API operation.
    ///
    /// This adds the "type" attribute to the JSON request according the type of
    /// the transaction (invoke or deploy).
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(tag = "type")]
    pub enum AddTransaction {
        #[serde(rename = "INVOKE_FUNCTION")]
        Invoke(InvokeFunction),
        #[serde(rename = "DEPLOY")]
        Deploy(Deploy),
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_deploy() {
            let json = include_bytes!("../../resources/deploy_transaction.json");
            let _deploy = serde_json::from_slice::<AddTransaction>(json).unwrap();
        }

        #[test]
        fn test_deploy_openzeppelin_account() {
            let json = include_bytes!("../../resources/deploy_openzeppelin_account.json");
            let _deploy = serde_json::from_slice::<AddTransaction>(json).unwrap();
        }

        #[test]
        fn test_invoke_with_signature() {
            let json = include_bytes!("../../resources/invoke_contract_with_signature.json");
            let _invoke = serde_json::from_slice::<AddTransaction>(json).unwrap();
        }
    }
}
