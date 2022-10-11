//! Structures used for serializing requests to Starkware's sequencer REST API.
use crate::core::{CallParam, ContractAddress, EntryPoint, Fee, TransactionSignatureElem};

pub mod contract {
    use std::fmt;

    use stark_hash::StarkHash;

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

    impl From<crate::rpc::v02::types::class::ContractEntryPoint> for SelectorAndOffset {
        fn from(entry_point: crate::rpc::v02::types::class::ContractEntryPoint) -> Self {
            Self {
                selector: EntryPoint(entry_point.selector),
                offset: ByteCodeOffset(StarkHash::from_u64(entry_point.offset)),
            }
        }
    }
}

pub mod add_transaction {
    use std::collections::HashMap;

    use crate::core::{
        ConstructorParam, ContractAddressSalt, TransactionNonce, TransactionVersion,
    };
    use crate::rpc::serde::{
        CallParamAsDecimalStr, ConstructorParamAsDecimalStr, FeeAsHexStr,
        TransactionSignatureElemAsDecimalStr, TransactionVersionAsHexStr,
    };

    use serde_with::serde_as;

    use super::contract::{EntryPointType, SelectorAndOffset};
    use super::{CallParam, ContractAddress, EntryPoint, Fee, TransactionSignatureElem};

    /// Definition of a contract.
    ///
    /// This is somewhat different compared to the contract definition we're using
    /// for class hash calculation. The actual program contents are not relevant
    /// for us, and they are sent as a gzip + base64 encoded string via the API.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct ContractDefinition {
        // gzip + base64 encoded JSON of the compiled contract JSON
        pub program: String,
        pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndOffset>>,
        pub abi: Option<serde_json::Value>,
    }

    impl TryFrom<crate::rpc::v02::types::ContractClass> for ContractDefinition {
        type Error = serde_json::Error;

        fn try_from(c: crate::rpc::v02::types::ContractClass) -> Result<Self, Self::Error> {
            let abi = match c.abi {
                Some(abi) => Some(serde_json::to_value(abi)?),
                None => None,
            };
            let mut entry_points: HashMap<EntryPointType, Vec<SelectorAndOffset>> =
                Default::default();
            entry_points.insert(
                EntryPointType::Constructor,
                c.entry_points_by_type
                    .constructor
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            );
            entry_points.insert(
                EntryPointType::External,
                c.entry_points_by_type
                    .external
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            );
            entry_points.insert(
                EntryPointType::L1Handler,
                c.entry_points_by_type
                    .l1_handler
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            );

            Ok(Self {
                program: c.program,
                entry_points_by_type: entry_points,
                abi,
            })
        }
    }

    /// Contract deployment transaction details.
    #[serde_as]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct Deploy {
        // Transacion properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        pub contract_address_salt: ContractAddressSalt,
        pub contract_definition: ContractDefinition,
        #[serde_as(as = "Vec<ConstructorParamAsDecimalStr>")]
        pub constructor_calldata: Vec<ConstructorParam>,
    }

    /// Invoke contract transaction details.
    #[serde_as]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct InvokeFunction {
        // Transacion properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        // AccountTransaction properties
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: Option<TransactionNonce>,

        pub contract_address: ContractAddress,
        pub entry_point_selector: Option<EntryPoint>,
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
    }

    /// Declare transaction details.
    #[serde_as]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct Declare {
        // Transacion properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        // AccountTransaction properties -- except for nonce which is non-optional here
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,

        pub contract_class: ContractDefinition,
        pub sender_address: ContractAddress,
        pub nonce: TransactionNonce,
    }

    /// Add transaction API operation.
    ///
    /// This adds the "type" attribute to the JSON request according the type of
    /// the transaction (invoke or deploy).
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(tag = "type")]
    pub enum AddTransaction {
        #[serde(rename = "INVOKE_FUNCTION")]
        Invoke(InvokeFunction),
        #[serde(rename = "DEPLOY")]
        Deploy(Deploy),
        #[serde(rename = "DECLARE")]
        Declare(Declare),
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
