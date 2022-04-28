//! Structures used for serializing requests to Starkware's sequencer REST API.
use crate::{
    core::{CallParam, CallSignatureElem, ContractAddress, EntryPoint},
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

    #[derive(Copy, Clone, Debug, serde::Deserialize, PartialEq, Hash, Eq)]
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

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SelectorAndOffset {
        pub selector: EntryPoint,
        pub offset: ByteCodeOffset,
    }
}
