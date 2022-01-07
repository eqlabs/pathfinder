//! Structures used for serializing requests to Starkware's sequencer REST API.
use crate::{
    rpc::types::request as rpc,
    serde::{H256AsRelaxedHexStr, U256AsBigDecimal},
};
use serde::{Deserialize, Serialize};
use std::convert::From;
use web3::types::{H256, U256};

/// Used to serialize payload for [Client::call](crate::sequencer::Client::call).
#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Call {
    #[serde_as(as = "H256AsRelaxedHexStr")]
    pub contract_address: H256,
    #[serde_as(as = "Vec<U256AsBigDecimal>")]
    pub calldata: Vec<U256>,
    #[serde_as(as = "H256AsRelaxedHexStr")]
    pub entry_point_selector: H256,
    #[serde_as(as = "Vec<U256AsBigDecimal>")]
    pub signature: Vec<U256>,
}

impl From<rpc::Call> for Call {
    fn from(call: rpc::Call) -> Self {
        Call {
            contract_address: call.contract_address,
            calldata: call
                .calldata
                .into_iter()
                .map(|x| {
                    let x: [u8; 32] = x.into();
                    x.into()
                })
                .collect(),
            entry_point_selector: call.entry_point_selector,
            signature: vec![],
        }
    }
}
