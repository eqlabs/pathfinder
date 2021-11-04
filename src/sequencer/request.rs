//! Structures used for serializing requests to Starkware's sequencer REST API.
use crate::sequencer::serde::U256AsBigDecimal;
use serde::Serialize;
use web3::types::{H256, U256};

/// Used to serialize payload for [Client::call](crate::sequencer::Client::call).
#[serde_with::serde_as]
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Call {
    pub contract_address: H256,
    #[serde_as(as = "Vec<U256AsBigDecimal>")]
    pub calldata: Vec<U256>,
    pub entry_point_selector: H256,
    pub signature: Vec<U256>,
}
