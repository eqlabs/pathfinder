//! Structures used for serializing requests to Starkware's sequencer REST API.
//! __Warning!__Prone to change as the structures are solely based on reverse
//! engineering raw API replies!   
use serde::Serialize;
use web3::types::{H256, U256};

/// Used to serialize payload for [Client::call](crate::sequencer::Client::call).
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Call {
    pub contract_address: H256,
    pub calldata: Vec<U256>,
    pub entry_point_selector: H256,
}
