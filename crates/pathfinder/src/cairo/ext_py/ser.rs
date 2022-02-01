//! The json serializable types

use crate::core::{CallParam, ContractAddress, EntryPoint};
use crate::rpc::types::BlockHashOrTag;

/// The command we send to the python loop.
#[derive(serde::Serialize, Debug)]
pub struct ChildCommand<'a> {
    pub contract_address: &'a ContractAddress,
    pub calldata: &'a [CallParam],
    pub entry_point_selector: &'a EntryPoint,
    pub at_block: &'a BlockHashOrTag,
}
