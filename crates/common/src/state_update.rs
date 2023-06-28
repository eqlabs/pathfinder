use std::collections::{HashMap, HashSet};

use crate::{
    BlockHash, CasmHash, ClassHash, ContractAddress, ContractNonce, SierraHash, StateCommitment,
    StorageAddress, StorageValue,
};

#[derive(Default, Debug, Clone, PartialEq)]
pub struct StateUpdate {
    pub block_hash: BlockHash,
    pub parent_state_commitment: StateCommitment,
    pub state_commitment: StateCommitment,
    pub contract_updates: HashMap<ContractAddress, ContractUpdate>,
    pub system_contract_updates: HashMap<ContractAddress, SystemContractUpdate>,
    pub declared_cairo_classes: HashSet<ClassHash>,
    pub declared_sierra_classes: HashMap<SierraHash, CasmHash>,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct ContractUpdate {
    pub storage: HashMap<StorageAddress, StorageValue>,
    /// The class associated with this update as the result of either a deploy or class replacement transaction.
    pub class: Option<ClassHash>,
    pub nonce: Option<ContractNonce>,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct SystemContractUpdate {
    pub storage: HashMap<StorageAddress, StorageValue>,
}

impl StateUpdate {
    pub fn with_block_hash(mut self, block_hash: BlockHash) -> Self {
        self.block_hash = block_hash;
        self
    }

    pub fn with_state_commitment(mut self, state_commitment: StateCommitment) -> Self {
        self.state_commitment = state_commitment;
        self
    }

    pub fn with_parent_state_commitment(
        mut self,
        parent_state_commitment: StateCommitment,
    ) -> Self {
        self.parent_state_commitment = parent_state_commitment;
        self
    }

    pub fn with_contract_nonce(mut self, contract: ContractAddress, nonce: ContractNonce) -> Self {
        self.contract_updates.entry(contract).or_default().nonce = Some(nonce);

        self
    }

    pub fn with_storage_update(
        mut self,
        contract: ContractAddress,
        key: StorageAddress,
        value: StorageValue,
    ) -> Self {
        self.contract_updates
            .entry(contract)
            .or_default()
            .storage
            .insert(key, value);

        self
    }

    pub fn with_deployed_contract(mut self, contract: ContractAddress, class: ClassHash) -> Self {
        self.contract_updates.entry(contract).or_default().class = Some(class);

        self
    }
}
