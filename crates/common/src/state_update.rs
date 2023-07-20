use std::collections::{HashMap, HashSet};

use fake::Dummy;

use crate::{
    BlockHash, CasmHash, ClassHash, ContractAddress, ContractNonce, SierraHash, StateCommitment,
    StorageAddress, StorageValue,
};

#[derive(Default, Debug, Clone, PartialEq, Dummy)]
pub struct StateUpdate {
    pub block_hash: BlockHash,
    pub parent_state_commitment: StateCommitment,
    pub state_commitment: StateCommitment,
    pub contract_updates: HashMap<ContractAddress, ContractUpdate>,
    pub system_contract_updates: HashMap<ContractAddress, SystemContractUpdate>,
    pub declared_cairo_classes: HashSet<ClassHash>,
    pub declared_sierra_classes: HashMap<SierraHash, CasmHash>,
}

#[derive(Default, Debug, Clone, PartialEq, Dummy)]
pub struct ContractUpdate {
    pub storage: HashMap<StorageAddress, StorageValue>,
    /// The class associated with this update as the result of either a deploy or class replacement transaction.
    pub class: Option<ContractClassUpdate>,
    pub nonce: Option<ContractNonce>,
}

#[derive(Default, Debug, Clone, PartialEq, Dummy)]
pub struct SystemContractUpdate {
    pub storage: HashMap<StorageAddress, StorageValue>,
}

#[derive(Debug, Clone, PartialEq, Dummy)]
pub enum ContractClassUpdate {
    Deploy(ClassHash),
    Replace(ClassHash),
}

impl ContractClassUpdate {
    pub fn class_hash(&self) -> ClassHash {
        match self {
            ContractClassUpdate::Deploy(x) => *x,
            ContractClassUpdate::Replace(x) => *x,
        }
    }
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

    pub fn with_system_storage_update(
        mut self,
        contract: ContractAddress,
        key: StorageAddress,
        value: StorageValue,
    ) -> Self {
        self.system_contract_updates
            .entry(contract)
            .or_default()
            .storage
            .insert(key, value);
        self
    }

    pub fn with_deployed_contract(mut self, contract: ContractAddress, class: ClassHash) -> Self {
        self.contract_updates.entry(contract).or_default().class =
            Some(ContractClassUpdate::Deploy(class));
        self
    }

    pub fn with_replaced_class(mut self, contract: ContractAddress, class: ClassHash) -> Self {
        self.contract_updates.entry(contract).or_default().class =
            Some(ContractClassUpdate::Replace(class));
        self
    }

    pub fn with_declared_sierra_class(mut self, sierra: SierraHash, casm: CasmHash) -> Self {
        self.declared_sierra_classes.insert(sierra, casm);
        self
    }

    pub fn with_declared_cairo_class(mut self, cairo: ClassHash) -> Self {
        self.declared_cairo_classes.insert(cairo);
        self
    }

    /// The number of individual changes in this state update.
    ///
    /// The total amount of:
    /// - system storage updates
    /// - contract storage updates
    /// - contract nonce updates
    /// - contract deployments
    /// - contract class replacements
    /// - class declarations
    pub fn change_count(&self) -> usize {
        self.declared_cairo_classes.len()
            + self.declared_sierra_classes.len()
            + self
                .system_contract_updates
                .iter()
                .map(|x| x.1.storage.len())
                .sum::<usize>()
            + self
                .contract_updates
                .iter()
                .map(|x| {
                    x.1.storage.len()
                        + x.1.class.as_ref().map(|_| 1).unwrap_or_default()
                        + x.1.nonce.as_ref().map(|_| 1).unwrap_or_default()
                })
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use crate::felt;

    use super::*;

    #[test]
    fn change_count() {
        let state_update = StateUpdate::default()
            .with_contract_nonce(ContractAddress(felt!("0x1")), ContractNonce(felt!("0x2")))
            .with_contract_nonce(ContractAddress(felt!("0x4")), ContractNonce(felt!("0x5")))
            .with_declared_cairo_class(ClassHash(felt!("0x3")))
            .with_declared_sierra_class(SierraHash(felt!("0x4")), CasmHash(felt!("0x5")))
            .with_deployed_contract(ContractAddress(felt!("0x1")), ClassHash(felt!("0x3")))
            .with_replaced_class(ContractAddress(felt!("0x33")), ClassHash(felt!("0x35")))
            .with_system_storage_update(
                ContractAddress::ONE,
                StorageAddress(felt!("0x10")),
                StorageValue(felt!("0x99")),
            )
            .with_storage_update(
                ContractAddress(felt!("0x33")),
                StorageAddress(felt!("0x10")),
                StorageValue(felt!("0x99")),
            );

        assert_eq!(state_update.change_count(), 8);
    }
}
