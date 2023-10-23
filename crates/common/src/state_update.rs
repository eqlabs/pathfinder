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

    /// Returns the contract's new [nonce](ContractNonce) value if it exists in this state update.
    ///
    /// Note that this will return [Some(ContractNonce::ZERO)] for a contract that has been deployed,
    /// but without an explicit nonce update. This is consistent with expectations.
    pub fn contract_nonce(&self, contract: ContractAddress) -> Option<ContractNonce> {
        self.contract_updates.get(&contract).and_then(|x| {
            x.nonce.or_else(|| {
                x.class.as_ref().and_then(|c| match c {
                    ContractClassUpdate::Deploy(_) => {
                        // The contract has been just deployed in the pending block, so
                        // its nonce is zero.
                        Some(ContractNonce::ZERO)
                    }
                    ContractClassUpdate::Replace(_) => None,
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macro_prelude::*;

    #[test]
    fn change_count() {
        let state_update = StateUpdate::default()
            .with_contract_nonce(contract_address!("0x1"), contract_nonce!("0x2"))
            .with_contract_nonce(contract_address!("0x4"), contract_nonce!("0x5"))
            .with_declared_cairo_class(class_hash!("0x3"))
            .with_declared_sierra_class(sierra_hash!("0x4"), casm_hash!("0x5"))
            .with_deployed_contract(contract_address!("0x1"), class_hash!("0x3"))
            .with_replaced_class(contract_address!("0x33"), class_hash!("0x35"))
            .with_system_storage_update(
                ContractAddress::ONE,
                storage_address!("0x10"),
                storage_value!("0x99"),
            )
            .with_storage_update(
                contract_address!("0x33"),
                storage_address!("0x10"),
                storage_value!("0x99"),
            );

        assert_eq!(state_update.change_count(), 8);
    }

    #[test]
    fn contract_nonce() {
        let state_update = StateUpdate::default()
            .with_contract_nonce(contract_address!("0x1"), contract_nonce!("0x2"))
            .with_deployed_contract(contract_address!("0x2"), class_hash!("0x4"))
            .with_contract_nonce(contract_address!("0x10"), contract_nonce!("0x20"))
            .with_deployed_contract(contract_address!("0x10"), class_hash!("0x12"))
            .with_replaced_class(contract_address!("0x123"), class_hash!("0x1244"))
            .with_replaced_class(contract_address!("0x1234"), class_hash!("0x12445"))
            .with_contract_nonce(contract_address!("0x1234"), contract_nonce!("0x1111"));

        assert!(state_update
            .contract_nonce(contract_address_bytes!(b"not present"))
            .is_none());

        let result = state_update.contract_nonce(contract_address!("0x1"));
        assert_eq!(result, Some(contract_nonce!("0x2")));

        // A newly deployed contract with an explicit nonce set.
        let result = state_update.contract_nonce(contract_address!("0x10"));
        assert_eq!(result, Some(contract_nonce!("0x20")));

        // A newly deployed contract without an explicit nonce set should be zero
        let result = state_update.contract_nonce(contract_address!("0x2"));
        assert_eq!(result, Some(ContractNonce::ZERO));

        // A replaced contract with an explicit nonce set.
        let result = state_update.contract_nonce(contract_address!("0x1234"));
        assert_eq!(result, Some(contract_nonce!("0x1111")));

        // A replaced class without an explicit nonce.
        assert!(state_update
            .contract_nonce(contract_address!("0x123"))
            .is_none());
    }
}
