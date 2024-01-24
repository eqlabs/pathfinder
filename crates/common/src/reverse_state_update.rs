use crate::{ClassHash, ContractNonce, StorageAddress, StorageValue};

#[derive(Debug)]
pub enum ReverseContractUpdate {
    Deleted,
    Updated(ReverseContractUpdateDetails),
}

impl ReverseContractUpdate {
    pub fn update_mut(&mut self) -> Option<&mut ReverseContractUpdateDetails> {
        match self {
            Self::Deleted => None,
            Self::Updated(update) => Some(update),
        }
    }
}

#[derive(Default, Debug)]
pub struct ReverseContractUpdateDetails {
    pub storage: Vec<(StorageAddress, Option<StorageValue>)>,
    pub nonce: Option<ContractNonce>,
    pub class: Option<ClassHash>,
}
