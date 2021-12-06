mod parse;
mod retrieve;
mod state_root;

use retrieve::*;

use web3::{types::U256, Transport, Web3};

use crate::ethereum::{
    log::StateUpdateLog,
    state_update::{parse::StateUpdateParser, retrieve::retrieve_transition_fact},
};

/// Describes the deployment of a new StarkNet contract.
#[derive(Debug, Clone, PartialEq)]
pub struct DeployedContract {
    pub address: U256,
    pub hash: U256,
    pub call_data: Vec<U256>,
}

/// A StarkNet contract's storage updates.
#[derive(Debug, Clone, PartialEq)]
pub struct ContractUpdate {
    pub address: U256,
    pub storage_updates: Vec<StorageUpdate>,
}

/// A StarkNet contract's storage update.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageUpdate {
    pub address: U256,
    pub value: U256,
}

/// The set of state updates of a StarkNet [StateUpdate].
///
/// Contains new [DeployedContracts](DeployedContract) as well as [ContractUpdates](ContractUpdate).
#[derive(Debug, Clone, PartialEq)]
pub struct StateUpdate {
    pub deployed_contracts: Vec<DeployedContract>,
    pub contract_updates: Vec<ContractUpdate>,
}

#[derive(Debug)]
pub enum RetrieveStateUpdateError {
    StateTransitionFactNotFound,
    MemoryPageHashesNotFound,
    MemoryPageLogNotFound,
    MemoryPageTransactionNotFound,
    Reorg,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for RetrieveStateUpdateError {
    fn from(err: anyhow::Error) -> Self {
        RetrieveStateUpdateError::Other(err)
    }
}

impl StateUpdate {
    /// Retrieves the [StateUpdate] associated with the given [StateUpdateLog] from L1.
    pub async fn retrieve<T: Transport>(
        transport: &Web3<T>,
        state_update: StateUpdateLog,
    ) -> Result<Self, RetrieveStateUpdateError> {
        let transition_fact = retrieve_transition_fact(transport, state_update).await?;

        let mempage_hashes = retrieve_mempage_hashes(transport, transition_fact).await?;

        let mempage_logs = retrieve_memory_page_logs(transport, mempage_hashes).await?;

        let mempage_data = retrieve_mempage_transaction_data(transport, mempage_logs).await?;

        // flatten memory page data (skip first page)
        let mempage_data = mempage_data
            .into_iter()
            .skip(1)
            .flatten()
            .collect::<Vec<_>>();

        // parse memory page data
        let update = StateUpdateParser::parse(mempage_data)?;
        Ok(update)
    }
}
