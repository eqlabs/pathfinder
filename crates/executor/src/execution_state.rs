use super::state_reader::PathfinderStateReader;
use crate::state_reader::LruCachedReader;
use blockifier::{block_context::BlockContext, state::cached_state::CachedState};
use pathfinder_common::{BlockHeader, ChainId, StateUpdate};

pub struct ExecutionState<'tx> {
    transaction: &'tx pathfinder_storage::Transaction<'tx>,
    pub chain_id: ChainId,
    pub header: BlockHeader,
    execute_on_parent_state: bool,
    pending_state: Option<StateUpdate>,
}

impl<'tx> ExecutionState<'tx> {
    pub(super) fn starknet_state(
        &mut self,
    ) -> anyhow::Result<(
        CachedState<LruCachedReader<PathfinderStateReader<'_>>>,
        BlockContext,
    )> {
        let block_context = super::block_context::construct_block_context(self)?;

        let block_number = if self.execute_on_parent_state {
            self.header.number.parent()
        } else {
            Some(self.header.number)
        };

        let raw_reader = PathfinderStateReader::new(
            self.transaction,
            block_number,
            self.pending_state.is_some(),
        );
        let mut cached_state = LruCachedReader::new_cached_state(raw_reader)?;

        self.pending_state.as_ref().map(|pending_state| {
            super::pending::apply_pending_update(&mut cached_state, pending_state)
        });

        Ok((cached_state, block_context))
    }

    pub fn trace(
        transaction: &'tx pathfinder_storage::Transaction<'tx>,
        chain_id: ChainId,
        header: BlockHeader,
        pending_state: Option<StateUpdate>,
    ) -> Self {
        Self {
            transaction,
            chain_id,
            header,
            pending_state,
            execute_on_parent_state: true,
        }
    }

    pub fn simulation(
        transaction: &'tx pathfinder_storage::Transaction<'tx>,
        chain_id: ChainId,
        header: BlockHeader,
        pending_state: Option<StateUpdate>,
    ) -> Self {
        Self {
            transaction,
            chain_id,
            header,
            pending_state,
            execute_on_parent_state: false,
        }
    }
}
