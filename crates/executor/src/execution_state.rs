use std::sync::Arc;

use blockifier::{block_context::BlockContext, state::cached_state::CachedState};
use pathfinder_common::{BlockNumber, BlockTimestamp, ChainId, SequencerAddress, StateUpdate};
use primitive_types::U256;

use super::state_reader::PathfinderStateReader;

pub struct ExecutionState {
    pub connection: pathfinder_storage::Connection,
    pub chain_id: ChainId,
    pub block_number: BlockNumber,
    pub block_timestamp: BlockTimestamp,
    pub sequencer_address: SequencerAddress,
    pub state_at_block: Option<BlockNumber>,
    pub gas_price: U256,
    pub pending_update: Option<Arc<StateUpdate>>,
}

impl ExecutionState {
    pub(super) fn starknet_state(
        &mut self,
    ) -> anyhow::Result<(CachedState<PathfinderStateReader<'_>>, BlockContext)> {
        let block_context = super::block_context::construct_block_context(self)?;

        let state_reader = PathfinderStateReader::new(
            &mut self.connection,
            self.state_at_block,
            self.pending_update.is_some(),
        )?;

        let mut state = CachedState::new(state_reader);

        self.pending_update.as_ref().map(|pending_update| {
            super::pending::apply_pending_update(&mut state, pending_update.as_ref())
        });

        Ok((state, block_context))
    }
}
