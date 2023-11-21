use super::state_reader::PathfinderStateReader;
use crate::{state_reader::LruCachedReader, IntoStarkFelt};
use anyhow::Context;
use blockifier::{
    block_context::BlockContext,
    state::{cached_state::CachedState, state_api::State},
};
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

        // Perform system contract updates if we are executing ontop of a parent block.
        // Currently this is only the block hash from 10 blocks ago.
        if self.execute_on_parent_state && self.header.number.get() >= 10 {
            let block_number_whose_hash_becomes_available =
                pathfinder_common::BlockNumber::new_or_panic(self.header.number.get() - 10);
            let (_, block_hash) = self
                .transaction
                .block_id(block_number_whose_hash_becomes_available.into())?
                .context("Getting historical block hash")?;

            tracing::trace!(%block_number_whose_hash_becomes_available, %block_hash, "Setting historical block hash");

            cached_state.set_storage_at(
                starknet_api::core::ContractAddress(starknet_api::core::PatriciaKey::try_from(
                    starknet_api::hash::StarkFelt::from(1u8),
                )?),
                starknet_api::state::StorageKey(starknet_api::core::PatriciaKey::try_from(
                    starknet_api::hash::StarkFelt::from(
                        block_number_whose_hash_becomes_available.get(),
                    ),
                )?),
                block_hash.0.into_starkfelt(),
            )
        }

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
