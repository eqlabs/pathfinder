use std::sync::Arc;

use super::pending::PendingStateReader;
use super::state_reader::PathfinderStateReader;
use crate::IntoStarkFelt;
use anyhow::Context;
use blockifier::{
    block::{pre_process_block, BlockInfo, BlockNumberHashPair},
    context::{BlockContext, ChainInfo},
    state::cached_state::{CachedState, GlobalContractCache},
    versioned_constants::VersionedConstants,
};
use pathfinder_common::{contract_address, BlockHeader, ChainId, ContractAddress, StateUpdate};
use starknet_api::core::PatriciaKey;

// NOTE: these are the same for _all_ networks
pub const ETH_FEE_TOKEN_ADDRESS: ContractAddress =
    contract_address!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7");
pub const STRK_FEE_TOKEN_ADDRESS: ContractAddress =
    contract_address!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

pub struct ExecutionState<'tx> {
    transaction: &'tx pathfinder_storage::Transaction<'tx>,
    pub chain_id: ChainId,
    pub header: BlockHeader,
    execute_on_parent_state: bool,
    pending_state: Option<Arc<StateUpdate>>,
}

impl<'tx> ExecutionState<'tx> {
    pub(super) fn starknet_state(
        &mut self,
    ) -> anyhow::Result<(
        CachedState<PendingStateReader<PathfinderStateReader<'_>>>,
        BlockContext,
    )> {
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
        let pending_state_reader = PendingStateReader::new(raw_reader, self.pending_state.clone());
        let mut cached_state = CachedState::new(pending_state_reader, GlobalContractCache::new(16));

        let chain_info = self.chain_info()?;
        let block_info = self.block_info()?;

        // Perform system contract updates if we are executing ontop of a parent block.
        // Currently this is only the block hash from 10 blocks ago.
        let old_block_number_and_hash = if self.execute_on_parent_state
            && self.header.number.get() >= 10
        {
            let block_number_whose_hash_becomes_available =
                pathfinder_common::BlockNumber::new_or_panic(self.header.number.get() - 10);
            let block_hash = self
                .transaction
                .block_hash(block_number_whose_hash_becomes_available.into())?
                .context("Getting historical block hash")?;

            tracing::trace!(%block_number_whose_hash_becomes_available, %block_hash, "Setting historical block hash");

            Some(BlockNumberHashPair {
                number: starknet_api::block::BlockNumber(
                    block_number_whose_hash_becomes_available.get(),
                ),
                hash: starknet_api::block::BlockHash(block_hash.0.into_starkfelt()),
            })
        } else {
            None
        };

        let block_context = pre_process_block(
            &mut cached_state,
            old_block_number_and_hash,
            block_info,
            chain_info,
            VersionedConstants::latest_constants().to_owned(),
        )?;

        Ok((cached_state, block_context))
    }

    fn chain_info(&self) -> anyhow::Result<ChainInfo> {
        let eth_fee_token_address = starknet_api::core::ContractAddress(
            PatriciaKey::try_from(ETH_FEE_TOKEN_ADDRESS.0.into_starkfelt())
                .expect("ETH fee token address overflow"),
        );
        let strk_fee_token_address = starknet_api::core::ContractAddress(
            PatriciaKey::try_from(STRK_FEE_TOKEN_ADDRESS.0.into_starkfelt())
                .expect("STRK fee token address overflow"),
        );

        let chain_id: Vec<_> = self
            .chain_id
            .0
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        let chain_id = String::from_utf8(chain_id)?;

        Ok(ChainInfo {
            chain_id: starknet_api::core::ChainId(chain_id),
            fee_token_addresses: blockifier::context::FeeTokenAddresses {
                strk_fee_token_address,
                eth_fee_token_address,
            },
        })
    }

    fn block_info(&self) -> anyhow::Result<BlockInfo> {
        Ok(BlockInfo {
            block_number: starknet_api::block::BlockNumber(self.header.number.get()),
            block_timestamp: starknet_api::block::BlockTimestamp(self.header.timestamp.get()),
            sequencer_address: starknet_api::core::ContractAddress(
                PatriciaKey::try_from(self.header.sequencer_address.0.into_starkfelt())
                    .expect("Sequencer address overflow"),
            ),
            gas_prices: blockifier::block::GasPrices {
                eth_l1_gas_price: self.header.eth_l1_gas_price.0.try_into()?,
                strk_l1_gas_price: self.header.strk_l1_gas_price.0.try_into()?,
                eth_l1_data_gas_price: todo!(),
                strk_l1_data_gas_price: todo!(),
            },
            use_kzg_da: false,
        })
    }

    pub fn trace(
        transaction: &'tx pathfinder_storage::Transaction<'tx>,
        chain_id: ChainId,
        header: BlockHeader,
        pending_state: Option<Arc<StateUpdate>>,
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
        pending_state: Option<Arc<StateUpdate>>,
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
