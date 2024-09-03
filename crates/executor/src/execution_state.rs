use std::sync::Arc;

use anyhow::Context;
use blockifier::blockifier::block::{pre_process_block, BlockInfo, BlockNumberHashPair};
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo};
use blockifier::state::cached_state::CachedState;
use blockifier::versioned_constants::VersionedConstants;
use pathfinder_common::{
    contract_address,
    BlockHeader,
    ChainId,
    ContractAddress,
    L1DataAvailabilityMode,
    StateUpdate,
};
use starknet_api::core::PatriciaKey;

use super::pending::PendingStateReader;
use super::state_reader::PathfinderStateReader;
use crate::IntoStarkFelt;

// NOTE: these are the same for _all_ networks
pub const ETH_FEE_TOKEN_ADDRESS: ContractAddress =
    contract_address!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7");
pub const STRK_FEE_TOKEN_ADDRESS: ContractAddress =
    contract_address!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

mod versioned_constants {
    use std::borrow::Cow;
    use std::sync::LazyLock;

    use pathfinder_common::StarknetVersion;

    use super::VersionedConstants;

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_0: &[u8] =
        include_bytes!("../resources/versioned_constants_13_0.json");

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_1: &[u8] =
        include_bytes!("../resources/versioned_constants_13_1.json");

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_1_1: &[u8] =
        include_bytes!("../resources/versioned_constants_13_1_1.json");

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_2: &[u8] =
        include_bytes!("../resources/versioned_constants_13_2.json");

    const STARKNET_VERSION_0_13_1: StarknetVersion = StarknetVersion::new(0, 13, 1, 0);

    const STARKNET_VERSION_0_13_1_1: StarknetVersion = StarknetVersion::new(0, 13, 1, 1);

    const STARKNET_VERSION_0_13_2: StarknetVersion = StarknetVersion::new(0, 13, 2, 0);

    const STARKNET_VERSION_0_13_2_1: StarknetVersion = StarknetVersion::new(0, 13, 2, 1);

    pub static BLOCKIFIER_VERSIONED_CONSTANTS_0_13_0: LazyLock<VersionedConstants> =
        LazyLock::new(|| {
            serde_json::from_slice(BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_0).unwrap()
        });

    pub static BLOCKIFIER_VERSIONED_CONSTANTS_0_13_1: LazyLock<VersionedConstants> =
        LazyLock::new(|| {
            serde_json::from_slice(BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_1).unwrap()
        });

    pub static BLOCKIFIER_VERSIONED_CONSTANTS_0_13_1_1: LazyLock<VersionedConstants> =
        LazyLock::new(|| {
            serde_json::from_slice(BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_1_1).unwrap()
        });

    pub static BLOCKIFIER_VERSIONED_CONSTANTS_0_13_2: LazyLock<VersionedConstants> =
        LazyLock::new(|| {
            serde_json::from_slice(BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_2).unwrap()
        });

    pub(super) fn for_version(
        version: &StarknetVersion,
        custom_versioned_constants: Option<VersionedConstants>,
    ) -> Cow<'static, VersionedConstants> {
        // We use 0.13.0 for all blocks _before_ 0.13.1.
        if version < &STARKNET_VERSION_0_13_1 {
            Cow::Borrowed(&BLOCKIFIER_VERSIONED_CONSTANTS_0_13_0)
        } else if version < &STARKNET_VERSION_0_13_1_1 {
            Cow::Borrowed(&BLOCKIFIER_VERSIONED_CONSTANTS_0_13_1)
        } else if version < &STARKNET_VERSION_0_13_2 {
            Cow::Borrowed(&BLOCKIFIER_VERSIONED_CONSTANTS_0_13_1_1)
        } else if version < &STARKNET_VERSION_0_13_2_1 {
            Cow::Borrowed(&BLOCKIFIER_VERSIONED_CONSTANTS_0_13_2)
        } else {
            custom_versioned_constants
                .map(Cow::Owned)
                .unwrap_or_else(|| Cow::Borrowed(VersionedConstants::latest_constants()))
        }
    }
}

pub struct ExecutionState<'tx> {
    transaction: &'tx pathfinder_storage::Transaction<'tx>,
    pub chain_id: ChainId,
    pub header: BlockHeader,
    execute_on_parent_state: bool,
    pending_state: Option<Arc<StateUpdate>>,
    allow_use_kzg_data: bool,
    custom_versioned_constants: Option<VersionedConstants>,
}

impl<'tx> ExecutionState<'tx> {
    pub(super) fn starknet_state(
        self,
    ) -> anyhow::Result<(
        CachedState<PendingStateReader<PathfinderStateReader<'tx>>>,
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
        let mut cached_state = CachedState::new(pending_state_reader);

        let chain_info = self.chain_info()?;
        let block_info = self.block_info()?;

        // Perform system contract updates if we are executing ontop of a parent block.
        // Currently this is only the block hash from 10 blocks ago.
        let old_block_number_and_hash = if self.header.number.get() >= 10 {
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

        let versioned_constants = versioned_constants::for_version(
            &self.header.starknet_version,
            self.custom_versioned_constants,
        );

        pre_process_block(
            &mut cached_state,
            old_block_number_and_hash,
            block_info.block_number,
        )?;

        let block_context = BlockContext::new(
            block_info,
            chain_info,
            versioned_constants.into_owned(),
            BouncerConfig::max(),
        );

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

        let chain_id = match self.chain_id {
            ChainId::MAINNET => starknet_api::core::ChainId::Mainnet,
            ChainId::SEPOLIA_TESTNET => starknet_api::core::ChainId::Sepolia,
            _ => starknet_api::core::ChainId::Other(chain_id),
        };

        Ok(ChainInfo {
            chain_id,
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
            gas_prices: blockifier::blockifier::block::GasPrices {
                eth_l1_gas_price: if self.header.eth_l1_gas_price.0 == 0 {
                    // Bad API design - the genesis block has 0 gas price, but
                    // blockifier doesn't allow for it. This isn't critical for
                    // consensus, so we just use 1.
                    1.try_into().unwrap()
                } else {
                    self.header.eth_l1_gas_price.0.try_into().unwrap()
                },
                strk_l1_gas_price: if self.header.strk_l1_gas_price.0 == 0 {
                    // Bad API design - the genesis block has 0 gas price, but
                    // blockifier doesn't allow for it. This isn't critical for
                    // consensus, so we just use 1.
                    1.try_into().unwrap()
                } else {
                    self.header.strk_l1_gas_price.0.try_into().unwrap()
                },
                eth_l1_data_gas_price: if self.header.eth_l1_data_gas_price.0 == 0 {
                    // Bad API design - pre-v0.13.1 blocks have 0 data gas price, but
                    // blockifier doesn't allow for it. This value is ignored for those
                    // transactions.
                    1.try_into().unwrap()
                } else {
                    self.header.eth_l1_data_gas_price.0.try_into().unwrap()
                },
                strk_l1_data_gas_price: if self.header.strk_l1_data_gas_price.0 == 0 {
                    // Bad API design - pre-v0.13.1 blocks have 0 data gas price, but
                    // blockifier doesn't allow for it. This value is ignored for those
                    // transactions.
                    1.try_into().unwrap()
                } else {
                    self.header.strk_l1_data_gas_price.0.try_into().unwrap()
                },
            },
            use_kzg_da: self.allow_use_kzg_data
                && self.header.l1_da_mode == L1DataAvailabilityMode::Blob,
        })
    }

    pub fn trace(
        transaction: &'tx pathfinder_storage::Transaction<'tx>,
        chain_id: ChainId,
        header: BlockHeader,
        pending_state: Option<Arc<StateUpdate>>,
        custom_versioned_constants: Option<VersionedConstants>,
    ) -> Self {
        Self {
            transaction,
            chain_id,
            header,
            pending_state,
            execute_on_parent_state: true,
            allow_use_kzg_data: true,
            custom_versioned_constants,
        }
    }

    pub fn simulation(
        transaction: &'tx pathfinder_storage::Transaction<'tx>,
        chain_id: ChainId,
        header: BlockHeader,
        pending_state: Option<Arc<StateUpdate>>,
        l1_blob_data_availability: L1BlobDataAvailability,
        custom_versioned_constants: Option<VersionedConstants>,
    ) -> Self {
        Self {
            transaction,
            chain_id,
            header,
            pending_state,
            execute_on_parent_state: false,
            allow_use_kzg_data: l1_blob_data_availability == L1BlobDataAvailability::Enabled,
            custom_versioned_constants,
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum L1BlobDataAvailability {
    Disabled,
    Enabled,
}
