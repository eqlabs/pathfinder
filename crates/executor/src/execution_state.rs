use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use blockifier::blockifier::block::pre_process_block;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo};
use blockifier::state::cached_state::CachedState;
use blockifier::versioned_constants::VersionedConstants;
use pathfinder_common::{
    BlockHeader,
    ChainId,
    ContractAddress,
    L1DataAvailabilityMode,
    StarknetVersion,
    StateUpdate,
};
use starknet_api::block::{BlockHashAndNumber, BlockInfo, GasPrice, NonzeroGasPrice};
use starknet_api::core::PatriciaKey;

use super::pending::PendingStateReader;
use super::state_reader::PathfinderStateReader;
use crate::IntoStarkFelt;

mod versioned_constants {
    use std::sync::LazyLock;

    use pathfinder_common::StarknetVersion;

    use super::VersionedConstants;

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_0: &[u8] =
        include_bytes!("../resources/versioned_constants_0_13_0.json");

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_1: &[u8] =
        include_bytes!("../resources/versioned_constants_0_13_1.json");

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_1_1: &[u8] =
        include_bytes!("../resources/versioned_constants_0_13_1_1.json");

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_2: &[u8] =
        include_bytes!("../resources/versioned_constants_0_13_2.json");

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_2_1: &[u8] =
        include_bytes!("../resources/versioned_constants_0_13_2_1.json");

    const BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_3: &[u8] =
        include_bytes!("../resources/versioned_constants_0_13_3.json");

    pub(super) const STARKNET_VERSION_0_13_0: StarknetVersion = StarknetVersion::new(0, 13, 0, 0);

    pub(super) const STARKNET_VERSION_0_13_1: StarknetVersion = StarknetVersion::new(0, 13, 1, 0);

    pub(super) const STARKNET_VERSION_0_13_1_1: StarknetVersion = StarknetVersion::new(0, 13, 1, 1);

    pub(super) const STARKNET_VERSION_0_13_2: StarknetVersion = StarknetVersion::new(0, 13, 2, 0);

    pub(super) const STARKNET_VERSION_0_13_2_1: StarknetVersion = StarknetVersion::new(0, 13, 2, 1);

    pub(super) const STARKNET_VERSION_0_13_3: StarknetVersion = StarknetVersion::new(0, 13, 3, 0);

    pub(super) const STARKNET_VERSION_0_13_4: StarknetVersion = StarknetVersion::new(0, 13, 4, 0);

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

    pub static BLOCKIFIER_VERSIONED_CONSTANTS_0_13_2_1: LazyLock<VersionedConstants> =
        LazyLock::new(|| {
            serde_json::from_slice(BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_2_1).unwrap()
        });

    pub static BLOCKIFIER_VERSIONED_CONSTANTS_0_13_3: LazyLock<VersionedConstants> =
        LazyLock::new(|| {
            serde_json::from_slice(BLOCKIFIER_VERSIONED_CONSTANTS_JSON_0_13_3).unwrap()
        });
}

#[derive(Clone, Debug, Default)]
pub struct VersionedConstantsMap {
    data: BTreeMap<StarknetVersion, VersionedConstants>,
}

impl VersionedConstantsMap {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    // Accepts only the last versions before versioned constants update.
    pub fn to_version(raw: &str) -> Option<StarknetVersion> {
        use versioned_constants::*;

        let version = raw.parse::<StarknetVersion>().ok()?;
        match version {
            STARKNET_VERSION_0_13_0
            | STARKNET_VERSION_0_13_1
            | STARKNET_VERSION_0_13_1_1
            | STARKNET_VERSION_0_13_2
            | STARKNET_VERSION_0_13_2_1
            | STARKNET_VERSION_0_13_3
            | STARKNET_VERSION_0_13_4 => Some(version),
            _ => None,
        }
    }

    // The version argument must be one of the last versions before
    // versioned constants update.
    pub fn insert_version(
        &mut self,
        version: StarknetVersion,
        constants: VersionedConstants,
    ) -> Option<VersionedConstants> {
        self.data.insert(version, constants)
    }

    pub fn insert_latest_version(
        &mut self,
        constants: VersionedConstants,
    ) -> Option<VersionedConstants> {
        self.insert_version(versioned_constants::STARKNET_VERSION_0_13_4, constants)
    }

    pub fn for_version(&self, version: &StarknetVersion) -> Cow<'static, VersionedConstants> {
        use versioned_constants::*;

        // We use 0.13.0 for all blocks _before_ 0.13.1.
        if version < &STARKNET_VERSION_0_13_1 {
            self.for_last_version(
                &STARKNET_VERSION_0_13_0,
                &BLOCKIFIER_VERSIONED_CONSTANTS_0_13_0,
            )
        } else if version < &STARKNET_VERSION_0_13_1_1 {
            self.for_last_version(
                &STARKNET_VERSION_0_13_1,
                &BLOCKIFIER_VERSIONED_CONSTANTS_0_13_1,
            )
        } else if version < &STARKNET_VERSION_0_13_2 {
            self.for_last_version(
                &STARKNET_VERSION_0_13_1_1,
                &BLOCKIFIER_VERSIONED_CONSTANTS_0_13_1_1,
            )
        } else if version < &STARKNET_VERSION_0_13_2_1 {
            self.for_last_version(
                &STARKNET_VERSION_0_13_2,
                &BLOCKIFIER_VERSIONED_CONSTANTS_0_13_2,
            )
        } else if version < &STARKNET_VERSION_0_13_3 {
            self.for_last_version(
                &STARKNET_VERSION_0_13_2_1,
                &BLOCKIFIER_VERSIONED_CONSTANTS_0_13_2_1,
            )
        } else if version < &STARKNET_VERSION_0_13_4 {
            self.for_last_version(
                &STARKNET_VERSION_0_13_3,
                &BLOCKIFIER_VERSIONED_CONSTANTS_0_13_3,
            )
        } else {
            self.for_last_version(
                &STARKNET_VERSION_0_13_4,
                VersionedConstants::latest_constants(),
            )
        }
    }

    fn for_last_version(
        &self,
        last_version: &StarknetVersion,
        last_version_default: &'static VersionedConstants,
    ) -> Cow<'static, VersionedConstants> {
        let last_version_override = self.data.get(last_version).cloned();
        last_version_override
            .map(Cow::Owned)
            .unwrap_or_else(|| Cow::Borrowed(last_version_default))
    }
}

pub struct ExecutionState<'tx> {
    transaction: &'tx pathfinder_storage::Transaction<'tx>,
    pub chain_id: ChainId,
    pub header: BlockHeader,
    execute_on_parent_state: bool,
    pending_state: Option<Arc<StateUpdate>>,
    allow_use_kzg_data: bool,
    versioned_constants_map: VersionedConstantsMap,
    eth_fee_address: ContractAddress,
    strk_fee_address: ContractAddress,
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

            Some(BlockHashAndNumber {
                number: starknet_api::block::BlockNumber(
                    block_number_whose_hash_becomes_available.get(),
                ),
                hash: starknet_api::block::BlockHash(block_hash.0.into_starkfelt()),
            })
        } else {
            None
        };

        let versioned_constants = self
            .versioned_constants_map
            .for_version(&self.header.starknet_version);

        pre_process_block(
            &mut cached_state,
            old_block_number_and_hash,
            block_info.block_number,
            &versioned_constants.os_constants,
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
            PatriciaKey::try_from(self.eth_fee_address.0.into_starkfelt())
                .expect("ETH fee token address overflow"),
        );
        let strk_fee_token_address = starknet_api::core::ContractAddress(
            PatriciaKey::try_from(self.strk_fee_address.0.into_starkfelt())
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
        let eth_l1_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.header.eth_l1_gas_price.0 == 0 {
                // Bad API design - the genesis block has 0 gas price, but
                // blockifier doesn't allow for it. This isn't critical for
                // consensus, so we just use 1.
                1
            } else {
                self.header.eth_l1_gas_price.0
            }))?;
        let strk_l1_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.header.strk_l1_gas_price.0 == 0 {
                // Bad API design - the genesis block has 0 gas price, but
                // blockifier doesn't allow for it. This isn't critical for
                // consensus, so we just use 1.
                1
            } else {
                self.header.strk_l1_gas_price.0
            }))?;
        let eth_l1_data_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.header.eth_l1_data_gas_price.0 == 0 {
                // Bad API design - pre-v0.13.1 blocks have 0 data gas price, but
                // blockifier doesn't allow for it. This value is ignored for those
                // transactions.
                1
            } else {
                self.header.eth_l1_data_gas_price.0
            }))?;
        let strk_l1_data_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.header.strk_l1_data_gas_price.0 == 0 {
                // Bad API design - pre-v0.13.1 blocks have 0 data gas price, but
                // blockifier doesn't allow for it. This value is ignored for those
                // transactions.
                1
            } else {
                self.header.strk_l1_data_gas_price.0
            }))?;
        let eth_l2_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.header.eth_l2_gas_price.0 == 0 {
                1
            } else {
                self.header.eth_l2_gas_price.0
            }))?;
        let strk_l2_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.header.strk_l2_gas_price.0 == 0 {
                1
            } else {
                self.header.strk_l2_gas_price.0
            }))?;

        Ok(BlockInfo {
            block_number: starknet_api::block::BlockNumber(self.header.number.get()),
            block_timestamp: starknet_api::block::BlockTimestamp(self.header.timestamp.get()),
            sequencer_address: starknet_api::core::ContractAddress(
                PatriciaKey::try_from(self.header.sequencer_address.0.into_starkfelt())
                    .expect("Sequencer address overflow"),
            ),
            gas_prices: starknet_api::block::GasPrices {
                eth_gas_prices: starknet_api::block::GasPriceVector {
                    l1_gas_price: eth_l1_gas_price,
                    l1_data_gas_price: eth_l1_data_gas_price,
                    l2_gas_price: eth_l2_gas_price,
                },
                strk_gas_prices: starknet_api::block::GasPriceVector {
                    l1_gas_price: strk_l1_gas_price,
                    l1_data_gas_price: strk_l1_data_gas_price,
                    l2_gas_price: strk_l2_gas_price,
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
        versioned_constants_map: VersionedConstantsMap,
        eth_fee_address: ContractAddress,
        strk_fee_address: ContractAddress,
    ) -> Self {
        Self {
            transaction,
            chain_id,
            header,
            pending_state,
            execute_on_parent_state: true,
            allow_use_kzg_data: true,
            versioned_constants_map,
            eth_fee_address,
            strk_fee_address,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn simulation(
        transaction: &'tx pathfinder_storage::Transaction<'tx>,
        chain_id: ChainId,
        header: BlockHeader,
        pending_state: Option<Arc<StateUpdate>>,
        l1_blob_data_availability: L1BlobDataAvailability,
        versioned_constants_map: VersionedConstantsMap,
        eth_fee_address: ContractAddress,
        strk_fee_address: ContractAddress,
    ) -> Self {
        Self {
            transaction,
            chain_id,
            header,
            pending_state,
            execute_on_parent_state: false,
            allow_use_kzg_data: l1_blob_data_availability == L1BlobDataAvailability::Enabled,
            versioned_constants_map,
            eth_fee_address,
            strk_fee_address,
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum L1BlobDataAvailability {
    Disabled,
    Enabled,
}
