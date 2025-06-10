use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use blockifier::blockifier::block::pre_process_block;
use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::blockifier::transaction_executor::TransactionExecutor;
use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo};
use blockifier::state::cached_state::CachedState;
use pathfinder_common::prelude::*;
use pathfinder_common::L1DataAvailabilityMode;
use starknet_api::block::{BlockHashAndNumber, GasPrice, NonzeroGasPrice};
use starknet_api::core::PatriciaKey;

use super::pending::PendingStateReader;
use super::state_reader::PathfinderStateReader;
use crate::state_reader::NativeClassCache;
use crate::types::BlockInfo;
use crate::IntoStarkFelt;

mod versions {
    use pathfinder_common::StarknetVersion;

    pub(super) const STARKNET_VERSION_0_13_1: StarknetVersion = StarknetVersion::new(0, 13, 1, 0);

    pub(super) const STARKNET_VERSION_0_13_1_1: StarknetVersion = StarknetVersion::new(0, 13, 1, 1);

    pub(super) const STARKNET_VERSION_0_13_2: StarknetVersion = StarknetVersion::new(0, 13, 2, 0);

    pub(super) const STARKNET_VERSION_0_13_2_1: StarknetVersion = StarknetVersion::new(0, 13, 2, 1);

    pub(super) const STARKNET_VERSION_0_13_3: StarknetVersion = StarknetVersion::new(0, 13, 3, 0);

    pub(super) const STARKNET_VERSION_0_13_4: StarknetVersion = StarknetVersion::new(0, 13, 4, 0);

    pub(super) const STARKNET_VERSION_0_13_5: StarknetVersion = StarknetVersion::new(0, 13, 5, 0);

    pub(super) const STARKNET_VERSION_0_14_0: StarknetVersion = StarknetVersion::new(0, 14, 0, 0);
}

#[derive(Clone, Debug)]
pub struct VersionedConstantsMap {
    data: BTreeMap<StarknetVersion, Cow<'static, VersionedConstants>>,
}

impl VersionedConstantsMap {
    pub fn new() -> Self {
        let mut data = BTreeMap::new();
        Self::fill_default(&mut data);
        Self { data }
    }

    pub fn custom(mut data: BTreeMap<StarknetVersion, Cow<'static, VersionedConstants>>) -> Self {
        Self::fill_default(&mut data);
        Self { data }
    }

    pub fn latest_version() -> StarknetVersion {
        versions::STARKNET_VERSION_0_13_5
    }

    fn fill_default(data: &mut BTreeMap<StarknetVersion, Cow<'static, VersionedConstants>>) {
        use versions::*;

        Self::insert_default(
            data,
            &STARKNET_VERSION_0_13_1,
            VersionedConstants::get(&starknet_api::block::StarknetVersion::V0_13_1)
                .expect("Failed to get versioned constants for 0.13.1"),
        );
        Self::insert_default(
            data,
            &STARKNET_VERSION_0_13_1_1,
            VersionedConstants::get(&starknet_api::block::StarknetVersion::V0_13_1_1)
                .expect("Failed to get versioned constants for 0.13.1.1"),
        );
        Self::insert_default(
            data,
            &STARKNET_VERSION_0_13_2,
            VersionedConstants::get(&starknet_api::block::StarknetVersion::V0_13_2)
                .expect("Failed to get versioned constants for 0.13.2"),
        );
        Self::insert_default(
            data,
            &STARKNET_VERSION_0_13_2_1,
            VersionedConstants::get(&starknet_api::block::StarknetVersion::V0_13_2_1)
                .expect("Failed to get versioned constants for 0.13.2.1"),
        );
        Self::insert_default(
            data,
            &STARKNET_VERSION_0_13_3,
            VersionedConstants::get(&starknet_api::block::StarknetVersion::V0_13_3)
                .expect("Failed to get versioned constants for 0.13.3"),
        );
        Self::insert_default(
            data,
            &STARKNET_VERSION_0_13_4,
            VersionedConstants::get(&starknet_api::block::StarknetVersion::V0_13_4)
                .expect("Failed to get versioned constants for 0.13.4"),
        );
        Self::insert_default(
            data,
            &STARKNET_VERSION_0_13_5,
            VersionedConstants::get(&starknet_api::block::StarknetVersion::V0_13_5)
                .expect("Failed to get versioned constants for 0.13.5"),
        );
        Self::insert_default(
            data,
            &STARKNET_VERSION_0_14_0,
            VersionedConstants::get(&starknet_api::block::StarknetVersion::V0_14_0)
                .expect("Failed to get versioned constants for 0.14.0"),
        );
    }

    fn insert_default(
        data: &mut BTreeMap<StarknetVersion, Cow<'static, VersionedConstants>>,
        key: &StarknetVersion,
        default_value: &'static VersionedConstants,
    ) {
        // should be try_insert, but that's still experimental...
        if !data.contains_key(key) {
            data.insert(*key, Cow::Borrowed(default_value));
        }
    }

    pub fn for_version(&self, version: &StarknetVersion) -> Cow<'static, VersionedConstants> {
        let mut rng = self.data.range(..=version);
        if let Some(kv) = rng.next_back() {
            kv.1.clone()
        } else {
            // We use 0.13.0 for all blocks before 0.13.1.
            Cow::Borrowed(
                VersionedConstants::get(&starknet_api::block::StarknetVersion::V0_13_0)
                    .expect("Failed to get versioned constants for 0.13.0"),
            )
        }
    }
}

impl Default for VersionedConstantsMap {
    fn default() -> Self {
        Self::new()
    }
}

pub type PathfinderExecutor<'tx> =
    TransactionExecutor<PendingStateReader<PathfinderStateReader<'tx>>>;
pub type PathfinderExecutionState<'tx> =
    CachedState<PendingStateReader<PathfinderStateReader<'tx>>>;

pub struct ExecutionState {
    pub chain_id: ChainId,
    pub block_info: BlockInfo,
    execute_on_parent_state: bool,
    pending_state: Option<Arc<StateUpdate>>,
    allow_use_kzg_data: bool,
    versioned_constants_map: VersionedConstantsMap,
    eth_fee_address: ContractAddress,
    strk_fee_address: ContractAddress,
    native_class_cache: Option<NativeClassCache>,
}

pub fn create_executor(
    db_tx: pathfinder_storage::Transaction<'_>,
    execution_state: ExecutionState,
) -> anyhow::Result<PathfinderExecutor<'_>> {
    let block_number = if execution_state.execute_on_parent_state {
        execution_state.block_info.number.parent()
    } else {
        Some(execution_state.block_info.number)
    };

    let chain_info = execution_state.chain_info()?;
    let block_info = execution_state.block_info()?;

    // Perform system contract updates if we are executing ontop of a parent block.
    // Currently this is only the block hash from 10 blocks ago.
    let old_block_number_and_hash = if execution_state.block_info.number.get() >= 10 {
        let block_number_whose_hash_becomes_available =
            pathfinder_common::BlockNumber::new_or_panic(
                execution_state.block_info.number.get() - 10,
            );
        let block_hash = db_tx
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

    let versioned_constants = execution_state
        .versioned_constants_map
        .for_version(&execution_state.block_info.starknet_version);

    let block_context = BlockContext::new(
        block_info,
        chain_info,
        versioned_constants.into_owned(),
        BouncerConfig::max(),
    );

    let raw_reader = PathfinderStateReader::new(
        db_tx,
        block_number,
        execution_state.pending_state.is_some(),
        execution_state.native_class_cache,
    );
    let pending_state_reader =
        PendingStateReader::new(raw_reader, execution_state.pending_state.clone());

    PathfinderExecutor::pre_process_and_create(
        pending_state_reader,
        block_context,
        old_block_number_and_hash,
        TransactionExecutorConfig::default(),
    )
    .context("Preprocessing state and transaction executor")
}

impl ExecutionState {
    pub(super) fn starknet_state(
        self,
        db_tx: pathfinder_storage::Transaction<'_>,
    ) -> anyhow::Result<(
        CachedState<PendingStateReader<PathfinderStateReader<'_>>>,
        BlockContext,
    )> {
        let block_number = if self.execute_on_parent_state {
            self.block_info.number.parent()
        } else {
            Some(self.block_info.number)
        };

        let chain_info = self.chain_info()?;
        let block_info = self.block_info()?;

        // Perform system contract updates if we are executing ontop of a parent block.
        // Currently this is only the block hash from 10 blocks ago.
        let old_block_number_and_hash = if self.block_info.number.get() >= 10 {
            let block_number_whose_hash_becomes_available =
                pathfinder_common::BlockNumber::new_or_panic(self.block_info.number.get() - 10);
            let block_hash = db_tx
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
            .for_version(&self.block_info.starknet_version);

        let raw_reader = PathfinderStateReader::new(
            db_tx,
            block_number,
            self.pending_state.is_some(),
            self.native_class_cache,
        );
        let pending_state_reader = PendingStateReader::new(raw_reader, self.pending_state.clone());
        let mut cached_state = CachedState::new(pending_state_reader);

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

    fn block_info(&self) -> anyhow::Result<starknet_api::block::BlockInfo> {
        let eth_l1_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.block_info.eth_l1_gas_price.0 == 0 {
                // Bad API design - the genesis block has 0 gas price, but
                // blockifier doesn't allow for it. This isn't critical for
                // consensus, so we just use 1.
                1
            } else {
                self.block_info.eth_l1_gas_price.0
            }))?;
        let strk_l1_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.block_info.strk_l1_gas_price.0 == 0 {
                // Bad API design - the genesis block has 0 gas price, but
                // blockifier doesn't allow for it. This isn't critical for
                // consensus, so we just use 1.
                1
            } else {
                self.block_info.strk_l1_gas_price.0
            }))?;
        let eth_l1_data_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.block_info.eth_l1_data_gas_price.0 == 0 {
                // Bad API design - pre-v0.13.1 blocks have 0 data gas price, but
                // blockifier doesn't allow for it. This value is ignored for those
                // transactions.
                1
            } else {
                self.block_info.eth_l1_data_gas_price.0
            }))?;
        let strk_l1_data_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.block_info.strk_l1_data_gas_price.0 == 0 {
                // Bad API design - pre-v0.13.1 blocks have 0 data gas price, but
                // blockifier doesn't allow for it. This value is ignored for those
                // transactions.
                1
            } else {
                self.block_info.strk_l1_data_gas_price.0
            }))?;
        let eth_l2_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.block_info.eth_l2_gas_price.0 == 0 {
                1
            } else {
                self.block_info.eth_l2_gas_price.0
            }))?;
        let strk_l2_gas_price =
            NonzeroGasPrice::new(GasPrice(if self.block_info.strk_l2_gas_price.0 == 0 {
                1
            } else {
                self.block_info.strk_l2_gas_price.0
            }))?;

        Ok(starknet_api::block::BlockInfo {
            block_number: starknet_api::block::BlockNumber(self.block_info.number.get()),
            block_timestamp: starknet_api::block::BlockTimestamp(self.block_info.timestamp.get()),
            sequencer_address: starknet_api::core::ContractAddress(
                PatriciaKey::try_from(self.block_info.sequencer_address.0.into_starkfelt())
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
                && self.block_info.l1_da_mode == L1DataAvailabilityMode::Blob,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn trace(
        chain_id: ChainId,
        header: BlockHeader,
        pending_state: Option<Arc<StateUpdate>>,
        versioned_constants_map: VersionedConstantsMap,
        eth_fee_address: ContractAddress,
        strk_fee_address: ContractAddress,
        native_class_cache: Option<NativeClassCache>,
    ) -> Self {
        Self {
            chain_id,
            block_info: header.into(),
            pending_state,
            execute_on_parent_state: true,
            allow_use_kzg_data: true,
            versioned_constants_map,
            eth_fee_address,
            strk_fee_address,
            native_class_cache,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn simulation(
        chain_id: ChainId,
        header: BlockHeader,
        pending_state: Option<Arc<StateUpdate>>,
        l1_blob_data_availability: L1BlobDataAvailability,
        versioned_constants_map: VersionedConstantsMap,
        eth_fee_address: ContractAddress,
        strk_fee_address: ContractAddress,
        native_class_cache: Option<NativeClassCache>,
    ) -> Self {
        Self {
            chain_id,
            block_info: header.into(),
            pending_state,
            execute_on_parent_state: false,
            allow_use_kzg_data: l1_blob_data_availability == L1BlobDataAvailability::Enabled,
            versioned_constants_map,
            eth_fee_address,
            strk_fee_address,
            native_class_cache,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validation(
        chain_id: ChainId,
        block_info: BlockInfo,
        pending_state: Option<Arc<StateUpdate>>,
        versioned_constants_map: VersionedConstantsMap,
        eth_fee_address: ContractAddress,
        strk_fee_address: ContractAddress,
        native_class_cache: Option<NativeClassCache>,
    ) -> Self {
        Self {
            chain_id,
            block_info,
            pending_state,
            execute_on_parent_state: true,
            allow_use_kzg_data: true,
            versioned_constants_map,
            eth_fee_address,
            strk_fee_address,
            native_class_cache,
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum L1BlobDataAvailability {
    Disabled,
    Enabled,
}

#[cfg(test)]
mod tests {
    use blockifier::blockifier_versioned_constants::ResourceCost;

    use super::versions::*;
    use super::VersionedConstantsMap;

    #[test]
    fn query_versioned_constants() {
        let vcm = VersionedConstantsMap::default();
        let constants = vcm.for_version(&STARKNET_VERSION_0_13_2);
        let value = constants.deprecated_l2_resource_gas_costs.gas_per_code_byte;
        assert_eq!(value, ResourceCost::new(875, 1000));

        let constants = vcm.for_version(&STARKNET_VERSION_0_13_2_1);
        let value = constants.deprecated_l2_resource_gas_costs.gas_per_code_byte;
        assert_eq!(value, ResourceCost::new(32, 1000));
    }
}
