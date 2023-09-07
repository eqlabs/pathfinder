//! Workaround for the orphan rule - implement conversion fns for types ourside our crate.

use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use pathfinder_common::{
    state_update::{ContractClassUpdate, ContractUpdate, SystemContractUpdate},
    BlockHash, BlockHeader, BlockNumber, BlockTimestamp, ClassCommitment, ClassHash,
    ContractAddress, ContractNonce, EventCommitment, GasPrice, SequencerAddress, StarknetVersion,
    StateCommitment, StateUpdate, StorageAddress, StorageCommitment, StorageValue,
    TransactionCommitment,
};
use stark_hash::Felt;

pub trait ToProto<T> {
    fn to_proto(self) -> T;
}

pub trait TryFromProto<T> {
    fn try_from_proto(proto: T) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl ToProto<p2p_proto::block::BlockHeader> for BlockHeader {
    fn to_proto(self) -> p2p_proto::block::BlockHeader {
        use p2p_proto::common::{Address, ChainId, Hash, Merkle};
        const ZERO_MERKLE: Merkle = Merkle {
            n_leaves: 0,
            root: Hash(Felt::ZERO),
        };
        p2p_proto::block::BlockHeader {
            parent_block: Hash(self.parent_hash.0),
            time: SystemTime::UNIX_EPOCH // FIXME Dunno how to convert
                .checked_add(Duration::from_secs(self.timestamp.get()))
                .unwrap(),
            sequencer_address: Address(self.sequencer_address.0),
            // FIXME: all of those zeros
            state_diffs: ZERO_MERKLE,
            state: ZERO_MERKLE,
            proof_fact: Hash(Felt::ZERO),
            transactions: ZERO_MERKLE,
            events: ZERO_MERKLE,
            receipts: ZERO_MERKLE,
            protocol_version: 0,
            chain_id: ChainId(Felt::ZERO),
            // FIXME extra fields added to make sync work
            block_hash: Hash(self.hash.0),
            gas_price: self.gas_price.0.to_be_bytes().into(),
            starknet_version: self.starknet_version.take_inner(),
        }
    }
}

impl ToProto<p2p_proto::state::StateDiff> for StateUpdate {
    fn to_proto(self) -> p2p_proto::state::StateDiff {
        use p2p_proto::common::Address;
        use p2p_proto::state::{ContractDiff, ContractStoredValue, StateDiff};
        StateDiff {
            tree_id: 0, // TODO there will initially be 2 trees, dunno which id is which
            contract_diffs: self
                .system_contract_updates
                .into_iter()
                .map(|(address, update)| {
                    let address = Address(address.0);
                    let values = update
                        .storage
                        .into_iter()
                        .map(|(storage_address, storage_value)| ContractStoredValue {
                            key: storage_address.0,
                            value: storage_value.0,
                        })
                        .collect();
                    let class_hash = Felt::ZERO;
                    let nonce = Felt::ZERO; // FIXME cannot distinguish between None and real 0 nonce
                    ContractDiff {
                        address,
                        nonce,
                        class_hash,
                        values,
                    }
                })
                .chain(self.contract_updates.into_iter().map(|(address, update)| {
                    let address = Address(address.0);
                    let ContractUpdate {
                        storage,
                        class,
                        nonce,
                    } = update;
                    let values = storage
                        .into_iter()
                        .map(|(storage_address, storage_value)| ContractStoredValue {
                            key: storage_address.0,
                            value: storage_value.0,
                        })
                        .collect();
                    let class_hash = class.map(|c| c.class_hash()).unwrap_or_default().0;
                    let nonce = nonce.unwrap_or_default().0;
                    ContractDiff {
                        address,
                        nonce,
                        class_hash,
                        values,
                    }
                }))
                .collect(),
            // FIXME missing: declared classes cairo & sierra, replaced classes, old and new state commitments
        }
    }
}

// FIXME at the moment this implementation is useless due to the massive difference between p2p and internal header representations,
// I'm not sure we want to keep it at all
impl TryFromProto<p2p_proto::block::BlockHeader> for BlockHeader {
    fn try_from_proto(proto: p2p_proto::block::BlockHeader) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            hash: BlockHash::ZERO, // FIXME
            parent_hash: BlockHash(proto.parent_block.0),
            number: BlockNumber::GENESIS, // FIXME
            timestamp: BlockTimestamp::new(
                proto.time.duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
            )
            .unwrap(), // FIXME
            gas_price: GasPrice::ZERO,    // FIXME
            sequencer_address: SequencerAddress(proto.sequencer_address.0),
            starknet_version: StarknetVersion::default(), // FIXME
            class_commitment: ClassCommitment::ZERO,      // FIXME
            event_commitment: EventCommitment::ZERO,      // FIXME
            state_commitment: StateCommitment::ZERO,      // FIXME
            storage_commitment: StorageCommitment::ZERO,  // FIXME
            transaction_commitment: TransactionCommitment::ZERO, // FIXME
            transaction_count: 0,                         // FIXME
            event_count: 0,                               // FIXME
        })
    }
}

// FIXME add missing stuff to the proto representation
impl TryFromProto<p2p_proto::state::StateDiff> for StateUpdate {
    fn try_from_proto(proto: p2p_proto::state::StateDiff) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        const SYSTEM_CONTRACT: ContractAddress = ContractAddress::ONE;
        let mut system_contract_update = SystemContractUpdate {
            storage: Default::default(),
        };
        let mut contract_updates = HashMap::new();
        proto.contract_diffs.into_iter().for_each(|diff| {
            if diff.address.0 == SYSTEM_CONTRACT.0 {
                diff.values.into_iter().for_each(|x| {
                    system_contract_update
                        .storage
                        .insert(StorageAddress(x.key), StorageValue(x.value));
                });
            } else {
                contract_updates.insert(
                    ContractAddress(diff.address.0),
                    ContractUpdate {
                        storage: diff
                            .values
                            .into_iter()
                            .map(|x| (StorageAddress(x.key), StorageValue(x.value)))
                            .collect(),
                        class: (diff.class_hash != ClassHash::ZERO.0)
                            .then_some(ContractClassUpdate::Deploy(ClassHash(diff.class_hash))), // FIXME - need db to check if deploy or replace
                        nonce: Some(ContractNonce(diff.nonce)), // FIXME unable to determine if 0 was intended or means None
                    },
                );
            }
        });

        Ok(Self {
            block_hash: BlockHash::ZERO,                    // FIXME
            parent_state_commitment: StateCommitment::ZERO, // FIXME
            state_commitment: StateCommitment::ZERO,        // FIXME
            contract_updates,
            system_contract_updates: [(SYSTEM_CONTRACT, system_contract_update)].into(),
            declared_cairo_classes: Default::default(), // FIXME
            declared_sierra_classes: Default::default(), // FIXME
        })
    }
}
