//! Workaround for the orphan rule - implement conversion fns for types ourside our crate.
use std::time::{Duration, SystemTime};

use pathfinder_common::{state_update::ContractUpdate, BlockHeader, StateUpdate};
use stark_hash::Felt;

pub trait ToProto<T> {
    fn to_proto(self) -> T;
}

impl ToProto<p2p_proto_v1::block::BlockHeader> for BlockHeader {
    fn to_proto(self) -> p2p_proto_v1::block::BlockHeader {
        use p2p_proto_v1::common::{Address, ChainId, Hash, Merkle};
        const ZERO_MERKLE: Merkle = Merkle {
            n_leaves: 0,
            root: Hash(Felt::ZERO),
        };
        p2p_proto_v1::block::BlockHeader {
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

impl ToProto<p2p_proto_v1::state::StateDiff> for StateUpdate {
    fn to_proto(self) -> p2p_proto_v1::state::StateDiff {
        use p2p_proto_v1::common::Address;
        use p2p_proto_v1::state::{ContractDiff, ContractStoredValue, StateDiff};
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
