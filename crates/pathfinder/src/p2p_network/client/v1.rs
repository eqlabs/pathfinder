pub mod conv {
    use std::{collections::HashMap, time::SystemTime};

    use pathfinder_common::{
        state_update::{ContractClassUpdate, ContractUpdate, SystemContractUpdate},
        BlockHash, BlockHeader, BlockNumber, BlockTimestamp, ClassCommitment, ClassHash,
        ContractAddress, ContractNonce, EventCommitment, GasPrice, SequencerAddress,
        StarknetVersion, StateCommitment, StateUpdate, StorageAddress, StorageCommitment,
        StorageValue, TransactionCommitment,
    };

    pub trait TryFromProto<T> {
        fn try_from_proto(proto: T) -> anyhow::Result<Self>
        where
            Self: Sized;
    }

    // FIXME at the moment this implementation is useless due to the massive difference between p2p and internal header representations,
    // I'm not sure we want to keep it at all
    impl TryFromProto<p2p_proto_v1::block::BlockHeader> for BlockHeader {
        fn try_from_proto(proto: p2p_proto_v1::block::BlockHeader) -> anyhow::Result<Self>
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
    impl TryFromProto<p2p_proto_v1::state::StateDiff> for StateUpdate {
        fn try_from_proto(proto: p2p_proto_v1::state::StateDiff) -> anyhow::Result<Self>
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
}
