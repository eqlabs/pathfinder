pub mod conv {
    use std::{collections::HashMap, time::SystemTime};

    use pathfinder_common::{
        state_update::{ContractClassUpdate, ContractUpdate, SystemContractUpdate},
        BlockHash, BlockNumber, BlockTimestamp, ClassHash, ContractAddress, ContractNonce,
        GasPrice, SequencerAddress, StarknetVersion, StateCommitment, StateUpdate, StorageAddress,
        StorageValue,
    };

    pub trait TryFromProto<T> {
        fn try_from_proto(proto: T) -> anyhow::Result<Self>
        where
            Self: Sized;
    }

    // Simple block header meant for the temporary p2p client hidden behind
    // the gateway client api, ie. does not contain any commitments
    // TODO: remove this once proper p2p friendly sync is implemented
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BlockHeader {
        pub hash: BlockHash,
        pub parent_hash: BlockHash,
        pub number: BlockNumber,
        pub timestamp: BlockTimestamp,
        pub gas_price: GasPrice,
        pub sequencer_address: SequencerAddress,
        pub starknet_version: StarknetVersion,
    }

    impl From<pathfinder_common::BlockHeader> for BlockHeader {
        fn from(h: pathfinder_common::BlockHeader) -> Self {
            Self {
                hash: h.hash,
                parent_hash: h.parent_hash,
                number: h.number,
                timestamp: h.timestamp,
                gas_price: h.gas_price,
                sequencer_address: h.sequencer_address,
                starknet_version: h.starknet_version,
            }
        }
    }

    impl TryFromProto<p2p_proto_v1::block::BlockHeader> for BlockHeader {
        fn try_from_proto(proto: p2p_proto_v1::block::BlockHeader) -> anyhow::Result<Self>
        where
            Self: Sized,
        {
            Ok(Self {
                hash: BlockHash(proto.block_hash.0),
                parent_hash: BlockHash(proto.parent_header.0),
                number: BlockNumber::new(proto.number)
                    .ok_or(anyhow::anyhow!("Invalid block number > i64::MAX"))?,
                timestamp: BlockTimestamp::new(
                    proto.time.duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
                )
                .ok_or(anyhow::anyhow!("Invalid block timestamp"))?,
                gas_price: GasPrice::from_be_slice(proto.gas_price.as_slice())?,
                sequencer_address: SequencerAddress(proto.sequencer_address.0),
                starknet_version: StarknetVersion::from(proto.starknet_version),
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
