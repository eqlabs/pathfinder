pub mod conv {
    use pathfinder_common::{
        state_update::SystemContractUpdate, BlockHash, BlockNumber, BlockTimestamp, ClassHash,
        ContractAddress, ContractNonce, GasPrice, SequencerAddress, StarknetVersion,
        StorageAddress, StorageValue,
    };
    use std::{collections::HashMap, time::SystemTime};

    pub trait TryFromProto<T> {
        fn try_from_proto(proto: T) -> anyhow::Result<Self>
        where
            Self: Sized;
    }

    /// Simple block header meant for the temporary p2p client hidden behind
    /// the gateway client api, ie.: does not contain any commitments
    ///
    /// TODO: remove this once proper p2p friendly sync is implemented
    #[derive(Debug, Clone, PartialEq)]
    pub struct BlockHeader {
        pub hash: BlockHash,
        pub parent_hash: BlockHash,
        pub number: BlockNumber,
        pub timestamp: BlockTimestamp,
        pub gas_price: GasPrice,
        pub sequencer_address: SequencerAddress,
        pub starknet_version: StarknetVersion,
    }

    /// Simple state update meant for the temporary p2p client hidden behind
    /// the gateway client api, ie.:
    /// - does not contain any commitments
    /// - does not specify if the class was declared or replaced
    ///
    /// TODO: remove this once proper p2p friendly sync is implemented
    ///
    /// How to manage this modest state update:
    /// 1. iterate through contact updates and check in the db if the contract is already there to figure out
    ///    which are the replaced classes
    /// 2. take the remaining ones which are then declared and then figure out which is Cairo 0 and which is Sierra
    #[derive(Default, Debug, Clone, PartialEq)]
    pub struct StateUpdate {
        pub contract_updates: HashMap<ContractAddress, ContractUpdate>,
        pub system_contract_updates: HashMap<ContractAddress, SystemContractUpdate>,
    }

    #[derive(Default, Debug, Clone, PartialEq)]
    pub struct ContractUpdate {
        pub storage: HashMap<StorageAddress, StorageValue>,
        /// The class associated with this update as the result of either a deploy or class replacement transaction.
        /// We don't explicitly know if it's one or the other
        pub class: Option<ClassHash>,
        pub nonce: Option<ContractNonce>,
    }

    impl From<pathfinder_common::StateUpdate> for StateUpdate {
        fn from(s: pathfinder_common::StateUpdate) -> Self {
            Self {
                contract_updates: s
                    .contract_updates
                    .into_iter()
                    .map(|(k, v)| (k, v.into()))
                    .collect(),
                system_contract_updates: s.system_contract_updates,
            }
        }
    }

    impl From<pathfinder_common::state_update::ContractUpdate> for ContractUpdate {
        fn from(c: pathfinder_common::state_update::ContractUpdate) -> Self {
            Self {
                storage: c.storage,
                class: c.class.map(|x| x.class_hash()),
                nonce: c.nonce,
            }
        }
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
                            class: diff.class_hash.map(ClassHash),
                            nonce: diff.nonce.map(ContractNonce),
                        },
                    );
                }
            });

            Ok(Self {
                contract_updates,
                system_contract_updates: [(SYSTEM_CONTRACT, system_contract_update)].into(),
            })
        }
    }
}
