pub mod conv {
    use pathfinder_common::{
        state_update::SystemContractUpdate,
        transaction::{
            DeclareTransactionV0V1, DeclareTransactionV2, DeployAccountTransaction,
            DeployTransaction, EntryPointType, InvokeTransactionV0, InvokeTransactionV1,
            L1HandlerTransaction, TransactionVariant,
        },
        BlockHash, BlockNumber, BlockTimestamp, CallParam, CasmHash, ClassHash, ConstructorParam,
        ContractAddress, ContractAddressSalt, ContractNonce, EntryPoint, Fee, GasPrice,
        SequencerAddress, StarknetVersion, StorageAddress, StorageValue, TransactionNonce,
        TransactionSignatureElem, TransactionVersion,
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
    ///    if it means replacement or declaration
    /// 2. take the remaining ones which are then treated as declared and then figure out which is Cairo 0 and which is Sierra
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

    impl TryFromProto<p2p_proto_v1::transaction::Transaction> for TransactionVariant {
        fn try_from_proto(proto: p2p_proto_v1::transaction::Transaction) -> anyhow::Result<Self>
        where
            Self: Sized,
        {
            use p2p_proto_v1::transaction::Transaction::*;

            Ok(match proto {
                DeclareV0(x) => TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                    class_hash: ClassHash(x.class_hash.0),
                    max_fee: Fee(x.max_fee),
                    nonce: TransactionNonce(x.nonce),
                    sender_address: ContractAddress(x.sender.0),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                }),
                DeclareV1(x) => TransactionVariant::DeclareV1(DeclareTransactionV0V1 {
                    class_hash: ClassHash(x.class_hash.0),
                    max_fee: Fee(x.max_fee),
                    nonce: TransactionNonce(x.nonce),
                    sender_address: ContractAddress(x.sender.0),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                }),
                DeclareV2(x) => TransactionVariant::DeclareV2(DeclareTransactionV2 {
                    class_hash: ClassHash(x.class_hash.0),
                    max_fee: Fee(x.max_fee),
                    nonce: TransactionNonce(x.nonce),
                    sender_address: ContractAddress(x.sender.0),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    compiled_class_hash: CasmHash(x.compiled_class_hash),
                }),
                DeclareV3(_) => unimplemented!(),
                Deploy(x) => TransactionVariant::Deploy(DeployTransaction {
                    contract_address: ContractAddress(x.address.0),
                    contract_address_salt: ContractAddressSalt(x.address_salt),
                    class_hash: ClassHash(x.class_hash.0),
                    constructor_calldata: x.calldata.into_iter().map(ConstructorParam).collect(),
                    version: match x.version {
                        0 => TransactionVersion::ZERO,
                        1 => TransactionVersion::ONE,
                        _ => anyhow::bail!("Invalid deploy transaction version"),
                    },
                }),
                DeployAccountV1(x) => TransactionVariant::DeployAccount(DeployAccountTransaction {
                    contract_address: ContractAddress(x.address.0),
                    max_fee: Fee(x.max_fee),
                    version: TransactionVersion::ONE,
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    nonce: TransactionNonce(x.nonce),
                    contract_address_salt: ContractAddressSalt(x.address_salt),
                    constructor_calldata: x.calldata.into_iter().map(CallParam).collect(),
                    class_hash: ClassHash(x.class_hash.0),
                }),
                DeployAccountV3(_) => unimplemented!(),
                InvokeV0(x) => TransactionVariant::InvokeV0(InvokeTransactionV0 {
                    calldata: x.calldata.into_iter().map(CallParam).collect(),
                    sender_address: ContractAddress(x.address.0),
                    entry_point_selector: EntryPoint(x.entry_point_selector),
                    entry_point_type: x.entry_point_type.map(|x| {
                        use p2p_proto_v1::transaction::EntryPointType::{External, L1Handler};
                        match x {
                            External => EntryPointType::External,
                            L1Handler => EntryPointType::L1Handler,
                        }
                    }),
                    max_fee: Fee(x.max_fee),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                }),
                InvokeV1(x) => TransactionVariant::InvokeV1(InvokeTransactionV1 {
                    calldata: x.calldata.into_iter().map(CallParam).collect(),
                    sender_address: ContractAddress(x.sender.0),
                    max_fee: Fee(x.max_fee),
                    signature: x
                        .signature
                        .parts
                        .into_iter()
                        .map(TransactionSignatureElem)
                        .collect(),
                    nonce: TransactionNonce(x.nonce),
                }),
                InvokeV3(_) => unimplemented!(),
                L1HandlerV1(x) => TransactionVariant::L1Handler(L1HandlerTransaction {
                    contract_address: ContractAddress(x.address.0),
                    entry_point_selector: EntryPoint(x.entry_point_selector),
                    nonce: TransactionNonce(x.nonce),
                    calldata: x.calldata.into_iter().map(CallParam).collect(),
                    // TODO there's a bug in the spec, all available L1 handler transactions up to now (Sep '23)
                    // carry version 0
                    // e.g.
                    // @block 10k
                    // https://alpha-mainnet.starknet.io/feeder_gateway/get_transaction?transactionHash=0x02e42cd5f71a2b09547083f82e267ac2f37ba71e09fa868ffce90d141531c3ba
                    // @block ~261k
                    // https://alpha-mainnet.starknet.io/feeder_gateway/get_transaction?transactionHash=0x02e42cd5f71a2b09547083f82e267ac2f37ba71e09fa868ffce90d141531c3ba
                    version: TransactionVersion::ZERO,
                }),
            })
        }
    }
}
