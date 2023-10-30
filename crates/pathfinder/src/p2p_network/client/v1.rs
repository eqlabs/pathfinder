pub mod types {
    use p2p_proto_v1::receipt::{
        DeclareTransactionReceipt, DeployAccountTransactionReceipt, DeployTransactionReceipt,
        InvokeTransactionReceipt, L1HandlerTransactionReceipt,
    };
    use pathfinder_common::{
        event::Event,
        transaction::{
            DeclareTransactionV0V1, DeclareTransactionV2, DeployAccountTransaction,
            DeployTransaction, EntryPointType, InvokeTransactionV0, InvokeTransactionV1,
            L1HandlerTransaction, TransactionVariant,
        },
        CallParam, CasmHash, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
        EntryPoint, EthereumAddress, EventData, EventKey, Fee, L1ToL2MessageNonce,
        L1ToL2MessagePayloadElem, L2ToL1MessagePayloadElem, TransactionHash, TransactionNonce,
        TransactionSignatureElem, TransactionVersion,
    };
    use starknet_gateway_types::reply::transaction as gw;

    /// We don't want to introduce circular dependencies between crates
    /// so in those cases we cannot use TryFrom and we need to work around for the orphan rule
    /// - implement conversion fns for types ourside our crate.
    pub trait TryFromDto<T> {
        fn try_from_dto(dto: T) -> anyhow::Result<Self>
        where
            Self: Sized;
    }

    /// Represents a simplified receipt (events and execution status excluded).
    ///
    /// This type is not in the `p2p` to avoid `p2p` dependence on `starknet_gateway_types`.
    #[derive(Clone, Debug, PartialEq)]
    pub struct Receipt {
        pub transaction_hash: TransactionHash,
        pub actual_fee: Fee,
        pub execution_resources: gw::ExecutionResources,
        pub l1_to_l2_consumed_message: Option<gw::L1ToL2Message>,
        pub l2_to_l1_messages: Vec<gw::L2ToL1Message>,
        // Empty means not reverted
        pub revert_error: String,
    }

    impl From<starknet_gateway_types::reply::transaction::Receipt> for Receipt {
        fn from(r: starknet_gateway_types::reply::transaction::Receipt) -> Self {
            Self {
                transaction_hash: TransactionHash(r.transaction_hash.0),
                actual_fee: r.actual_fee.unwrap_or_default(),
                execution_resources: r.execution_resources.unwrap_or_default(),
                l1_to_l2_consumed_message: r.l1_to_l2_consumed_message,
                l2_to_l1_messages: r.l2_to_l1_messages,
                revert_error: r.revert_error.unwrap_or_default(),
            }
        }
    }

    impl TryFromDto<p2p_proto_v1::transaction::Transaction> for TransactionVariant {
        fn try_from_dto(dto: p2p_proto_v1::transaction::Transaction) -> anyhow::Result<Self>
        where
            Self: Sized,
        {
            use p2p_proto_v1::transaction::Transaction::*;

            Ok(match dto {
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

    impl TryFrom<p2p_proto_v1::receipt::Receipt> for Receipt {
        type Error = anyhow::Error;

        fn try_from(proto: p2p_proto_v1::receipt::Receipt) -> anyhow::Result<Self>
        where
            Self: Sized,
        {
            use p2p_proto_v1::receipt::Receipt::{
                Declare, Deploy, DeployAccount, Invoke, L1Handler,
            };

            match proto {
                Invoke(InvokeTransactionReceipt { common })
                | Declare(DeclareTransactionReceipt { common })
                | L1Handler(L1HandlerTransactionReceipt { common, .. })
                | Deploy(DeployTransactionReceipt { common, .. })
                | DeployAccount(DeployAccountTransactionReceipt { common, .. }) => Ok(Self {
                    transaction_hash: TransactionHash(common.transaction_hash.0),
                    actual_fee: Fee(common.actual_fee),
                    execution_resources: gw::ExecutionResources {
                        builtin_instance_counter: gw::BuiltinCounters {
                            output_builtin: common.execution_resources.builtins.output.into(),
                            pedersen_builtin: common.execution_resources.builtins.pedersen.into(),
                            range_check_builtin: common
                                .execution_resources
                                .builtins
                                .range_check
                                .into(),
                            ecdsa_builtin: common.execution_resources.builtins.ecdsa.into(),
                            bitwise_builtin: common.execution_resources.builtins.bitwise.into(),
                            ec_op_builtin: common.execution_resources.builtins.ec_op.into(),
                            keccak_builtin: common.execution_resources.builtins.keccak.into(),
                            poseidon_builtin: common.execution_resources.builtins.poseidon.into(),
                            segment_arena_builtin: common
                                .execution_resources
                                .builtins
                                .segment_arena
                                .into(),
                        },
                        n_steps: common.execution_resources.steps.into(),
                        n_memory_holes: common.execution_resources.memory_holes.into(),
                    },
                    l1_to_l2_consumed_message: match common.consumed_message {
                        Some(x) => Some(gw::L1ToL2Message {
                            from_address: EthereumAddress(x.from_address.0),
                            payload: x
                                .payload
                                .into_iter()
                                .map(L1ToL2MessagePayloadElem)
                                .collect(),
                            selector: EntryPoint(x.entry_point_selector),
                            to_address: ContractAddress::new(x.to_address).ok_or_else(|| {
                                anyhow::anyhow!("Invalid contract address > u32::MAX")
                            })?,
                            nonce: Some(L1ToL2MessageNonce(x.nonce)),
                        }),
                        None => None,
                    },
                    l2_to_l1_messages: common
                        .messages_sent
                        .into_iter()
                        .map(|x| gw::L2ToL1Message {
                            from_address: ContractAddress(x.from_address),
                            payload: x
                                .payload
                                .into_iter()
                                .map(L2ToL1MessagePayloadElem)
                                .collect(),
                            to_address: EthereumAddress(x.to_address.0),
                        })
                        .collect(),
                    revert_error: common.revert_reason,
                }),
            }
        }
    }

    impl TryFromDto<p2p_proto_v1::event::Event> for Event {
        fn try_from_dto(proto: p2p_proto_v1::event::Event) -> anyhow::Result<Self>
        where
            Self: Sized,
        {
            Ok(Self {
                from_address: ContractAddress(proto.from_address),
                keys: proto.keys.into_iter().map(EventKey).collect(),
                data: proto.data.into_iter().map(EventData).collect(),
            })
        }
    }
}
