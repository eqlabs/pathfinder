use std::borrow::Cow;

use anyhow::Context;
use pathfinder_common::{
    receipt::{
        BuiltinCounters, ExecutionDataAvailability, ExecutionResources, ExecutionStatus,
        L2ToL1Message, Receipt,
    },
    state_update::StateUpdateCounts,
    transaction::{
        DataAvailabilityMode, DeclareTransactionV0V1, DeclareTransactionV2, DeclareTransactionV3,
        DeployAccountTransactionV1, DeployAccountTransactionV3, DeployTransaction,
        InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3, L1HandlerTransaction,
        ResourceBound, ResourceBounds, Transaction, TransactionVariant,
    },
    AccountDeploymentDataElem, BlockCommitmentSignature, BlockCommitmentSignatureElem, BlockHash,
    BlockHeader, BlockNumber, BlockTimestamp, ByteCodeOffset, CallParam, CasmHash, ClassCommitment,
    ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt, EntryPoint, EthereumAddress,
    EventCommitment, EventData, EventKey, Fee, GasPrice, L1DataAvailabilityMode,
    L2ToL1MessagePayloadElem, SequencerAddress, SignedBlockHeader, StateCommitment,
    StorageCommitment, TransactionCommitment, TransactionHash, TransactionIndex, TransactionNonce,
    TransactionSignatureElem, TransactionVersion,
};
use pathfinder_crypto::Felt;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// We don't want to introduce circular dependencies between crates
/// and we need to work around for the orphan rule - implement conversion fns for types ourside our crate.
pub trait TryFromDto<T> {
    fn try_from_dto(dto: T) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl TryFromDto<p2p_proto::header::SignedBlockHeader> for SignedBlockHeader {
    /// ## Important
    ///
    /// This conversion leaves `class_commitment` and `storage_commitment` fields zeroed.
    /// The caller must make sure to fill them with the correct values after the conversion succeeds.
    fn try_from_dto(dto: p2p_proto::header::SignedBlockHeader) -> anyhow::Result<Self> {
        anyhow::ensure!(dto.signatures.len() == 1, "expected exactly one signature");
        let signature = dto
            .signatures
            .into_iter()
            .map(|sig| BlockCommitmentSignature {
                r: BlockCommitmentSignatureElem(sig.r),
                s: BlockCommitmentSignatureElem(sig.s),
            })
            .next()
            .expect("exactly one element");
        Ok(SignedBlockHeader {
            header: BlockHeader {
                hash: BlockHash(dto.block_hash.0),
                parent_hash: BlockHash(dto.parent_hash.0),
                number: BlockNumber::new(dto.number)
                    .ok_or(anyhow::anyhow!("block number > i64::MAX"))?,
                timestamp: BlockTimestamp::new(dto.time)
                    .ok_or(anyhow::anyhow!("block timestamp > i64::MAX"))?,
                eth_l1_gas_price: GasPrice(dto.gas_price_wei),
                strk_l1_gas_price: GasPrice(dto.gas_price_fri),
                eth_l1_data_gas_price: GasPrice(dto.data_gas_price_wei),
                strk_l1_data_gas_price: GasPrice(dto.data_gas_price_fri),
                sequencer_address: SequencerAddress(dto.sequencer_address.0),
                starknet_version: dto.protocol_version.parse()?,
                class_commitment: ClassCommitment::ZERO,
                event_commitment: EventCommitment(dto.events.root.0),
                state_commitment: StateCommitment(dto.state.root.0),
                storage_commitment: StorageCommitment::ZERO,
                transaction_commitment: TransactionCommitment(dto.transactions.root.0),
                transaction_count: dto.transactions.n_leaves.try_into()?,
                event_count: dto.events.n_leaves.try_into()?,
                l1_da_mode: TryFromDto::try_from_dto(dto.l1_data_availability_mode)?,
            },
            signature,
            state_update_counts: StateUpdateCounts {
                storage_diffs: dto.num_storage_diffs,
                nonce_updates: dto.num_nonce_updates,
                declared_classes: dto.num_declared_classes,
                deployed_contracts: dto.num_deployed_contracts,
            },
        })
    }
}

impl TryFromDto<p2p_proto::transaction::Transaction> for Transaction {
    fn try_from_dto(dto: p2p_proto::transaction::Transaction) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Transaction {
            hash: TransactionHash(dto.hash.0),
            variant: TransactionVariant::try_from_dto(dto.variant)?,
        })
    }
}

impl TryFromDto<p2p_proto::transaction::TransactionVariant> for TransactionVariant {
    /// ## Important
    ///
    /// This conversion does not compute deployed contract address for deploy account transactions
    /// ([`TransactionVariant::DeployAccountV1`] and [`TransactionVariant::DeployAccountV3`]),
    /// filling it with a zero address instead. The caller is responsible for performing the computation after the conversion succeeds.
    fn try_from_dto(dto: p2p_proto::transaction::TransactionVariant) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        use p2p_proto::transaction::TransactionVariant::{
            DeclareV0, DeclareV1, DeclareV2, DeclareV3, Deploy, DeployAccountV1, DeployAccountV3,
            InvokeV0, InvokeV1, InvokeV3, L1HandlerV0,
        };
        Ok(match dto {
            DeclareV0(x) => Self::DeclareV0(DeclareTransactionV0V1 {
                class_hash: ClassHash(x.class_hash.0),
                max_fee: Fee(x.max_fee),
                nonce: TransactionNonce::ZERO,
                sender_address: ContractAddress(x.sender.0),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
            }),
            DeclareV1(x) => Self::DeclareV1(DeclareTransactionV0V1 {
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
            DeclareV2(x) => Self::DeclareV2(DeclareTransactionV2 {
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
            DeclareV3(x) => Self::DeclareV3(DeclareTransactionV3 {
                class_hash: ClassHash(x.class_hash.0),
                nonce: TransactionNonce(x.nonce),
                nonce_data_availability_mode: DataAvailabilityMode::try_from_dto(x.nonce_domain)?,
                fee_data_availability_mode: DataAvailabilityMode::try_from_dto(x.fee_domain)?,
                resource_bounds: ResourceBounds::try_from_dto(x.resource_bounds)?,
                tip: pathfinder_common::Tip(x.tip.try_into()?),
                paymaster_data: vec![pathfinder_common::PaymasterDataElem(x.paymaster_data.0)],
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                account_deployment_data: vec![AccountDeploymentDataElem(
                    x.account_deployment_data.0,
                )],
                sender_address: ContractAddress(x.sender.0),
                compiled_class_hash: CasmHash(x.compiled_class_hash),
            }),
            Deploy(x) => Self::Deploy(DeployTransaction {
                contract_address: ContractAddress::ZERO,
                contract_address_salt: ContractAddressSalt(x.address_salt),
                class_hash: ClassHash(x.class_hash.0),
                constructor_calldata: x.calldata.into_iter().map(ConstructorParam).collect(),
                version: match x.version {
                    0 => TransactionVersion::ZERO,
                    1 => TransactionVersion::ONE,
                    _ => anyhow::bail!("Invalid deploy transaction version"),
                },
            }),
            DeployAccountV1(x) => Self::DeployAccountV1(DeployAccountTransactionV1 {
                contract_address: ContractAddress::ZERO,
                max_fee: Fee(x.max_fee),
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
            DeployAccountV3(x) => Self::DeployAccountV3(DeployAccountTransactionV3 {
                contract_address: ContractAddress::ZERO,
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                nonce: TransactionNonce(x.nonce),
                nonce_data_availability_mode: DataAvailabilityMode::try_from_dto(x.nonce_domain)?,
                fee_data_availability_mode: DataAvailabilityMode::try_from_dto(x.fee_domain)?,
                resource_bounds: ResourceBounds::try_from_dto(x.resource_bounds)?,
                tip: pathfinder_common::Tip(x.tip.try_into()?),
                paymaster_data: vec![pathfinder_common::PaymasterDataElem(x.paymaster_data.0)],
                contract_address_salt: ContractAddressSalt(x.address_salt),
                constructor_calldata: x.calldata.into_iter().map(CallParam).collect(),
                class_hash: ClassHash(x.class_hash.0),
            }),
            InvokeV0(x) => Self::InvokeV0(InvokeTransactionV0 {
                calldata: x.calldata.into_iter().map(CallParam).collect(),
                sender_address: ContractAddress(x.address.0),
                entry_point_selector: EntryPoint(x.entry_point_selector),
                entry_point_type: None,
                max_fee: Fee(x.max_fee),
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
            }),
            InvokeV1(x) => Self::InvokeV1(InvokeTransactionV1 {
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
            InvokeV3(x) => Self::InvokeV3(InvokeTransactionV3 {
                signature: x
                    .signature
                    .parts
                    .into_iter()
                    .map(TransactionSignatureElem)
                    .collect(),
                nonce: TransactionNonce(x.nonce),
                nonce_data_availability_mode: DataAvailabilityMode::try_from_dto(x.nonce_domain)?,
                fee_data_availability_mode: DataAvailabilityMode::try_from_dto(x.fee_domain)?,
                resource_bounds: ResourceBounds::try_from_dto(x.resource_bounds)?,
                tip: pathfinder_common::Tip(x.tip.try_into()?),
                paymaster_data: vec![pathfinder_common::PaymasterDataElem(x.paymaster_data.0)],
                account_deployment_data: vec![AccountDeploymentDataElem(
                    x.account_deployment_data.0,
                )],
                calldata: x.calldata.into_iter().map(CallParam).collect(),
                sender_address: ContractAddress(x.sender.0),
            }),
            L1HandlerV0(x) => Self::L1Handler(L1HandlerTransaction {
                contract_address: ContractAddress(x.address.0),
                entry_point_selector: EntryPoint(x.entry_point_selector),
                nonce: TransactionNonce(x.nonce),
                calldata: x.calldata.into_iter().map(CallParam).collect(),
            }),
        })
    }
}

impl TryFromDto<(p2p_proto::receipt::Receipt, TransactionIndex)> for Receipt {
    fn try_from_dto(
        (dto, transaction_index): (p2p_proto::receipt::Receipt, TransactionIndex),
    ) -> anyhow::Result<Self> {
        use p2p_proto::receipt::Receipt::{Declare, Deploy, DeployAccount, Invoke, L1Handler};
        use p2p_proto::receipt::{
            DeclareTransactionReceipt, DeployAccountTransactionReceipt, DeployTransactionReceipt,
            InvokeTransactionReceipt, L1HandlerTransactionReceipt,
        };
        match dto {
            Invoke(InvokeTransactionReceipt { common })
            | Declare(DeclareTransactionReceipt { common })
            | L1Handler(L1HandlerTransactionReceipt { common, .. })
            | Deploy(DeployTransactionReceipt { common, .. })
            | DeployAccount(DeployAccountTransactionReceipt { common, .. }) => Ok(Self {
                transaction_hash: TransactionHash(common.transaction_hash.0),
                actual_fee: Fee(common.actual_fee),
                execution_resources: ExecutionResources {
                    builtins: BuiltinCounters {
                        output: common.execution_resources.builtins.output.into(),
                        pedersen: common.execution_resources.builtins.pedersen.into(),
                        range_check: common.execution_resources.builtins.range_check.into(),
                        ecdsa: common.execution_resources.builtins.ecdsa.into(),
                        bitwise: common.execution_resources.builtins.bitwise.into(),
                        ec_op: common.execution_resources.builtins.ec_op.into(),
                        keccak: common.execution_resources.builtins.keccak.into(),
                        poseidon: common.execution_resources.builtins.poseidon.into(),
                        segment_arena: 0,
                    },
                    n_steps: common.execution_resources.steps.into(),
                    n_memory_holes: common.execution_resources.memory_holes.into(),
                    data_availability: ExecutionDataAvailability {
                        l1_gas: GasPrice::try_from(common.execution_resources.l1_gas)?.0,
                        l1_data_gas: GasPrice::try_from(common.execution_resources.l1_data_gas)?.0,
                    },
                },
                l2_to_l1_messages: common
                    .messages_sent
                    .into_iter()
                    .map(|x| L2ToL1Message {
                        from_address: ContractAddress(x.from_address),
                        payload: x
                            .payload
                            .into_iter()
                            .map(L2ToL1MessagePayloadElem)
                            .collect(),
                        to_address: EthereumAddress(x.to_address.0),
                    })
                    .collect(),
                execution_status: if common.revert_reason.is_empty() {
                    ExecutionStatus::Succeeded
                } else {
                    ExecutionStatus::Reverted {
                        reason: common.revert_reason,
                    }
                },
                transaction_index,
            }),
        }
    }
}

impl TryFromDto<p2p_proto::transaction::ResourceBounds> for ResourceBounds {
    fn try_from_dto(dto: p2p_proto::transaction::ResourceBounds) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            l1_gas: ResourceBound {
                max_amount: pathfinder_common::ResourceAmount(dto.l1_gas.max_amount.try_into()?),
                max_price_per_unit: pathfinder_common::ResourcePricePerUnit(
                    dto.l1_gas.max_price_per_unit.try_into()?,
                ),
            },
            l2_gas: ResourceBound {
                max_amount: pathfinder_common::ResourceAmount(dto.l2_gas.max_amount.try_into()?),
                max_price_per_unit: pathfinder_common::ResourcePricePerUnit(
                    dto.l2_gas.max_price_per_unit.try_into()?,
                ),
            },
        })
    }
}

impl TryFromDto<String> for DataAvailabilityMode {
    fn try_from_dto(dto: String) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        match dto.as_str() {
            "L1" => Ok(Self::L1),
            "L2" => Ok(Self::L2),
            _ => anyhow::bail!("Invalid data availability mode"),
        }
    }
}

impl TryFromDto<p2p_proto::event::Event> for pathfinder_common::event::Event {
    fn try_from_dto(proto: p2p_proto::event::Event) -> anyhow::Result<Self>
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

impl TryFromDto<p2p_proto::common::L1DataAvailabilityMode> for L1DataAvailabilityMode {
    fn try_from_dto(dto: p2p_proto::common::L1DataAvailabilityMode) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        use p2p_proto::common::L1DataAvailabilityMode::{Blob, Calldata};
        Ok(match dto {
            Calldata => Self::Calldata,
            Blob => Self::Blob,
        })
    }
}

#[derive(Debug)]
pub struct CairoDefinition(pub Vec<u8>);

impl TryFromDto<p2p_proto::class::Cairo0Class> for CairoDefinition {
    fn try_from_dto(dto: p2p_proto::class::Cairo0Class) -> anyhow::Result<Self> {
        #[derive(Debug, Serialize)]
        struct SelectorAndOffset {
            pub selector: EntryPoint,
            pub offset: ByteCodeOffset,
        }

        #[derive(Debug, Serialize)]
        struct CairoEntryPoints {
            #[serde(rename = "EXTERNAL")]
            pub external: Vec<SelectorAndOffset>,
            #[serde(rename = "L1_HANDLER")]
            pub l1_handler: Vec<SelectorAndOffset>,
            #[serde(rename = "CONSTRUCTOR")]
            pub constructor: Vec<SelectorAndOffset>,
        }

        #[derive(Debug, Serialize)]
        #[serde(deny_unknown_fields)]
        struct Cairo<'a> {
            // Contract ABI, which has no schema definition.
            pub abi: Cow<'a, RawValue>,
            // Main program definition. __We assume that this is valid JSON.__
            pub program: Cow<'a, RawValue>,
            // The contract entry points.
            pub entry_points_by_type: CairoEntryPoints,
        }

        let from_dto = |x: Vec<p2p_proto::class::EntryPoint>| {
            x.into_iter()
                .map(|e| SelectorAndOffset {
                    selector: EntryPoint(e.selector),
                    offset: ByteCodeOffset(e.offset),
                })
                .collect::<Vec<_>>()
        };

        let abi = dto.abi;
        let program = dto.program;
        let external = from_dto(dto.externals);
        let l1_handler = from_dto(dto.l1_handlers);
        let constructor = from_dto(dto.constructors);

        #[derive(Debug, Deserialize)]
        struct Abi<'a>(#[serde(borrow)] &'a RawValue);

        let class_def = Cairo {
            abi: Cow::Borrowed(serde_json::from_slice::<Abi<'_>>(&abi).unwrap().0),
            program: serde_json::from_slice(&program)
                .context("verify that cairo class program is UTF-8")?,
            entry_points_by_type: CairoEntryPoints {
                external,
                l1_handler,
                constructor,
            },
        };
        let class_def =
            serde_json::to_vec(&class_def).context("serialize cairo class definition")?;
        Ok(Self(class_def))
    }
}

#[derive(Debug)]
pub struct SierraDefinition {
    pub sierra: Vec<u8>,
    pub casm: Vec<u8>,
}

impl TryFromDto<p2p_proto::class::Cairo1Class> for SierraDefinition {
    fn try_from_dto(dto: p2p_proto::class::Cairo1Class) -> anyhow::Result<Self> {
        #[derive(Debug, Serialize)]
        pub struct SelectorAndFunctionIndex {
            pub selector: EntryPoint,
            pub function_idx: u64,
        }

        #[derive(Debug, Serialize)]
        pub struct SierraEntryPoints {
            #[serde(rename = "EXTERNAL")]
            pub external: Vec<SelectorAndFunctionIndex>,
            #[serde(rename = "L1_HANDLER")]
            pub l1_handler: Vec<SelectorAndFunctionIndex>,
            #[serde(rename = "CONSTRUCTOR")]
            pub constructor: Vec<SelectorAndFunctionIndex>,
        }

        #[derive(Debug, Serialize)]
        pub struct Sierra<'a> {
            /// Contract ABI.
            pub abi: Cow<'a, str>,

            /// Main program definition.
            pub sierra_program: Vec<Felt>,

            // Version
            pub contract_class_version: Cow<'a, str>,

            /// The contract entry points
            pub entry_points_by_type: SierraEntryPoints,
        }

        let from_dto = |x: Vec<p2p_proto::class::SierraEntryPoint>| {
            x.into_iter()
                .map(|e| SelectorAndFunctionIndex {
                    selector: EntryPoint(e.selector),
                    function_idx: e.index,
                })
                .collect::<Vec<_>>()
        };

        let abi = std::str::from_utf8(&dto.abi).context("parsing abi as utf8")?;
        let entry_points = SierraEntryPoints {
            external: from_dto(dto.entry_points.externals),
            l1_handler: from_dto(dto.entry_points.l1_handlers),
            constructor: from_dto(dto.entry_points.constructors),
        };
        let program = dto.program;
        let contract_class_version = dto.contract_class_version;
        let casm = dto.compiled;

        let sierra = Sierra {
            abi: Cow::Borrowed(abi),
            sierra_program: program,
            contract_class_version: contract_class_version.into(),
            entry_points_by_type: entry_points,
        };

        let sierra = serde_json::to_vec(&sierra).context("serialize sierra class definition")?;

        Ok(Self { sierra, casm })
    }
}
