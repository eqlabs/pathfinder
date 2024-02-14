use std::borrow::Cow;

use anyhow::{Context, Ok};
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use p2p_proto::{
    class::{Cairo0Class, Cairo1Class},
    receipt::{
        DeclareTransactionReceipt, DeployAccountTransactionReceipt, DeployTransactionReceipt,
        InvokeTransactionReceipt, L1HandlerTransactionReceipt,
    },
};
use pathfinder_common::{
    receipt::{BuiltinCounters, ExecutionResources, ExecutionStatus, L2ToL1Message},
    BlockCommitmentSignature, BlockCommitmentSignatureElem, BlockHash, BlockNumber, BlockTimestamp,
    ByteCodeOffset, CasmHash, ClassHash, ContractAddress, EntryPoint, EthereumAddress,
    EventCommitment, Fee, GasPrice, L2ToL1MessagePayloadElem, SequencerAddress, SierraHash,
    StarknetVersion, StateCommitment, TransactionCommitment, TransactionHash,
};
use pathfinder_crypto::Felt;
use serde::Deserialize;
use serde_json::value::RawValue;
use starknet_gateway_types::{
    class_definition::{self, SierraEntryPoints},
    class_hash::from_parts::{compute_cairo_class_hash, compute_sierra_class_hash},
    request::contract::{SelectorAndFunctionIndex, SelectorAndOffset},
};

/// Represents a simplified [`pathfinder_common::SignedBlockHeader`], ie. excluding class commitment and storage commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlockHeader {
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
    pub number: BlockNumber,
    pub timestamp: BlockTimestamp,
    pub eth_l1_gas_price: GasPrice,
    pub sequencer_address: SequencerAddress,
    pub starknet_version: StarknetVersion,
    pub event_commitment: EventCommitment,
    pub state_commitment: StateCommitment,
    pub transaction_commitment: TransactionCommitment,
    pub transaction_count: usize,
    pub event_count: usize,
    pub signature: BlockCommitmentSignature,
}

impl TryFrom<p2p_proto::header::SignedBlockHeader> for SignedBlockHeader {
    type Error = anyhow::Error;

    fn try_from(dto: p2p_proto::header::SignedBlockHeader) -> Result<Self, Self::Error> {
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
            hash: BlockHash(dto.block_hash.0),
            parent_hash: BlockHash(dto.parent_hash.0),
            number: BlockNumber::new(dto.number)
                .ok_or(anyhow::anyhow!("block number > i64::MAX"))?,
            timestamp: BlockTimestamp::new(dto.time)
                .ok_or(anyhow::anyhow!("block timestamp > i64::MAX"))?,
            eth_l1_gas_price: dto.gas_price.into(),
            sequencer_address: SequencerAddress(dto.sequencer_address.0),
            starknet_version: dto.protocol_version.into(),
            event_commitment: EventCommitment(dto.events.root.0),
            state_commitment: StateCommitment(dto.state.root.0),
            transaction_commitment: TransactionCommitment(dto.transactions.root.0),
            transaction_count: dto.transactions.n_leaves.try_into()?,
            event_count: dto.events.n_leaves.try_into()?,
            signature,
        })
    }
}

impl
    From<(
        pathfinder_common::BlockHeader,
        pathfinder_common::BlockCommitmentSignature,
    )> for SignedBlockHeader
{
    fn from(
        (header, signature): (
            pathfinder_common::BlockHeader,
            pathfinder_common::BlockCommitmentSignature,
        ),
    ) -> Self {
        Self {
            hash: header.hash,
            parent_hash: header.parent_hash,
            number: header.number,
            timestamp: header.timestamp,
            eth_l1_gas_price: header.eth_l1_gas_price,
            sequencer_address: header.sequencer_address,
            starknet_version: header.starknet_version,
            event_commitment: header.event_commitment,
            state_commitment: header.state_commitment,
            transaction_commitment: header.transaction_commitment,
            transaction_count: header.transaction_count,
            event_count: header.event_count,
            signature,
        }
    }
}

/// Represents a simplified [`pathfinder_common::receipt::Receipt`] (events and transaction index excluded).
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Receipt {
    pub actual_fee: Option<Fee>,
    pub execution_resources: Option<ExecutionResources>,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub execution_status: ExecutionStatus,
    pub transaction_hash: TransactionHash,
}

impl From<pathfinder_common::receipt::Receipt> for Receipt {
    fn from(x: pathfinder_common::receipt::Receipt) -> Self {
        Self {
            transaction_hash: x.transaction_hash,
            actual_fee: x.actual_fee,
            execution_resources: x.execution_resources,
            l2_to_l1_messages: x.l2_to_l1_messages,
            execution_status: x.execution_status,
        }
    }
}

impl TryFrom<p2p_proto::receipt::Receipt> for Receipt {
    type Error = anyhow::Error;

    fn try_from(proto: p2p_proto::receipt::Receipt) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        use p2p_proto::receipt::Receipt::{Declare, Deploy, DeployAccount, Invoke, L1Handler};

        match proto {
            Invoke(InvokeTransactionReceipt { common })
            | Declare(DeclareTransactionReceipt { common })
            | L1Handler(L1HandlerTransactionReceipt { common, .. })
            | Deploy(DeployTransactionReceipt { common, .. })
            | DeployAccount(DeployAccountTransactionReceipt { common, .. }) => Ok(Self {
                transaction_hash: TransactionHash(common.transaction_hash.0),
                actual_fee: Some(Fee(common.actual_fee)),
                execution_resources: Some(ExecutionResources {
                    builtin_instance_counter: BuiltinCounters {
                        output_builtin: common.execution_resources.builtins.output.into(),
                        pedersen_builtin: common.execution_resources.builtins.pedersen.into(),
                        range_check_builtin: common.execution_resources.builtins.range_check.into(),
                        ecdsa_builtin: common.execution_resources.builtins.ecdsa.into(),
                        bitwise_builtin: common.execution_resources.builtins.bitwise.into(),
                        ec_op_builtin: common.execution_resources.builtins.ec_op.into(),
                        keccak_builtin: common.execution_resources.builtins.keccak.into(),
                        poseidon_builtin: common.execution_resources.builtins.poseidon.into(),
                        segment_arena_builtin: 0,
                    },
                    n_steps: common.execution_resources.steps.into(),
                    n_memory_holes: common.execution_resources.memory_holes.into(),
                    data_availability: None,
                }),
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
            }),
        }
    }
}

pub fn cairo_hash_and_def_from_dto(c0: Cairo0Class) -> anyhow::Result<(ClassHash, Vec<u8>)> {
    let from_dto = |x: Vec<p2p_proto::class::EntryPoint>| {
        x.into_iter()
            .map(|e| SelectorAndOffset {
                selector: EntryPoint(e.selector),
                offset: ByteCodeOffset(e.offset),
            })
            .collect::<Vec<_>>()
    };

    let abi = c0.abi;
    let program = c0.program;
    let external = from_dto(c0.externals);
    let l1_handler = from_dto(c0.l1_handlers);
    let constructor = from_dto(c0.constructors);

    let external_entry_points = external.clone();
    let l1_handler_entry_points = l1_handler.clone();
    let constructor_entry_points = constructor.clone();

    let class_hash = compute_cairo_class_hash(
        &abi,
        &program,
        external_entry_points,
        l1_handler_entry_points,
        constructor_entry_points,
    )
    .context("compute cairo class hash")?;

    #[derive(Debug, Deserialize)]
    struct Abi<'a>(#[serde(borrow)] &'a RawValue);

    let class_def = class_definition::Cairo {
        abi: Cow::Borrowed(serde_json::from_slice::<Abi<'_>>(&abi).unwrap().0),
        program: serde_json::from_slice(&program)
            .context("verify that cairo class program is UTF-8")?,
        entry_points_by_type: class_definition::CairoEntryPoints {
            external,
            l1_handler,
            constructor,
        },
    };
    let class_def = serde_json::to_vec(&class_def).context("serialize cairo class definition")?;
    Ok((class_hash, class_def))
}

pub fn cairo_def_from_dto(c0: Cairo0Class) -> anyhow::Result<Vec<u8>> {
    let from_dto = |x: Vec<p2p_proto::class::EntryPoint>| {
        x.into_iter()
            .map(|e| SelectorAndOffset {
                selector: EntryPoint(e.selector),
                offset: ByteCodeOffset(e.offset),
            })
            .collect::<Vec<_>>()
    };

    let abi = c0.abi;
    let program = c0.program;
    let external = from_dto(c0.externals);
    let l1_handler = from_dto(c0.l1_handlers);
    let constructor = from_dto(c0.constructors);

    #[derive(Debug, Deserialize)]
    struct Abi<'a>(#[serde(borrow)] &'a RawValue);

    let class_def = class_definition::Cairo {
        abi: Cow::Borrowed(serde_json::from_slice::<Abi<'_>>(&abi).unwrap().0),
        program: serde_json::from_slice(&program)
            .context("verify that cairo class program is UTF-8")?,
        entry_points_by_type: class_definition::CairoEntryPoints {
            external,
            l1_handler,
            constructor,
        },
    };
    let class_def = serde_json::to_vec(&class_def).context("serialize cairo class definition")?;
    Ok(class_def)
}

pub fn sierra_defs_and_hashes_from_dto(
    c1: Cairo1Class,
) -> anyhow::Result<(SierraHash, Vec<u8>, CasmHash, Vec<u8>)> {
    let from_dto = |x: Vec<p2p_proto::class::SierraEntryPoint>| {
        x.into_iter()
            .map(|e| SelectorAndFunctionIndex {
                selector: EntryPoint(e.selector),
                function_idx: e.index,
            })
            .collect::<Vec<_>>()
    };

    let abi = std::str::from_utf8(&c1.abi).context("parsing abi as utf8")?;
    let entry_points = SierraEntryPoints {
        external: from_dto(c1.entry_points.externals),
        l1_handler: from_dto(c1.entry_points.l1_handlers),
        constructor: from_dto(c1.entry_points.constructors),
    };
    let program = c1.program;
    let contract_class_version = c1.contract_class_version;
    let compiled = c1.compiled;

    let program_clone = program.clone();
    let entry_points_clone = entry_points.clone();
    let sierra_hash = SierraHash(
        compute_sierra_class_hash(
            abi,
            program_clone,
            &contract_class_version,
            entry_points_clone,
        )
        .context("compute sierra clash hash")?
        .0,
    );

    let ccc: CasmContractClass =
        serde_json::from_slice(&compiled).context("deserialize casm class")?;

    let casm_hash = CasmHash(
        Felt::from_be_bytes(ccc.compiled_class_hash().to_be_bytes())
            .context("compute casm class hash")?,
    );

    let class_def = class_definition::Sierra {
        abi: Cow::Borrowed(abi),
        sierra_program: program,
        contract_class_version: contract_class_version.into(),
        entry_points_by_type: entry_points,
    };

    let class_def = serde_json::to_vec(&class_def).context("serialize sierra class definition")?;

    Ok((sierra_hash, class_def, casm_hash, compiled))
}

pub fn sierra_defs_from_dto(c1: Cairo1Class) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let from_dto = |x: Vec<p2p_proto::class::SierraEntryPoint>| {
        x.into_iter()
            .map(|e| SelectorAndFunctionIndex {
                selector: EntryPoint(e.selector),
                function_idx: e.index,
            })
            .collect::<Vec<_>>()
    };

    let abi = std::str::from_utf8(&c1.abi).context("parsing abi as utf8")?;
    let entry_points = SierraEntryPoints {
        external: from_dto(c1.entry_points.externals),
        l1_handler: from_dto(c1.entry_points.l1_handlers),
        constructor: from_dto(c1.entry_points.constructors),
    };
    let program = c1.program;
    let contract_class_version = c1.contract_class_version;
    let compiled_def = c1.compiled;

    let sierra_def = class_definition::Sierra {
        abi: Cow::Borrowed(abi),
        sierra_program: program,
        contract_class_version: contract_class_version.into(),
        entry_points_by_type: entry_points,
    };

    let sierra_def =
        serde_json::to_vec(&sierra_def).context("serialize sierra class definition")?;

    Ok((sierra_def, compiled_def))
}
