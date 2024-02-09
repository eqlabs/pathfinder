use std::borrow::Cow;

use anyhow::Context;
use p2p_proto::{
    class::{Cairo0Class, Cairo1Class},
    receipt::{
        DeclareTransactionReceipt, DeployAccountTransactionReceipt, DeployTransactionReceipt,
        InvokeTransactionReceipt, L1HandlerTransactionReceipt,
    },
};
use pathfinder_common::{
    ByteCodeOffset, CasmHash, ClassHash, ContractAddress, EntryPoint, EthereumAddress, Fee,
    L2ToL1MessagePayloadElem, SierraHash, TransactionHash,
};
use pathfinder_crypto::Felt;
use serde::Deserialize;
use serde_json::value::RawValue;
use starknet_gateway_types::{
    class_definition::{self, SierraEntryPoints},
    class_hash::from_parts::{compute_cairo_class_hash, compute_sierra_class_hash},
    reply::transaction as gw,
    request::contract::{SelectorAndFunctionIndex, SelectorAndOffset},
};

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
                actual_fee: Fee(common.actual_fee),
                execution_resources: gw::ExecutionResources {
                    builtin_instance_counter: gw::BuiltinCounters {
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
                },
                l1_to_l2_consumed_message: None,
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

    use cairo_lang_starknet::casm_contract_class::CasmContractClass;

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
