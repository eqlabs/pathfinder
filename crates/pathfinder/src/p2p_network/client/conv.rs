use std::borrow::Cow;

use anyhow::Context;
use p2p_proto::class::{Cairo0Class, Cairo1Class};
use pathfinder_common::{ByteCodeOffset, CasmHash, ClassHash, EntryPoint, SierraHash};
use serde::Deserialize;
use serde_json::value::RawValue;
use starknet_gateway_types::{
    class_definition::{self, SierraEntryPoints},
    class_hash::from_parts::{compute_cairo_class_hash, compute_sierra_class_hash},
    request::contract::{SelectorAndFunctionIndex, SelectorAndOffset},
};

// pub fn cairo_hash_and_def_from_dto(c0: Cairo0Class) -> anyhow::Result<(ClassHash, Vec<u8>)> {
//     let from_dto = |x: Vec<p2p_proto::class::EntryPoint>| {
//         x.into_iter()
//             .map(|e| SelectorAndOffset {
//                 selector: EntryPoint(e.selector),
//                 offset: ByteCodeOffset(e.offset),
//             })
//             .collect::<Vec<_>>()
//     };

//     let abi = c0.abi;
//     let program = c0.program;
//     let external = from_dto(c0.externals);
//     let l1_handler = from_dto(c0.l1_handlers);
//     let constructor = from_dto(c0.constructors);

//     let external_entry_points = external.clone();
//     let l1_handler_entry_points = l1_handler.clone();
//     let constructor_entry_points = constructor.clone();

//     let class_hash = compute_cairo_class_hash(
//         &abi,
//         &program,
//         external_entry_points,
//         l1_handler_entry_points,
//         constructor_entry_points,
//     )
//     .context("compute cairo class hash")?;

//     #[derive(Debug, Deserialize)]
//     struct Abi<'a>(#[serde(borrow)] &'a RawValue);

//     let class_def = class_definition::Cairo {
//         abi: Cow::Borrowed(serde_json::from_slice::<Abi<'_>>(&abi).unwrap().0),
//         program: serde_json::from_slice(&program)
//             .context("verify that cairo class program is UTF-8")?,
//         entry_points_by_type: class_definition::CairoEntryPoints {
//             external,
//             l1_handler,
//             constructor,
//         },
//     };
//     let class_def = serde_json::to_vec(&class_def).context("serialize cairo class definition")?;
//     Ok((class_hash, class_def))
// }

// pub fn sierra_defs_and_hashes_from_dto(
//     c1: Cairo1Class,
// ) -> anyhow::Result<(SierraHash, Vec<u8>, CasmHash, Vec<u8>)> {
//     let from_dto = |x: Vec<p2p_proto::class::SierraEntryPoint>| {
//         x.into_iter()
//             .map(|e| SelectorAndFunctionIndex {
//                 selector: EntryPoint(e.selector),
//                 function_idx: e.index,
//             })
//             .collect::<Vec<_>>()
//     };

//     let abi = std::str::from_utf8(&c1.abi).context("parsing abi as utf8")?;
//     let entry_points = SierraEntryPoints {
//         external: from_dto(c1.entry_points.externals),
//         l1_handler: from_dto(c1.entry_points.l1_handlers),
//         constructor: from_dto(c1.entry_points.constructors),
//     };
//     let program = c1.program;
//     let contract_class_version = c1.contract_class_version;
//     let compiled = c1.compiled;

//     let program_clone = program.clone();
//     let entry_points_clone = entry_points.clone();
//     let sierra_hash = SierraHash(
//         compute_sierra_class_hash(
//             abi,
//             program_clone,
//             &contract_class_version,
//             entry_points_clone,
//         )
//         .context("compute sierra clash hash")?
//         .0,
//     );

//     let casm_hash = pathfinder_compiler::casm_class_hash(&compiled)?;

//     let class_def = class_definition::Sierra {
//         abi: Cow::Borrowed(abi),
//         sierra_program: program,
//         contract_class_version: contract_class_version.into(),
//         entry_points_by_type: entry_points,
//     };

//     let class_def = serde_json::to_vec(&class_def).context("serialize sierra class definition")?;

//     Ok((sierra_hash, class_def, casm_hash, compiled))
// }
