//! Workaround for the orphan rule - implement conversion fns for types ourside
//! our crate.
use p2p_proto::class::{Cairo0Class, Cairo1Class, Cairo1EntryPoints, EntryPoint, SierraEntryPoint};
use starknet_gateway_types::class_definition::{Cairo, Sierra};
use starknet_gateway_types::request::contract::{SelectorAndFunctionIndex, SelectorAndOffset};

pub fn sierra_def_into_dto(sierra: Sierra<'_>) -> Cairo1Class {
    let into_dto = |x: SelectorAndFunctionIndex| SierraEntryPoint {
        selector: x.selector.0,
        index: x.function_idx,
    };

    let entry_points = Cairo1EntryPoints {
        externals: sierra
            .entry_points_by_type
            .external
            .into_iter()
            .map(into_dto)
            .collect(),
        l1_handlers: sierra
            .entry_points_by_type
            .l1_handler
            .into_iter()
            .map(into_dto)
            .collect(),
        constructors: sierra
            .entry_points_by_type
            .constructor
            .into_iter()
            .map(into_dto)
            .collect(),
    };

    Cairo1Class {
        abi: sierra.abi.to_string(),
        program: sierra.sierra_program,
        entry_points,
        contract_class_version: sierra.contract_class_version.into(),
    }
}

pub fn cairo_def_into_dto(cairo: Cairo<'_>) -> Cairo0Class {
    let into_dto = |x: SelectorAndOffset| EntryPoint {
        selector: x.selector.0,
        offset: u64::from_be_bytes(
            x.offset.0.as_be_bytes()[24..]
                .try_into()
                .expect("slice len matches"),
        ),
    };

    let mut gzip_encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    serde_json::to_writer(&mut gzip_encoder, &cairo.program).unwrap();
    let program = gzip_encoder.finish().unwrap();
    let program = base64::encode(program);

    Cairo0Class {
        abi: cairo.abi.to_string(),
        externals: cairo
            .entry_points_by_type
            .external
            .into_iter()
            .map(into_dto)
            .collect(),
        l1_handlers: cairo
            .entry_points_by_type
            .l1_handler
            .into_iter()
            .map(into_dto)
            .collect(),
        constructors: cairo
            .entry_points_by_type
            .constructor
            .into_iter()
            .map(into_dto)
            .collect(),
        program,
    }
}
