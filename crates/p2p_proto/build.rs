use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "proto/class.proto",
            "proto/common.proto",
            "proto/event.proto",
            "proto/header.proto",
            "proto/receipt.proto",
            "proto/state.proto",
            "proto/transaction.proto",
        ],
        &["proto"],
    )?;

    Ok(())
}
