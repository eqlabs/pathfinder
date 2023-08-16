use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "proto/block.proto",
            "proto/common.proto",
            "proto/event.proto",
            "proto/mempool.proto",
            "proto/receipt.proto",
            "proto/snapshot.proto",
            "proto/state.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
