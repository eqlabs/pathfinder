use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "proto/block.proto",
            "proto/common.proto",
            "proto/event.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
