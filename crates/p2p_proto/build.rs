use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "proto/common.proto",
            "proto/propagation.proto",
            "proto/sync.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
