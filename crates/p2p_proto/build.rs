use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/common.proto", "proto/block.proto"], &["proto"])?;
    Ok(())
}
