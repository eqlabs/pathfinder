# P2P Protocol Buffers

This crate contains the Protocol Buffer definitions and generated Rust code for the Starknet P2P protocol.

## Syncing Protocol Definitions

To sync the protocol definitions with the latest from Starkware:

```bash
make sync
```

This will fetch the latest protocol definitions from the [starknet-p2p-specs](https://github.com/starknet-io/starknet-p2p-specs) repository and update the Rust module structure accordingly.

**Requirements:**
- Python 3.10+ (the scripts will check and give a clear error if your version is too old)
- Git (for fetching the latest specs)

## Generated Code

The generated Rust code is automatically included in the build process via `build.rs`. The protocol definitions are located in the `proto/` directory and the generated bindings are included in `src/lib.rs`.
