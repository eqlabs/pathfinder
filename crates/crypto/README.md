# pathfinder_crypto

This crate contains cryptographic primitives used by Starknet:

- Algebra: Finite field and the elliptic curve algebra
- Hashing: Pedersen and Poseidon hash functions
- Signature: ECDSA over the Stark curve.

### Usage

Import the crate in your `Cargo.toml` and use the library as needed. A hash example:

```rust
use pathfinder_crypto::algebra::field::Felt;
use pathfinder_crypto::hash::pedersen_hash;

fn main() {
    let (a, b) = (Felt::ZERO, Felt::ZERO);
    let hash = pedersen_hash(a, b);
    println!("a: {a}");
    println!("b: {b}");
    println!("pedersen_hash(a,b): {hash}");
}
```

### Optimizations

The crate utilize space-time trade-offs to reduce the cost of elliptic curve operations.
This require the generation of lookup-tables as seen in the `/examples/consts_xx.rs` files.
These tables are generated for the elliptic curve generator and the four constant EC-points used by the Pedersen hash.

While the Poseidon hash does not use elliptic curve operations, it does use round constants that may be compressed, which is done in `examples/consts_poseidon.rs`.

The generated constants are placed in:
- `src/algebra/curve/consts.rs`: Constants for curve generator G.
- `src/hash/pedersen/consts.rs`: Constants for Pedersen hash generator points.
- `src/hash/poseidon/consts.rs`: Constants for Poseidon hash.

The space-time trade-off for elliptic curves are set to use chunks of eight bits per lookup, which can be configured by running the generator scripts in the `examples` folder.


