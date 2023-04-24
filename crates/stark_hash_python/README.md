# stark_hash_rust

Python wrapper of the Rust implementations of Pedersen and Poseidon hash functions from pathfinder.

## Installation

```bash
pip install stark_hash_rust
```

## Usage

The functions implemented by this module are drop-in replacements for the pure-Python implementations
used in `cairo-lang`:

* [pedersen_hash_func](https://github.com/starkware-libs/cairo-lang/blob/c954f154bbab04c3fb27f7598b015a9475fc628e/src/starkware/crypto/signature/fast_pedersen_hash.py#L47)
* [pedersen_hash](https://github.com/starkware-libs/cairo-lang/blob/c954f154bbab04c3fb27f7598b015a9475fc628e/src/starkware/crypto/signature/fast_pedersen_hash.py#L34)
* [poseidon_hash_func](https://github.com/starkware-libs/cairo-lang/blob/c954f154bbab04c3fb27f7598b015a9475fc628e/src/starkware/cairo/common/poseidon_hash.py#L15)
* [poseidon_hash](https://github.com/starkware-libs/cairo-lang/blob/c954f154bbab04c3fb27f7598b015a9475fc628e/src/starkware/cairo/common/poseidon_hash.py#L22)
* [poseidon_hash_many](https://github.com/starkware-libs/cairo-lang/blob/c954f154bbab04c3fb27f7598b015a9475fc628e/src/starkware/cairo/common/poseidon_hash.py#L46)
* [poseidon_perm](https://github.com/starkware-libs/cairo-lang/blob/c954f154bbab04c3fb27f7598b015a9475fc628e/src/starkware/cairo/common/poseidon_hash.py#L7)

You can use them directly, or monkey-patch cairo-lang:

```python
import stark_hash_rust
import starkware.crypto.signature.fast_pedersen_hash
import starkware.cairo.common.poseidon_hash

starkware.crypto.signature.fast_pedersen_hash.pedersen_hash_func = (
    stark_hash_rust.pedersen_hash_func
)
starkware.crypto.signature.fast_pedersen_hash.pedersen_hash = (
    stark_hash_rust.pedersen_hash
)
starkware.cairo.common.poseidon_hash.poseidon_hash = stark_hash_rust.poseidon_hash
starkware.cairo.common.poseidon_hash.poseidon_hash_func = (
    stark_hash_rust.poseidon_hash_func
)
starkware.cairo.common.poseidon_hash.poseidon_hash_many = (
    stark_hash_rust.poseidon_hash_many
)
starkware.cairo.common.poseidon_hash.poseidon_perm = stark_hash_rust.poseidon_perm
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](http://www.apache.org/licenses/LICENSE-2.0))
 * MIT license
   ([LICENSE-MIT](http://opensource.org/licenses/MIT))
