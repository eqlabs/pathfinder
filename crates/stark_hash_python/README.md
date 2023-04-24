# starknet_pathfinder_crypto

Python wrapper of the Rust implementations of Pedersen and Poseidon hash functions from pathfinder.

## Installation

```bash
pip install starknet_pathfinder_crypto
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
import starknet_pathfinder_crypto
import starkware.crypto.signature.fast_pedersen_hash
import starkware.cairo.common.poseidon_hash

starkware.crypto.signature.fast_pedersen_hash.pedersen_hash_func = (
    starknet_pathfinder_crypto.pedersen_hash_func
)
starkware.crypto.signature.fast_pedersen_hash.pedersen_hash = (
    starknet_pathfinder_crypto.pedersen_hash
)
starkware.cairo.common.poseidon_hash.poseidon_hash = starknet_pathfinder_crypto.poseidon_hash
starkware.cairo.common.poseidon_hash.poseidon_hash_func = (
    starknet_pathfinder_crypto.poseidon_hash_func
)
starkware.cairo.common.poseidon_hash.poseidon_hash_many = (
    starknet_pathfinder_crypto.poseidon_hash_many
)
starkware.cairo.common.poseidon_hash.poseidon_perm = starknet_pathfinder_crypto.poseidon_perm
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](http://www.apache.org/licenses/LICENSE-2.0))
 * MIT license
   ([LICENSE-MIT](http://opensource.org/licenses/MIT))
