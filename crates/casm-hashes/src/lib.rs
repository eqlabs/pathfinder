use std::collections::HashMap;
use std::sync::LazyLock;

use pathfinder_common::{CasmHash, ClassHash};
use pathfinder_crypto::Felt;

static PRECOMPUTED_CASM_V2_HASHES: LazyLock<HashMap<ClassHash, CasmHash>> = LazyLock::new(|| {
    let mut h = HashMap::new();

    let mainnet_casm_hashes_v2 = include_bytes!("../fixtures/mainnet-casm-v2-hashes.bin");
    for chunk in mainnet_casm_hashes_v2.chunks_exact(64) {
        let class_hash = ClassHash(
            Felt::from_be_slice(&chunk[0..32])
                .expect("Invalid class hash in precomputed CASM v2 hashes"),
        );
        let casm_hash = CasmHash(
            Felt::from_be_slice(&chunk[32..64])
                .expect("Invalid CASM hash in precomputed CASM v2 hashes"),
        );
        h.insert(class_hash, casm_hash);
    }

    let sepolia_testnet_casm_hashes_v2 =
        include_bytes!("../fixtures/testnet-sepolia-casm-v2-hashes.bin");
    for chunk in sepolia_testnet_casm_hashes_v2.chunks_exact(64) {
        let class_hash = ClassHash(
            Felt::from_be_slice(&chunk[0..32])
                .expect("Invalid class hash in precomputed CASM v2 hashes"),
        );
        let casm_hash = CasmHash(
            Felt::from_be_slice(&chunk[32..64])
                .expect("Invalid CASM hash in precomputed CASM v2 hashes"),
        );
        h.insert(class_hash, casm_hash);
    }

    h
});

/// Returns the precomputed CASM v2 hash for the given class hash, if it exists.
///
/// In Starknet 0.14.1 and later CASM hashes are computed using a new algorithm
/// (Blake2 hash). This function provides access to a set of precomputed CASM v2
/// hashes for known class hashes (generated from classes on Mainnet and Sepolia
/// testnet) to avoid the need for recomputation.
pub fn get_precomputed_casm_v2_hash(class_hash: &ClassHash) -> Option<&CasmHash> {
    PRECOMPUTED_CASM_V2_HASHES.get(class_hash)
}
