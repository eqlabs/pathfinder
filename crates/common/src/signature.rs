use fake::Dummy;
use pathfinder_crypto::hash::poseidon_hash_many;
use pathfinder_crypto::signature::{ecdsa_verify_partial, SignatureError};
use pathfinder_crypto::Felt;

use crate::{BlockCommitmentSignatureElem, BlockHash, PublicKey, StateDiffCommitment};

#[derive(Default, Debug, Clone, PartialEq, Eq, Dummy)]
pub struct BlockCommitmentSignature {
    pub r: BlockCommitmentSignatureElem,
    pub s: BlockCommitmentSignatureElem,
}

impl BlockCommitmentSignature {
    // TODO remove fallback to pre-0.13.2 verification method after 0.13.2 is rolled
    // out on mainnet.
    pub fn verify(
        &self,
        public_key: PublicKey,
        block_hash: BlockHash,
        state_diff_commitment: StateDiffCommitment,
    ) -> Result<(), SignatureError> {
        self.verify_0_13_2(public_key, block_hash)
            .or_else(|_| self.verify_pre_0_13_2(public_key, block_hash, state_diff_commitment))
    }

    fn verify_pre_0_13_2(
        &self,
        public_key: PublicKey,
        block_hash: BlockHash,
        state_diff_commitment: StateDiffCommitment,
    ) -> Result<(), SignatureError> {
        let msg = Felt::from(poseidon_hash_many(&[
            block_hash.0.into(),
            state_diff_commitment.0.into(),
        ]));
        ecdsa_verify_partial(public_key.0, msg, self.r.0, self.s.0)
    }

    fn verify_0_13_2(
        &self,
        public_key: PublicKey,
        block_hash: BlockHash,
    ) -> Result<(), SignatureError> {
        ecdsa_verify_partial(public_key.0, block_hash.0, self.r.0, self.s.0)
    }
}

#[cfg(test)]
mod test {
    use crate::macro_prelude::*;
    use crate::{BlockCommitmentSignature, StateDiffCommitment};

    #[test]
    fn pre_0_13_2_verification_method() {
        // From https://alpha-mainnet.starknet.io/feeder_gateway/get_public_key
        let public_key =
            public_key!("0x48253ff2c3bed7af18bde0b611b083b39445959102d4947c51c4db6aa4f4e58");
        // From https://alpha-mainnet.starknet.io/feeder_gateway/get_signature?blockNumber=635000
        let block_hash =
            block_hash!("0x164685e53f274ecb60a3941303a6ee913aeb9016fbca5ba65c1cb8bdaee17a0");
        let state_diff_commitment = state_diff_commitment!(
            "0x620efa2bd1149abe485486efa35c29571b4883f9f54a7f4938389276b0579ff"
        );
        let signature = BlockCommitmentSignature {
            r: block_commitment_signature_elem!(
                "0x222679bdc9007386f5c2de62e89839b442799f356b24657af77e2a8aa87e74d"
            ),
            s: block_commitment_signature_elem!(
                "0x16c9d0bab74fe4f268705559e16ebb36a5326e75c6a580e6ad3194fb9a0b1ed"
            ),
        };

        signature
            .verify(public_key, block_hash, state_diff_commitment)
            .unwrap();
    }

    #[test]
    fn _0_13_2_verification_method_for_the_last_0_13_1_1_block() {
        // From https://integration-sepolia.starknet.io/feeder_gateway/get_public_key
        let public_key =
            public_key!("0x4e4856eb36dbd5f4a7dca29f7bb5232974ef1fb7eb5b597c58077174c294da1");
        // From https://integration-sepolia.starknet.io/feeder_gateway/get_signature?blockNumber=35747
        let block_hash =
            block_hash!("0x77140bef51bbb4d1932f17cc5081825ff18465a1df4440ca0429a4fa80f1dc5");
        let signature = BlockCommitmentSignature {
            r: block_commitment_signature_elem!(
                "0x44b4fef018bb755107ed0caab714f628c0804b2a8787664c5210e607aed3004"
            ),
            s: block_commitment_signature_elem!(
                "0x2ea6ecf5d11f0eba14e867c8d771ab958b55e45ded7ce93a1fe78045593f22b"
            ),
        };

        // Use some fake state diff commitment which should be ignored by the
        // verification method because there should be no fallback to the
        // pre-0.13.2 verification method in this case.
        signature
            .verify(public_key, block_hash, StateDiffCommitment::ZERO)
            .unwrap();
    }

    #[test]
    fn _0_13_2_verification_method_for_the_first_0_13_2_block() {
        // From https://integration-sepolia.starknet.io/feeder_gateway/get_public_key
        let public_key =
            public_key!("0x4e4856eb36dbd5f4a7dca29f7bb5232974ef1fb7eb5b597c58077174c294da1");
        // From https://integration-sepolia.starknet.io/feeder_gateway/get_signature?blockNumber=35748
        let block_hash =
            block_hash!("0x1ea2a9cfa3df5297d58c0a04d09d276bc68d40fe64701305bbe2ed8f417e869");
        let signature = BlockCommitmentSignature {
            r: block_commitment_signature_elem!(
                "0x45161746eecbeae297f45a1f407ab702310f4e52c5e9350ed6f542fa8e98413"
            ),
            s: block_commitment_signature_elem!(
                "0x3e67cfbc5b179ba55a3b687228d8fe40626233f6691b4aabe308fcd6d71dcdb"
            ),
        };

        // Use some fake state diff commitment which should be ignored by the
        // verification method because there should be no fallback to the
        // pre-0.13.2 verification method in this case.
        signature
            .verify(public_key, block_hash, StateDiffCommitment::ZERO)
            .unwrap();
    }
}
