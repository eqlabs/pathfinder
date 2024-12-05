use fake::Dummy;

use crate::{BlockCommitmentSignatureElem, BlockHash, PublicKey};

#[derive(Default, Debug, Clone, PartialEq, Eq, Dummy)]
pub struct BlockCommitmentSignature {
    pub r: BlockCommitmentSignatureElem,
    pub s: BlockCommitmentSignatureElem,
}

impl BlockCommitmentSignature {
    pub fn verify(
        &self,
        public_key: PublicKey,
        block_hash: BlockHash,
    ) -> Result<(), pathfinder_crypto::signature::SignatureError> {
        pathfinder_crypto::signature::ecdsa_verify_partial(
            public_key.0,
            block_hash.0,
            self.r.0,
            self.s.0,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::macro_prelude::*;
    use crate::BlockCommitmentSignature;

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
        signature.verify(public_key, block_hash).unwrap();
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
        signature.verify(public_key, block_hash).unwrap();
    }
}
