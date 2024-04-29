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
    pub fn verify(
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
}

#[cfg(test)]
mod test {
    use crate::macro_prelude::*;
    use crate::BlockCommitmentSignature;

    #[test]
    fn test_verify() {
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

        assert!(signature
            .verify(public_key, block_hash, state_diff_commitment)
            .is_ok());
    }
}
