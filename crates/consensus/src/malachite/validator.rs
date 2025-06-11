use super::{MalachiteContext, ValidatorAddress};

/// A public key for the malachite context.
pub type PublicKey = malachite_signing_ed25519::PublicKey;

/// A validator's voting power
pub type VotingPower = u64;

/// A validator in the consensus protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub address: ValidatorAddress,
    pub public_key: PublicKey,
    pub voting_power: VotingPower,
}

impl PartialOrd for Validator {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Validator {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl malachite_types::Validator<MalachiteContext> for Validator {
    fn address(&self) -> &ValidatorAddress {
        &self.address
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn voting_power(&self) -> VotingPower {
        self.voting_power
    }
}
