use crate::{permute_comp, PoseidonState};
use stark_curve::FieldElement;

/// Hashes a number of messages using the Poseidon hash
pub fn poseidon_hash(msgs: &[FieldElement]) -> FieldElement {
    let mut state = [FieldElement::ZERO, FieldElement::ZERO, FieldElement::ZERO];
    for msg in msgs {
        state[0] += msg;
        permute_comp(&mut state);
    }
    state[0]
}

/// The PoseidonHasher can build up a hash by appending to state
pub struct PoseidonHasher {
    state: PoseidonState,
}

impl PoseidonHasher {
    /// Creates a new PoseidonHasher
    pub fn new() -> PoseidonHasher {
        PoseidonHasher {
            state: [FieldElement::ZERO, FieldElement::ZERO, FieldElement::ZERO],
        }
    }

    /// Absorbs message into the hash
    pub fn write(&mut self, msg: FieldElement) {
        self.state[0] += msg;
        permute_comp(&mut self.state);
    }

    /// Extracts a single hash output
    pub fn extract(&mut self) -> FieldElement {
        let hash = self.state[0];
        permute_comp(&mut self.state);
        hash
    }

    /// Finish and return hash
    pub fn finish(self) -> FieldElement {
        self.state[0]
    }
}

impl Default for PoseidonHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{poseidon_hash, PoseidonHasher};
    use stark_curve::FieldElement;
    use stark_hash::Felt;

    #[test]
    fn test_sponge() {
        let result = FieldElement::from(
            Felt::from_hex_str("30ACF0EF3C4549E3684B19652015FD9EADF7BDBA2A1A46CB29B9E18E6622296")
                .unwrap(),
        );

        // Construct messages, the first few integers
        let msgs = [
            FieldElement::ZERO,
            FieldElement::ONE,
            FieldElement::TWO,
            FieldElement::THREE,
        ];

        // Construct hash from hasher
        let mut hasher = PoseidonHasher::new();
        for msg in msgs {
            hasher.write(msg);
        }
        let hasher_result = hasher.finish();

        // Construct hash from hash function
        let hash_result = poseidon_hash(&msgs);

        // Check they are equal
        assert_eq!(hasher_result, hash_result);
        assert_eq!(result, hash_result);
    }
}
