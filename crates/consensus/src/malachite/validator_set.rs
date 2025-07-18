use std::sync::Arc;

use super::{ConsensusBounded, MalachiteContext, Validator};

/// A validator set represents a group of consensus participants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    pub validators: Arc<Vec<Validator>>,
}

impl ValidatorSet {
    pub fn new(validators: impl IntoIterator<Item = Validator>) -> Self {
        let mut validators: Vec<_> = validators.into_iter().collect();
        validators.sort();
        validators.dedup();

        assert!(!validators.is_empty());

        Self {
            validators: Arc::new(validators),
        }
    }
}

impl<V: ConsensusBounded + 'static> malachite_types::ValidatorSet<MalachiteContext<V>> for ValidatorSet {
    fn count(&self) -> usize {
        self.validators.len()
    }

    fn total_voting_power(&self) -> malachite_types::VotingPower {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    fn get_by_address(
        &self,
        address: &<MalachiteContext<V> as malachite_types::Context>::Address,
    ) -> Option<&<MalachiteContext<V> as malachite_types::Context>::Validator> {
        self.validators.iter().find(|v| &v.address == address)
    }

    fn get_by_index(
        &self,
        index: usize,
    ) -> Option<&<MalachiteContext<V> as malachite_types::Context>::Validator> {
        self.validators.get(index)
    }
}
