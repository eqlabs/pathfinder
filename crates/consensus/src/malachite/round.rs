/// A round number in the consensus protocol.
///
/// Each height of the blockchain can go through multiple rounds of consensus
/// before reaching agreement. The round number starts at 0 and increments when
/// consensus fails to be reached in the current round.
///
/// A round can also be "nil" which represents no round.
#[derive(Clone, Copy, PartialOrd, Ord, Debug, PartialEq, Eq)]
pub struct Round(malachite_types::Round);

impl Round {
    pub fn new(round: u32) -> Self {
        Self(malachite_types::Round::new(round))
    }

    pub fn nil() -> Self {
        Self(malachite_types::Round::Nil)
    }

    pub fn as_u32(&self) -> Option<u32> {
        self.0.as_u32()
    }

    pub(crate) fn into_inner(self) -> malachite_types::Round {
        self.0
    }
}

impl From<malachite_types::Round> for Round {
    fn from(round: malachite_types::Round) -> Self {
        Self(round)
    }
}

impl From<u32> for Round {
    fn from(round: u32) -> Self {
        Self(malachite_types::Round::from(round))
    }
}

impl serde::Serialize for Round {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0.as_u32() {
            Some(value) => serializer.serialize_u32(value),
            None => serializer.serialize_none(),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Round {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let round_opt = Option::<u32>::deserialize(deserializer)?;
        match round_opt {
            Some(value) => Ok(Self(malachite_types::Round::from(value))),
            None => Ok(Self(malachite_types::Round::Nil)),
        }
    }
}

impl std::fmt::Display for Round {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            malachite_types::Round::Nil => write!(f, "nil"),
            malachite_types::Round::Some(value) => write!(f, "{value}"),
        }
    }
}
