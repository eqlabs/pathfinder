use std::fmt::Display;
use std::num::NonZeroU64;

use fake::Dummy;
use rand::Rng;

use crate::common::{BlockNumberOrHash, Hash};
use crate::{proto, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, Default)]
#[protobuf(name = "crate::proto::sync::common::StateDiffCommitment")]
pub struct StateDiffCommitment {
    pub state_diff_length: u64,
    pub root: Hash,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::common::Iteration")]
pub struct Iteration {
    pub start: BlockNumberOrHash,
    pub direction: Direction,
    pub limit: u64,
    pub step: Step,
}

/// Guaranteed to always be `>= 1`, defaults to `1` if constructed from `None`
/// or `Some(0)`
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Step(NonZeroU64);

impl Step {
    pub fn into_inner(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Dummy)]
pub enum Direction {
    Forward,
    Backward,
}

impl From<u64> for Step {
    fn from(input: u64) -> Self {
        Self(NonZeroU64::new(input).unwrap_or(NonZeroU64::MIN))
    }
}

impl From<Option<u64>> for Step {
    fn from(input: Option<u64>) -> Self {
        Self::from(input.unwrap_or_default())
    }
}

impl Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> Dummy<T> for Step {
    fn dummy_with_rng<R: Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self(rng.gen())
    }
}

impl ToProtobuf<u64> for Step {
    fn to_protobuf(self) -> u64 {
        self.into_inner()
    }
}

impl TryFromProtobuf<u64> for Step {
    fn try_from_protobuf(input: u64, _: &'static str) -> Result<Self, std::io::Error> {
        Ok(Self::from(input))
    }
}

impl ToProtobuf<i32> for Direction {
    fn to_protobuf(self) -> i32 {
        use proto::sync::common::iteration::Direction::{Backward, Forward};
        match self {
            Direction::Forward => Forward as i32,
            Direction::Backward => Backward as i32,
        }
    }
}

impl TryFromProtobuf<i32> for Direction {
    fn try_from_protobuf(input: i32, field_name: &'static str) -> Result<Self, std::io::Error> {
        use proto::sync::common::iteration::Direction::{Backward, Forward};
        Ok(
            match TryFrom::try_from(input).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid direction field element {field_name} enum value: {e}"),
                )
            })? {
                Backward => Direction::Backward,
                Forward => Direction::Forward,
            },
        )
    }
}
