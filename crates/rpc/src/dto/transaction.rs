use pathfinder_common::TransactionHash;

use crate::dto;
use crate::dto::serialize;
use crate::dto::serialize::{SerializeForVersion, Serializer};

pub struct TxnHash<'a>(pub &'a TransactionHash);

impl SerializeForVersion for TxnHash<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        dto::Felt(&self.0 .0).serialize(serializer)
    }
}
