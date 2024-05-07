use crate::dto;
use crate::dto::serialize::{self, SerializeForVersion, Serializer};

pub struct StateUpdate<'a>(pub &'a pathfinder_common::StateUpdate);
pub struct PendingStateUpdate<'a>(pub &'a pathfinder_common::StateUpdate);

pub struct StateDiff<'a>(pub &'a pathfinder_common::StateUpdate);

impl SerializeForVersion for StateUpdate<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("block_hash", &dto::BlockHash(&self.0.block_hash))?;
        serializer.serialize_field("old_root", &dto::Felt(&self.0.state_commitment.0))?;
        serializer.serialize_field("new_root", &dto::Felt(&self.0.parent_state_commitment.0))?;
        serializer.serialize_field("state_diff", &StateDiff(&self.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for PendingStateUpdate<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("old_root", &dto::Felt(&self.0.state_commitment.0))?;
        serializer.serialize_field("state_diff", &StateDiff(&self.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for StateDiff<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        todo!()
    }
}
