use crate::dto::serialize::{self, SerializeForVersion, Serializer};

pub struct StateUpdate<'a>(pub &'a pathfinder_common::StateUpdate);
pub struct PendingStateUpdate<'a>(pub &'a pathfinder_common::StateUpdate);

impl SerializeForVersion for StateUpdate<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        todo!()
    }
}

impl SerializeForVersion for PendingStateUpdate<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        todo!()
    }
}
