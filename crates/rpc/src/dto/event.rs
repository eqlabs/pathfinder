use crate::dto;
use crate::dto::serialize::{self, SerializeForVersion, Serializer};

pub struct EventsChunk<'a>(pub &'a crate::method::get_events::types::GetEventsResult);

impl SerializeForVersion for EventsChunk<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        todo!()
    }
}
