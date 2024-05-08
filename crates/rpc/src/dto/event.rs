use crate::dto;
use crate::dto::serialize::{self, SerializeForVersion, Serializer};

pub struct EventsChunk<'a>(pub &'a crate::method::get_events::types::GetEventsResult);

pub struct EmittedEvent<'a>(pub &'a crate::method::get_events::types::EmittedEvent);

impl SerializeForVersion for EventsChunk<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter(
            "events",
            self.0.events.len(),
            &mut self.0.events.iter().map(EmittedEvent),
        )?;
        serializer.serialize_optional("continuation_token", self.0.continuation_token.as_ref())?;

        serializer.end()
    }
}

impl SerializeForVersion for EmittedEvent<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        todo!()
    }
}
