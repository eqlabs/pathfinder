use pathfinder_common::{ContractAddress, EventData, EventKey};

use crate::dto;
use crate::dto::serialize::{self, SerializeForVersion, Serializer};

pub struct EventsChunk<'a>(pub &'a crate::method::get_events::types::GetEventsResult);

pub struct EmittedEvent<'a>(pub &'a crate::method::get_events::types::EmittedEvent);
pub struct Event<'a> {
    pub address: &'a ContractAddress,
    pub keys: &'a [EventKey],
    pub data: &'a [EventData],
}
pub struct EventContext<'a> {
    pub keys: &'a [EventKey],
    pub data: &'a [EventData],
}

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
        let mut serializer = serializer.serialize_struct()?;

        serializer.flatten(&Event {
            address: &self.0.from_address,
            keys: &self.0.keys,
            data: &self.0.data,
        })?;

        serializer
            .serialize_optional("block_hash", self.0.block_hash.as_ref().map(dto::BlockHash))?;
        serializer.serialize_optional("block_number", self.0.block_number.map(dto::BlockNumber))?;
        serializer.serialize_field("transaction_hash", &dto::TxnHash(&self.0.transaction_hash))?;

        serializer.end()
    }
}

impl SerializeForVersion for Event<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("from_address", &dto::Address(self.address))?;
        serializer.flatten(&EventContext {
            keys: self.keys,
            data: self.data,
        })?;

        serializer.end()
    }
}

impl SerializeForVersion for EventContext<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter(
            "keys",
            self.keys.len(),
            &mut self.keys.iter().map(|x| dto::Felt(&x.0)),
        )?;
        serializer.serialize_iter(
            "data",
            self.data.len(),
            &mut self.data.iter().map(|x| dto::Felt(&x.0)),
        )?;

        serializer.end()
    }
}
