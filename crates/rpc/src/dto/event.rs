use pathfinder_common::{ContractAddress, EventData, EventKey};

use crate::dto;
use crate::dto::serialize::{self, SerializeForVersion, Serializer};

pub struct Event<'a> {
    pub address: &'a ContractAddress,
    pub keys: &'a [EventKey],
    pub data: &'a [EventData],
}

pub struct EventContext<'a> {
    pub keys: &'a [EventKey],
    pub data: &'a [EventData],
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
