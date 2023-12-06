use fake::Dummy;
use pathfinder_crypto::Felt;

use crate::common::{BlockId, Fin, Hash, Iteration};
use crate::{proto, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::event::Event")]
pub struct Event {
    pub from_address: Felt,
    pub keys: Vec<Felt>,
    pub data: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::event::TxnEvents")]
pub struct TxnEvents {
    pub events: Vec<Event>,
    pub transaction_hash: Hash,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::event::EventsRequest")]
pub struct EventsRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::event::Events")]
pub struct Events {
    pub items: Vec<TxnEvents>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::event::EventsResponse")]
pub struct EventsResponse {
    #[optional]
    pub id: Option<BlockId>,
    #[rename(responses)]
    pub kind: EventsResponseKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum EventsResponseKind {
    Events(Events),
    Fin(Fin),
}

impl From<Fin> for EventsResponse {
    fn from(fin: Fin) -> Self {
        EventsResponse {
            id: None,
            kind: EventsResponseKind::Fin(fin),
        }
    }
}

impl EventsResponse {
    pub fn into_fin(self) -> Option<Fin> {
        self.kind.into_fin()
    }
}

impl EventsResponseKind {
    pub fn into_events(self) -> Option<Events> {
        match self {
            EventsResponseKind::Events(events) => Some(events),
            EventsResponseKind::Fin(_) => None,
        }
    }

    pub fn into_fin(self) -> Option<Fin> {
        match self {
            EventsResponseKind::Events(_) => None,
            EventsResponseKind::Fin(fin) => Some(fin),
        }
    }
}

impl ToProtobuf<proto::event::events_response::Responses> for EventsResponseKind {
    fn to_protobuf(self) -> proto::event::events_response::Responses {
        use proto::event::events_response::Responses::{Events, Fin};
        match self {
            EventsResponseKind::Events(events) => Events(events.to_protobuf()),
            EventsResponseKind::Fin(fin) => Fin(fin.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::event::events_response::Responses> for EventsResponseKind {
    fn try_from_protobuf(
        input: proto::event::events_response::Responses,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::event::events_response::Responses::{Events, Fin};
        match input {
            Events(events) => Ok(EventsResponseKind::Events(self::Events::try_from_protobuf(
                events, field_name,
            )?)),
            Fin(fin) => Ok(EventsResponseKind::Fin(self::Fin::try_from_protobuf(
                fin, field_name,
            )?)),
        }
    }
}
