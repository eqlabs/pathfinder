use crate::common::{BlockId, Fin, Hash, Iteration};
use crate::{proto, ToProtobuf, TryFromProtobuf};
use stark_hash::Felt;

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::event::Event")]
pub struct Event {
    pub from_address: Felt,
    pub keys: Vec<Felt>,
    pub data: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::event::TxnEvents")]
pub struct TxnEvents {
    pub events: Vec<Event>,
    pub transaction_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::event::EventsRequest")]
pub struct EventsRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::event::Events")]
pub struct Events {
    pub items: Vec<TxnEvents>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::event::EventsResponse")]
pub struct EventsResponse {
    #[optional]
    pub id: Option<BlockId>,
    pub responses: Responses,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Responses {
    Events(Events),
    Fin(Fin),
}

impl Responses {
    pub fn into_events(self) -> Option<Events> {
        match self {
            Responses::Events(events) => Some(events),
            Responses::Fin(_) => None,
        }
    }

    pub fn into_fin(self) -> Option<Fin> {
        match self {
            Responses::Events(_) => None,
            Responses::Fin(fin) => Some(fin),
        }
    }
}

impl ToProtobuf<proto::event::events_response::Responses> for Responses {
    fn to_protobuf(self) -> proto::event::events_response::Responses {
        use proto::event::events_response::Responses::{Events, Fin};
        match self {
            Responses::Events(events) => Events(events.to_protobuf()),
            Responses::Fin(fin) => Fin(fin.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::event::events_response::Responses> for Responses {
    fn try_from_protobuf(
        input: proto::event::events_response::Responses,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::event::events_response::Responses::{Events, Fin};
        match input {
            Events(events) => Ok(Responses::Events(self::Events::try_from_protobuf(
                events, field_name,
            )?)),
            Fin(fin) => Ok(Responses::Fin(self::Fin::try_from_protobuf(
                fin, field_name,
            )?)),
        }
    }
}
