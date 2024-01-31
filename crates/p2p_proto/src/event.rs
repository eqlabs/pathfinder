use fake::Dummy;
use pathfinder_crypto::Felt;

use crate::common::{Hash, Iteration};
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::event::Event")]
pub struct Event {
    pub transaction_hash: Hash,
    pub from_address: Felt,
    pub keys: Vec<Felt>,
    pub data: Vec<Felt>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::event::EventsRequest")]
pub struct EventsRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum EventsResponse {
    Event(Event),
    Fin,
}

impl ToProtobuf<proto::event::EventsResponse> for EventsResponse {
    fn to_protobuf(self) -> proto::event::EventsResponse {
        use proto::event::events_response::EventMessage::{Event, Fin};
        proto::event::EventsResponse {
            event_message: Some(match self {
                Self::Event(event) => Event(event.to_protobuf()),
                Self::Fin => Fin(proto::common::Fin {}),
            }),
        }
    }
}

impl TryFromProtobuf<proto::event::EventsResponse> for EventsResponse {
    fn try_from_protobuf(
        input: proto::event::EventsResponse,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::event::events_response::EventMessage::{Event, Fin};
        Ok(match proto_field(input.event_message, field_name)? {
            Event(events) => Self::Event(TryFromProtobuf::try_from_protobuf(events, field_name)?),
            Fin(_) => Self::Fin,
        })
    }
}
