use fake::Dummy;
use pathfinder_crypto::Felt;
use pathfinder_tagged::Tagged;
use pathfinder_tagged_debug_derive::TaggedDebug;

use crate::common::Hash;
use crate::sync::common::Iteration;
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::event::Event")]
pub struct Event {
    pub transaction_hash: Hash,
    pub from_address: Felt,
    pub keys: Vec<Felt>,
    pub data: Vec<Felt>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::sync::event::EventsRequest")]
pub struct EventsRequest {
    pub iteration: Iteration,
}

#[derive(Default, Clone, PartialEq, Eq, Dummy, TaggedDebug)]
pub enum EventsResponse {
    Event(Event),
    #[default]
    Fin,
}

impl ToProtobuf<proto::sync::event::EventsResponse> for EventsResponse {
    fn to_protobuf(self) -> proto::sync::event::EventsResponse {
        use proto::sync::event::events_response::EventMessage::{Event, Fin};
        proto::sync::event::EventsResponse {
            event_message: Some(match self {
                Self::Event(event) => Event(event.to_protobuf()),
                Self::Fin => Fin(proto::common::Fin {}),
            }),
        }
    }
}

impl TryFromProtobuf<proto::sync::event::EventsResponse> for EventsResponse {
    fn try_from_protobuf(
        input: proto::sync::event::EventsResponse,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::sync::event::events_response::EventMessage::{Event, Fin};
        Ok(match proto_field(input.event_message, field_name)? {
            Event(events) => Self::Event(TryFromProtobuf::try_from_protobuf(events, field_name)?),
            Fin(_) => Self::Fin,
        })
    }
}
