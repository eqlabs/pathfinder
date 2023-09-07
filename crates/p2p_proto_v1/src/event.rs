use crate::common::BlockId;
use crate::{ToProtobuf, TryFromProtobuf};
use stark_hash::Felt;

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::event::Event")]
pub struct Event {
    pub from_address: Felt,
    pub keys: Vec<Felt>,
    pub data: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::event::GetEvents")]
pub struct GetEvents {
    pub id: BlockId,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::event::Events")]
pub struct Events {
    pub events: Vec<Event>,
}
