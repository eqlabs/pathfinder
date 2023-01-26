#[cfg(feature = "test-utils")]
use fake::{Dummy, Fake};
use stark_hash::Felt;

use crate::{ToProtobuf, TryFromProtobuf};

use super::common::{BlockBody, BlockHeader};
use super::proto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetBlockHeaders(GetBlockHeaders),
    GetBlockBodies(GetBlockBodies),
    GetStateDiffs(GetStateDiffs),
    Status(Status),
}

const MAX_UNCOMPRESSED_MESSAGE_SIZE: usize = 1024 * 1024;

impl Request {
    pub fn from_protobuf_encoding(bytes: &[u8]) -> std::io::Result<Self> {
        use prost::Message;

        let bytes = zstd::bulk::decompress(bytes, MAX_UNCOMPRESSED_MESSAGE_SIZE)?;
        let request = proto::sync::Request::decode(bytes.as_ref())?;

        TryFromProtobuf::try_from_protobuf(request, "message")
    }

    pub fn into_protobuf_encoding(self) -> std::io::Result<Vec<u8>> {
        use prost::Message;

        let request: proto::sync::Request = self.to_protobuf();
        let encoded_len = request.encoded_len();
        if encoded_len > MAX_UNCOMPRESSED_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "Protobuf encoded message would exceed maximum message size",
            ));
        }
        let mut buf = Vec::with_capacity(request.encoded_len());
        request
            .encode(&mut buf)
            .expect("Buffer provides enough capacity");
        let buf = zstd::bulk::compress(buf.as_ref(), 1)?;
        Ok(buf)
    }
}

impl TryFromProtobuf<proto::sync::Request> for Request {
    fn try_from_protobuf(
        value: proto::sync::Request,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        match value.request {
            Some(r) => match r {
                proto::sync::request::Request::GetBlockHeaders(r) => Ok(Request::GetBlockHeaders(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
                proto::sync::request::Request::GetBlockBodies(r) => Ok(Request::GetBlockBodies(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
                proto::sync::request::Request::GetStateDiffs(r) => Ok(Request::GetStateDiffs(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
                proto::sync::request::Request::Status(r) => Ok(Request::Status(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field {field_name}"),
            )),
        }
    }
}

impl ToProtobuf<proto::sync::Request> for Request {
    fn to_protobuf(self) -> proto::sync::Request {
        proto::sync::Request {
            request: Some(match self {
                Request::GetBlockHeaders(r) => {
                    proto::sync::request::Request::GetBlockHeaders(r.to_protobuf())
                }
                Request::GetBlockBodies(r) => {
                    proto::sync::request::Request::GetBlockBodies(r.to_protobuf())
                }
                Request::GetStateDiffs(r) => {
                    proto::sync::request::Request::GetStateDiffs(r.to_protobuf())
                }
                Request::Status(r) => proto::sync::request::Request::Status(r.to_protobuf()),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
pub enum Direction {
    Forward,
    Backward,
}

impl TryFromProtobuf<i32> for Direction {
    fn try_from_protobuf(input: i32, field_name: &'static str) -> Result<Self, std::io::Error> {
        let input = proto::sync::Direction::from_i32(input).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse {field_name}"),
            )
        })?;
        Ok(match input {
            proto::sync::Direction::Backward => Direction::Backward,
            proto::sync::Direction::Forward => Direction::Forward,
        })
    }
}

impl ToProtobuf<i32> for Direction {
    fn to_protobuf(self) -> i32 {
        match self {
            Direction::Forward => proto::sync::Direction::Forward as i32,
            Direction::Backward => proto::sync::Direction::Backward as i32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::sync::GetBlockHeaders")]
pub struct GetBlockHeaders {
    pub start_block: Felt,
    pub count: u64,
    pub size_limit: u64,
    pub direction: Direction,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::sync::GetBlockBodies")]
pub struct GetBlockBodies {
    pub start_block: Felt,
    pub count: u64,
    pub size_limit: u64,
    pub direction: Direction,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::sync::GetStateDiffs")]
pub struct GetStateDiffs {
    pub start_block: Felt,
    pub count: u64,
    pub size_limit: u64,
    pub direction: Direction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    BlockHeaders(BlockHeaders),
    BlockBodies(BlockBodies),
    StateDiffs(StateDiffs),
    Status(Status),
}

impl Response {
    pub fn from_protobuf_encoding(bytes: &[u8]) -> std::io::Result<Self> {
        use prost::Message;

        let bytes = zstd::bulk::decompress(bytes, MAX_UNCOMPRESSED_MESSAGE_SIZE)?;
        let response = proto::sync::Response::decode(bytes.as_ref())?;

        TryFromProtobuf::try_from_protobuf(response, "message")
    }

    pub fn into_protobuf_encoding(self) -> std::io::Result<Vec<u8>> {
        use prost::Message;

        let response: proto::sync::Response = self.to_protobuf();
        let encoded_len = response.encoded_len();
        if encoded_len > MAX_UNCOMPRESSED_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "Protobuf encoded message would exceed maximum message size",
            ));
        }
        let mut buf = Vec::with_capacity(response.encoded_len());
        response
            .encode(&mut buf)
            .expect("Buffer provides enough capacity");
        let buf = zstd::bulk::compress(buf.as_ref(), 1)?;
        Ok(buf)
    }
}

impl TryFromProtobuf<proto::sync::Response> for Response {
    fn try_from_protobuf(
        value: proto::sync::Response,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        match value.response {
            Some(r) => match r {
                proto::sync::response::Response::BlockHeaders(h) => Ok(Response::BlockHeaders(
                    TryFromProtobuf::try_from_protobuf(h, field_name)?,
                )),
                proto::sync::response::Response::BlockBodies(r) => Ok(Response::BlockBodies(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
                proto::sync::response::Response::StateDiffs(r) => Ok(Response::StateDiffs(
                    TryFromProtobuf::try_from_protobuf(r, field_name)?,
                )),
                proto::sync::response::Response::Status(s) => Ok(Response::Status(
                    TryFromProtobuf::try_from_protobuf(s, field_name)?,
                )),
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field {field_name}"),
            )),
        }
    }
}

impl ToProtobuf<proto::sync::Response> for Response {
    fn to_protobuf(self) -> proto::sync::Response {
        proto::sync::Response {
            response: Some(match self {
                Response::BlockHeaders(r) => {
                    proto::sync::response::Response::BlockHeaders(r.to_protobuf())
                }
                Response::BlockBodies(r) => {
                    proto::sync::response::Response::BlockBodies(r.to_protobuf())
                }
                Response::StateDiffs(r) => {
                    proto::sync::response::Response::StateDiffs(r.to_protobuf())
                }
                Response::Status(r) => proto::sync::response::Response::Status(r.to_protobuf()),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::sync::BlockHeaders")]
pub struct BlockHeaders {
    pub headers: Vec<BlockHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::sync::BlockBodies")]
pub struct BlockBodies {
    pub block_bodies: Vec<BlockBody>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::sync::StateDiffs")]
pub struct StateDiffs {
    pub block_state_updates: Vec<BlockStateUpdateWithHash>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::sync::state_diffs::BlockStateUpdateWithHash")]
pub struct BlockStateUpdateWithHash {
    pub block_hash: Felt,
    pub state_update: super::propagation::BlockStateUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::sync::Status")]
pub struct Status {
    pub height: u64,
    pub hash: Felt,
    pub chain_id: Felt,
}
