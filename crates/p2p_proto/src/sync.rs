use stark_hash::StarkHash;

use super::common::{invalid_data, BlockBody, BlockHeader};
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

        request.try_into().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unable to decode request: {}", e),
            )
        })
    }

    pub fn into_protobuf_encoding(self) -> std::io::Result<Vec<u8>> {
        use prost::Message;

        let request: proto::sync::Request = self.into();
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

impl TryFrom<proto::sync::Request> for Request {
    type Error = std::io::Error;

    fn try_from(value: proto::sync::Request) -> Result<Self, Self::Error> {
        match value.request {
            Some(r) => match r {
                proto::sync::request::Request::GetBlockHeaders(r) => {
                    Ok(Request::GetBlockHeaders(r.try_into()?))
                }
                proto::sync::request::Request::GetBlockBodies(r) => {
                    Ok(Request::GetBlockBodies(r.try_into()?))
                }
                proto::sync::request::Request::GetStateDiffs(r) => {
                    Ok(Request::GetStateDiffs(r.try_into()?))
                }
                proto::sync::request::Request::Status(r) => Ok(Request::Status(r.try_into()?)),
            },
            None => Err(invalid_data("Missing request message")),
        }
    }
}

impl From<Request> for proto::sync::Request {
    fn from(r: Request) -> Self {
        Self {
            request: Some(match r {
                Request::GetBlockHeaders(r) => {
                    proto::sync::request::Request::GetBlockHeaders(r.into())
                }
                Request::GetBlockBodies(r) => {
                    proto::sync::request::Request::GetBlockBodies(r.into())
                }
                Request::GetStateDiffs(r) => proto::sync::request::Request::GetStateDiffs(r.into()),
                Request::Status(r) => proto::sync::request::Request::Status(r.into()),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}

impl From<Direction> for bool {
    fn from(d: Direction) -> Self {
        match d {
            Direction::Forward => false,
            Direction::Backward => true,
        }
    }
}

impl From<bool> for Direction {
    fn from(d: bool) -> Self {
        match d {
            true => Direction::Backward,
            false => Direction::Forward,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlockHeaders {
    pub start_block: StarkHash,
    pub count: u64,
    pub size_limit: u64,
    pub direction: Direction,
}

impl TryFrom<proto::sync::GetBlockHeaders> for GetBlockHeaders {
    type Error = std::io::Error;

    fn try_from(value: proto::sync::GetBlockHeaders) -> Result<Self, Self::Error> {
        Ok(Self {
            start_block: value
                .start_block
                .ok_or_else(|| invalid_data("Missing start_block message"))?
                .try_into()?,
            count: value.count,
            size_limit: value.size_limit,
            direction: value.backward.into(),
        })
    }
}

impl From<GetBlockHeaders> for proto::sync::GetBlockHeaders {
    fn from(headers: GetBlockHeaders) -> Self {
        Self {
            request_id: 0,
            start_block: Some(headers.start_block.into()),
            count: headers.count,
            size_limit: headers.size_limit,
            backward: headers.direction.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlockBodies {
    pub start_block: StarkHash,
    pub count: u64,
    pub size_limit: u64,
    pub direction: Direction,
}

impl TryFrom<proto::sync::GetBlockBodies> for GetBlockBodies {
    type Error = std::io::Error;

    fn try_from(value: proto::sync::GetBlockBodies) -> Result<Self, Self::Error> {
        Ok(Self {
            start_block: value
                .start_block
                .ok_or_else(|| invalid_data("Missing start_block message"))?
                .try_into()?,
            count: value.count,
            size_limit: value.size_limit,
            direction: value.backward.into(),
        })
    }
}

impl From<GetBlockBodies> for proto::sync::GetBlockBodies {
    fn from(value: GetBlockBodies) -> Self {
        Self {
            request_id: 0,
            start_block: Some(value.start_block.into()),
            count: value.count,
            size_limit: value.size_limit,
            backward: value.direction.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetStateDiffs {
    pub start_block: StarkHash,
    pub count: u64,
    pub size_limit: u64,
    pub direction: Direction,
}

impl TryFrom<proto::sync::GetStateDiffs> for GetStateDiffs {
    type Error = std::io::Error;

    fn try_from(value: proto::sync::GetStateDiffs) -> Result<Self, Self::Error> {
        Ok(Self {
            start_block: value
                .start_block
                .ok_or_else(|| invalid_data("Missing start_block message"))?
                .try_into()?,
            count: value.count,
            size_limit: value.size_limit,
            direction: value.backward.into(),
        })
    }
}

impl From<GetStateDiffs> for proto::sync::GetStateDiffs {
    fn from(headers: GetStateDiffs) -> Self {
        Self {
            request_id: 0,
            start_block: Some(headers.start_block.into()),
            count: headers.count,
            size_limit: headers.size_limit,
            backward: headers.direction.into(),
        }
    }
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

        response.try_into().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unable to decode response: {}", e),
            )
        })
    }

    pub fn into_protobuf_encoding(self) -> std::io::Result<Vec<u8>> {
        use prost::Message;

        let response: proto::sync::Response = self.into();
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

impl TryFrom<proto::sync::Response> for Response {
    type Error = std::io::Error;

    fn try_from(value: proto::sync::Response) -> Result<Self, Self::Error> {
        match value.response {
            Some(r) => match r {
                proto::sync::response::Response::BlockHeaders(h) => {
                    Ok(Response::BlockHeaders(h.try_into()?))
                }
                proto::sync::response::Response::BlockBodies(r) => {
                    Ok(Response::BlockBodies(r.try_into()?))
                }
                proto::sync::response::Response::StateDiffs(r) => {
                    Ok(Response::StateDiffs(r.try_into()?))
                }
                proto::sync::response::Response::Status(s) => Ok(Response::Status(s.try_into()?)),
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Missing response message",
            )),
        }
    }
}

impl From<Response> for proto::sync::Response {
    fn from(r: Response) -> Self {
        Self {
            response: Some(match r {
                Response::BlockHeaders(r) => {
                    proto::sync::response::Response::BlockHeaders(r.into())
                }
                Response::BlockBodies(r) => proto::sync::response::Response::BlockBodies(r.into()),
                Response::StateDiffs(r) => proto::sync::response::Response::StateDiffs(r.into()),
                Response::Status(r) => proto::sync::response::Response::Status(r.into()),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaders {
    pub headers: Vec<BlockHeader>,
}

impl TryFrom<proto::sync::BlockHeaders> for BlockHeaders {
    type Error = std::io::Error;

    fn try_from(value: proto::sync::BlockHeaders) -> Result<Self, Self::Error> {
        let headers: Result<Vec<_>, _> = value.headers.into_iter().map(TryInto::try_into).collect();
        let headers = headers.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse block header: {}", e),
            )
        })?;
        Ok(Self { headers })
    }
}

impl From<BlockHeaders> for proto::sync::BlockHeaders {
    fn from(headers: BlockHeaders) -> Self {
        Self {
            request_id: 0,
            headers: headers.headers.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBodies {
    pub block_bodies: Vec<BlockBody>,
}

impl TryFrom<proto::sync::BlockBodies> for BlockBodies {
    type Error = std::io::Error;

    fn try_from(value: proto::sync::BlockBodies) -> Result<Self, Self::Error> {
        Ok(Self {
            block_bodies: value
                .block_bodies
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| invalid_data(&format!("Failed to parse block bodies: {}", e)))?,
        })
    }
}

impl From<BlockBodies> for proto::sync::BlockBodies {
    fn from(value: BlockBodies) -> Self {
        Self {
            request_id: 0,
            block_bodies: value.block_bodies.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDiffs {
    pub block_state_updates: Vec<BlockStateUpdateWithHash>,
}

impl TryFrom<proto::sync::StateDiffs> for StateDiffs {
    type Error = std::io::Error;

    fn try_from(value: proto::sync::StateDiffs) -> Result<Self, Self::Error> {
        Ok(Self {
            block_state_updates: value
                .block_state_updates
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    invalid_data(&format!("Failed to parse block state updates: {}", e))
                })?,
        })
    }
}

impl From<StateDiffs> for proto::sync::StateDiffs {
    fn from(value: StateDiffs) -> Self {
        Self {
            request_id: 0,
            block_state_updates: value
                .block_state_updates
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStateUpdateWithHash {
    pub block_hash: StarkHash,
    pub state_update: super::propagation::BlockStateUpdate,
}

impl TryFrom<proto::sync::state_diffs::BlockStateUpdateWithHash> for BlockStateUpdateWithHash {
    type Error = std::io::Error;

    fn try_from(
        value: proto::sync::state_diffs::BlockStateUpdateWithHash,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            block_hash: value
                .block_hash
                .ok_or_else(|| invalid_data("Missing block_hash field"))?
                .try_into()?,
            state_update: value
                .state_update
                .ok_or_else(|| invalid_data("Missing state_update field"))?
                .try_into()?,
        })
    }
}

impl From<BlockStateUpdateWithHash> for proto::sync::state_diffs::BlockStateUpdateWithHash {
    fn from(value: BlockStateUpdateWithHash) -> Self {
        Self {
            block_hash: Some(value.block_hash.into()),
            state_update: Some(value.state_update.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub height: u64,
    pub hash: StarkHash,
    pub chain_id: StarkHash,
}

impl TryFrom<proto::sync::Status> for Status {
    type Error = std::io::Error;

    fn try_from(value: proto::sync::Status) -> Result<Self, Self::Error> {
        Ok(Self {
            height: value.height,
            hash: value
                .hash
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Missing hash field")
                })?
                .try_into()?,
            chain_id: value
                .chain_id
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Missing chain_id field")
                })?
                .try_into()?,
        })
    }
}

impl From<Status> for proto::sync::Status {
    fn from(status: Status) -> Self {
        Self {
            height: status.height,
            hash: Some(status.hash.into()),
            chain_id: Some(status.chain_id.into()),
        }
    }
}
