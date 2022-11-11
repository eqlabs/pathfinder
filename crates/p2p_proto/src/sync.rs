use stark_hash::StarkHash;

use super::common::BlockHeader;
use super::proto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetBlockHeaders(GetBlockHeaders),
}

impl Request {
    pub fn from_protobuf_encoding(bytes: &[u8]) -> std::io::Result<Self> {
        use prost::Message;

        let request = proto::sync::Request::decode(bytes)?;

        request.try_into().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unable to decode request: {}", e),
            )
        })
    }

    pub fn into_protobuf_encoding(self) -> Vec<u8> {
        use prost::Message;

        let request: proto::sync::Request = self.into();
        let mut buf = Vec::with_capacity(request.encoded_len());
        request
            .encode(&mut buf)
            .expect("Buffer provides enough capacity");
        buf
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
                proto::sync::request::Request::GetBlockBodies(_) => todo!(),
                proto::sync::request::Request::GetStateDiffs(_) => todo!(),
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Missing request message",
            )),
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
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
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
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Missing start_block field",
                    )
                })?
                .try_into()?,
            count: value.count,
            size_limit: value.size_limit,
            direction: match value.backward {
                true => Direction::Backward,
                false => Direction::Forward,
            },
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
            backward: match headers.direction {
                Direction::Backward => true,
                Direction::Forward => false,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    BlockHeaders(BlockHeaders),
}

impl Response {
    pub fn from_protobuf_encoding(bytes: &[u8]) -> std::io::Result<Self> {
        use prost::Message;

        let response = proto::sync::Response::decode(bytes)?;

        response.try_into().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unable to decode response: {}", e),
            )
        })
    }

    pub fn into_protobuf_encoding(self) -> Vec<u8> {
        use prost::Message;

        let response: proto::sync::Response = self.into();
        let mut buf = Vec::with_capacity(response.encoded_len());
        response
            .encode(&mut buf)
            .expect("Buffer provides enough capacity");
        buf
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
                proto::sync::response::Response::BlockBodies(_) => todo!(),
                proto::sync::response::Response::StateDiffs(_) => todo!(),
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
        let headers: Result<Vec<_>, _> = value.headers.into_iter().map(|h| h.try_into()).collect();
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
