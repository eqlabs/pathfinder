#[cfg(feature = "test-utils")]
use fake::{Dummy, Fake};
use stark_hash::Felt;

use crate::{ToProtobuf, TryFromProtobuf};

use super::common::{BlockBody, BlockHeader};
use super::proto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    NewBlockHeader(NewBlockHeader),
    NewBlockBody(NewBlockBody),
    NewBlockState(NewBlockState),
}

impl Message {
    pub fn from_protobuf_encoding(bytes: &[u8]) -> std::io::Result<Self> {
        use prost::Message;

        let message = proto::propagation::Message::decode(bytes)?;

        TryFromProtobuf::try_from_protobuf(message, "message")
    }

    pub fn into_protobuf_encoding(self) -> Vec<u8> {
        use prost::Message;

        let message: proto::propagation::Message = self.to_protobuf();
        let mut buf = Vec::with_capacity(message.encoded_len());
        message
            .encode(&mut buf)
            .expect("Buffer provides enough capacity");
        buf
    }
}

impl TryFromProtobuf<proto::propagation::Message> for Message {
    fn try_from_protobuf(
        value: proto::propagation::Message,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        match value.message {
            Some(m) => match m {
                proto::propagation::message::Message::NewBlockHeader(m) => Ok(
                    Message::NewBlockHeader(TryFromProtobuf::try_from_protobuf(m, field_name)?),
                ),
                proto::propagation::message::Message::NewBlockBody(m) => Ok(Message::NewBlockBody(
                    TryFromProtobuf::try_from_protobuf(m, field_name)?,
                )),
                proto::propagation::message::Message::NewBlockState(m) => Ok(
                    Message::NewBlockState(TryFromProtobuf::try_from_protobuf(m, field_name)?),
                ),
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field {field_name}"),
            )),
        }
    }
}

impl ToProtobuf<proto::propagation::Message> for Message {
    fn to_protobuf(self) -> proto::propagation::Message {
        let message = match self {
            Message::NewBlockHeader(h) => proto::propagation::message::Message::NewBlockHeader(
                proto::propagation::NewBlockHeader {
                    header: Some(h.header.to_protobuf()),
                },
            ),
            Message::NewBlockBody(h) => proto::propagation::message::Message::NewBlockBody(
                proto::propagation::NewBlockBody {
                    block_hash: Some(h.block_hash.to_protobuf()),
                    body: Some(h.body.to_protobuf()),
                },
            ),
            Message::NewBlockState(h) => proto::propagation::message::Message::NewBlockState(
                proto::propagation::NewBlockState {
                    block_hash: Some(h.block_hash.to_protobuf()),
                    state_update: Some(h.state_update.to_protobuf()),
                },
            ),
        };
        proto::propagation::Message {
            message: Some(message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::propagation::NewBlockHeader")]
pub struct NewBlockHeader {
    pub header: BlockHeader,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::propagation::NewBlockBody")]
pub struct NewBlockBody {
    pub block_hash: Felt,
    pub body: BlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::propagation::NewBlockState")]
pub struct NewBlockState {
    pub block_hash: Felt,
    pub state_update: BlockStateUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::propagation::BlockStateUpdate")]
pub struct BlockStateUpdate {
    pub contract_diffs: Vec<ContractDiff>,
    pub deployed_contracts: Vec<DeployedContract>,
    pub declared_contract_class_hashes: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::propagation::block_state_update::ContractDiff")]
pub struct ContractDiff {
    pub contract_address: Felt,
    pub nonce: Felt,
    pub storage_diffs: Vec<StorageDiff>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::propagation::block_state_update::StorageDiff")]
pub struct StorageDiff {
    pub key: Felt,
    pub value: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[cfg_attr(feature = "test-utils", derive(Dummy))]
#[protobuf(name = "crate::proto::propagation::block_state_update::DeployedContract")]
pub struct DeployedContract {
    pub contract_address: Felt,
    pub contract_class_hash: Felt,
}
