use stark_hash::StarkHash;

use super::common::{invalid_data, parse_felt_vector, BlockBody, BlockHeader};
use super::proto;

#[derive(Debug)]
pub enum Message {
    NewBlockHeader(NewBlockHeader),
    NewBlockBody(NewBlockBody),
    NewBlockState(NewBlockState),
}

impl Message {
    pub fn from_protobuf_encoding(bytes: &[u8]) -> std::io::Result<Self> {
        use prost::Message;

        let message = proto::propagation::Message::decode(bytes)?;

        message.try_into().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unable to decode message: {}", e),
            )
        })
    }

    pub fn into_protobuf_encoding(self) -> Vec<u8> {
        use prost::Message;

        let message: proto::propagation::Message = self.into();
        let mut buf = Vec::with_capacity(message.encoded_len());
        message
            .encode(&mut buf)
            .expect("Buffer provides enough capacity");
        buf
    }
}

impl TryFrom<proto::propagation::Message> for Message {
    type Error = std::io::Error;

    fn try_from(value: proto::propagation::Message) -> Result<Self, Self::Error> {
        match value.message {
            Some(m) => match m {
                proto::propagation::message::Message::NewBlockHeader(m) => {
                    Ok(Message::NewBlockHeader(m.try_into()?))
                }
                proto::propagation::message::Message::NewBlockBody(m) => {
                    Ok(Message::NewBlockBody(m.try_into()?))
                }
                proto::propagation::message::Message::NewBlockState(m) => {
                    Ok(Message::NewBlockState(m.try_into()?))
                }
            },
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Missing message message",
            )),
        }
    }
}

impl From<Message> for proto::propagation::Message {
    fn from(m: Message) -> Self {
        let message = match m {
            Message::NewBlockHeader(h) => proto::propagation::message::Message::NewBlockHeader(
                proto::propagation::NewBlockHeader {
                    header: Some(h.block_header.into()),
                },
            ),
            Message::NewBlockBody(h) => proto::propagation::message::Message::NewBlockBody(
                proto::propagation::NewBlockBody {
                    block_hash: Some(h.block_hash.into()),
                    body: Some(h.body.into()),
                },
            ),
            Message::NewBlockState(h) => proto::propagation::message::Message::NewBlockState(
                proto::propagation::NewBlockState {
                    block_hash: Some(h.block_hash.into()),
                    state_update: Some(h.state_update.into()),
                },
            ),
        };
        Self {
            message: Some(message),
        }
    }
}

#[derive(Debug)]
pub struct NewBlockHeader {
    pub block_header: BlockHeader,
}

impl TryFrom<proto::propagation::NewBlockHeader> for NewBlockHeader {
    type Error = std::io::Error;

    fn try_from(header: proto::propagation::NewBlockHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            block_header: header
                .header
                .ok_or_else(|| invalid_data("Missing header field"))?
                .try_into()?,
        })
    }
}

impl From<NewBlockHeader> for proto::propagation::NewBlockHeader {
    fn from(header: NewBlockHeader) -> Self {
        Self {
            header: Some(header.block_header.into()),
        }
    }
}

#[derive(Debug)]
pub struct NewBlockBody {
    pub block_hash: StarkHash,
    pub body: BlockBody,
}

impl TryFrom<proto::propagation::NewBlockBody> for NewBlockBody {
    type Error = std::io::Error;

    fn try_from(body: proto::propagation::NewBlockBody) -> Result<Self, Self::Error> {
        Ok(Self {
            block_hash: body
                .block_hash
                .ok_or_else(|| invalid_data("Missing block_hash field"))?
                .try_into()?,
            body: body
                .body
                .ok_or_else(|| invalid_data("Missing body field"))?
                .try_into()?,
        })
    }
}

impl From<NewBlockBody> for proto::propagation::NewBlockBody {
    fn from(body: NewBlockBody) -> Self {
        Self {
            block_hash: Some(body.block_hash.into()),
            body: Some(body.body.into()),
        }
    }
}

#[derive(Debug)]
pub struct NewBlockState {
    pub block_hash: StarkHash,
    pub state_update: BlockStateUpdate,
}

impl TryFrom<proto::propagation::NewBlockState> for NewBlockState {
    type Error = std::io::Error;

    fn try_from(state: proto::propagation::NewBlockState) -> Result<Self, Self::Error> {
        Ok(Self {
            block_hash: state
                .block_hash
                .ok_or_else(|| invalid_data("Missing block_hash field"))?
                .try_into()?,
            state_update: state
                .state_update
                .ok_or_else(|| invalid_data("Missing state_update field"))?
                .try_into()?,
        })
    }
}

impl From<NewBlockState> for proto::propagation::NewBlockState {
    fn from(state: NewBlockState) -> Self {
        Self {
            block_hash: Some(state.block_hash.into()),
            state_update: Some(state.state_update.into()),
        }
    }
}

#[derive(Debug)]
pub struct BlockStateUpdate {
    pub contract_diffs: Vec<ContractDiff>,
    pub deployed_contracts: Vec<DeployedContract>,
    pub declared_contract_class_hashes: Vec<StarkHash>,
}

impl TryFrom<proto::propagation::BlockStateUpdate> for BlockStateUpdate {
    type Error = std::io::Error;

    fn try_from(update: proto::propagation::BlockStateUpdate) -> Result<Self, Self::Error> {
        Ok(Self {
            contract_diffs: update
                .contract_diffs
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| invalid_data(&format!("Error parsing contract_diffs: {}", e)))?,
            deployed_contracts: update
                .deployed_contracts
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| invalid_data(&format!("Error parsing deployed_contracts: {}", e)))?,
            declared_contract_class_hashes: parse_felt_vector(
                update.declared_contract_class_hashes,
                "declared_contract_class_hashes",
            )?,
        })
    }
}

impl From<BlockStateUpdate> for proto::propagation::BlockStateUpdate {
    fn from(update: BlockStateUpdate) -> Self {
        Self {
            request_id: 0,
            contract_diffs: update.contract_diffs.into_iter().map(Into::into).collect(),
            deployed_contracts: update
                .deployed_contracts
                .into_iter()
                .map(Into::into)
                .collect(),
            declared_contract_class_hashes: update
                .declared_contract_class_hashes
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct ContractDiff {
    pub contract_address: StarkHash,
    pub nonce: StarkHash,
    pub storage_diffs: Vec<StorageDiff>,
}

impl TryFrom<proto::propagation::block_state_update::ContractDiff> for ContractDiff {
    type Error = std::io::Error;

    fn try_from(
        diff: proto::propagation::block_state_update::ContractDiff,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            contract_address: diff
                .contract_address
                .ok_or_else(|| invalid_data("Missing contract_address field"))?
                .try_into()?,
            nonce: diff
                .nonce
                .ok_or_else(|| invalid_data("Missing nonce field"))?
                .try_into()?,
            storage_diffs: diff
                .storage_diffs
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| invalid_data(&format!("Error parsing storage diffs: {}", e)))?,
        })
    }
}

impl From<ContractDiff> for proto::propagation::block_state_update::ContractDiff {
    fn from(diff: ContractDiff) -> Self {
        Self {
            contract_address: Some(diff.contract_address.into()),
            nonce: Some(diff.nonce.into()),
            storage_diffs: diff.storage_diffs.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug)]
pub struct StorageDiff {
    pub key: StarkHash,
    pub value: StarkHash,
}

impl TryFrom<proto::propagation::block_state_update::StorageDiff> for StorageDiff {
    type Error = std::io::Error;

    fn try_from(
        diff: proto::propagation::block_state_update::StorageDiff,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            key: diff
                .key
                .ok_or_else(|| invalid_data("Missing key field"))?
                .try_into()?,
            value: diff
                .value
                .ok_or_else(|| invalid_data("Missing value field"))?
                .try_into()?,
        })
    }
}

impl From<StorageDiff> for proto::propagation::block_state_update::StorageDiff {
    fn from(diff: StorageDiff) -> Self {
        Self {
            key: Some(diff.key.into()),
            value: Some(diff.value.into()),
        }
    }
}

#[derive(Debug)]
pub struct DeployedContract {
    pub contract_address: StarkHash,
    pub contract_class_hash: StarkHash,
}

impl TryFrom<proto::propagation::block_state_update::DeployedContract> for DeployedContract {
    type Error = std::io::Error;

    fn try_from(
        deployed_contract: proto::propagation::block_state_update::DeployedContract,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            contract_address: deployed_contract
                .contract_address
                .ok_or_else(|| invalid_data("Missing contract_address field"))?
                .try_into()?,
            contract_class_hash: deployed_contract
                .contract_class_hash
                .ok_or_else(|| invalid_data("Missing contract_class_hash field"))?
                .try_into()?,
        })
    }
}

impl From<DeployedContract> for proto::propagation::block_state_update::DeployedContract {
    fn from(deployed: DeployedContract) -> Self {
        Self {
            contract_address: Some(deployed.contract_address.into()),
            contract_class_hash: Some(deployed.contract_class_hash.into()),
        }
    }
}
