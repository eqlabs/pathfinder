use std::time::SystemTime;

use fake::{Dummy, Fake, Faker};
use tagged::Tagged;
use tagged_debug_derive::TaggedDebug;

use crate::common::{
    Address,
    BlockId,
    ConsensusSignature,
    Hash,
    Iteration,
    L1DataAvailabilityMode,
    Patricia,
    StateDiffCommitment,
};
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};

#[derive(Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, TaggedDebug)]
#[protobuf(name = "crate::proto::header::SignedBlockHeader")]
pub struct SignedBlockHeader {
    pub block_hash: Hash,
    pub parent_hash: Hash,
    pub number: u64,
    pub time: u64,
    pub sequencer_address: Address,
    pub state_root: Hash,
    pub state_diff_commitment: StateDiffCommitment,
    pub transactions: Patricia,
    pub events: Patricia,
    pub receipts: Hash,
    pub protocol_version: String,
    pub gas_price_fri: u128,
    pub gas_price_wei: u128,
    pub data_gas_price_fri: u128,
    pub data_gas_price_wei: u128,
    #[optional]
    pub l2_gas_price_fri: Option<u128>,
    #[optional]
    pub l2_gas_price_wei: Option<u128>,
    pub l1_data_availability_mode: L1DataAvailabilityMode,
    pub signatures: Vec<ConsensusSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum NewBlock {
    Id(BlockId),
    Header(BlockHeadersResponse),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::header::BlockHeadersRequest")]
pub struct BlockHeadersRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Dummy)]
pub enum BlockHeadersResponse {
    Header(Box<SignedBlockHeader>),
    #[default]
    Fin,
}

impl<T> Dummy<T> for SignedBlockHeader {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            block_hash: Faker.fake_with_rng(rng),
            time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            parent_hash: Faker.fake_with_rng(rng),
            number: Faker.fake_with_rng(rng),
            sequencer_address: Faker.fake_with_rng(rng),
            state_root: Faker.fake_with_rng(rng),
            state_diff_commitment: Faker.fake_with_rng(rng),
            transactions: Faker.fake_with_rng(rng),
            events: Faker.fake_with_rng(rng),
            receipts: Faker.fake_with_rng(rng),
            protocol_version: Faker.fake_with_rng(rng),
            gas_price_fri: Faker.fake_with_rng(rng),
            gas_price_wei: Faker.fake_with_rng(rng),
            data_gas_price_fri: Faker.fake_with_rng(rng),
            data_gas_price_wei: Faker.fake_with_rng(rng),
            l2_gas_price_fri: Faker.fake_with_rng(rng),
            l2_gas_price_wei: Faker.fake_with_rng(rng),
            l1_data_availability_mode: Faker.fake_with_rng(rng),
            signatures: Faker.fake_with_rng(rng),
        }
    }
}

impl ToProtobuf<proto::header::NewBlock> for NewBlock {
    fn to_protobuf(self) -> proto::header::NewBlock {
        use proto::header::new_block::MaybeFull::{Header, Id};
        proto::header::NewBlock {
            maybe_full: Some(match self {
                Self::Id(block_number) => Id(block_number.to_protobuf()),
                Self::Header(header) => Header(header.to_protobuf()),
            }),
        }
    }
}

impl TryFromProtobuf<proto::header::NewBlock> for NewBlock {
    fn try_from_protobuf(
        input: proto::header::NewBlock,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::header::new_block::MaybeFull::{Header, Id};
        Ok(match proto_field(input.maybe_full, field_name)? {
            Id(i) => Self::Id(TryFromProtobuf::try_from_protobuf(i, field_name)?),
            Header(h) => Self::Header(TryFromProtobuf::try_from_protobuf(h, field_name)?),
        })
    }
}

impl ToProtobuf<proto::header::BlockHeadersResponse> for BlockHeadersResponse {
    fn to_protobuf(self) -> proto::header::BlockHeadersResponse {
        use proto::header::block_headers_response::HeaderMessage::{Fin, Header};
        proto::header::BlockHeadersResponse {
            header_message: Some(match self {
                Self::Header(header) => Header(header.to_protobuf()),
                Self::Fin => Fin(proto::common::Fin {}),
            }),
        }
    }
}

impl TryFromProtobuf<proto::header::BlockHeadersResponse> for BlockHeadersResponse {
    fn try_from_protobuf(
        input: proto::header::BlockHeadersResponse,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::header::block_headers_response::HeaderMessage::{Fin, Header};
        Ok(match proto_field(input.header_message, field_name)? {
            Header(header) => Self::Header(Box::new(SignedBlockHeader::try_from_protobuf(
                header, field_name,
            )?)),
            Fin(_) => Self::Fin,
        })
    }
}
