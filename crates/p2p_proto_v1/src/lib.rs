#[allow(clippy::module_inception)]
pub mod proto {
    #[allow(clippy::large_enum_variant)]
    pub mod block {
        include!(concat!(env!("OUT_DIR"), "/starknet.block.rs"));
    }
    pub mod common {
        include!(concat!(env!("OUT_DIR"), "/starknet.common.rs"));
    }
    pub mod event {
        include!(concat!(env!("OUT_DIR"), "/starknet.event.rs"));
    }
    pub mod mempool {
        include!(concat!(env!("OUT_DIR"), "/starknet.mempool.rs"));
    }
    pub mod receipt {
        include!(concat!(env!("OUT_DIR"), "/starknet.receipt.rs"));
    }
    pub mod snapshot {
        include!(concat!(env!("OUT_DIR"), "/starknet.snapshot.rs"));
    }
    pub mod state {
        include!(concat!(env!("OUT_DIR"), "/starknet.state.rs"));
    }
    pub mod transaction {
        include!(concat!(env!("OUT_DIR"), "/starknet.transaction.rs"));
    }
}

pub trait ToProtobuf<Output>
where
    Self: Sized,
{
    fn to_protobuf(self) -> Output;
}

impl ToProtobuf<u64> for u64 {
    fn to_protobuf(self) -> u64 {
        self
    }
}

impl ToProtobuf<u32> for u32 {
    fn to_protobuf(self) -> u32 {
        self
    }
}

impl ToProtobuf<u8> for u8 {
    fn to_protobuf(self) -> u8 {
        self
    }
}

impl ToProtobuf<String> for String {
    fn to_protobuf(self) -> String {
        self
    }
}

impl<M, T: ToProtobuf<M>> ToProtobuf<Vec<M>> for Vec<T> {
    fn to_protobuf(self) -> Vec<M> {
        self.into_iter().map(ToProtobuf::to_protobuf).collect()
    }
}

impl<M, T: ToProtobuf<M>> ToProtobuf<Option<M>> for Option<T> {
    fn to_protobuf(self) -> Option<M> {
        self.map(ToProtobuf::to_protobuf)
    }
}

pub trait TryFromProtobuf<M>
where
    Self: Sized,
{
    fn try_from_protobuf(input: M, field_name: &'static str) -> Result<Self, std::io::Error>;
}

impl TryFromProtobuf<u64> for u64 {
    fn try_from_protobuf(input: u64, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<u32> for u32 {
    fn try_from_protobuf(input: u32, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<u8> for u8 {
    fn try_from_protobuf(input: u8, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<String> for String {
    fn try_from_protobuf(input: String, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl<T: TryFromProtobuf<U>, U> TryFromProtobuf<Option<U>> for T {
    fn try_from_protobuf(
        input: Option<U>,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        let input = input.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing field {field_name}"),
            )
        })?;
        TryFromProtobuf::try_from_protobuf(input, field_name)
    }
}

impl<T: TryFromProtobuf<U>, U> TryFromProtobuf<Vec<U>> for Vec<T> {
    fn try_from_protobuf(input: Vec<U>, field_name: &'static str) -> Result<Self, std::io::Error> {
        input
            .into_iter()
            .map(|e| TryFromProtobuf::try_from_protobuf(e, field_name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse {field_name}: {e}"),
                )
            })
    }
}

use p2p_proto_derive::*;
pub mod block;
pub mod common;
pub mod event;
pub mod mempool;
pub mod receipt;
pub mod snapshot;
pub mod state;
pub mod transaction;

// Trying to estimate the overhead of the classes message so that we know what is the limit
// on compressed class definition size, varint delimiting of the message is taken into account
//
// 0 classes == 22 bytes
// 1 x 1MiB class == 82 bytes; 60 bytes/class
// 3 x 1MiB class == 196 bytes; 58 bytes/class
// 10 x 1MiB class == 588 bytes; 59 bytes/class
//
// It's generally safe to assume:
// N classes == 22 + 60 * N bytes
#[cfg(test)]
#[rstest::rstest]
#[test]
fn check_classes_message_overhead(
    #[values((0, 22), (1, 82), (3, 196), (10, 588))] num_classes_expected_overhead: (usize, usize),
) {
    let (num_classes, expected_overhead) = num_classes_expected_overhead;
    use crate::proto::block::{block_bodies_response::BlockPart, BlockBodiesResponse};
    use crate::proto::common::{BlockId, Hash};
    use crate::proto::state::{Class, Classes};
    use prost::Message;
    const _1MIB: usize = 1024 * 1024;
    let response = |classes| BlockBodiesResponse {
        id: Some(BlockId { height: u64::MAX }),
        block_part: Some(BlockPart::Classes(Classes {
            tree_id: u32::MAX,
            classes,
        })),
    };
    let class = Class {
        compiled_hash: Some(Hash {
            elements: vec![0xFF; 32],
        }),
        definition: vec![0xFF; _1MIB],
        total_chunks: Some(u32::MAX),
        chunk_count: Some(u32::MAX),
    };
    let len = response(vec![class; num_classes])
        .encode_length_delimited_to_vec()
        .len();
    assert_eq!(len - (num_classes * _1MIB), expected_overhead);
}
