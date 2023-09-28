#[allow(clippy::module_inception)]
pub mod proto {
    #[allow(clippy::large_enum_variant)]
    pub mod block {
        include!(concat!(env!("OUT_DIR"), "/starknet.block.rs"));
    }
    pub mod common {
        include!(concat!(env!("OUT_DIR"), "/starknet.common.rs"));
    }
    pub mod consensus {
        include!(concat!(env!("OUT_DIR"), "/starknet.consensus.rs"));
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

impl ToProtobuf<i32> for i32 {
    fn to_protobuf(self) -> i32 {
        self
    }
}

impl ToProtobuf<bool> for bool {
    fn to_protobuf(self) -> bool {
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

impl TryFromProtobuf<i32> for i32 {
    fn try_from_protobuf(input: i32, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<u8> for u8 {
    fn try_from_protobuf(input: u8, _field_name: &'static str) -> Result<Self, std::io::Error> {
        Ok(input)
    }
}

impl TryFromProtobuf<bool> for bool {
    fn try_from_protobuf(input: bool, _field_name: &'static str) -> Result<Self, std::io::Error> {
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
pub mod consensus;
pub mod event;
pub mod mempool;
pub mod receipt;
pub mod snapshot;
pub mod state;
pub mod transaction;

/// Constants that allow us to estimate the maximum payload of a class definition message
/// see the test below for more details
pub const PER_MESSAGE_OVERHEAD: usize = 58;
pub const PER_CLASS_OVERHEAD: usize = 60;
pub const MESSAGE_SIZE_LIMIT: usize = 1024 * 1024;

/// Trying to estimate the overhead of the classes message so that we know what is the limit
/// on compressed class definition size, varint delimiting of the message is taken into account
///
/// 0 classes == 58 bytes
/// 1 x 1MiB class == 118 bytes; 60 bytes/class
/// 3 x 1MiB class == 232 bytes; 58 bytes/class
/// 10 x 1MiB class == 624 bytes; 57 bytes/class
///
/// It's generally safe to assume:
/// N classes == 58 + 60 * N bytes
#[cfg(test)]
#[rstest::rstest]
#[test]
fn check_classes_message_overhead(
    #[values((0, 58), (1, 118), (3, 232), (10, 624))] num_classes_expected_overhead: (usize, usize),
) {
    let (num_classes, expected_overhead) = num_classes_expected_overhead;
    use crate::proto::block::{block_bodies_response::BodyMessage, BlockBodiesResponse};
    use crate::proto::common::{BlockId, Hash};
    use crate::proto::state::{Class, Classes};
    use prost::Message;
    let response = |classes| BlockBodiesResponse {
        id: Some(BlockId {
            header: Some(Hash {
                elements: vec![0xFF; 32],
            }),
            number: u64::MAX,
        }),
        body_message: Some(BodyMessage::Classes(Classes {
            domain: u32::MAX,
            classes,
        })),
    };
    let class = Class {
        compiled_hash: Some(Hash {
            elements: vec![0xFF; 32],
        }),
        definition: vec![0xFF; MESSAGE_SIZE_LIMIT],
        total_parts: Some(u32::MAX),
        part_num: Some(u32::MAX),
    };
    let len = response(vec![class; num_classes])
        .encode_length_delimited_to_vec()
        .len();
    assert_eq!(len - (num_classes * MESSAGE_SIZE_LIMIT), expected_overhead);
}

pub const ENCODED_HEADER_SIZE: usize = 447;
pub const HEADERS_MESSAGE_OVERHEAD: usize = 1;

pub const MAX_HEADERS_PER_MESSAGE: usize =
    (MESSAGE_SIZE_LIMIT - HEADERS_MESSAGE_OVERHEAD + ENCODED_HEADER_SIZE) / ENCODED_HEADER_SIZE;

/// 0 hdrs == 1 byte
/// 1 hdr  == 448 bytes; 447 bytes/header
/// 3 hdrs == 1340 bytes; 447 bytes/header
/// 10 hdrs == 4462 bytes; 447 bytes/class
/// 100 hdrs == 44603 bytes; 447 bytes/class
/// 1000 hdrs == 446003 bytes; 447 bytes/class
///
/// It's generally safe to assume:
/// N headers == 1 + 447 * N bytes
#[cfg(test)]
#[rstest::rstest]
#[test]
fn check_headers_message_size_upper_bound(
    #[values((0, 1), (1, 448), (3, 1340), (10, 4462), (100, 44603), (1000, 446003), (10000, 4460004))]
    num_headers_expected_overhead: (usize, usize),
) {
    let (num_headers, expected_overhead) = num_headers_expected_overhead;
    use std::vec;

    use crate::proto::block::{
        block_headers_response_part::HeaderMessage, BlockHeader, BlockHeadersResponse,
        BlockHeadersResponsePart,
    };
    use crate::proto::common::{Address, Hash, Patricia};
    use prost::Message;
    use prost_types::Timestamp;
    use proto::common::Merkle;
    let a = || {
        Some(Address {
            elements: vec![0xFF; 32],
        })
    };
    let h = || {
        Some(Hash {
            elements: vec![0xFF; 32],
        })
    };
    let m = || {
        Some(Merkle {
            n_leaves: u32::MAX,
            root: h(),
        })
    };
    let p = || {
        Some(Patricia {
            height: u32::MAX,
            root: h(),
        })
    };
    let part = BlockHeadersResponsePart {
        header_message: Some(HeaderMessage::Header(BlockHeader {
            parent_header: h(),
            number: u64::MAX,
            time: Some(Timestamp {
                seconds: i64::MAX,
                nanos: i32::MAX,
            }),
            sequencer_address: a(),
            state_diffs: m(),
            state: p(),
            proof_fact: h(),
            transactions: m(),
            events: m(),
            receipts: m(),
            block_hash: h(),
            gas_price: vec![0xFF; 32],
            starknet_version: "999.999.999".into(),
        })),
    };
    let len = BlockHeadersResponse {
        part: vec![part; num_headers],
    }
    .encode_length_delimited_to_vec()
    .len();
    eprintln!("len: {}", len);
    assert_eq!(len, expected_overhead);
}

#[cfg(test)]
#[rstest::rstest]
#[test]
fn check_headers_message_size_lower_bound(
    #[values((0, 1), (1, 75), (3, 224), (10, 742), (100, 7402), (1000, 74003), (10000, 740003))]
    num_headers_expected_overhead: (usize, usize),
) {
    let (num_headers, expected_overhead) = num_headers_expected_overhead;
    use std::vec;

    use crate::proto::block::{
        block_headers_response_part::HeaderMessage, BlockHeader, BlockHeadersResponse,
        BlockHeadersResponsePart,
    };
    use crate::proto::common::{Address, Hash, Patricia};
    use prost::Message;
    use prost_types::Timestamp;
    use proto::common::Merkle;
    let a = || {
        Some(Address {
            elements: vec![0x1; 1],
        })
    };
    let h = || {
        Some(Hash {
            elements: vec![0xFF; 1],
        })
    };
    let m = || {
        Some(Merkle {
            n_leaves: 64,
            root: h(),
        })
    };
    let p = || {
        Some(Patricia {
            height: 64,
            root: h(),
        })
    };
    let part = BlockHeadersResponsePart {
        header_message: Some(HeaderMessage::Header(BlockHeader {
            parent_header: h(),
            number: 0,
            time: Some(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
            sequencer_address: a(),
            state_diffs: m(),
            state: p(),
            proof_fact: h(),
            transactions: m(),
            events: m(),
            receipts: m(),
            block_hash: h(),
            gas_price: vec![1; 1],
            starknet_version: Default::default(),
        })),
    };
    let len = BlockHeadersResponse {
        part: vec![part; num_headers],
    }
    .encode_length_delimited_to_vec()
    .len();
    eprintln!("len: {}", len);
    assert_eq!(len, expected_overhead);
}
