/// Constants that allow us to estimate the maximum payload of certain types of messages
/// Maximum size of an encoded protobuf message in bytes
pub const MESSAGE_SIZE_LIMIT: usize = 20 * 1024 * 1024;
pub const CLASSES_MESSAGE_OVERHEAD: usize = 58;
/// Upper bound
pub const PER_CLASS_OVERHEAD: usize = 96;
/// Upper bound
pub const ENCODED_HEADER_SIZE: usize = 483;
pub const HEADERS_MESSAGE_OVERHEAD: usize = 1;
/// Lower bound
pub const MAX_HEADERS_PER_MESSAGE: usize =
    (MESSAGE_SIZE_LIMIT - HEADERS_MESSAGE_OVERHEAD + ENCODED_HEADER_SIZE) / ENCODED_HEADER_SIZE;
/// A wild guess at an upper bound to allow discarding classes that couldn't have been created by the cairo compiler
/// so must come from a faulty/malicious agent.
pub const MAX_PARTS_PER_CLASS: u32 = 10;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::block::{block_bodies_response::BodyMessage, BlockBodiesResponse};
    use crate::proto::block::{
        block_headers_response_part::HeaderMessage, BlockHeader, BlockHeadersResponse,
        BlockHeadersResponsePart,
    };
    use crate::proto::common::{Address, BlockId, Hash, Merkle, Patricia};
    use crate::proto::state::{Class, Classes};
    use prost::Message;
    use prost_types::Timestamp;

    impl Address {
        pub fn full() -> Self {
            Self {
                elements: vec![0xFF; 32],
            }
        }
    }

    impl Hash {
        pub fn full() -> Self {
            Self {
                elements: vec![0xFF; 32],
            }
        }
    }

    impl Merkle {
        pub fn full() -> Self {
            Self {
                root: Some(Hash::full()),
                n_leaves: u32::MAX,
            }
        }
    }

    impl Patricia {
        pub fn full() -> Self {
            Self {
                root: Some(Hash::full()),
                height: u32::MAX,
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn check_classes_message_overhead_upper_bound() {
        let response = |classes| BlockBodiesResponse {
            id: Some(BlockId {
                header: Some(Hash::full()),
                number: u64::MAX,
            }),
            body_message: Some(BodyMessage::Classes(Classes {
                domain: u32::MAX,
                classes,
            })),
        };
        let class = Class {
            compiled_hash: Some(Hash::full()),
            definition: vec![0xFF; MESSAGE_SIZE_LIMIT],
            total_parts: Some(u32::MAX),
            part_num: Some(u32::MAX),
            casm_hash: Some(Hash::full()),
        };
        let len = response(vec![class]).encode_length_delimited_to_vec().len();
        assert_eq!(
            len,
            CLASSES_MESSAGE_OVERHEAD + (PER_CLASS_OVERHEAD + MESSAGE_SIZE_LIMIT)
        );
    }

    #[cfg(test)]
    #[rstest::rstest]
    #[test]
    fn check_headers_message_size_upper_bound() {
        let part = BlockHeadersResponsePart {
            header_message: Some(HeaderMessage::Header(BlockHeader {
                parent_header: Some(Hash::full()),
                number: u64::MAX,
                time: Some(Timestamp {
                    seconds: i64::MAX,
                    nanos: i32::MAX,
                }),
                sequencer_address: Some(Address::full()),
                state_diffs: Some(Merkle::full()),
                state: Some(Patricia::full()),
                proof_fact: Some(Hash::full()),
                transactions: Some(Merkle::full()),
                events: Some(Merkle::full()),
                receipts: Some(Merkle::full()),
                hash: Some(Hash::full()),
                gas_price: vec![0xFF; 32],
                starknet_version: "999.999.999".into(),
                state_commitment: Some(Hash::full()),
            })),
        };
        let len = BlockHeadersResponse { part: vec![part] }
            .encode_length_delimited_to_vec()
            .len();
        assert_eq!(len, HEADERS_MESSAGE_OVERHEAD + ENCODED_HEADER_SIZE);
    }
}
