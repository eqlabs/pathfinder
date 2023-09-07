//! Sync related data retrieval from storage as requested by other p2p clients
use super::conv::ToProto;
use anyhow::Context;
use p2p_proto_v1::block::{
    BlockBodiesResponse, BlockBodiesResponsePart, BlockHeadersResponse, BlockHeadersResponsePart,
    GetBlockBodies, GetBlockHeaders,
};
use p2p_proto_v1::common::{BlockId, Hash};
use pathfinder_common::{BlockNumber, ClassHash};
use pathfinder_storage::{Storage, Transaction};

pub mod v0;
pub mod v1;
