#![allow(dead_code, unused_variables)]

mod tracking;

use std::ops::RangeBounds;

use anyhow::Result;
use pathfinder_common::{BlockHash, BlockNumber};

#[derive(Clone)]
pub struct BlockHeader {
    parent: BlockHash,
    hash: BlockHash,
    number: BlockNumber,
    // TODO
}

pub struct BlockBody {
    // TODO
}

pub struct StateUpdate {
    // TODO
}

/// Source of starknet block data.
#[allow(unused_variables)]
#[async_trait::async_trait]
pub trait Source: std::marker::Send + std::marker::Sync {
    async fn block_headers(
        &self,
        range: impl RangeBounds<BlockNumber> + std::marker::Send,
    ) -> Result<Vec<BlockHeader>> {
        unimplemented!();
    }

    async fn block_bodies(
        &self,
        range: impl RangeBounds<BlockNumber> + std::marker::Send,
    ) -> Result<Vec<BlockBody>> {
        unimplemented!();
    }

    async fn state_updates(
        &self,
        range: impl RangeBounds<BlockNumber> + std::marker::Send,
    ) -> Result<Vec<StateUpdate>> {
        unimplemented!();
    }
}
