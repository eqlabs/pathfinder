#![deny(rust_2018_idioms)]

pub mod config;
pub mod consensus;
pub mod monitoring;
pub mod p2p_network;
pub mod state;
pub mod sync;
pub mod validator;

pub enum SyncMessageToConsensus {
    /// Ask consensus for the finalized block with given number.
    GetFinalizedBlock {
        number: pathfinder_common::BlockNumber,
        reply: FinalizedBlockReply,
    },
    /// Notify consensus that a finalized block has been committed to storage.
    ConfirmFinalizedBlockCommitted {
        number: pathfinder_common::BlockNumber,
    },
    ValidateBlock {
        // TODO: Stubbed for now, as an example. When used by P2P sync it should contain the block
        // commit certificate. Also, since this is never sent, the result is not used. In the
        // future, the result is used to update peer scoring and is also updating the tip of the
        // chain state for sync.
        block: std::sync::Arc<pathfinder_common::L2Block>,
        reply: ValidateBlockReply,
    },
}

pub type FinalizedBlockReply =
    tokio::sync::oneshot::Sender<Option<std::sync::Arc<pathfinder_common::L2Block>>>;

pub type ValidateBlockReply = tokio::sync::oneshot::Sender<validator::ValidationResult>;
