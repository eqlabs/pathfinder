#![deny(rust_2018_idioms)]

pub mod config;
pub mod consensus;
pub mod monitoring;
pub mod p2p_network;
pub mod state;
pub mod sync;
pub mod validator;

pub enum SyncMessageToConsensus {
    /// Ask consensus for the finalized and decided upon block with given
    /// number. The only difference from a committed block is that the state
    /// tries are not updated yet, so the state commitment is not computed
    /// and hence the block hash cannot be computed yet.
    GetConsensusFinalizedBlock {
        number: pathfinder_common::BlockNumber,
        reply: ConsensusFinalizedBlockReply,
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

pub type ConsensusFinalizedBlockReply =
    tokio::sync::oneshot::Sender<Option<Box<pathfinder_common::ConsensusFinalizedL2Block>>>;

pub type ValidateBlockReply = tokio::sync::oneshot::Sender<validator::ValidationResult>;
