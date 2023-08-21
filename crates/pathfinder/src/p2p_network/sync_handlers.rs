//! Sync related data retrieval from storage as requested by other p2p clients

use anyhow::Context;
use pathfinder_storage::{Storage, Transaction};

pub mod v0;

const MAX_BLOCKS_COUNT: u64 = 100;

pub enum GetBlocksReply {
    Header(p2p_proto::block::BlockHeader),
    StateDiff(p2p_proto::state::StateDiff),
}

type GetBlocksReplyTx = tokio::sync::mpsc::Sender<GetBlocksReply>;
type GetBlocksReplyRx = tokio::sync::mpsc::Receiver<GetBlocksReply>;

pub async fn get_blocks(
    request: p2p_proto::block::GetBlocks,
    storage: &Storage,
    reply_tx: GetBlocksReplyTx,
) -> anyhow::Result<()> {
    // TODO check if there are faster ways to do this
    // for example retrieve data in batches instead of one by one
    todo!("retrieve one item, push into channel, repeat; max msg limit is maintained")
}

async fn spawn_blocking_get<Request, Response, Getter>(
    request: Request,
    storage: &Storage,
    getter: Getter,
) -> anyhow::Result<Response>
where
    Request: Send + 'static,
    Response: Send + 'static,
    Getter: FnOnce(Transaction<'_>, Request) -> anyhow::Result<Response> + Send + 'static,
{
    let storage = storage.clone();
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;
        let tx = connection
            .transaction()
            .context("Creating database transaction")?;
        getter(tx, request)
    })
    .await
    .context("Database read panic or shutting down")?
}

fn block_header(tx: Transaction<'_>, id: ()) -> anyhow::Result<p2p_proto::block::BlockHeader> {
    todo!()
}

fn state_diff(tx: Transaction<'_>, id: ()) -> anyhow::Result<p2p_proto::state::StateDiff> {
    todo!()
}
