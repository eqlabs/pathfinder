use std::{sync::Arc, time::Duration};

use futures::Future;
use pathfinder_ethereum::L1StateUpdate;
use pathfinder_rpc::v02::types::syncing;
use rusqlite::Transaction;
use starknet_gateway_types::reply::Block;
use tokio::sync::{mpsc, Mutex, Notify};

use pathfinder_common::{BlockId, Chain, StarknetBlockHash, StarknetBlockNumber, StateCommitment};
use pathfinder_ethereum::{EthereumClientApi, StarknetEthereumClient};
use pathfinder_rpc::SyncState;
use pathfinder_storage::{StarknetBlocksTable, Storage};
use starknet_gateway_client::ClientApi;
use starknet_gateway_types::error::StarknetErrorCode::BlockNotFound;
use starknet_gateway_types::{error::SequencerError, reply::MaybePendingBlock};

#[cfg(test)]
pub mod ex {
    use pathfinder_common::EthereumAddress;
    use pathfinder_ethereum::{core_contract, EthereumClient};
    use primitive_types::H160;
    use starknet_gateway_client::Client;

    use super::*;

    const ETH_URL: &str = "https://eth.llamarpc.com";
    const SEQ_URL: &str = "https://alpha-mainnet.starknet.io/gateway";

    // TODO(SM): remove
    // cargo test --package pathfinder --lib -- state::source::ex::example --exact --nocapture
    #[tokio::test]
    async fn example() -> anyhow::Result<()> {
        let eth = StarknetEthereumClient::new(
            EthereumClient::new(ETH_URL.parse().expect("url")),
            EthereumAddress(H160::from_slice(&core_contract::MAINNET)),
        );

        let seq = Client::with_base_url(SEQ_URL.parse().expect("url"))?;

        let sync = Arc::new(SyncState::default());
        let chain = Chain::Mainnet;
        let storage = Storage::in_memory()?;

        let ctx = SyncContext::new(eth, seq, chain, sync, storage);

        let poll = Duration::from_secs(30) / 10;
        let src = Source::new(ctx);
        src.add("L1", poll_l1, poll).await;
        src.add("L2", poll_l2, poll).await;
        src.add("sync", poll_status, poll).await;
        // TODO(SM): add "pending"
        let mut src = src.run();

        while let Some(event) = src.get().await {
            println!("{event:?}");
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Head {
    pub block_number: StarknetBlockNumber,
    pub block_hash: StarknetBlockHash,
    pub state_commitment: StateCommitment,
}

pub struct SyncContext<ETH, SEQ>
where
    ETH: EthereumClientApi + Send + Sync + 'static,
    SEQ: ClientApi + Send + Sync + 'static,
{
    eth: ETH,
    seq: SEQ,
    head: Option<Head>,
    sync: Arc<SyncState>,
    chain: Chain,
    storage: Storage,
}

impl<ETH, SEQ> SyncContext<ETH, SEQ>
where
    ETH: EthereumClientApi + Send + Sync + 'static,
    SEQ: ClientApi + Send + Sync + 'static,
{
    pub fn new(eth: ETH, seq: SEQ, chain: Chain, sync: Arc<SyncState>, storage: Storage) -> Self {
        Self {
            eth,
            seq,
            sync,
            head: None,
            chain,
            storage,
        }
    }

    pub async fn db<R, F>(&self, f: F) -> anyhow::Result<R>
    where
        R: Send + 'static,
        F: (FnOnce(Transaction<'_>) -> anyhow::Result<R>) + Send + 'static,
    {
        let mut db = self.storage.connection()?;
        tokio::task::spawn_blocking(move || {
            let tx = db.transaction()?;
            f(tx)
        })
        .await?
    }
}

async fn poll_l1(
    ctx: Arc<Mutex<SyncContext<StarknetEthereumClient, starknet_gateway_client::Client>>>,
) -> anyhow::Result<Option<Event>> {
    let state = {
        let eth = &ctx.lock().await.eth;
        eth.get_starknet_state().await?
    };
    Ok(Some(Event::L1(state)))
}

async fn poll_l2(
    ctx: Arc<Mutex<SyncContext<StarknetEthereumClient, starknet_gateway_client::Client>>>,
) -> anyhow::Result<Option<Event>> {
    let head = ctx.lock().await.head;
    let next = head
        .map(|head| head.block_number + 1)
        .unwrap_or(StarknetBlockNumber::GENESIS);

    let block_result = {
        let seq = &ctx.lock().await.seq;
        seq.block(BlockId::Number(next)).await
    };

    let block = match block_result {
        Ok(MaybePendingBlock::Block(block)) => block,
        Ok(MaybePendingBlock::Pending(_)) => {
            anyhow::bail!("Received 'pending' block");
        }
        Err(SequencerError::StarknetError(e)) if e.code == BlockNotFound => {
            return Ok(head.map(|head| Event::L2(l2::Event::Head(head))))
        }
        Err(e) => {
            tracing::warn!(error=?e, "Sequencer request failed");
            return Ok(None);
        }
    };

    Ok(Some(Event::L2(l2::Event::Block(block))))
}

async fn poll_status(
    ctx: Arc<Mutex<SyncContext<StarknetEthereumClient, starknet_gateway_client::Client>>>,
) -> anyhow::Result<Option<Event>> {
    let latest = {
        let seq = &ctx.lock().await.seq;
        seq.block(BlockId::Latest).await?
    };
    let latest = match latest {
        MaybePendingBlock::Block(block) => {
            syncing::NumberedBlock::from((block.block_hash, block.block_number))
        }
        _ => return Ok(None),
    };

    let current = {
        let ctx = ctx.lock().await;
        ctx.db(|tx| {
            Ok(StarknetBlocksTable::get_latest_hash_and_number(&tx)?
                .map(syncing::NumberedBlock::from))
        })
        .await?
    };
    let current = match current {
        Some(block) => block,
        // _ => return Ok(None), // TODO(SM): restore
        _ => syncing::NumberedBlock::from((
            StarknetBlockHash(stark_hash::Felt::ZERO),
            StarknetBlockNumber::GENESIS,
        )),
    };

    Ok(Some(Event::Sync(syncing::Syncing::Status(
        syncing::Status {
            starting: current,
            current,
            highest: latest,
        },
    ))))
}

// TODO(SM): split `sync` into event producer (stream?) and consumer (.reduce on stream?)

mod l2 {

    #[derive(Debug)]
    pub enum Event {
        // handle: check commitments, resolve state, download classes, etc
        Block(super::Block),

        // handle: check if 'latest' matches current head, do a reorg if not
        Head(super::Head),
    }
}

#[derive(Debug)]
enum Event {
    Sync(syncing::Syncing),
    L1(L1StateUpdate),
    L2(l2::Event),
    // Pending(...)
}

pub struct Source<T, C> {
    tx: mpsc::Sender<T>,
    rx: mpsc::Receiver<T>,
    go: Arc<Notify>,
    ctx: Arc<Mutex<C>>,
}

impl<T: Send + 'static, C: Send + 'static> Source<T, C> {
    pub fn new(ctx: C) -> Self {
        let (tx, rx) = mpsc::channel(32);
        let go = Arc::new(Notify::new());
        let ctx = Arc::new(Mutex::new(ctx));
        Self { tx, rx, go, ctx }
    }

    pub async fn add<F, G>(&self, name: &str, f: F, poll: Duration)
    where
        F: (Fn(Arc<Mutex<C>>) -> G) + Send + 'static,
        G: Future<Output = anyhow::Result<Option<T>>> + Send,
    {
        let name = name.to_owned();
        let is_ready = Arc::new(Notify::new());

        let tx = self.tx.clone();
        let go = self.go.clone();
        let ctx = self.ctx.clone();
        let ready = is_ready.clone();
        tokio::spawn(async move {
            ready.notify_one();
            go.notified().await;
            while !tx.is_closed() {
                let r = f(ctx.clone());
                let r = r.await;
                match r {
                    Ok(Some(x)) => {
                        let r = tx.send(x).await;
                        if r.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(name=name, reason=?e, "Poll failed");
                    }
                    _ => (),
                }
                tokio::time::sleep(poll).await;
            }
        });
        is_ready.notified().await
    }

    pub fn run(self) -> Self {
        self.go.notify_waiters();
        self
    }

    pub fn stop(&mut self) {
        self.rx.close()
    }

    pub async fn get(&mut self) -> Option<T> {
        self.rx.recv().await
    }
}
