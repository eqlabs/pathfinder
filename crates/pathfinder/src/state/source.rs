use std::sync::Arc;

use futures::Future;
use pathfinder_ethereum::L1StateUpdate;
use pathfinder_rpc::v02::types::syncing;
use tokio::sync::{mpsc, Mutex, Notify};

use super::l2;

mod ex {
    use pathfinder_common::{
        Chain, EthereumAddress, StarknetBlockHash, StarknetBlockNumber, StateCommitment,
    };
    use pathfinder_ethereum::{EthereumClient, EthereumClientApi, StarknetEthereumClient};
    use pathfinder_rpc::SyncState;
    use pathfinder_storage::{RefsTable, Storage};
    use primitive_types::H160;
    use starknet_gateway_client::ClientApi;

    use super::*;

    pub struct SyncContext<ETH, SEQ>
    where
        ETH: EthereumClientApi + Send + Sync + 'static,
        SEQ: ClientApi + Send + Sync + 'static,
    {
        eth: ETH,
        seq: SEQ,
        head: Option<(StarknetBlockNumber, StarknetBlockHash, StateCommitment)>,
        sync: Arc<SyncState>,
        chain: Chain,
        storage: Storage,
    }

    impl<ETH, SEQ> SyncContext<ETH, SEQ>
    where
        ETH: EthereumClientApi + Send + Sync + 'static,
        SEQ: ClientApi + Send + Sync + 'static,
    {
        pub fn new(
            eth: ETH,
            seq: SEQ,
            chain: Chain,
            sync: Arc<SyncState>,
            storage: Storage,
        ) -> Self {
            Self {
                eth,
                seq,
                sync,
                head: None,
                chain,
                storage,
            }
        }
    }

    async fn sync_l1(
        ctx: Arc<Mutex<SyncContext<StarknetEthereumClient, starknet_gateway_client::Client>>>,
    ) -> anyhow::Result<Option<Event>> {
        let state = {
            let eth = &ctx.lock().await.eth;
            eth.get_starknet_state().await?
        };

        let head = {
            let storage = &ctx.lock().await.storage;
            tokio::task::block_in_place(move || {
                let mut db = storage.connection()?;
                let tx = db.transaction()?;
                RefsTable::get_l1_l2_head(&tx)
            })?
        }
        .map(|block| block.0)
        .unwrap_or_default();

        Ok(if state.block_number > head {
            Some(Event::L1(state))
        } else {
            None
        })
    }

    async fn sync_l2(
        _ctx: Arc<Mutex<SyncContext<StarknetEthereumClient, starknet_gateway_client::Client>>>,
    ) -> anyhow::Result<Option<Event>> {
        Ok(None)
    }

    async fn sync_status(
        _ctx: Arc<Mutex<SyncContext<StarknetEthereumClient, starknet_gateway_client::Client>>>,
    ) -> anyhow::Result<Option<Event>> {
        Ok(None)
    }

    async fn run() -> anyhow::Result<()> {
        let url: reqwest::Url = "127.0.0.1:3000".parse().expect("url");
        let eth = StarknetEthereumClient::new(
            EthereumClient::new(url.clone()),
            EthereumAddress(H160::zero()),
        );
        let seq = starknet_gateway_client::Client::with_base_url(url)?;
        let chain = Chain::Mainnet;
        let sync = Arc::new(SyncState::default());
        let storage = Storage::in_memory()?;

        let ctx = SyncContext::new(eth, seq, chain, sync, storage);

        let mut src = Source::new(ctx)
            .add(sync_l1)
            .add(sync_l2)
            .add(sync_status)
            .run();

        while let Some(x) = src.get().await {
            println!("{x:?}");
        }

        Ok(())
    }
}

// TODO(SM): split `sync` into event producer (stream?) and consumer (.reduce on stream?)

#[derive(Debug)]
enum Event {
    L1(L1StateUpdate),
    L2(l2::Event),
    Sync(syncing::Status),
    // P2P(...)
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

    pub fn add<F, G>(self, f: F) -> Self
    where
        F: (Fn(Arc<Mutex<C>>) -> G) + Send + 'static,
        G: Future<Output = anyhow::Result<Option<T>>> + Send,
    {
        let tx = self.tx.clone();
        let go = self.go.clone();
        let ctx = self.ctx.clone();
        tokio::spawn(async move {
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
                    Ok(None) => {
                        // TODO(SM): success-retry delay
                    }
                    Err(_e) => {
                        // TODO(SM): failure-retry delay
                        continue;
                    }
                }
            }
        });
        self
    }

    fn run(self) -> Self {
        self.go.notify_waiters();
        self
    }

    async fn get(&mut self) -> Option<T> {
        self.rx.recv().await
    }
}
