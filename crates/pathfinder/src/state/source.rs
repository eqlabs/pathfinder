use std::{sync::Arc, time::Duration};

use futures::Future;
use pathfinder_ethereum::L1StateUpdate;
use pathfinder_rpc::v02::types::syncing;
use tokio::sync::{mpsc, Mutex, Notify};

use super::l2;

#[cfg(test)]
mod ex {
    use pathfinder_common::{
        BlockId, Chain, EthereumAddress, StarknetBlockHash, StarknetBlockNumber, StateCommitment,
    };
    use pathfinder_ethereum::{
        core_contract, EthereumClient, EthereumClientApi, StarknetEthereumClient,
    };
    use pathfinder_rpc::SyncState;
    use pathfinder_storage::{StarknetBlocksTable, Storage};
    use primitive_types::H160;
    use starknet_gateway_client::{Client, ClientApi};
    use starknet_gateway_types::reply::MaybePendingBlock;

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
        _ctx: Arc<Mutex<SyncContext<StarknetEthereumClient, starknet_gateway_client::Client>>>,
    ) -> anyhow::Result<Option<Event>> {
        // TODO(SM): impl L2
        Ok(None)
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
            let db = &mut ctx.lock().await.storage.connection()?;
            let tx = db.transaction()?;
            StarknetBlocksTable::get_latest_hash_and_number(&tx)?
                .map(|(hash, num)| syncing::NumberedBlock::from((hash, num)))
        };
        let current = match current {
            Some(block) => block,
            // _ => return Ok(None), // TODO(SM): restore
            _ => syncing::NumberedBlock::from((
                StarknetBlockHash(stark_hash::Felt::ZERO),
                StarknetBlockNumber(42),
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
        //src.add("L2", poll_l2, poll).await;
        src.add("sync", poll_status, poll).await;
        let mut src = src.run();

        while let Some(event) = src.get().await {
            println!("{event:?}");
        }

        Ok(())
    }
}

// TODO(SM): split `sync` into event producer (stream?) and consumer (.reduce on stream?)

#[derive(Debug)]
enum Event {
    L1(L1StateUpdate),
    L2(l2::Event),
    Sync(syncing::Syncing),
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
