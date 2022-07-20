use anyhow::Context;
use stark_hash::StarkHash;

fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();

    if std::env::args().count() != 2 {
        let me = std::env::args()
            .next()
            .map(std::borrow::Cow::Owned)
            .unwrap_or(std::borrow::Cow::Borrowed("me"));
        eprintln!("USAGE: {me} DATABASE_FILE");
        eprintln!("this utility will go block by block, starting from the latest block");
        eprintln!("estimating each transaction on the previous block and reporting any discrepancies with fees");
        std::process::exit(1);
    }

    let storage = pathfinder_lib::storage::Storage::migrate(
        std::env::args()
            .nth(1)
            .context("missing DATABASE_FILE argument")?
            .into(),
        pathfinder_lib::storage::JournalMode::WAL,
    )?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_io()
        .enable_time()
        .build()?;

    let (stopflag, stop_rx) = tokio::sync::oneshot::channel::<()>();

    let processes = std::num::NonZeroUsize::new(24).unwrap();

    // FIXME: with this high process count it's boring to wait for them to ramp up
    let (handle, jh) = rt.block_on(async move {
        pathfinder_lib::cairo::ext_py::start(
            std::env::args().nth(1).unwrap().into(),
            processes,
            async move {
                let _ = stop_rx.await;
            },
            pathfinder_lib::core::Chain::Mainnet,
        )
        .await
    })?;

    let (work_tx, work_rx) = tokio::sync::mpsc::channel(8);
    let (ready_tx, ready_rx) = tokio::sync::mpsc::channel(1);

    let reporter = std::thread::spawn(move || report_ready(ready_rx));
    let processor = rt.spawn(estimate(work_rx, handle, processes, ready_tx));
    feed_work(storage, work_tx)?;

    rt.block_on(async move {
        processor.await.unwrap();
        let _ = stopflag.send(());
        jh.await.unwrap();
    });

    reporter.join().unwrap();

    Ok(())
}

#[derive(Debug)]
struct Work {
    call: pathfinder_lib::rpc::types::request::Call,
    at_block: pathfinder_lib::rpc::types::BlockHashOrTag,
    gas_price: pathfinder_lib::cairo::ext_py::GasPriceSource,
    actual_fee: web3::types::H256,
    span: tracing::Span,
}

#[derive(Debug)]
struct ReadyResult {
    actual_fee: web3::types::H256,
    result: Result<
        pathfinder_lib::rpc::types::reply::FeeEstimate,
        pathfinder_lib::cairo::ext_py::CallFailure,
    >,
    span: tracing::Span,
}

fn feed_work(
    storage: pathfinder_lib::storage::Storage,
    sender: tokio::sync::mpsc::Sender<Work>,
) -> Result<(), anyhow::Error> {
    let mut connection = storage.connection()?;
    let mode = connection.query_row("PRAGMA journal_mode", [], |row| {
        Ok(row.get_ref_unwrap(0).as_str().map(|s| s.to_owned())?)
    })?;
    if mode != "wal" {
        tracing::warn!("This will lock up the database file for a long time");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    let tx = connection.transaction()?;
    let mut prep = tx.prepare(
            "select b2.hash as target_block_hash, tx.hash, tx.tx, tx.receipt, b.gas_price, b2.number, b.number
               from starknet_blocks b
               join starknet_transactions tx on (b.hash = tx.block_hash)
               join starknet_blocks b2 on (b2.number = b.number - 1)
           order by b.number desc, tx.idx asc",
        )?;

    let mut work = prep.query([])?;

    let mut last_block = None;
    let mut previously_declared_deployed_in_the_same_block = std::collections::HashSet::new();
    let mut rows = 0usize;
    let mut invokes = 0usize;
    let mut declares = 0usize;
    let mut deploys = 0usize;
    let mut same_tx_deploy_call = 0usize;

    while let Some(next) = work.next()? {
        rows += 1;

        let target_hash = StarkHash::from_be_slice(next.get_ref_unwrap(0).as_blob()?).unwrap();
        let tx_hash = StarkHash::from_be_slice(next.get_ref_unwrap(1).as_blob()?).unwrap();
        let tx = zstd::decode_all(next.get_ref_unwrap(2).as_blob()?)?;
        let receipt = zstd::decode_all(next.get_ref_unwrap(3).as_blob()?).unwrap();
        let gas_price_at_block = {
            let mut raw = [0u8; 32];
            let slice = next.get_ref_unwrap(4).as_blob()?;
            raw[32 - slice.len()..].copy_from_slice(slice);
            web3::types::H256::from(raw)
        };

        let prev_block_number = next.get_ref_unwrap(5).as_i64().unwrap() as u64;
        let block_number = next.get_ref_unwrap(6).as_i64().unwrap() as u64;

        match last_block {
            Some(x) if x != block_number => previously_declared_deployed_in_the_same_block.clear(),
            Some(_) => {}
            None => {
                last_block = Some(block_number);
            }
        }

        assert_eq!(block_number, prev_block_number + 1);

        let actual_fee = serde_json::from_slice::<SimpleReceipt>(&receipt)
            .unwrap()
            .actual_fee
            .unwrap_or(StarkHash::ZERO);

        let tx = serde_json::from_slice::<SimpleTransaction>(&tx).with_context(|| {
            let tx = String::from_utf8_lossy(&tx);
            format!("deserialize tx out of {tx_hash} {tx}")
        })?;

        let call = match tx {
            SimpleTransaction::Invoke(tx)
                if !previously_declared_deployed_in_the_same_block
                    .contains(&tx.contract_address.0) =>
            {
                tx.into()
            }
            SimpleTransaction::Invoke(SimpleInvoke {
                contract_address, ..
            }) => {
                tracing::debug!(contract_address=%contract_address.0, "same block deployed contract found");
                same_tx_deploy_call += 1;
                continue;
            }
            SimpleTransaction::Declare(_) => {
                declares += 1;
                continue;
            }
            SimpleTransaction::Deploy(SimpleDeploy { contract_address }) => {
                deploys += 1;
                previously_declared_deployed_in_the_same_block.insert(contract_address.0);
                continue;
            }
        };

        /*
        if actual_fee == StarkHash::ZERO {
            // rest will not be useful to go through
            tracing::info!("stopping scrolling since found actual_fee = 0");
            break;
        }
        */

        let actual_fee = web3::types::H256::from(actual_fee.to_be_bytes());

        invokes += 1;

        let span = tracing::info_span!("tx", %tx_hash, block_number);

        sender
            .blocking_send(Work {
                call,
                at_block: pathfinder_lib::rpc::types::BlockHashOrTag::Hash(
                    pathfinder_lib::core::StarknetBlockHash(target_hash),
                ),
                // use the b.gas_price to get as close as possible
                gas_price: pathfinder_lib::cairo::ext_py::GasPriceSource::Current(
                    gas_price_at_block,
                ),
                actual_fee,
                span,
            })
            .map_err(|_| anyhow::anyhow!("sending to processor failed"))?;
    }

    // drop work_sender to signal no more work is incoming
    drop(sender);
    tracing::info!(
        rows,
        invokes,
        declares,
        deploys,
        same_tx_deploy_call,
        "completed query"
    );
    Ok(())
}

async fn estimate(
    mut rx: tokio::sync::mpsc::Receiver<Work>,
    handle: pathfinder_lib::cairo::ext_py::Handle,
    processes: std::num::NonZeroUsize,
    ready_tx: tokio::sync::mpsc::Sender<ReadyResult>,
) {
    use futures::stream::StreamExt;
    use tracing::Instrument;

    let mut waiting = futures::stream::FuturesUnordered::new();
    let mut rx_open = true;

    loop {
        tokio::select! {
            next_work = rx.recv(), if rx_open => {
                match next_work {
                    Some(Work {call, at_block, gas_price, actual_fee, span}) => {
                        let outer = span.clone();
                        let fut = handle.estimate_fee(call, at_block, gas_price, None);
                        waiting.push(async move {
                            ReadyResult {
                                actual_fee,
                                result: fut.await,
                                span,
                            }
                        }.instrument(outer));
                    },
                    None => {
                        rx_open = false;
                    },
                }
            },
            ready = waiting.next(), if !waiting.is_empty() => {
                ready_tx.send(ready.expect("we never poll empty")).await.unwrap();
            }
            else => { break; }
        }

        // switch to polling only the waiting processes not to grow anything unboundedly
        while waiting.len() >= processes.get() {
            let ready = waiting.next().await;
            ready_tx
                .send(ready.expect("we never poll empty"))
                .await
                .unwrap();
        }
    }
}

fn report_ready(mut rx: tokio::sync::mpsc::Receiver<ReadyResult>) {
    let mut eq = 0usize;
    let mut ne = 0usize;
    let mut fail = 0usize;

    while let Some(ReadyResult {
        actual_fee,
        result,
        span,
    }) = rx.blocking_recv()
    {
        let _g = span.enter();
        match result {
            Ok(fees) if fees.fee == actual_fee => {
                eq += 1;
                tracing::info!(eq, ne, fail, "ok");
            }
            Ok(fees) => {
                ne += 1;

                let fee = web3::types::U256::from_big_endian(fees.fee.as_bytes());
                let actual_fee = web3::types::U256::from_big_endian(actual_fee.as_bytes());
                let gas_price = web3::types::U256::from_big_endian(fees.gas_price.as_bytes());

                // this hasn't yet happened that any of the numbers would be
                // even more than u64...
                let diff = if fee > actual_fee {
                    fee - actual_fee
                } else {
                    actual_fee - fee
                };
                let gas = diff
                    .checked_div(gas_price)
                    .expect("gas_price != 0 is not actually checked anywhere");

                tracing::info!(eq, ne, fail, "bad fee {diff} or {gas} gas");
            }
            Err(e) => {
                fail += 1;
                tracing::info!(eq, ne, fail, err=?e, "fail");
            }
        }
    }
}

#[derive(serde::Deserialize, Debug)]
struct SimpleReceipt {
    actual_fee: Option<StarkHash>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum SimpleTransaction {
    #[serde(rename = "DEPLOY")]
    Deploy(SimpleDeploy),
    #[serde(rename = "DECLARE")]
    Declare(SimpleDeclare),
    #[serde(rename = "INVOKE_FUNCTION")]
    Invoke(SimpleInvoke),
}

#[derive(serde::Deserialize, Debug)]
struct SimpleDeploy {
    contract_address: pathfinder_lib::core::ContractAddress,
}

#[derive(serde::Deserialize, Debug)]
struct SimpleDeclare {}

#[serde_with::serde_as]
#[derive(serde::Deserialize, Debug)]
struct SimpleInvoke {
    contract_address: pathfinder_lib::core::ContractAddress,
    #[serde_as(as = "Vec<pathfinder_lib::rpc::serde::CallParamAsDecimalStr>")]
    pub calldata: Vec<pathfinder_lib::core::CallParam>,
    pub entry_point_selector: pathfinder_lib::core::EntryPoint,
    #[serde_as(as = "Vec<pathfinder_lib::rpc::serde::TransactionSignatureElemAsDecimalStr>")]
    #[serde(default)]
    pub signature: Vec<pathfinder_lib::core::TransactionSignatureElem>,
    #[serde_as(as = "pathfinder_lib::rpc::serde::FeeAsHexStr")]
    pub max_fee: pathfinder_lib::core::Fee,
    #[serde(default)]
    #[serde_as(as = "Option<pathfinder_lib::rpc::serde::TransactionVersionAsHexStr>")]
    pub version: Option<pathfinder_lib::core::TransactionVersion>,
}

impl From<SimpleInvoke> for pathfinder_lib::rpc::types::request::Call {
    fn from(tx: SimpleInvoke) -> Self {
        pathfinder_lib::rpc::types::request::Call {
            contract_address: tx.contract_address,
            calldata: tx.calldata,
            entry_point_selector: tx.entry_point_selector,
            signature: tx
                .signature
                .into_iter()
                .map(|x| pathfinder_lib::core::CallSignatureElem(x.0))
                .collect(),
            max_fee: tx.max_fee,
            version: tx
                .version
                .unwrap_or(pathfinder_lib::rpc::types::request::Call::DEFAULT_VERSION),
        }
    }
}
