use anyhow::Context;
use stark_hash::Felt;

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

    let storage = pathfinder_storage::Storage::migrate(
        std::env::args()
            .nth(1)
            .context("missing DATABASE_FILE argument")?
            .into(),
        pathfinder_storage::JournalMode::WAL,
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
        pathfinder_rpc::cairo::ext_py::start(
            std::env::args().nth(1).unwrap().into(),
            processes,
            async move {
                let _ = stop_rx.await;
            },
            pathfinder_common::Chain::Mainnet,
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
    transaction: pathfinder_rpc::v02::types::request::BroadcastedTransaction,
    at_block: pathfinder_common::StarknetBlockHash,
    gas_price: pathfinder_rpc::cairo::ext_py::GasPriceSource,
    actual_fee: ethers::types::H256,
    span: tracing::Span,
}

#[derive(Debug)]
struct ReadyResult {
    actual_fee: ethers::types::H256,
    result: Result<
        pathfinder_rpc::v02::types::reply::FeeEstimate,
        pathfinder_rpc::cairo::ext_py::CallFailure,
    >,
    span: tracing::Span,
}

fn feed_work(
    storage: pathfinder_storage::Storage,
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
    let mut l1_handlers = 0usize;
    let mut same_tx_deploy_call = 0usize;

    while let Some(next) = work.next()? {
        rows += 1;

        let target_hash = Felt::from_be_slice(next.get_ref_unwrap(0).as_blob()?).unwrap();
        let tx_hash = Felt::from_be_slice(next.get_ref_unwrap(1).as_blob()?).unwrap();
        let tx = zstd::decode_all(next.get_ref_unwrap(2).as_blob()?)?;
        let receipt = zstd::decode_all(next.get_ref_unwrap(3).as_blob()?).unwrap();
        let gas_price_at_block = {
            let mut raw = [0u8; 32];
            let slice = next.get_ref_unwrap(4).as_blob()?;
            raw[32 - slice.len()..].copy_from_slice(slice);
            ethers::types::H256::from(raw)
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
            .unwrap_or(Felt::ZERO);

        let tx = serde_json::from_slice::<SimpleTransaction>(&tx).with_context(|| {
            let tx = String::from_utf8_lossy(&tx);
            format!("deserialize tx out of {tx_hash} {tx}")
        })?;

        let transaction = match tx {
            SimpleTransaction::Invoke(tx)
                if !previously_declared_deployed_in_the_same_block
                    .contains(tx.contract_address.get()) =>
            {
                tx.into()
            }
            SimpleTransaction::Invoke(SimpleInvoke {
                contract_address, ..
            }) => {
                tracing::debug!(contract_address=%contract_address.get(), "same block deployed contract found");
                same_tx_deploy_call += 1;
                continue;
            }
            SimpleTransaction::Declare(_) => {
                declares += 1;
                continue;
            }
            SimpleTransaction::Deploy(tx) => {
                deploys += 1;
                previously_declared_deployed_in_the_same_block.insert(*tx.contract_address.get());
                continue;
            }
            SimpleTransaction::DeployAccount(tx) => tx.into(),
            SimpleTransaction::L1Handler(_) => {
                l1_handlers += 1;
                continue;
            }
        };

        /*
        if actual_fee == Felt::ZERO {
            // rest will not be useful to go through
            tracing::info!("stopping scrolling since found actual_fee = 0");
            break;
        }
        */

        let actual_fee = ethers::types::H256::from(actual_fee.to_be_bytes());

        invokes += 1;

        let span = tracing::info_span!("tx", %tx_hash, block_number);

        sender
            .blocking_send(Work {
                transaction,
                at_block: pathfinder_common::StarknetBlockHash(target_hash),
                // use the b.gas_price to get as close as possible
                gas_price: pathfinder_rpc::cairo::ext_py::GasPriceSource::Current(
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
        l1_handlers,
        "completed query"
    );
    Ok(())
}

async fn estimate(
    mut rx: tokio::sync::mpsc::Receiver<Work>,
    handle: pathfinder_rpc::cairo::ext_py::Handle,
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
                    Some(Work {transaction, at_block, gas_price, actual_fee, span}) => {
                        let outer = span.clone();
                        let fut = handle.estimate_fee(transaction, at_block.into(), gas_price, None, None);
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
            Ok(fees) if fees.overall_fee == actual_fee => {
                eq += 1;
                tracing::info!(eq, ne, fail, "ok");
            }
            Ok(fees) => {
                ne += 1;

                let fee = ethers::types::U256::from_big_endian(fees.overall_fee.as_bytes());
                let actual_fee = ethers::types::U256::from_big_endian(actual_fee.as_bytes());
                let gas_price = ethers::types::U256::from_big_endian(fees.gas_price.as_bytes());

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
    actual_fee: Option<Felt>,
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
    #[serde(rename = "L1_HANDLER")]
    L1Handler(SimpleL1Handler),
    #[serde(rename = "DEPLOY_ACCOUNT")]
    DeployAccount(SimpleDeployAccount),
}

#[derive(serde::Deserialize, Debug)]
struct SimpleDeploy {
    contract_address: pathfinder_common::ContractAddress,
}

#[derive(serde::Deserialize, Debug)]
struct SimpleDeclare {}

#[serde_with::serde_as]
#[derive(serde::Deserialize, Debug)]
struct SimpleDeployAccount {
    #[serde_as(as = "pathfinder_serde::TransactionVersionAsHexStr")]
    pub version: pathfinder_common::TransactionVersion,
    #[serde_as(as = "pathfinder_serde::FeeAsHexStr")]
    pub max_fee: pathfinder_common::Fee,
    #[serde_as(as = "Vec<pathfinder_serde::TransactionSignatureElemAsDecimalStr>")]
    #[serde(default)]
    pub signature: Vec<pathfinder_common::TransactionSignatureElem>,
    #[serde(default = "default_transaction_nonce")]
    pub nonce: pathfinder_common::TransactionNonce,

    contract_address_salt: pathfinder_common::ContractAddressSalt,
    #[serde_as(as = "Vec<pathfinder_serde::CallParamAsDecimalStr>")]
    pub constructor_calldata: Vec<pathfinder_common::CallParam>,
    pub class_hash: pathfinder_common::ClassHash,
}

#[serde_with::serde_as]
#[derive(serde::Deserialize, Debug)]
struct SimpleInvoke {
    #[serde(default)]
    #[serde_as(as = "Option<pathfinder_serde::TransactionVersionAsHexStr>")]
    pub version: Option<pathfinder_common::TransactionVersion>,
    #[serde_as(as = "pathfinder_serde::FeeAsHexStr")]
    pub max_fee: pathfinder_common::Fee,
    #[serde_as(as = "Vec<pathfinder_serde::TransactionSignatureElemAsDecimalStr>")]
    #[serde(default)]
    pub signature: Vec<pathfinder_common::TransactionSignatureElem>,
    #[serde(default = "default_transaction_nonce")]
    pub nonce: pathfinder_common::TransactionNonce,

    contract_address: pathfinder_common::ContractAddress,
    #[serde_as(as = "Vec<pathfinder_serde::CallParamAsDecimalStr>")]
    pub calldata: Vec<pathfinder_common::CallParam>,
    #[serde(default)]
    pub entry_point_selector: Option<pathfinder_common::EntryPoint>,
}

fn default_transaction_nonce() -> pathfinder_common::TransactionNonce {
    pathfinder_rpc::v02::types::request::Call::DEFAULT_NONCE
}

impl From<SimpleInvoke> for pathfinder_rpc::v02::types::request::BroadcastedTransaction {
    fn from(tx: SimpleInvoke) -> Self {
        use pathfinder_rpc::v02::types::request::*;

        match tx.version {
            Some(version) => match version.without_query_version() {
                0 => BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                    BroadcastedInvokeTransactionV0 {
                        version,
                        max_fee: tx.max_fee,
                        signature: tx.signature,
                        nonce: None,
                        contract_address: tx.contract_address,
                        entry_point_selector: tx
                            .entry_point_selector
                            .unwrap_or(pathfinder_common::EntryPoint(Felt::ZERO)),
                        calldata: tx.calldata,
                    },
                )),
                1 => BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                    BroadcastedInvokeTransactionV1 {
                        version,
                        max_fee: tx.max_fee,
                        signature: tx.signature,
                        nonce: tx.nonce,
                        sender_address: tx.contract_address,
                        calldata: tx.calldata,
                    },
                )),
                _ => panic!(
                    "Unsupported transaction version in transaction {:?}",
                    tx.version
                ),
            },
            None => BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                BroadcastedInvokeTransactionV0 {
                    version: pathfinder_common::TransactionVersion::ZERO,
                    max_fee: tx.max_fee,
                    signature: tx.signature,
                    nonce: None,
                    contract_address: tx.contract_address,
                    entry_point_selector: tx
                        .entry_point_selector
                        .unwrap_or(pathfinder_common::EntryPoint(Felt::ZERO)),
                    calldata: tx.calldata,
                },
            )),
        }
    }
}

impl From<SimpleDeployAccount> for pathfinder_rpc::v02::types::request::BroadcastedTransaction {
    fn from(tx: SimpleDeployAccount) -> Self {
        use pathfinder_rpc::v02::types::request::*;

        BroadcastedTransaction::DeployAccount(BroadcastedDeployAccountTransaction {
            version: tx.version,
            max_fee: tx.max_fee,
            signature: tx.signature,
            nonce: tx.nonce,
            contract_address_salt: tx.contract_address_salt,
            constructor_calldata: tx.constructor_calldata,
            class_hash: tx.class_hash,
        })
    }
}

#[derive(serde::Deserialize, Debug)]
struct SimpleL1Handler {}
