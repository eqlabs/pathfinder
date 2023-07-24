//! External python process pool for execute calls.
//!
//! The python processes are executing `$REPO_ROOT/py/src/call.py` and communicate over by sending
//! and receiving json + `'\n'`. Main entry point is the [`service::start`] which manages running
//! given number of N processes. The python script uses sqlite to read pathfinder's database, which
//! should not cause issues in WAL mode.
//!
//! Use of the call functionality happens through [`Handle::call`], which hands out futures in
//! exchange for [`Call`] and "when" in chain, former selects the contract and method to call,
//! latter selectes "when" to call it on the history. None of the block or tags are resolved over
//! at rust side, because transactions cannot carry over between processes.
//!
//! While the python script does attempt to resolve "latest", it probably needs fixing. To make it
//! support "pending", a feature needs to be added which flushes the "open" pending to a
//! global_state, and after that, calls can be made to it's `block_hash` for which we probably need
//! to add an alternative way to use a hash directly rather as a root than assume it's a block hash.

use crate::v02::types::reply::FeeEstimate;
use crate::v02::types::request::{
    BroadcastedDeclareTransaction, BroadcastedInvokeTransaction, BroadcastedTransaction, Call,
};
use pathfinder_common::{BlockTimestamp, CallResultValue, ClassHash, EthereumAddress, StateUpdate};
use starknet_gateway_types::request::add_transaction;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

mod de;

use de::ErrorKind;

mod ser;

use ser::UsedChain;
pub use ser::{BlockHashNumberOrLatest, Pending};

mod sub_process;

mod service;

pub use service::start;

use self::types::TransactionSimulation;

pub mod types;

/// Handle to the python executors work queue. Cloneable and shareable.
#[derive(Clone)]
pub struct Handle {
    command_tx: mpsc::Sender<(Command, tracing::Span)>,
    chain: UsedChain,
}

impl Handle {
    /// Execute the given call on the python cairo-lang executors.
    pub async fn call(
        &self,
        call: Call,
        at_block: BlockHashNumberOrLatest,
        diffs: Option<Arc<StateUpdate>>,
        block_timestamp: Option<BlockTimestamp>,
    ) -> Result<Vec<CallResultValue>, CallFailure> {
        use tracing::field::Empty;
        let (response, rx) = oneshot::channel();

        let continued_span = tracing::info_span!("ext_py_call", pid = Empty);

        self.command_tx
            .send((
                Command::Call {
                    call,
                    at_block,
                    chain: self.chain,
                    diffs,
                    block_timestamp,
                    response,
                },
                continued_span,
            ))
            .await
            .map_err(|_| CallFailure::Shutdown)?;

        match rx.await {
            Ok(x) => x,
            Err(_closed) => Err(CallFailure::Shutdown),
        }
    }

    /// Fee estimation is a superset of call with the call result value discarded.
    ///
    /// Returns the fee as a three components.
    pub async fn estimate_fee(
        &self,
        transactions: Vec<BroadcastedTransaction>,
        at_block: BlockHashNumberOrLatest,
        gas_price: GasPriceSource,
        diffs: Option<Arc<StateUpdate>>,
        block_timestamp: Option<BlockTimestamp>,
    ) -> Result<Vec<FeeEstimate>, CallFailure> {
        use tracing::field::Empty;
        let (response, rx) = oneshot::channel();

        let continued_span = tracing::info_span!("ext_py_est_fee", pid = Empty);

        let transactions = transactions
            .into_iter()
            .map(map_tx)
            .collect::<Result<Vec<_>, _>>()?;

        self.command_tx
            .send((
                Command::EstimateFee {
                    transactions,
                    at_block,
                    gas_price,
                    chain: self.chain,
                    diffs,
                    block_timestamp,
                    response,
                },
                continued_span,
            ))
            .await
            .map_err(|_| CallFailure::Shutdown)?;

        match rx.await {
            Ok(x) => x,
            Err(_closed) => Err(CallFailure::Shutdown),
        }
    }

    pub async fn estimate_message_fee(
        &self,
        sender_address: EthereumAddress,
        message: Call,
        at_block: BlockHashNumberOrLatest,
        gas_price: GasPriceSource,
        diffs: Option<Arc<StateUpdate>>,
        block_timestamp: Option<BlockTimestamp>,
    ) -> Result<FeeEstimate, CallFailure> {
        use tracing::field::Empty;
        let (response, rx) = oneshot::channel();

        let continued_span = tracing::info_span!("ext_py_est_msg_fee", pid = Empty);

        self.command_tx
            .send((
                Command::EstimateMessageFee {
                    sender_address,
                    message,
                    at_block,
                    gas_price,
                    chain: self.chain,
                    diffs,
                    block_timestamp,
                    response,
                },
                continued_span,
            ))
            .await
            .map_err(|_| CallFailure::Shutdown)?;

        match rx.await {
            Ok(x) => x,
            Err(_closed) => Err(CallFailure::Shutdown),
        }
    }

    pub async fn simulate_transaction(
        &self,
        at_block: BlockHashNumberOrLatest,
        gas_price: GasPriceSource,
        diffs: Option<Arc<StateUpdate>>,
        block_timestamp: Option<BlockTimestamp>,
        transactions: Vec<BroadcastedTransaction>,
        skip_validate: bool,
    ) -> Result<Vec<TransactionSimulation>, CallFailure> {
        use tracing::field::Empty;
        let (response, rx) = oneshot::channel();

        let continued_span = tracing::info_span!("ext_py_sim_tx", pid = Empty);

        let transactions: Result<Vec<TransactionAndClassHashHint>, _> =
            transactions.into_iter().map(map_tx).collect();
        let transactions = transactions?;

        self.command_tx
            .send((
                Command::SimulateTransaction {
                    transactions,
                    at_block,
                    gas_price,
                    chain: self.chain,
                    diffs,
                    block_timestamp,
                    response,
                    skip_validate,
                },
                continued_span,
            ))
            .await
            .map_err(|_| CallFailure::Shutdown)?;

        match rx.await {
            Ok(x) => x,
            Err(_closed) => Err(CallFailure::Shutdown),
        }
    }
}

fn map_tx(tx: BroadcastedTransaction) -> Result<TransactionAndClassHashHint, CallFailure> {
    Ok(match tx {
        BroadcastedTransaction::DeployAccount(tx) => TransactionAndClassHashHint {
            transaction: add_transaction::AddTransaction::DeployAccount(
                add_transaction::DeployAccount {
                    version: tx.version,
                    max_fee: tx.max_fee,
                    signature: tx.signature,
                    nonce: tx.nonce,
                    class_hash: tx.class_hash,
                    contract_address_salt: tx.contract_address_salt,
                    constructor_calldata: tx.constructor_calldata,
                },
            ),
            class_hash_hint: None,
        },
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(tx)) => {
            let class_hash = tx
                .contract_class
                .class_hash()
                .map_err(|_| CallFailure::Internal("Failed to calculate class hash"))?;
            use starknet_gateway_types::class_hash::ComputedClassHash;
            let class_hash = match class_hash {
                ComputedClassHash::Cairo(c) => ClassHash(c.0),
                ComputedClassHash::Sierra(s) => ClassHash(s.0),
            };
            TransactionAndClassHashHint {
                transaction: add_transaction::AddTransaction::Declare(add_transaction::Declare {
                    version: tx.version,
                    max_fee: tx.max_fee,
                    signature: tx.signature,
                    contract_class: add_transaction::ContractDefinition::Cairo(
                        tx.contract_class.try_into().map_err(|_| {
                            CallFailure::Internal("contract class serialization failure")
                        })?,
                    ),
                    sender_address: tx.sender_address,
                    nonce: tx.nonce,
                    compiled_class_hash: None,
                }),
                class_hash_hint: Some(class_hash),
            }
        }
        BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(tx)) => {
            let class_hash = tx
                .contract_class
                .class_hash()
                .map_err(|_| CallFailure::Internal("Failed to calculate class hash"))?;
            use starknet_gateway_types::class_hash::ComputedClassHash;
            let class_hash = match class_hash {
                ComputedClassHash::Cairo(c) => ClassHash(c.0),
                ComputedClassHash::Sierra(s) => ClassHash(s.0),
            };
            TransactionAndClassHashHint {
                transaction: add_transaction::AddTransaction::Declare(add_transaction::Declare {
                    version: tx.version,
                    max_fee: tx.max_fee,
                    signature: tx.signature,
                    contract_class: add_transaction::ContractDefinition::Sierra(
                        tx.contract_class.try_into().map_err(|_| {
                            CallFailure::Internal("contract class serialization failure")
                        })?,
                    ),
                    sender_address: tx.sender_address,
                    nonce: tx.nonce,
                    compiled_class_hash: Some(tx.compiled_class_hash),
                }),
                class_hash_hint: Some(class_hash),
            }
        }
        BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(tx)) => {
            TransactionAndClassHashHint {
                transaction: add_transaction::AddTransaction::Invoke(
                    add_transaction::InvokeFunction {
                        version: tx.version,
                        max_fee: tx.max_fee,
                        signature: tx.signature,
                        nonce: tx.nonce,
                        sender_address: tx.sender_address,
                        calldata: tx.calldata,
                    },
                ),
                class_hash_hint: None,
            }
        }
    })
}

/// Reasons for a call to fail.
#[derive(Debug, PartialEq, Eq)]
pub enum CallFailure {
    /// The requested block could not be found.
    NoSuchBlock,
    /// The called top-level contract could not be found.
    NoSuchContract,
    /// The called top-level entry point could not be found.
    InvalidEntryPoint,
    /// `cairo-lang` failed the call, string has the exception name.
    ExecutionFailed(String),
    /// Internal, opaque-ish failure reason, none of them signal an issue with the call.
    Internal(&'static str),
    /// Channel related issue or shutting down.
    Shutdown,
}

/// Where should the call code get the used `BlockInfo::gas_price`
#[derive(Debug)]
pub enum GasPriceSource {
    /// Use gasPrice recorded on the `starknet_blocks::gas_price`.
    ///
    /// This is not implied by other arguments such as `at_block` because we might need to
    /// manufacture a block hash for some future use cases.
    PastBlock,
    /// Use this latest value from `eth_gasPrice`.
    Current(primitive_types::U256),
}

impl GasPriceSource {
    const GAS_PRICE_ZERO: primitive_types::U256 = primitive_types::U256::zero();
    /// Convert to `&U256`, for use in serialization.
    pub fn as_price(&self) -> &primitive_types::U256 {
        match self {
            GasPriceSource::PastBlock => &Self::GAS_PRICE_ZERO,
            GasPriceSource::Current(price) => price,
        }
    }
}

impl From<ErrorKind> for CallFailure {
    fn from(e: ErrorKind) -> Self {
        use ErrorKind::*;
        match e {
            NoSuchBlock => CallFailure::NoSuchBlock,
            NoSuchContract => CallFailure::NoSuchContract,
            InvalidEntryPoint => CallFailure::InvalidEntryPoint,
            InvalidSchemaVersion => CallFailure::Internal("Wrong database version"),
            InvalidCommand => CallFailure::Internal("Invalid json sent"),
        }
    }
}

/// Alias for the "mpmc" queue. Flume could had been used, but this is probably as fast as it needs
/// to be.
type SharedReceiver<T> = Arc<Mutex<mpsc::Receiver<T>>>;

/// Command from outside of the module wrapped by [`Handle`] to be sent for execution in python.
///
/// The used chain is tagged along not to require knowledge of it at the callers of [`Handle`] but to
/// keep it per-request at the python level.
#[derive(Debug)]
enum Command {
    Call {
        call: Call,
        at_block: BlockHashNumberOrLatest,
        chain: UsedChain,
        diffs: Option<Arc<StateUpdate>>,
        block_timestamp: Option<BlockTimestamp>,
        response: oneshot::Sender<Result<Vec<CallResultValue>, CallFailure>>,
    },
    EstimateFee {
        transactions: Vec<TransactionAndClassHashHint>,
        at_block: BlockHashNumberOrLatest,
        gas_price: GasPriceSource,
        chain: UsedChain,
        diffs: Option<Arc<StateUpdate>>,
        block_timestamp: Option<BlockTimestamp>,
        response: oneshot::Sender<Result<Vec<FeeEstimate>, CallFailure>>,
    },
    EstimateMessageFee {
        sender_address: EthereumAddress,
        message: Call,
        at_block: BlockHashNumberOrLatest,
        gas_price: GasPriceSource,
        chain: UsedChain,
        diffs: Option<Arc<StateUpdate>>,
        block_timestamp: Option<BlockTimestamp>,
        response: oneshot::Sender<Result<FeeEstimate, CallFailure>>,
    },
    SimulateTransaction {
        transactions: Vec<TransactionAndClassHashHint>,
        at_block: BlockHashNumberOrLatest,
        skip_validate: bool,
        gas_price: GasPriceSource,
        chain: UsedChain,
        diffs: Option<Arc<StateUpdate>>,
        block_timestamp: Option<BlockTimestamp>,
        response: oneshot::Sender<Result<Vec<TransactionSimulation>, CallFailure>>,
    },
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct TransactionAndClassHashHint {
    pub transaction: add_transaction::AddTransaction,
    pub class_hash_hint: Option<ClassHash>,
}

impl Command {
    fn is_closed(&self) -> bool {
        use Command::*;
        match self {
            Call { response, .. } => response.is_closed(),
            EstimateFee { response, .. } => response.is_closed(),
            EstimateMessageFee { response, .. } => response.is_closed(),
            SimulateTransaction { response, .. } => response.is_closed(),
        }
    }

    fn fail(self, err: CallFailure) -> Result<(), CallFailure> {
        use Command::*;
        match self {
            Call { response, .. } => response.send(Err(err)).map_err(|e| e.unwrap_err()),
            EstimateFee { response, .. } => response.send(Err(err)).map_err(|e| e.unwrap_err()),
            EstimateMessageFee { response, .. } => {
                response.send(Err(err)).map_err(|e| e.unwrap_err())
            }
            SimulateTransaction { response, .. } => {
                response.send(Err(err)).map_err(|e| e.unwrap_err())
            }
        }
    }

    async fn closed(&mut self) {
        use Command::*;
        match self {
            Call { response, .. } => response.closed().await,
            EstimateFee { response, .. } => response.closed().await,
            EstimateMessageFee { response, .. } => response.closed().await,
            SimulateTransaction { response, .. } => response.closed().await,
        }
    }
}

/// Informational events from python process executors.
#[derive(Debug)]
enum SubProcessEvent {
    ProcessLaunched(u32),
}

/// The reason the [`sub_process::launch_python`] exited.
#[derive(Debug)]
enum SubprocessExitReason {
    UnrecoverableIO,
    Shutdown,
    Death,
    Cancellation,
    // If you add more reasons, remember to modify `all_labels`
}

impl SubprocessExitReason {
    fn as_label(&self) -> &'static str {
        match self {
            SubprocessExitReason::UnrecoverableIO => "unrecoverable_io",
            SubprocessExitReason::Shutdown => "shutdown",
            SubprocessExitReason::Death => "subprocess_died",
            SubprocessExitReason::Cancellation => "request_cancelled",
        }
    }

    fn all_labels() -> impl Iterator<Item = &'static str> {
        use SubprocessExitReason::*;
        // this is quite the hassle maintaining this but so far we don't really have a better way
        // in rust than to do this
        [UnrecoverableIO, Shutdown, Death, Cancellation]
            .into_iter()
            .map(|x| x.as_label())
    }
}

/// Errors which can happen during an RPC alike round with the subprocess.
enum SubprocessError {
    /// Input or output related issues; most likely a broken pipe due to child process dying.
    IO,
    /// Python sent us invalid response
    InvalidJson(serde_json::Error),
    /// Python sent us a response we couldn't understand
    InvalidResponse,
}

impl From<std::io::Error> for SubprocessError {
    fn from(_: std::io::Error) -> Self {
        SubprocessError::IO
    }
}

/// Which process, with what opaque native reason exited because of which codepath was taken.
type SubprocessExitInfo = (u32, Option<std::process::ExitStatus>, SubprocessExitReason);

#[cfg(test)]
mod tests {
    use super::BlockHashNumberOrLatest;
    use crate::{
        cairo::ext_py::GasPriceSource,
        v02::types::request::{BroadcastedDeployAccountTransaction, BroadcastedTransaction},
    };
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        BlockHash, BlockHeader, BlockNumber, BlockTimestamp, CallParam, CallResultValue, Chain,
        ClassCommitment, ClassHash, ContractAddressSalt, ContractNonce, ContractRoot,
        ContractStateHash, EntryPoint, GasPrice, StateCommitment, StateUpdate, StorageAddress,
        StorageCommitment, StorageValue, TransactionVersion,
    };
    use pathfinder_merkle_tree::StorageCommitmentTree;
    use pathfinder_storage::{JournalMode, Storage, Transaction};
    use stark_hash::Felt;
    use std::num::NonZeroU32;
    use std::path::PathBuf;
    use tokio::sync::oneshot;

    #[test_log::test(tokio::test)]
    async fn call_like_in_python_ten_times() {
        use futures::stream::StreamExt;

        let db_file = tempfile::NamedTempFile::new().unwrap();

        let s = Storage::migrate(PathBuf::from(db_file.path()), JournalMode::WAL)
            .unwrap()
            .create_pool(NonZeroU32::new(1).unwrap())
            .unwrap();

        let mut conn = s.connection().unwrap();

        let tx = conn.transaction().unwrap();

        deploy_test_contract_in_block_one(&tx);

        tx.commit().unwrap();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let (handle, jh) = super::start(
            PathBuf::from(db_file.path()),
            std::num::NonZeroUsize::new(2).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
            Chain::Testnet,
        )
        .await
        .unwrap();

        let count = 10;

        let mut jhs = (0..count)
            .map(move |_| {
                tokio::task::spawn({
                    let handle = handle.clone();
                    async move {
                        handle.call(
                            super::Call {
                                contract_address: contract_address!("057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"),
                                calldata: vec![call_param!("0x84")],
                                entry_point_selector: Some(EntryPoint::hashed(&b"get_value"[..])),
                                signature: Default::default(),
                                max_fee: super::Call::DEFAULT_MAX_FEE,
                                version: super::Call::DEFAULT_VERSION,
                                nonce: super::Call::DEFAULT_NONCE,
                            },
                            BlockHash(
                                Felt::from_be_slice(&b"some blockhash somewhere"[..]).unwrap(),
                            ).into(),
                            None,
                            None,
                        ).await.unwrap();
                    }
                })
            })
            .collect::<futures::stream::FuturesUnordered<_>>();

        for _ in 0..count {
            jhs.next().await.unwrap().unwrap();
        }

        shutdown_tx.send(()).unwrap();

        jh.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn estimate_fee_for_example() {
        use crate::v03::method::estimate_fee::tests::ext_py::{
            test_storage_with_account, valid_invoke_v1,
        };

        let (_db_dir, storage, account_address, latest_block_hash, latest_block_number) =
            test_storage_with_account(GasPrice(1));
        let db_path = storage.path();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let (handle, jh) = super::start(
            PathBuf::from(db_path),
            std::num::NonZeroUsize::new(1).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
            // chain doesn't matter here because we are not estimating any real transaction
            Chain::Testnet,
        )
        .await
        .unwrap();

        let transactions = vec![valid_invoke_v1(account_address)];

        const EXPECTED_GAS_CONSUMED: u64 = 4938;

        for (gas_price_u64, block, use_past_block) in [
            (1, latest_block_number.into(), true),
            (10, latest_block_hash.into(), false),
            (123, BlockHashNumberOrLatest::Latest, false),
        ] {
            let gas_price = gas_price_u64.into();
            let fee = handle
                .estimate_fee(
                    transactions.clone(),
                    block,
                    if use_past_block {
                        GasPriceSource::PastBlock
                    } else {
                        GasPriceSource::Current(gas_price)
                    },
                    None,
                    None,
                )
                .await
                .unwrap();

            assert_eq!(
                fee,
                vec![crate::v02::types::reply::FeeEstimate {
                    gas_consumed: EXPECTED_GAS_CONSUMED.into(),
                    gas_price,
                    overall_fee: (EXPECTED_GAS_CONSUMED * gas_price_u64).into(),
                }],
                "block: {block}, gas_price: {gas_price}"
            );
        }

        shutdown_tx.send(()).unwrap();

        jh.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn estimate_fee_for_deploy_account() {
        // TODO: refactor the outer parts to a with_test_env or similar?
        let db_file = tempfile::NamedTempFile::new().unwrap();

        let s = Storage::migrate(PathBuf::from(db_file.path()), JournalMode::WAL)
            .unwrap()
            .create_pool(NonZeroU32::new(1).unwrap())
            .unwrap();

        let mut conn = s.connection().unwrap();

        let tx = conn.transaction().unwrap();

        let account_contract_class_hash = deploy_account_contract_in_block_one(&tx);

        tx.commit().unwrap();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let (handle, jh) = super::start(
            PathBuf::from(db_file.path()),
            std::num::NonZeroUsize::new(1).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
            // chain doesn't matter here because we are not estimating any real transaction
            Chain::Testnet,
        )
        .await
        .unwrap();

        let transactions = vec![BroadcastedTransaction::DeployAccount(
            BroadcastedDeployAccountTransaction {
                version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                max_fee: super::Call::DEFAULT_MAX_FEE,
                signature: Default::default(),
                nonce: super::Call::DEFAULT_NONCE,
                contract_address_salt: ContractAddressSalt(Felt::ZERO),
                class_hash: account_contract_class_hash,
                constructor_calldata: vec![],
            },
        )];

        let at_block_fee = handle
            .estimate_fee(
                transactions.clone(),
                BlockNumber::new_or_panic(1).into(),
                super::GasPriceSource::PastBlock,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            at_block_fee,
            vec![crate::v02::types::reply::FeeEstimate {
                gas_consumed: 0xc19.into(),
                gas_price: 1.into(),
                overall_fee: 0xc19.into(),
            }]
        );

        shutdown_tx.send(()).unwrap();

        jh.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn call_with_unknown_contract() {
        let db_file = tempfile::NamedTempFile::new().unwrap();

        let s = Storage::migrate(PathBuf::from(db_file.path()), JournalMode::WAL)
            .unwrap()
            .create_pool(NonZeroU32::new(1).unwrap())
            .unwrap();

        let mut conn = s.connection().unwrap();

        let tx = conn.transaction().unwrap();

        deploy_test_contract_in_block_one(&tx);

        tx.commit().unwrap();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let (handle, jh) = super::start(
            PathBuf::from(db_file.path()),
            std::num::NonZeroUsize::new(1).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
            Chain::Testnet,
        )
        .await
        .unwrap();

        let call = super::Call {
            // this is one bit off from other examples
            contract_address: contract_address!(
                "057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e375"
            ),
            calldata: vec![call_param!("0x84")],
            entry_point_selector: Some(EntryPoint::hashed(&b"get_value"[..])),
            signature: Default::default(),
            max_fee: super::Call::DEFAULT_MAX_FEE,
            version: super::Call::DEFAULT_VERSION,
            nonce: super::Call::DEFAULT_NONCE,
        };

        let result = handle
            .call(
                call,
                BlockHash(Felt::from_be_slice(&b"some blockhash somewhere"[..]).unwrap()).into(),
                None,
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(result, super::CallFailure::NoSuchContract);

        let _ = shutdown_tx.send(());
        jh.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn call_with_pending_updates() {
        use starknet_gateway_types::request::Tag;

        let db_file = tempfile::NamedTempFile::new().unwrap();

        let s = Storage::migrate(PathBuf::from(db_file.path()), JournalMode::WAL)
            .unwrap()
            .create_pool(NonZeroU32::new(1).unwrap())
            .unwrap();

        let mut conn = s.connection().unwrap();

        let tx = conn.transaction().unwrap();

        deploy_test_contract_in_block_one(&tx);

        tx.commit().unwrap();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let (handle, jh) = super::start(
            PathBuf::from(db_file.path()),
            std::num::NonZeroUsize::new(1).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
            Chain::Testnet,
        )
        .await
        .unwrap();

        let target_contract =
            contract_address!("057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374");

        let storage_address = felt!("0x84");

        let call = super::Call {
            contract_address: target_contract,
            calldata: vec![CallParam(storage_address)],
            entry_point_selector: Some(EntryPoint::hashed(&b"get_value"[..])),
            signature: Default::default(),
            max_fee: super::Call::DEFAULT_MAX_FEE,
            version: super::Call::DEFAULT_VERSION,
            nonce: super::Call::DEFAULT_NONCE,
        };

        let res = handle
            .call(call.clone(), Tag::Latest.try_into().unwrap(), None, None)
            .await
            .unwrap();

        assert_eq!(res, &[CallResultValue(Felt::from(3u64))]);

        let update = StateUpdate::default().with_storage_update(
            target_contract,
            StorageAddress::new_or_panic(storage_address),
            storage_value!("0x4"),
        );
        let update = std::sync::Arc::new(update);

        let res = handle
            .call(call, Tag::Latest.try_into().unwrap(), Some(update), None)
            .await
            .unwrap();

        assert_eq!(res, &[CallResultValue(Felt::from(4u64))]);

        shutdown_tx.send(()).unwrap();

        jh.await.unwrap();
    }

    fn deploy_test_contract_in_block_one(tx: &Transaction<'_>) -> ClassHash {
        let test_contract_definition =
            starknet_gateway_test_fixtures::class_definitions::CONTRACT_DEFINITION;
        let test_contract_address =
            contract_address!("057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374");

        let storage_updates = [(storage_address!("0x84"), storage_value!("0x3"))];

        let (test_contract_state_hash, test_contract_class_hash) =
            deploy_contract(tx, test_contract_definition, &storage_updates);

        // and then add the contract states to the global tree
        let mut storage_commitment_tree =
            StorageCommitmentTree::load(tx, StorageCommitment(Felt::ZERO)).unwrap();

        storage_commitment_tree
            .set(test_contract_address, test_contract_state_hash)
            .unwrap();
        let (storage_commitment, nodes) = storage_commitment_tree.commit().unwrap();
        tx.insert_storage_trie(storage_commitment, &nodes).unwrap();
        let class_commitment = ClassCommitment(Felt::ZERO);

        let header = BlockHeader::builder()
            .with_number(BlockNumber::new_or_panic(1))
            .with_state_commitment(StateCommitment::calculate(
                storage_commitment,
                class_commitment,
            ))
            .with_timestamp(BlockTimestamp::new_or_panic(1))
            .with_gas_price(GasPrice(1))
            .with_storage_commitment(storage_commitment)
            .with_class_commitment(class_commitment)
            .finalize_with_hash(block_hash_bytes!(b"some blockhash somewhere"));
        tx.insert_block_header(&header).unwrap();

        let state_update = StateUpdate::default()
            .with_block_hash(header.hash)
            // The parent commitment is not set, but it shouldn't matter for this.
            .with_state_commitment(header.state_commitment)
            .with_storage_update(
                test_contract_address,
                storage_updates[0].0,
                storage_updates[0].1,
            )
            .with_deployed_contract(test_contract_address, test_contract_class_hash);

        tx.insert_state_update(header.number, &state_update)
            .unwrap();

        test_contract_class_hash
    }

    fn deploy_account_contract_in_block_one(tx: &Transaction<'_>) -> ClassHash {
        let account_contract_definition =
            starknet_gateway_test_fixtures::class_definitions::DUMMY_ACCOUNT;

        let account_contract_address = contract_address!("0x123");

        let (account_contract_state_hash, account_contract_class_hash) =
            deploy_contract(tx, account_contract_definition, &[]);

        // and then add the contract states to the global tree
        let mut storage_commitment_tree =
            StorageCommitmentTree::load(tx, StorageCommitment(Felt::ZERO)).unwrap();

        storage_commitment_tree
            .set(account_contract_address, account_contract_state_hash)
            .unwrap();
        let (storage_commitment, nodes) = storage_commitment_tree.commit().unwrap();
        tx.insert_storage_trie(storage_commitment, &nodes).unwrap();
        let class_commitment = ClassCommitment(Felt::ZERO);

        let header = BlockHeader::builder()
            .with_number(BlockNumber::new_or_panic(1))
            .with_state_commitment(StateCommitment::calculate(
                storage_commitment,
                class_commitment,
            ))
            .with_timestamp(BlockTimestamp::new_or_panic(1))
            .with_gas_price(GasPrice(1))
            .with_storage_commitment(storage_commitment)
            .with_class_commitment(class_commitment)
            .finalize_with_hash(block_hash_bytes!(b"some blockhash somewhere"));
        tx.insert_block_header(&header).unwrap();

        let state_update = StateUpdate::default()
            .with_block_hash(header.hash)
            // The parent commitment is not set, but it shouldn't matter for this.
            .with_state_commitment(header.state_commitment)
            .with_deployed_contract(account_contract_address, account_contract_class_hash);

        tx.insert_state_update(header.number, &state_update)
            .unwrap();

        account_contract_class_hash
    }

    fn deploy_contract(
        tx: &Transaction<'_>,
        contract_definition: &[u8],
        storage_updates: &[(StorageAddress, StorageValue)],
    ) -> (ContractStateHash, ClassHash) {
        use pathfinder_merkle_tree::ContractsStorageTree;

        let class_hash =
            starknet_gateway_types::class_hash::compute_class_hash(contract_definition).unwrap();
        let class_hash = class_hash.hash();

        // create class
        tx.insert_cairo_class(class_hash, contract_definition)
            .unwrap();

        // set up contract state tree
        let mut contract_state = ContractsStorageTree::load(tx, ContractRoot(Felt::ZERO));
        for (storage_address, storage_value) in storage_updates {
            contract_state
                .set(*storage_address, *storage_value)
                .unwrap();
        }
        let (contract_root, nodes) = contract_state.commit().unwrap();
        tx.insert_contract_trie(contract_root, &nodes).unwrap();

        let contract_nonce = ContractNonce(Felt::ZERO);

        let contract_state_hash =
            pathfinder_merkle_tree::contract_state::calculate_contract_state_hash(
                class_hash,
                contract_root,
                contract_nonce,
            );

        // set up contract state table
        tx.insert_contract_state(
            contract_state_hash,
            class_hash,
            contract_root,
            contract_nonce,
        )
        .unwrap();

        (contract_state_hash, class_hash)
    }
}
