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

use crate::core::CallResultValue;
use crate::rpc::types::{reply::FeeEstimate, request::Call};
use crate::sequencer::reply::StateUpdate;
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
        call: Call,
        at_block: BlockHashNumberOrLatest,
        gas_price: GasPriceSource,
        diffs: Option<Arc<StateUpdate>>,
    ) -> Result<FeeEstimate, CallFailure> {
        use tracing::field::Empty;
        let (response, rx) = oneshot::channel();

        let continued_span = tracing::info_span!("ext_py_est_fee", pid = Empty);

        self.command_tx
            .send((
                Command::EstimateFee {
                    call,
                    at_block,
                    gas_price,
                    chain: self.chain,
                    diffs,
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
}

/// Reasons for a call to fail.
#[derive(Debug, PartialEq)]
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
    ///
    /// U256 is not used for serialization matters, [u8; 32] could be used as well. python side's
    /// serialization limits this value to u128 but in general `eth_gasPrice` is U256.
    Current(web3::types::H256),
}

impl GasPriceSource {
    /// Convert to an option of H256, for serialization.
    fn as_option(&self) -> Option<&web3::types::H256> {
        match self {
            GasPriceSource::PastBlock => None,
            GasPriceSource::Current(price) => Some(price),
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
        response: oneshot::Sender<Result<Vec<CallResultValue>, CallFailure>>,
    },
    EstimateFee {
        call: Call,
        at_block: BlockHashNumberOrLatest,
        /// Price input for the fee estimation, also communicated back in response
        gas_price: GasPriceSource,
        chain: UsedChain,
        diffs: Option<Arc<StateUpdate>>,
        response: oneshot::Sender<Result<FeeEstimate, CallFailure>>,
    },
}

impl Command {
    fn is_closed(&self) -> bool {
        use Command::*;
        match self {
            Call { response, .. } => response.is_closed(),
            EstimateFee { response, .. } => response.is_closed(),
        }
    }

    fn fail(self, err: CallFailure) -> Result<(), CallFailure> {
        use Command::*;
        match self {
            Call { response, .. } => response.send(Err(err)).map_err(|e| e.unwrap_err()),
            EstimateFee { response, .. } => response.send(Err(err)).map_err(|e| e.unwrap_err()),
        }
    }

    async fn closed(&mut self) {
        use Command::*;
        match self {
            Call { response, .. } => response.closed().await,
            EstimateFee { response, .. } => response.closed().await,
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

#[cfg(test)]
mod tests {

    use super::sub_process::launch_python;
    use stark_hash::StarkHash;
    use std::path::PathBuf;
    use tokio::sync::oneshot;

    #[test_log::test(tokio::test)]
    #[ignore = "needs python venv"]
    async fn start_with_wrong_database_schema_fails() {
        let db_file = tempfile::NamedTempFile::new().unwrap();

        let s = crate::storage::Storage::migrate(
            PathBuf::from(db_file.path()),
            crate::storage::JournalMode::WAL,
        )
        .unwrap();

        {
            let conn = s.connection().unwrap();
            conn.execute("pragma user_version = 0", []).unwrap();
        }

        let (_work_tx, work_rx) = tokio::sync::mpsc::channel(1);
        let work_rx = tokio::sync::Mutex::new(work_rx);
        let (status_tx, _status_rx) = tokio::sync::mpsc::channel(1);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let err = launch_python(
            db_file.path().into(),
            work_rx.into(),
            status_tx,
            shutdown_rx,
        )
        .await;

        println!("{:?}", err.unwrap_err());
    }

    #[test_log::test(tokio::test)]
    #[ignore = "needs python venv"]
    async fn call_like_in_python_ten_times() {
        use futures::stream::StreamExt;

        let db_file = tempfile::NamedTempFile::new().unwrap();

        let s = crate::storage::Storage::migrate(
            PathBuf::from(db_file.path()),
            crate::storage::JournalMode::WAL,
        )
        .unwrap();

        let mut conn = s.connection().unwrap();
        conn.execute("PRAGMA foreign_keys = off", []).unwrap();

        let tx = conn.transaction().unwrap();

        fill_example_state(&tx);

        tx.commit().unwrap();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let (handle, jh) = super::start(
            PathBuf::from(db_file.path()),
            std::num::NonZeroUsize::new(2).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
            crate::core::Chain::Goerli,
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
                                contract_address: crate::core::ContractAddress(
                                    StarkHash::from_hex_str(
                                        "057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                                    )
                                    .unwrap(),
                                ),
                                calldata: vec![crate::core::CallParam(
                                    StarkHash::from_hex_str("0x84").unwrap(),
                                )],
                                entry_point_selector: crate::core::EntryPoint::hashed(&b"get_value"[..]),
                                signature: Default::default(),
                                max_fee: super::Call::DEFAULT_MAX_FEE,
                                version: super::Call::DEFAULT_VERSION,
                            },
                            crate::core::StarknetBlockHash(
                                StarkHash::from_be_slice(&b"some blockhash somewhere"[..]).unwrap(),
                            ).into(),
                            None
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
    #[ignore = "needs python venv"]
    async fn estimate_fee_for_example() {
        // TODO: refactor the outer parts to a with_test_env or similar?
        let db_file = tempfile::NamedTempFile::new().unwrap();

        let s = crate::storage::Storage::migrate(
            PathBuf::from(db_file.path()),
            crate::storage::JournalMode::WAL,
        )
        .unwrap();

        let mut conn = s.connection().unwrap();
        conn.execute("PRAGMA foreign_keys = off", []).unwrap();

        let tx = conn.transaction().unwrap();

        fill_example_state(&tx);

        tx.commit().unwrap();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let (handle, jh) = super::start(
            PathBuf::from(db_file.path()),
            std::num::NonZeroUsize::new(1).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
            // chain doesn't matter here because we are not estimating any real transaction
            crate::core::Chain::Goerli,
        )
        .await
        .unwrap();

        let call = super::Call {
            contract_address: crate::core::ContractAddress(
                StarkHash::from_hex_str(
                    "057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                )
                .unwrap(),
            ),
            calldata: vec![crate::core::CallParam(
                StarkHash::from_hex_str("0x84").unwrap(),
            )],
            entry_point_selector: crate::core::EntryPoint::hashed(&b"get_value"[..]),
            signature: Default::default(),
            max_fee: super::Call::DEFAULT_MAX_FEE,
            version: super::Call::DEFAULT_VERSION,
        };

        let at_block_fee = handle
            .estimate_fee(
                call.clone(),
                crate::core::StarknetBlockHash(
                    StarkHash::from_be_slice(&b"some blockhash somewhere"[..]).unwrap(),
                )
                .into(),
                super::GasPriceSource::PastBlock,
                None,
            )
            .await
            .unwrap();

        use web3::types::H256;

        assert_eq!(
            at_block_fee,
            crate::rpc::types::reply::FeeEstimate {
                consumed: H256::from_low_u64_be(0x53f),
                gas_price: H256::from_low_u64_be(1),
                fee: H256::from_low_u64_be(0x540)
            }
        );

        let current_fee = handle
            .estimate_fee(
                call,
                crate::core::StarknetBlockHash(
                    StarkHash::from_be_slice(&b"some blockhash somewhere"[..]).unwrap(),
                )
                .into(),
                super::GasPriceSource::Current(H256::from_low_u64_be(10)),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            current_fee,
            crate::rpc::types::reply::FeeEstimate {
                consumed: H256::from_low_u64_be(0x53f),
                gas_price: H256::from_low_u64_be(10),
                fee: H256::from_low_u64_be(0x3478)
            }
        );

        shutdown_tx.send(()).unwrap();

        jh.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    #[ignore = "needs python venv"]
    async fn call_with_unknown_contract() {
        let db_file = tempfile::NamedTempFile::new().unwrap();

        let s = crate::storage::Storage::migrate(
            PathBuf::from(db_file.path()),
            crate::storage::JournalMode::WAL,
        )
        .unwrap();

        let mut conn = s.connection().unwrap();
        conn.execute("PRAGMA foreign_keys = off", []).unwrap();

        let tx = conn.transaction().unwrap();

        fill_example_state(&tx);

        tx.commit().unwrap();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let (handle, jh) = super::start(
            PathBuf::from(db_file.path()),
            std::num::NonZeroUsize::new(1).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
            crate::core::Chain::Goerli,
        )
        .await
        .unwrap();

        let call = super::Call {
            contract_address: crate::core::ContractAddress(
                StarkHash::from_hex_str(
                    // this is one bit off from other examples
                    "057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e375",
                )
                .unwrap(),
            ),
            calldata: vec![crate::core::CallParam(
                StarkHash::from_hex_str("0x84").unwrap(),
            )],
            entry_point_selector: crate::core::EntryPoint::hashed(&b"get_value"[..]),
            signature: Default::default(),
            max_fee: super::Call::DEFAULT_MAX_FEE,
            version: super::Call::DEFAULT_VERSION,
        };

        let result = handle
            .call(
                call,
                crate::core::StarknetBlockHash(
                    StarkHash::from_be_slice(&b"some blockhash somewhere"[..]).unwrap(),
                )
                .into(),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(result, super::CallFailure::NoSuchContract);

        let _ = shutdown_tx.send(());
        jh.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    #[ignore = "needs python venv"]
    async fn call_with_pending_updates() {
        use crate::sequencer::reply::StateUpdate;

        let db_file = tempfile::NamedTempFile::new().unwrap();

        let s = crate::storage::Storage::migrate(
            PathBuf::from(db_file.path()),
            crate::storage::JournalMode::WAL,
        )
        .unwrap();

        let mut conn = s.connection().unwrap();
        conn.execute("PRAGMA foreign_keys = off", []).unwrap();

        let tx = conn.transaction().unwrap();

        fill_example_state(&tx);

        tx.commit().unwrap();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let (handle, jh) = super::start(
            PathBuf::from(db_file.path()),
            std::num::NonZeroUsize::new(1).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
            crate::core::Chain::Goerli,
        )
        .await
        .unwrap();

        let target_contract = crate::core::ContractAddress(
            StarkHash::from_hex_str(
                "057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
            )
            .unwrap(),
        );

        let storage_address = StarkHash::from_hex_str("0x84").unwrap();

        let call = super::Call {
            contract_address: target_contract,
            calldata: vec![crate::core::CallParam(storage_address)],
            entry_point_selector: crate::core::EntryPoint::hashed(&b"get_value"[..]),
            signature: Default::default(),
            max_fee: super::Call::DEFAULT_MAX_FEE,
            version: super::Call::DEFAULT_VERSION,
        };

        let res = handle
            .call(
                call.clone(),
                crate::rpc::types::Tag::Latest.try_into().unwrap(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(res, &[crate::core::CallResultValue(StarkHash::from(3u64))]);

        let update = std::sync::Arc::new(StateUpdate {
            block_hash: None,
            old_root: crate::core::GlobalRoot(StarkHash::ZERO),
            new_root: crate::core::GlobalRoot(StarkHash::ZERO),
            state_diff: crate::sequencer::reply::state_update::StateDiff {
                storage_diffs: {
                    let mut map = std::collections::HashMap::new();
                    map.insert(
                        target_contract,
                        vec![crate::sequencer::reply::state_update::StorageDiff {
                            key: crate::core::StorageAddress(storage_address),
                            value: crate::core::StorageValue(
                                StarkHash::from_hex_str("0x4").unwrap(),
                            ),
                        }],
                    );
                    map
                },
                deployed_contracts: vec![],
                declared_contracts: vec![],
            },
        });

        let res = handle
            .call(
                call,
                crate::rpc::types::Tag::Latest.try_into().unwrap(),
                Some(update),
            )
            .await
            .unwrap();

        assert_eq!(res, &[crate::core::CallResultValue(StarkHash::from(4u64))]);

        shutdown_tx.send(()).unwrap();

        jh.await.unwrap();
    }

    fn fill_example_state(tx: &rusqlite::Transaction<'_>) {
        let contract_definition = zstd::decode_all(std::io::Cursor::new(include_bytes!(
            "../../fixtures/contract_definition.json.zst"
        )))
        .unwrap();

        let address = StarkHash::from_hex_str(
            "057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
        )
        .unwrap();
        let expected_hash = StarkHash::from_hex_str(
            "050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b",
        )
        .unwrap();

        let (abi, bytecode, hash) =
            crate::state::class_hash::extract_abi_code_hash(&*contract_definition).unwrap();

        assert_eq!(hash.0, expected_hash);

        crate::storage::ContractCodeTable::insert(tx, hash, &abi, &bytecode, &contract_definition)
            .unwrap();

        crate::storage::ContractsTable::upsert(tx, crate::core::ContractAddress(address), hash)
            .unwrap();

        // this will create the table, not created by migration
        crate::state::state_tree::ContractsStateTree::load(
            tx,
            crate::core::ContractRoot(StarkHash::ZERO),
        )
        .unwrap();

        crate::state::state_tree::GlobalStateTree::load(
            tx,
            crate::core::GlobalRoot(StarkHash::ZERO),
        )
        .unwrap();

        tx.execute("insert into tree_contracts (hash, data, ref_count) values (?1, ?2, 1)",
            rusqlite::params![
                &hex::decode("04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028").unwrap()[..],
                &hex::decode("00000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000084fb").unwrap()[..],
            ]).unwrap();

        tx.execute(
            "insert into contract_states (state_hash, hash, root) values (?1, ?2, ?3)",
            rusqlite::params![
                &hex::decode("002e9723e54711aec56e3fb6ad1bb8272f64ec92e0a43a20feed943b1d4f73c5")
                    .unwrap()[..],
                &hex::decode("050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b")
                    .unwrap()[..],
                &hex::decode("04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028")
                    .unwrap()[..],
            ],
        )
        .unwrap();

        tx.execute(
            "insert into tree_global (hash, data, ref_count) values (?, ?, 1)",
            rusqlite::params![
                &hex::decode("0704dfcbc470377c68e6f5ffb83970ebd0d7c48d5b8d2f4ed61a24e795e034bd").unwrap()[..],
                &hex::decode("002e9723e54711aec56e3fb6ad1bb8272f64ec92e0a43a20feed943b1d4f73c5057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374fb").unwrap()[..],
            ],
        )
        .unwrap();

        tx.execute(
            "insert into starknet_blocks (hash, number, timestamp, root, gas_price) values (?, 1, 1, ?, X'01')",
            rusqlite::params![
                &StarkHash::from_be_slice(&b"some blockhash somewhere"[..])
                    .unwrap()
                    .to_be_bytes()[..],
                &hex::decode("0704dfcbc470377c68e6f5ffb83970ebd0d7c48d5b8d2f4ed61a24e795e034bd")
                    .unwrap()[..],
            ],
        )
        .unwrap();

        if false {
            let mut stmt = tx
                .prepare("select starknet_block_hash from global_state")
                .unwrap();
            let mut rows = stmt.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                let first = row.get_ref(0).expect("get column");

                println!("{:?}", first);

                let first = first.as_blob().expect("cannot read it as a blob");
                println!("{}", hex::encode(first));
            }
        }
    }
}
