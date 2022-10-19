///! Utilities for easier construction of RPC tests.
use crate::{state::PendingData, storage::Storage};
use ::serde::Serialize;
use rusqlite::Transaction;
use std::fmt::Debug;

pub struct Test<'a> {
    method: &'a str,
    line: u32,
    storage: Storage,
}

impl<'a> Test<'a> {
    /// Create test setup with empty in-memory storage.
    pub fn new(method: &'a str, line: u32) -> Self {
        Self {
            method,
            line,
            storage: Storage::in_memory().unwrap(),
        }
    }

    /// Initialize test setup storage using function `f`.
    /// `f` **must produce a sequence of the items put into the storage
    /// in the very same order as they were inserted**.
    pub fn with_storage<StorageInitFn, StorageInitIntoIterator, StorageInitItem>(
        self,
        f: StorageInitFn,
    ) -> TestWithStorage<'a, StorageInitIntoIterator::IntoIter>
    where
        StorageInitIntoIterator: IntoIterator<Item = StorageInitItem>,
        StorageInitFn: FnOnce(&Transaction<'_>) -> StorageInitIntoIterator,
    {
        let mut connection = self.storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        let storage_init = f(&tx);
        tx.commit().unwrap();
        TestWithStorage {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: storage_init.into_iter(),
        }
    }
}

pub struct TestWithStorage<'a, StorageInitIter> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
}

impl<'a, StorageInitIter> TestWithStorage<'a, StorageInitIter> {
    /// The first call to `pending` will yield empty pending data and then TODO
    ///
    ///
    /// TODO Initialize test setup with pending data in the following order:
    /// 1. pending is __disabled__
    /// 2. pending is __enabled__ and __empty__
    /// 3. pending is __enabled__ and yields elements from the __TODO__
    ///    in consecutive test cases
    ///
    /// TODO how it relates to number of params test cases and if it's
    /// appended or prepended to the test cases vector
    /// TODO Initialize test setup storage using function `f`.
    /// `f` **must produce a sequence of the items put into the storage
    /// in the very same order as they were inserted**.
    ///
    /// FIXME: PendingInitItem does not need to be generic, this is a genuine type
    pub fn with_pending_empty_and_then<PendingInitFn, PendingInitIntoIterator, PendingInitItem>(
        self,
        f: PendingInitFn,
    ) -> TestWithPending<'a, StorageInitIter, PendingInitIntoIterator::IntoIter>
    where
        PendingInitIntoIterator: IntoIterator<Item = PendingInitItem>,
        PendingInitFn: FnOnce(&Transaction<'_>) -> PendingInitIntoIterator,
    {
        let mut connection = self.storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        let pending_init = f(&tx);
        tx.commit().unwrap();
        TestWithPending {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: pending_init.into_iter(),
        }
    }
}

pub struct TestWithPending<'a, StorageInitIter, PendingInitIter> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    pending_init: PendingInitIter,
}

impl<'a, StorageInitIter, PendingInitIter> TestWithPending<'a, StorageInitIter, PendingInitIter> {
    /// Initialize test setup with a sequence of test params.
    /// Each item in the sequence corresponds to a separate test case.
    #[allow(dead_code)]
    pub fn with_params<ParamsIntoIterator, ParamsItem>(
        self,
        params: ParamsIntoIterator,
    ) -> TestWithParams<'a, StorageInitIter, PendingInitIter, ParamsIntoIterator::IntoIter>
    where
        ParamsItem: Serialize,
        ParamsIntoIterator: IntoIterator<Item = ParamsItem>,
    {
        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: self.pending_init,
            params: params.into_iter(),
        }
    }

    /// Initialize test setup with a sequence of test params
    /// which are of type `serde_json::Value`.
    /// Each item in the sequence corresponds to a separate test case.
    ///
    /// Useful for handling test cases where consecutive param sets
    /// contain vastly different variants.
    #[allow(dead_code)]
    pub fn with_params_json0<ParamsIntoIterator>(
        self,
        params: ParamsIntoIterator,
    ) -> TestWithParams<'a, StorageInitIter, PendingInitIter, ParamsIntoIterator::IntoIter>
    where
        ParamsIntoIterator: IntoIterator<Item = &'a serde_json::Value>,
    {
        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: self.pending_init,
            params: params.into_iter(),
        }
    }

    /// Initialize test setup with a single json array.
    /// Each item in the json array corresponds to a separate test case.
    /// **Any other json type will be automatically wrapped in a json
    /// array and treated as a single test case.**
    ///
    /// Useful for handling test cases where consecutive param sets
    /// contain vastly different variants.
    pub fn with_params_json(
        self,
        params: serde_json::Value,
    ) -> TestWithParams<
        'a,
        StorageInitIter,
        PendingInitIter,
        impl Clone + Iterator<Item = serde_json::Value>,
    > {
        let params = match params {
            serde_json::Value::Array(v) => v,
            _ => vec![params],
        };

        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: self.pending_init,
            params: params.into_iter(),
        }
    }
}

pub struct TestWithParams<'a, StorageInitIter, PendingInitIter, ParamsIter> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    pending_init: PendingInitIter,
    params: ParamsIter,
}

impl<'a, StorageInitIter, PendingInitIter, ParamsIter>
    TestWithParams<'a, StorageInitIter, PendingInitIter, ParamsIter>
{
    /// Map actual `jsonrpsee::core::Error` replies from the RPC server to a more manageable type,
    /// so that expressing the actual expected outputs is easier.
    /// The mapping function also takes the line and test case numbers.
    pub fn map_err<MapErrFn, MappedError>(
        self,
        f: MapErrFn,
    ) -> TestWithMapErr<'a, StorageInitIter, PendingInitIter, ParamsIter, MapErrFn>
    where
        MapErrFn: FnOnce(jsonrpsee::core::Error, u32, usize) -> MappedError,
    {
        TestWithMapErr {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: self.pending_init,
            params: self.params,
            map_err_fn: f,
        }
    }

    /// Map actual `jsonrpsee::core::Error` replies from the RPC server to [StarkWare error codes](crate::rpc::types::reply::ErrorCode),
    /// so that expressing the actual expected outputs is easier.
    /// Panics if the mapping fails, outputing the actual `jsonrpsee::core::Error`, line, and test case numbers.
    pub fn map_err_to_starkware_error_code(
        self,
    ) -> TestWithMapErr<
        'a,
        StorageInitIter,
        PendingInitIter,
        ParamsIter,
        impl Copy
            + FnOnce(jsonrpsee::core::Error, u32, usize) -> crate::rpc::v01::types::reply::ErrorCode,
    > {
        self.map_err(|error, line, test_case| match &error {
            jsonrpsee::core::Error::Call(jsonrpsee::types::error::CallError::Custom(custom)) => {
                match crate::rpc::v01::types::reply::ErrorCode::try_from(custom.code()) {
                    Ok(error_code) => error_code,
                    Err(_) => panic!("line {line}, test case {test_case}: {error}"),
                }
            }
            _ => panic!("line {line}, test case {test_case}: {error}"),
        })
    }
}

pub struct TestWithMapErr<'a, StorageInitIter, PendingInitIter, ParamsIter, MapErrFn> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    pending_init: PendingInitIter,
    params: ParamsIter,
    map_err_fn: MapErrFn,
}

impl<'a, StorageInitIter, PendingInitIter, ParamsIter, MapErrFn>
    TestWithMapErr<'a, StorageInitIter, PendingInitIter, ParamsIter, MapErrFn>
{
    /// Initialize test setup with a sequence of expected test outputs.
    ///
    /// - Each item in the resulting sequence corresponds to a separate test case.
    /// - This function panics if the lenght of the `expected` sequence
    /// is different from the `params` sequence in [`GotStorage::with_params`].
    #[allow(dead_code)]
    pub fn with_expected<ExpectedIntoIterator, ExpectedIter, ExpectedOk, MappedError>(
        self,
        expected: ExpectedIntoIterator,
    ) -> TestWithExpected<'a, PendingInitIter, ParamsIter, ExpectedIntoIterator::IntoIter, MapErrFn>
    where
        ExpectedIntoIterator: IntoIterator<Item = Result<ExpectedOk, MappedError>>,
        <ExpectedIntoIterator as IntoIterator>::IntoIter: Clone,
        ExpectedOk: Clone,
        ParamsIter: Clone + Iterator,
    {
        let expected_iter = expected.into_iter();
        let expected_cnt = expected_iter.clone().count();
        let params_cnt = self.params.clone().count();
        std::assert_eq!(params_cnt, expected_cnt,
                        "numbers of test cases from vectors differ (params: {params_cnt}, expected outputs: {expected_cnt}), line {}", self.line);
        TestWithExpected {
            method: self.method,
            line: self.line,
            storage: self.storage,
            pending_init: self.pending_init,
            params: self.params,
            expected: expected_iter,
            map_err_fn: self.map_err_fn,
        }
    }

    /// Initialize test setup with a sequence of expected test outputs
    /// by mapping from the storage initialization sequence.
    /// Useful for test cases where expected outputs are the same or very
    /// similar types to what was inserted into storage upon its initialization.
    ///
    /// - Each item in the resulting sequence corresponds to a separate test case.
    /// - This function panics if the lenght of the `expected` sequence
    /// is different from the `params` sequence in [`GotStorage::with_params`].
    pub fn map_expected<
        StorageAndPendingInitToExpectedMapperFn,
        ExpectedIntoIterator,
        ExpectedOk,
        MappedError,
    >(
        self,
        f: StorageAndPendingInitToExpectedMapperFn,
    ) -> TestWithExpected<'a, PendingInitIter, ParamsIter, ExpectedIntoIterator::IntoIter, MapErrFn>
    where
        PendingInitIter: Clone,
        StorageAndPendingInitToExpectedMapperFn:
            FnOnce(StorageInitIter, PendingInitIter) -> ExpectedIntoIterator,
        ExpectedIntoIterator: IntoIterator<Item = Result<ExpectedOk, MappedError>>,
        <ExpectedIntoIterator as IntoIterator>::IntoIter: Clone,
        ExpectedOk: Clone,
        ParamsIter: Clone + Iterator,
    {
        let expected_iter = f(self.storage_init, self.pending_init.clone()).into_iter();
        let expected_cnt = expected_iter.clone().count();
        let params_cnt = self.params.clone().count();
        std::assert_eq!(params_cnt, expected_cnt,
                        "numbers of test cases from vectors differ (params: {params_cnt}, expected outputs: {expected_cnt}), line {}", self.line);
        TestWithExpected {
            method: self.method,
            line: self.line,
            storage: self.storage,
            pending_init: self.pending_init,
            params: self.params,
            expected: expected_iter,
            map_err_fn: self.map_err_fn,
        }
    }
}

pub struct TestWithExpected<'a, PendingInitIter, ParamsIter, ExpectedIter, MapErrFn> {
    method: &'a str,
    line: u32,
    storage: Storage,
    pending_init: PendingInitIter,
    params: ParamsIter,
    expected: ExpectedIter,
    map_err_fn: MapErrFn,
}

impl<'a, PendingInitIter, ParamsIter, ExpectedIter, ExpectedOk, MapErrFn, MappedError>
    TestWithExpected<'a, PendingInitIter, ParamsIter, ExpectedIter, MapErrFn>
where
    ParamsIter: Iterator,
    ExpectedIter: Iterator<Item = Result<ExpectedOk, MappedError>>,
    ExpectedOk: Clone + ::serde::de::DeserializeOwned + Debug + PartialEq,
    MapErrFn: FnOnce(jsonrpsee::core::Error, u32, usize) -> MappedError + Copy,
    MappedError: Debug + PartialEq,
{
    /// Runs the test cases.
    pub async fn run(self)
    where
        <ParamsIter as Iterator>::Item: Debug + Serialize,
    {
        use crate::core::Chain;
        use crate::rpc::{
            test_client::client,
            {RpcApi, RpcServer},
        };
        use crate::sequencer::Client;
        use crate::state::SyncState;
        use jsonrpsee::rpc_params;
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        use std::sync::Arc;

        let storage = self.storage;
        let sequencer = Client::new(Chain::Testnet).unwrap();
        let sync_state = Arc::new(SyncState::default());
        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);

        let line = self.line;

        let (__handle, addr) = RpcServer::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            api,
        )
        .run()
        .await
        .unwrap_or_else(|error| panic!("line {line}, failed to create test server {error}"));

        let params_iter = self.params;
        let expected_iter = self.expected;

        let client = client(addr);

        for (i, (params, expected)) in params_iter.zip(expected_iter).enumerate() {
            let serialized_params = serde_json::to_string(&params).unwrap_or_else(|_| {
                panic!(
                    "line {line}, test case {i}, inputs should be serializable to JSON {params:?}"
                )
            });
            let params = rpc_params!(params);
            let actual = client.request::<ExpectedOk>(self.method, params).await;
            let actual = actual.map_err(|error| (self.map_err_fn)(error, self.line, i));
            std::assert_eq!(
                actual,
                expected,
                "line {line}, test case {i}, inputs {serialized_params}"
            );
        }
    }
}
