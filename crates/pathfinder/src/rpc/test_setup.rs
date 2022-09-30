///! Utilities for easier construction of RPC tests.
use crate::storage::Storage;
use rusqlite::Transaction;

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
    /// Initialize test setup with a sequence of test params.
    /// Each item in the sequence corresponds to a separate test case.
    #[allow(dead_code)]
    pub fn with_params<ParamsIntoIterator, ParamsItem>(
        self,
        params: ParamsIntoIterator,
    ) -> TestWithParams<'a, StorageInitIter, ParamsIntoIterator::IntoIter>
    where
        ParamsItem: ::serde::Serialize,
        ParamsIntoIterator: IntoIterator<Item = ParamsItem>,
    {
        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
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
    ) -> TestWithParams<'a, StorageInitIter, ParamsIntoIterator::IntoIter>
    where
        ParamsIntoIterator: IntoIterator<Item = &'a serde_json::Value>,
    {
        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            params: params.into_iter(),
        }
    }

    /// # Usage
    ///
    /// Initialize test setup with a single json array.
    /// Each item in the json array corresponds to a separate test case.
    /// Each test case can either be a:
    /// - json array, to represent **positional args**,
    /// - or a json object, to represent **named args**.
    ///
    /// # Examples
    ///
    /// ```
    /// with_params_json(json!([
    ///     ["a single", "positional test case"]
    /// ]))
    /// with_params_json(json!([
    ///     {"arg0": "a single",
    ///      "arg1": "named test case"}
    /// ]))
    /// with_params_json(json!([
    ///     ["1st", "positional test case"],
    ///     ["2nd", "positional", "test case"]
    /// ]))
    /// with_params_json(json!([
    ///     {"arg0": "1st",
    ///      "arg1": "named test case"},
    ///     {"arg0": "2nd",
    ///      "arg1": "named test",
    ///      "arg2": "case"}
    /// ]))
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the outer most json type is not an array.
    ///
    /// # Rationale
    ///
    /// Useful for handling test cases where consecutive param sets
    /// contain vastly different variants.
    pub fn with_params_json(
        self,
        params: serde_json::Value,
    ) -> TestWithParams<'a, StorageInitIter, impl Clone + Iterator<Item = serde_json::Value>> {
        let params = match params {
            serde_json::Value::Array(v) => v,
            _ => panic!(
                "The outer most json type has to be an array that contains parameter sets,
            either positional or named."
            ),
        };

        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            params: params.into_iter(),
        }
    }
}

pub struct TestWithParams<'a, StorageInitIter, ParamsIter> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    params: ParamsIter,
}

impl<'a, StorageInitIter, ParamsIter> TestWithParams<'a, StorageInitIter, ParamsIter> {
    /// Map actual `jsonrpsee::core::Error` replies from the RPC server to a more manageable type,
    /// so that expressing the actual expected outputs is easier.
    /// The mapping function also takes the line and test case numbers.
    pub fn map_err<MapErrFn, MappedError>(
        self,
        f: MapErrFn,
    ) -> TestWithMapErr<'a, StorageInitIter, ParamsIter, MapErrFn>
    where
        MapErrFn: FnOnce(jsonrpsee::core::Error, u32, usize) -> MappedError,
    {
        TestWithMapErr {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
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

pub struct TestWithMapErr<'a, StorageInitIter, ParamsIter, MapErrFn> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    params: ParamsIter,
    map_err_fn: MapErrFn,
}

impl<'a, StorageInitIter, ParamsIter, MapErrFn>
    TestWithMapErr<'a, StorageInitIter, ParamsIter, MapErrFn>
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
    ) -> TestWithExpected<'a, ParamsIter, ExpectedIntoIterator::IntoIter, MapErrFn>
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
        StorageInitToExpectedMapperFn,
        ExpectedIntoIterator,
        ExpectedOk,
        MappedError,
    >(
        self,
        f: StorageInitToExpectedMapperFn,
    ) -> TestWithExpected<'a, ParamsIter, ExpectedIntoIterator::IntoIter, MapErrFn>
    where
        StorageInitToExpectedMapperFn: FnOnce(StorageInitIter) -> ExpectedIntoIterator,
        ExpectedIntoIterator: IntoIterator<Item = Result<ExpectedOk, MappedError>>,
        <ExpectedIntoIterator as IntoIterator>::IntoIter: Clone,
        ExpectedOk: Clone,
        ParamsIter: Clone + Iterator,
    {
        let expected_iter = f(self.storage_init).into_iter();
        let expected_cnt = expected_iter.clone().count();
        let params_cnt = self.params.clone().count();
        std::assert_eq!(params_cnt, expected_cnt,
                        "numbers of test cases from vectors differ (params: {params_cnt}, expected outputs: {expected_cnt}), line {}", self.line);
        TestWithExpected {
            method: self.method,
            line: self.line,
            storage: self.storage,
            params: self.params,
            expected: expected_iter,
            map_err_fn: self.map_err_fn,
        }
    }
}

pub struct TestWithExpected<'a, ParamsIter, ExpectedIter, MapErrFn> {
    method: &'a str,
    line: u32,
    storage: Storage,
    params: ParamsIter,
    expected: ExpectedIter,
    map_err_fn: MapErrFn,
}

impl<'a, ParamsIter, ExpectedIter, ExpectedOk, MapErrFn, MappedError>
    TestWithExpected<'a, ParamsIter, ExpectedIter, MapErrFn>
where
    ParamsIter: Iterator,
    ExpectedIter: Iterator<Item = Result<ExpectedOk, MappedError>>,
    ExpectedOk: Clone + ::serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
    MapErrFn: FnOnce(jsonrpsee::core::Error, u32, usize) -> MappedError + Copy,
    MappedError: std::fmt::Debug + PartialEq,
{
    /// Runs the test cases.
    pub async fn run(self)
    where
        <ParamsIter as Iterator>::Item: ::serde::Serialize,
    {
        use crate::core::Chain;
        use crate::rpc::{
            test_client::client,
            {RpcApi, RpcServer},
        };
        use crate::sequencer::Client;
        use crate::state::SyncState;
        use futures::stream::StreamExt;
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        use std::sync::Arc;

        let storage = self.storage;
        let sequencer = Client::new(Chain::Testnet).unwrap();
        let sync_state = Arc::new(SyncState::default());
        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
        let (__handle, addr) = RpcServer::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            api,
        )
        .run()
        .await
        .unwrap();

        let params_iter = self.params;
        let expected_iter = self.expected;

        let client = client(addr);

        let actual_results = params_iter
            .enumerate()
            .map(|(i, params)| {
                let params = serde_json::to_value(params).expect(&format!(
                    "failed to serialize input params: line {}, test case {i}",
                    self.line
                ));
                client.request::<ExpectedOk>(self.method, params)
            })
            .collect::<futures::stream::FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await;

        for (i, (actual, expected)) in actual_results.into_iter().zip(expected_iter).enumerate() {
            std::assert_eq!(
                actual.map_err(|error| (self.map_err_fn)(error, self.line, i)),
                expected,
                "line {}, test case {i}",
                self.line
            );
        }
    }
}
