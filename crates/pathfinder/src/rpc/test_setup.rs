///! Utilities for easier construction of RPC tests.
use crate::core::Chain;
use crate::rpc::test_client::client;
use crate::rpc::{RpcApi, RpcServer};
use crate::sequencer::reply::{PendingBlock, StateUpdate};
use crate::sequencer::Client;
use crate::state::PendingData;
use crate::state::SyncState;
use crate::storage::{fixtures::RawPendingData, Storage};
use ::serde::de::DeserializeOwned;
use ::serde::Serialize;
use jsonrpsee::http_server::HttpServerHandle;
use jsonrpsee::types::ParamsSer;
use rusqlite::Transaction;
use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

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
    /// The calls to `pending` will yield pending data from
    /// 1. the iterable collection created by the mapping function `f`
    /// 2. and when the resulting iterator is exhausted __empty__ pending data is returned
    pub fn map_pending_then_empty<PendingInitFn, PendingInitIntoIterator>(
        self,
        f: PendingInitFn,
    ) -> TestWithPending<'a, StorageInitIter, PendingInitIntoIterator::IntoIter>
    where
        StorageInitIter: Clone,
        PendingInitIntoIterator: IntoIterator,
        <PendingInitIntoIterator as IntoIterator>::Item: Into<RawPendingData>,
        PendingInitFn: FnOnce(&Transaction<'_>, StorageInitIter) -> PendingInitIntoIterator,
    {
        let mut connection = self.storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        let pending_init = f(&tx, self.storage_init.clone());
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
    /// Initialize test setup with a single JSON array `params`.
    /// Each item in `params` corresponds to a separate test case.
    ///
    /// An item in the `params` outermost JSON array should either be:
    /// - an array, it will then be treated as __positional__ params to the RPC method,
    /// - an object, it will then be treated as __named__ params to the RPC method.
    ///
    /// Panics if `params` is not a JSON array.
    /// Panics if any item in `params` outermost JSON array is neither an array nor an object.
    ///
    /// Useful for handling test cases where consecutive param sets
    /// contain vastly different variants.
    pub fn with_params(
        self,
        params: serde_json::Value,
    ) -> TestWithParams<'a, StorageInitIter, PendingInitIter> {
        let params = unwrap_json_array(params, self.line);

        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: self.pending_init,
            params,
        }
    }
}

pub struct TestWithParams<'a, StorageInitIter, PendingInitIter> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    pending_init: PendingInitIter,
    params: Vec<serde_json::Value>,
}

impl<'a, StorageInitIter, PendingInitIter> TestWithParams<'a, StorageInitIter, PendingInitIter> {
    /// Map actual `jsonrpsee::core::Error` replies from the RPC server to a more manageable type,
    /// so that expressing the actual expected outputs is easier.
    /// The mapping function also takes the line and test case numbers.
    pub fn map_err<MapErrFn, MappedError>(
        self,
        f: MapErrFn,
    ) -> TestWithMapErr<'a, StorageInitIter, PendingInitIter, MapErrFn>
    where
        MapErrFn: FnOnce(jsonrpsee::core::Error, &str) -> MappedError,
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
        impl Copy + FnOnce(jsonrpsee::core::Error, &str) -> crate::rpc::v01::types::reply::ErrorCode,
    > {
        self.map_err(|error, test_case_descr| match &error {
            jsonrpsee::core::Error::Call(jsonrpsee::types::error::CallError::Custom(custom)) => {
                match crate::rpc::v01::types::reply::ErrorCode::try_from(custom.code()) {
                    Ok(error_code) => error_code,
                    Err(_) => {
                        panic!("{test_case_descr}, mapping to starkware error code failed: {error}")
                    }
                }
            }
            _ => panic!("{test_case_descr}, expected custom call error, got: {error}"),
        })
    }
}

pub struct TestWithMapErr<'a, StorageInitIter, PendingInitIter, MapErrFn> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    pending_init: PendingInitIter,
    params: Vec<serde_json::Value>,
    map_err_fn: MapErrFn,
}

impl<'a, StorageInitIter, PendingInitIter, MapErrFn>
    TestWithMapErr<'a, StorageInitIter, PendingInitIter, MapErrFn>
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
    ) -> TestWithExpected<'a, PendingInitIter, ExpectedIntoIterator::IntoIter, MapErrFn>
    where
        ExpectedIntoIterator: IntoIterator<Item = Result<ExpectedOk, MappedError>>,
        <ExpectedIntoIterator as IntoIterator>::IntoIter: Clone,
        ExpectedOk: Clone,
    {
        let expected_iter = expected.into_iter();
        let expected_cnt = expected_iter.clone().count();
        let params_cnt = self.params.len();
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
    ) -> TestWithExpected<'a, PendingInitIter, ExpectedIntoIterator::IntoIter, MapErrFn>
    where
        PendingInitIter: Clone,
        StorageAndPendingInitToExpectedMapperFn:
            FnOnce(StorageInitIter, PendingInitIter) -> ExpectedIntoIterator,
        ExpectedIntoIterator: IntoIterator<Item = Result<ExpectedOk, MappedError>>,
        <ExpectedIntoIterator as IntoIterator>::IntoIter: Clone,
        ExpectedOk: Clone,
    {
        let expected_iter = f(self.storage_init, self.pending_init.clone()).into_iter();
        let expected_cnt = expected_iter.clone().count();
        let params_cnt = self.params.len();
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

pub struct TestWithExpected<'a, PendingInitIter, ExpectedIter, MapErrFn> {
    method: &'a str,
    line: u32,
    storage: Storage,
    pending_init: PendingInitIter,
    params: Vec<serde_json::Value>,
    expected: ExpectedIter,
    map_err_fn: MapErrFn,
}

impl<'a, PendingInitIter, ExpectedIter, MapErrFn>
    TestWithExpected<'a, PendingInitIter, ExpectedIter, MapErrFn>
{
    /// Add scenarios where pending support is disabled and internal server error is expected.
    /// Each item in `params` corresponds to a separate test case and each should
    /// represent some vaild input to the tested method that refers to the pending block.
    ///
    /// An item in the `params` outermost JSON array should either be:
    /// - an array, it will then be treated as __positional__ params to the RPC method,
    /// - an object, it will then be treated as __named__ params to the RPC method.
    ///
    /// Panics if `params` is not a JSON array.
    /// Panics if any item in `params` outermost JSON array is neither an array nor an object.
    pub fn then_expect_internal_err_when_pending_disabled(
        self,
        params: serde_json::Value,
        error_msg: &'a str,
    ) -> TestWithPendingDisabled<'a, PendingInitIter, ExpectedIter, MapErrFn> {
        let params = unwrap_json_array(params, self.line);

        TestWithPendingDisabled {
            method: self.method,
            line: self.line,
            storage: self.storage,
            pending_init: self.pending_init,
            params: self.params,
            expected: self.expected,
            map_err_fn: self.map_err_fn,
            pending_disabled: PendingDisabled { params, error_msg },
        }
    }
}

/// Holds data required for a disabled pending scenario
struct PendingDisabled<'a> {
    params: Vec<serde_json::Value>,
    error_msg: &'a str,
}

pub struct TestWithPendingDisabled<'a, PendingInitIter, ExpectedIter, MapErrFn> {
    method: &'a str,
    line: u32,
    storage: Storage,
    pending_init: PendingInitIter,
    params: Vec<serde_json::Value>,
    expected: ExpectedIter,
    map_err_fn: MapErrFn,
    pending_disabled: PendingDisabled<'a>,
}

impl<'a, PendingInitIter, ExpectedIter, ExpectedOk, MapErrFn, MappedError>
    TestWithPendingDisabled<'a, PendingInitIter, ExpectedIter, MapErrFn>
where
    PendingInitIter: Iterator,
    <PendingInitIter as Iterator>::Item: Into<RawPendingData>,
    ExpectedIter: Iterator<Item = Result<ExpectedOk, MappedError>>,
    ExpectedOk: Clone + DeserializeOwned + Debug + PartialEq,
    MapErrFn: FnOnce(jsonrpsee::core::Error, &str) -> MappedError + Copy,
    MappedError: Debug + PartialEq,
{
    /// Runs the test cases.
    pub async fn run(self) {
        let storage = self.storage;
        let sequencer = Client::new(Chain::Testnet).unwrap();
        let sync_state = Arc::new(SyncState::default());
        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);

        let line = self.line;
        let params_iter = self.params.into_iter();
        let expected_iter = self.expected;
        let mut pending_iter = self.pending_init;

        // Iterate through all the 'normal' scenarios
        for (test_case, (params, expected)) in params_iter.zip(expected_iter).enumerate() {
            let serialized_params = serialize_params(&params, line, test_case);
            let test_case_descr = test_case_descr(line, test_case, &serialized_params);
            let api = api_with_maybe_pending(&serialized_params, &mut pending_iter, &api).await;
            let (_handle, addr) = run_server(api, &test_case_descr).await;
            let client = client(addr);
            let params = serde_json::to_value(params).unwrap();
            let params = rpc_params(&params);
            let actual = client.request::<ExpectedOk>(self.method, params).await;
            let actual = actual.map_err(|error| (self.map_err_fn)(error, &test_case_descr));
            std::assert_eq!(actual, expected, "{test_case_descr}",);
        }

        // Now the 'disabled pending' scenario
        let params_array = self.pending_disabled.params;
        let expected_error_msg = self.pending_disabled.error_msg;
        let test_case = r#""disabled pending""#;

        for params in params_array {
            let serialized_params = serialize_params(&params, line, test_case);
            let test_case_descr = test_case_descr(line, test_case, &serialized_params);
            let (_handle, addr) = run_server(api.clone(), &test_case_descr).await;
            let client = client(addr);
            let params = rpc_params(&params);
            let actual = client.request::<ExpectedOk>(self.method, params).await;
            let error = actual.expect_err(&test_case_descr);

            use jsonrpsee::{core::error::Error, types::error::CallError};

            assert_matches::assert_matches!(error, Error::Call(CallError::Custom(error_object)) => {
                pretty_assertions::assert_eq!(error_object.message(), expected_error_msg, "{test_case_descr}");
                // Internal error
                // https://www.jsonrpc.org/specification#error_object
                pretty_assertions::assert_eq!(error_object.code(), -32603, "{test_case_descr}");
            });
        }
    }
}

fn serialize_params<Params: Debug + Serialize, TestCase: ToString>(
    params: &Params,
    line: u32,
    test_case: TestCase,
) -> String {
    serde_json::to_string(&params).unwrap_or_else(|_| {
        panic!(
            "line {line}, test case {}, inputs should be serializable to JSON: {params:?}",
            test_case.to_string()
        )
    })
}

fn test_case_descr<TestCase: ToString>(
    line: u32,
    test_case: TestCase,
    serialized_params: &str,
) -> String {
    format!(
        "line {line}, test case {}, inputs {}",
        test_case.to_string(),
        serialized_params,
    )
}

async fn api_with_maybe_pending<PendingInitIter>(
    serialized_params: &str,
    pending_init_iter: &mut PendingInitIter,
    api: &RpcApi,
) -> RpcApi
where
    PendingInitIter: Iterator,
    <PendingInitIter as Iterator>::Item: Into<RawPendingData>,
{
    // I know, this is fishy, but it still works because `pending` is stictly defined
    if serialized_params.contains(r#"pending"#) {
        match pending_init_iter.next() {
            // Some valid pending data fixture is available, use it
            Some(pending_data) => {
                let pending_data = pending_data.into();
                let block = pending_data.block.unwrap_or(PendingBlock::dummy_for_test());
                let state_update = pending_data
                    .state_update
                    .unwrap_or(StateUpdate::dummy_for_test());
                let pending_data = PendingData::default();
                pending_data
                    .set(Arc::new(block), Arc::new(state_update))
                    .await;
                api.clone().with_pending_data(pending_data)
            }
            // All valid pending data fixtures have been exhausted so __simulate empty pending data from now on__
            None => api.clone().with_pending_data(PendingData::default()),
        }
    } else {
        // Pending was not requested so just treat pending data as disabled
        api.clone()
    }
}

async fn run_server(api: RpcApi, failure_msg: &str) -> (HttpServerHandle, SocketAddr) {
    RpcServer::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        api,
    )
    .run()
    .await
    .expect(&failure_msg)
}

/// Workaround before rpc_params! is actually removed from __all__ tests
fn rpc_params<'a>(params: &'a serde_json::Value) -> Option<ParamsSer<'a>> {
    match params {
        serde_json::Value::Array(x) => Some(x.clone().into()),
        serde_json::Value::Object(x) => {
            let x = x
                .iter()
                .map(|(k, v)| (k.as_str(), v.clone()))
                .collect::<std::collections::BTreeMap<&'a str, serde_json::Value>>();

            Some(x.into())
        }
        _ => unreachable!("{params}"),
    }
}

fn json_value_type_name(value: &serde_json::Value) -> &str {
    match value {
        serde_json::Value::Null => "JSON null",
        serde_json::Value::Bool(_) => "JSON bool",
        serde_json::Value::Number(_) => "JSON number",
        serde_json::Value::String(_) => "JSON string",
        serde_json::Value::Array(_) => "JSON array",
        serde_json::Value::Object(_) => "JSON object",
    }
}

fn unwrap_json_array(params: serde_json::Value, line: u32) -> Vec<serde_json::Value> {
    let params = match params {
        serde_json::Value::Array(array) => array,
        _ => {
            let type_name = json_value_type_name(&params);
            panic!("line {line}, params sets for all test cases should be passed in a single JSON array, but got {params}, which is a {type_name}");
        }
    };

    params.iter().for_each(|x| if !x.is_array() && !x.is_object() {
        let type_name = json_value_type_name(x);
        panic!("line {line}, each params set for a single test case should be a JSON array or a JSON object \
            to represent positional or named method params respectively, but got {x}, which is a {type_name}")
    });

    params
}
