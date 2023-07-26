//! This test was separated because the `metrics` crate uses a singleton recorder, so keeping a test
//! that relies on metric values in a separate binary makes more sense than using an inter-test
//! locking mechanism which can cause weird test failures without any obvious clue to what might
//! have caused those failures in the first place.

#[tokio::test]
async fn api_versions_are_routed_correctly_for_all_methods() {
    use pathfinder_common::test_utils::metrics::{FakeRecorder, ScopedRecorderGuard};
    use pathfinder_rpc::middleware::versioning::test_utils::{method_names, paths};
    use pathfinder_rpc::test_client::TestClientBuilder;
    use pathfinder_rpc::{context::RpcContext, metrics::logger::RpcMetricsLogger, RpcServer};
    use serde_json::json;

    let context = RpcContext::for_tests();
    let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
        .with_logger(RpcMetricsLogger)
        .run()
        .await
        .unwrap();

    let v03_methods = method_names::COMMON_FOR_V03_V04
        .into_iter()
        .chain(method_names::V03_ONLY.into_iter())
        .collect::<Vec<_>>();
    let v04_methods = method_names::COMMON_FOR_V03_V04
        .into_iter()
        .chain(method_names::V04_ONLY.into_iter())
        .collect::<Vec<_>>();
    let pathfinder_methods = method_names::COMMON_FOR_ALL
        .into_iter()
        .chain(method_names::PATHFINDER_ONLY.into_iter())
        .collect();

    for (paths, version, methods) in vec![
        (paths::V03, "v0.3", v03_methods),
        (paths::V04, "v0.4", v04_methods),
        (paths::PATHFINDER, "v0.1", pathfinder_methods),
    ]
    .into_iter()
    {
        let recorder = FakeRecorder::default();
        let handle = recorder.handle();
        // Automatically deregister the recorder
        let _guard = ScopedRecorderGuard::new(recorder);

        // Perform all the calls but don't assert the results just yet
        for (i, path) in paths.iter().map(ToOwned::to_owned).enumerate() {
            let client = TestClientBuilder::default()
                .address(address)
                .endpoint(path.into())
                .build()
                .unwrap();

            for method in methods.iter() {
                let res = client.request::<serde_json::Value>(method, json!([])).await;

                match res {
                    Err(jsonrpsee::core::Error::Call(
                        jsonrpsee::types::error::CallError::Custom(e),
                    )) if e.code() == jsonrpsee::types::error::METHOD_NOT_FOUND_CODE => {
                        panic!("Unregistered method called, path: {path}, method: {method}")
                    }
                    Ok(_) | Err(_) => {
                        let expected_counter = (i as u64) + 1;
                        let actual_counter = handle.get_counter_value_by_label(
                            "rpc_method_calls_total",
                            [("method", method), ("version", version)],
                        );
                        assert_eq!(
                            actual_counter, expected_counter,
                            "path: {path}, method: {method}"
                        );
                    }
                }
            }
        }
    }
}
