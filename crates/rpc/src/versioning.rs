//! Middleware that proxies requests at a specified URI to internal
//! RPC method calls.
use http::{response::Builder, status::StatusCode};
use hyper::{Body, Request, Response};
use jsonrpsee::core::error::GenericTransportError;
use jsonrpsee::core::http_helpers::read_body;
use jsonrpsee::types::error::{reject_too_big_request, ErrorCode, ErrorResponse};
use jsonrpsee::types::Id;
use tower::BoxError;

#[derive(thiserror::Error, Debug)]
pub enum VersioningError {
    #[error("Invalid path")]
    InvalidPath,
    #[error("Too large: {0}")]
    TooLarge(u32),
    #[error("Malformed")]
    Malformed,
    #[error("Internal")]
    Internal,
}

impl VersioningError {
    fn to_response(&self) -> Response<Body> {
        match self {
            VersioningError::InvalidPath => response::not_found(),
            VersioningError::TooLarge(limit) => response::too_large(*limit),
            VersioningError::Malformed => response::malformed(),
            VersioningError::Internal => response::internal(),
        }
    }
}

pub async fn prefix_rpc_method_names_with_version(
    request: Request<Body>,
    max_request_body_size: u32,
) -> Result<Request<Body>, BoxError> {
    let prefixes = match request.uri().path() {
        // An empty path "" is treated the same as "/".
        // However for a non-empty path adding a trailing slash
        // makes it a different path from the original,
        // that's why we have to account for those separately.
        "/" | "/rpc/v0.2" | "/rpc/v0.2/" => &[("starknet_", "v0.2_"), ("pathfinder_", "v0.2_")][..],
        "/rpc/v0.3" | "/rpc/v0.3/" => &[("starknet_", "v0.3_"), ("pathfinder_", "v0.3_")][..],
        "/rpc/pathfinder/v0.1" | "/rpc/pathfinder/v0.1/" => &[("pathfinder_", "v0.1_")][..],
        _ => {
            return Err(BoxError::from(VersioningError::InvalidPath));
        }
    };

    // Retain the parts to then later recreate the request
    let (parts, body) = request.into_parts();

    let (body, is_single) = match read_body(&parts.headers, body, max_request_body_size).await {
        Ok(x) => x,
        Err(GenericTransportError::TooLarge) => {
            return Err(BoxError::from(VersioningError::TooLarge(
                max_request_body_size,
            )))
        }
        Err(GenericTransportError::Malformed) => {
            return Err(BoxError::from(VersioningError::Malformed))
        }
        Err(GenericTransportError::Inner(_)) => {
            return Err(BoxError::from(VersioningError::Internal))
        }
    };

    let new_body = if is_single {
        match serde_json::from_slice::<jsonrpsee::types::Request<'_>>(&body) {
            Ok(mut request) => {
                prefix_method(&mut request, prefixes);
                serde_json::to_vec(&request).map(Option::Some)
            }
            Err(_) => Ok(None),
        }
    } else {
        match serde_json::from_slice::<Vec<jsonrpsee::types::Request<'_>>>(&body) {
            Ok(mut batch) => {
                batch
                    .iter_mut()
                    .for_each(|request| prefix_method(request, prefixes));
                serde_json::to_vec(&batch).map(Option::Some)
            }
            Err(_) => Ok(None),
        }
    };

    let body = match new_body {
        // Body was read and processed successfuly
        Ok(Some(new_body)) => new_body,
        // Body was read successfully but processing failed,
        // pass the original payload to the inner service for proper error handling
        Ok(None) => body,
        // Reserialization failed
        Err(_) => return Err(BoxError::from(VersioningError::Internal)),
    };

    let request: Request<Body> = Request::from_parts(parts, body.into());

    Ok(request)
}

pub fn try_map_errors_to_responses(
    result: Result<Response<Body>, BoxError>,
) -> Result<Response<Body>, BoxError> {
    match result {
        Ok(response) => Ok(response),
        Err(error) => match error.downcast_ref::<VersioningError>() {
            Some(error) => Ok(error.to_response()),
            None => Err(error),
        },
    }
}

fn prefix_method(request: &mut jsonrpsee::types::Request<'_>, prefixes: &[(&str, &str)]) {
    for (old, new) in prefixes {
        if request.method.starts_with(old) {
            let method = new.to_string() + &request.method;
            request.method = method.into();
            break;
        }
    }
}

/// These responses are 1:1 to what jsonrpsee could have exported
mod response {
    use jsonrpsee::types::ErrorObject;

    use super::*;

    const CONTENT_TYPE: &str = "content-type";
    const TEXT: &str = "text/plain";
    const JSON: &str = "application/json; charset=utf-8";

    pub(super) fn not_found() -> Response<Body> {
        with_canonical_reason(StatusCode::NOT_FOUND)
    }

    pub(super) fn too_large(limit: u32) -> Response<Body> {
        with_error(StatusCode::PAYLOAD_TOO_LARGE, reject_too_big_request(limit))
    }

    pub(super) fn malformed() -> Response<Body> {
        with_error(StatusCode::BAD_REQUEST, ErrorCode::ParseError)
    }

    pub(super) fn internal() -> Response<Body> {
        with_error(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError)
    }

    fn with_error<'a>(code: StatusCode, error: impl Into<ErrorObject<'a>>) -> Response<Body> {
        let body = ErrorResponse::borrowed(error.into(), Id::Null);
        let body = serde_json::to_string(&body)
            .expect("error response is serializable")
            .into();

        Builder::new()
            .status(code)
            .header(CONTENT_TYPE, JSON)
            .body(body)
            .expect("response is properly formed")
    }

    fn with_canonical_reason(code: StatusCode) -> Response<Body> {
        Builder::new()
            .status(code)
            .header(CONTENT_TYPE, TEXT)
            .body(
                code.canonical_reason()
                    .expect("canonical reason is defined")
                    .into(),
            )
            .expect("response is properly formed")
    }
}

#[cfg(test)]
mod tests {

    const COMMON_FOR_V02_V03: [&str; 23] = [
        "starknet_addDeclareTransaction",
        "starknet_addDeployAccountTransaction",
        "starknet_addInvokeTransaction",
        "starknet_blockHashAndNumber",
        "starknet_blockNumber",
        "starknet_call",
        "starknet_chainId",
        "starknet_estimateFee",
        "starknet_getBlockWithTxHashes",
        "starknet_getBlockWithTxs",
        "starknet_getBlockTransactionCount",
        "starknet_getClass",
        "starknet_getClassAt",
        "starknet_getClassHashAt",
        "starknet_getEvents",
        "starknet_getNonce",
        "starknet_getStateUpdate",
        "starknet_getStorageAt",
        "starknet_getTransactionByBlockIdAndIndex",
        "starknet_getTransactionByHash",
        "starknet_getTransactionReceipt",
        "starknet_pendingTransactions",
        "starknet_syncing",
    ];
    const COMMON_FOR_ALL: [&str; 2] = ["pathfinder_getProof", "pathfinder_getTransactionStatus"];
    const V03_ONLY: [&str; 1] = ["starknet_simulateTransaction"];
    const PATHFINDER_ONLY: [&str; 1] = ["pathfinder_version"];

    const V02_PATHS: &[&str] = &["", "/", "/rpc/v0.2", "/rpc/v0.2/"];
    const V03_PATHS: &[&str] = &["/rpc/v0.3", "/rpc/v0.3/"];
    const PATHFINDER_PATHS: &[&str] = &["/rpc/pathfinder/v0.1", "/rpc/pathfinder/v0.1/"];

    #[tokio::test]
    async fn api_versions_are_routed_correctly_for_all_methods() {
        use crate::test_client::TestClientBuilder;
        use crate::{RpcContext, RpcMetricsLogger, RpcServer};
        use pathfinder_common::test_utils::metrics::{FakeRecorder, RecorderGuard};
        use serde_json::json;

        let context = RpcContext::for_tests();
        let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
            .with_logger(RpcMetricsLogger)
            .run()
            .await
            .unwrap();

        let v02_methods = COMMON_FOR_V02_V03
            .into_iter()
            .chain(COMMON_FOR_ALL.into_iter())
            .collect::<Vec<_>>();
        let v03_methods = v02_methods
            .clone()
            .into_iter()
            .chain(V03_ONLY.into_iter())
            .collect::<Vec<_>>();
        let pathfinder_methods = COMMON_FOR_ALL
            .into_iter()
            .chain(PATHFINDER_ONLY.into_iter())
            .collect();

        for (paths, version, methods) in vec![
            (V02_PATHS, "v0.2", v02_methods),
            (V03_PATHS, "v0.3", v03_methods),
            (PATHFINDER_PATHS, "v0.1", pathfinder_methods),
        ]
        .into_iter()
        {
            let recorder = FakeRecorder::default();
            let handle = recorder.handle();
            // Other concurrent tests could be setting their own recorders
            let guard = RecorderGuard::lock(recorder);

            let paths_len = paths.len();
            let paths_iter = paths.iter();

            // Perform all the calls but don't assert the results just yet
            for path in paths_iter.clone().map(ToOwned::to_owned) {
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
                            // Don't poison the internal lock
                            drop(guard);
                            panic!("Unregistered method called, path: {path}, method: {method}")
                        }
                        Ok(_) | Err(_) => {}
                    }
                }
            }

            // Drop the global recorder guard to avoid poisoning its internal lock if
            // the following asserts fail which would fail other tests using the `RecorderGuard`
            // at the same time.
            //
            // The recorder itself still exists since dropping the guard only unregisters the recorder
            // and leaks it making the handle still valid past this point.
            drop(guard);

            // Now we can safely assert all results
            for path in paths_iter.clone() {
                for method in methods.iter() {
                    let expected_counter = paths_len as u64;
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

    // In an unintentional way OFC: if a method is INTENDED to be available
    // on many paths then this is absolutely allowed.
    #[tokio::test]
    async fn api_versions_dont_leak_between_each_other() {
        use crate::test_client::TestClientBuilder;
        use crate::{RpcContext, RpcServer};
        use serde_json::json;

        let context = RpcContext::for_tests();
        let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
            .run()
            .await
            .unwrap();

        let not_in_v02 = V03_ONLY
            .into_iter()
            .clone()
            .chain(PATHFINDER_ONLY.into_iter())
            .collect::<Vec<_>>();
        let not_in_v03 = PATHFINDER_ONLY.into_iter().collect::<Vec<_>>();
        let not_in_pathfinder = COMMON_FOR_V02_V03
            .into_iter()
            .chain(V03_ONLY.into_iter())
            .collect::<Vec<_>>();

        for (paths, methods) in vec![
            (V02_PATHS, not_in_v02),
            (V03_PATHS, not_in_v03),
            (PATHFINDER_PATHS, not_in_pathfinder),
        ]
        .into_iter()
        {
            for path in paths.iter().map(ToOwned::to_owned) {
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
                            // Hurray, this method is not supposed to be available on this path
                        }
                        Ok(_) | Err(_) => {
                            panic!("Method {method} leaked into path: {path}")
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn invalid_path() {
        use crate::{RpcContext, RpcServer};

        let context = RpcContext::for_tests();
        let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
            .run()
            .await
            .unwrap();

        let url = format!("http://{address}/invalid/path");

        let status_code = reqwest::Client::new()
            .post(url)
            .body("")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();

        assert_eq!(status_code, 404);
    }
}
