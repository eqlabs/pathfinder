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
enum VersioningError {
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

pub(crate) async fn prefix_rpc_method_names_with_version(
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

pub(crate) fn try_map_errors_to_responses(
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

pub mod test_utils {
    pub mod method_names {
        pub const COMMON_FOR_V02_V03: [&str; 23] = [
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
        pub const COMMON_FOR_ALL: [&str; 2] =
            ["pathfinder_getProof", "pathfinder_getTransactionStatus"];
        pub const V03_ONLY: [&str; 1] = ["starknet_simulateTransaction"];
        pub const PATHFINDER_ONLY: [&str; 1] = ["pathfinder_version"];
    }

    pub mod paths {
        pub const V02: &[&str] = &["", "/", "/rpc/v0.2", "/rpc/v0.2/"];
        pub const V03: &[&str] = &["/rpc/v0.3", "/rpc/v0.3/"];
        pub const PATHFINDER: &[&str] = &["/rpc/pathfinder/v0.1", "/rpc/pathfinder/v0.1/"];
    }
}

#[cfg(test)]
mod tests {

    use super::test_utils::{method_names, paths};

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

        let not_in_v02 = method_names::V03_ONLY
            .into_iter()
            .clone()
            .chain(method_names::PATHFINDER_ONLY.into_iter())
            .collect::<Vec<_>>();
        let not_in_v03 = method_names::PATHFINDER_ONLY
            .into_iter()
            .collect::<Vec<_>>();
        let not_in_pathfinder = method_names::COMMON_FOR_V02_V03
            .into_iter()
            .chain(method_names::V03_ONLY.into_iter())
            .collect::<Vec<_>>();

        for (paths, methods) in vec![
            (paths::V02, not_in_v02),
            (paths::V03, not_in_v03),
            (paths::PATHFINDER, not_in_pathfinder),
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
