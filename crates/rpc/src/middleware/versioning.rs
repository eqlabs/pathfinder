//! Middleware that proxies requests at a specified URI to internal
//! RPC method calls.
use http::{response::Builder, status::StatusCode};
use hyper::body::HttpBody;
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
    #[error("JSON-RPC notification queries are not allowed, please specify the `id` property")]
    Notification,
    #[error("MethodNotAllowed")]
    MethodNotAllowed,
    #[error("HealthCheck")]
    HealthCheck,
}

impl VersioningError {
    fn to_response(&self) -> Response<Body> {
        match self {
            VersioningError::InvalidPath => response::not_found(),
            VersioningError::TooLarge(limit) => response::too_large(*limit),
            VersioningError::Malformed => response::malformed(),
            VersioningError::Internal => response::internal(),
            VersioningError::Notification => response::notification(),
            VersioningError::MethodNotAllowed => response::method_not_allowed(),
            VersioningError::HealthCheck => response::ok_with_empty_body(),
        }
    }
}

pub(crate) async fn prefix_rpc_method_names_with_version(
    request: Request<Body>,
    max_request_body_size: u32,
) -> Result<Request<Body>, BoxError> {
    // Retain the parts to then later recreate the request
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    // An empty path "" is treated the same as "/".
    // However for a non-empty path adding a trailing slash
    // makes it a different path from the original,
    // that's why we have to account for those separately.
    let prefixes = match path {
        // Special health check endpoint to satisfy bots
        // - we don't really care about the http method here
        // - root is treated as a health check endpoint **only if it has an empty body**
        "/" if body.is_end_stream() => {
            return Err(BoxError::from(VersioningError::HealthCheck));
        }
        // RPC endpoints
        "/" | "/rpc/v0.3" | "/rpc/v0.3/" => &[("starknet_", "v0.3_"), ("pathfinder_", "v0.3_")][..],
        "/rpc/v0.4" | "/rpc/v0.4/" => &[("starknet_", "v0.4_"), ("pathfinder_", "v0.4_")][..],
        "/rpc/pathfinder/v0.1" | "/rpc/pathfinder/v0.1/" => &[("pathfinder_", "v0.1_")][..],
        _ => {
            return Err(BoxError::from(VersioningError::InvalidPath));
        }
    };

    // Only POST & OPTIONS is allowed for the RPC endpoints
    // but OPTIONS is handled by the cors middleware
    if parts.method != http::Method::POST {
        return Err(BoxError::from(VersioningError::MethodNotAllowed));
    }

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
            Err(_) => match serde_json::from_slice::<
                jsonrpsee::types::Notification<'_, Option<&serde_json::value::RawValue>>,
            >(&body)
            {
                // Pathfinder explicitly disallows JSON-RPC Notifications from the client
                Ok(_) => return Err(BoxError::from(VersioningError::Notification)),
                Err(_) => Ok(None),
            },
        }
    } else {
        match serde_json::from_slice::<Vec<jsonrpsee::types::Request<'_>>>(&body) {
            Ok(mut batch) => {
                batch
                    .iter_mut()
                    .for_each(|request| prefix_method(request, prefixes));
                serde_json::to_vec(&batch).map(Option::Some)
            }
            Err(_) => {
                match serde_json::from_slice::<Vec<serde_json::Value>>(&body) {
                    Ok(json_array) => {
                        // Pathfinder explicitly disallows JSON-RPC Notifications from the client
                        if json_array.into_iter().any(|item| {
                            item.as_object()
                                .map(|obj| {
                                    !obj.contains_key("id")
                                        && obj.contains_key("jsonrpc")
                                        && obj.contains_key("method")
                                })
                                .unwrap_or_default()
                        }) {
                            return Err(BoxError::from(VersioningError::Notification));
                        }

                        Ok(None)
                    }
                    Err(_) => Ok(None),
                }
            }
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

    pub(super) fn ok_with_empty_body() -> Response<Body> {
        with_body(StatusCode::OK, Body::empty())
    }

    pub(super) fn not_found() -> Response<Body> {
        with_canonical_reason(StatusCode::NOT_FOUND)
    }

    pub(super) fn too_large(limit: u32) -> Response<Body> {
        with_rpc_error(StatusCode::PAYLOAD_TOO_LARGE, reject_too_big_request(limit))
    }

    pub(super) fn malformed() -> Response<Body> {
        with_rpc_error(StatusCode::BAD_REQUEST, ErrorCode::ParseError)
    }

    pub(super) fn internal() -> Response<Body> {
        with_rpc_error(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError)
    }

    pub(super) fn notification() -> Response<Body> {
        let error = ErrorObject::owned(ErrorCode::InvalidRequest.code(), "Invalid request, JSON-RPC notification queries are not allowed, please specify the `id` property\n", Option::<()>::None);
        with_rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error)
    }

    pub(super) fn method_not_allowed() -> Response<Body> {
        with_body(
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST or OPTIONS method is allowed\n",
        )
    }

    fn with_rpc_error<'a>(code: StatusCode, error: impl Into<ErrorObject<'a>>) -> Response<Body> {
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

    fn with_body(code: StatusCode, body: impl Into<Body>) -> Response<Body> {
        Builder::new()
            .status(code)
            .header(CONTENT_TYPE, TEXT)
            .body(body.into())
            .expect("response is properly formed")
    }
}

pub mod test_utils {
    pub mod method_names {
        pub const COMMON_FOR_V03_V04: [&str; 23] = [
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
        pub const V04_ONLY: [&str; 1] = ["starknet_simulateTransactions"];
        pub const PATHFINDER_ONLY: [&str; 1] = ["pathfinder_version"];
    }

    pub mod paths {
        pub const V03: &[&str] = &["", "/", "/rpc/v0.3", "/rpc/v0.3/"];
        pub const V04: &[&str] = &["/rpc/v0.4", "/rpc/v0.4/"];
        pub const PATHFINDER: &[&str] = &["/rpc/pathfinder/v0.1", "/rpc/pathfinder/v0.1/"];
    }
}

#[cfg(test)]
mod tests {
    use super::prefix_rpc_method_names_with_version;
    use super::test_utils::{method_names, paths};
    use crate::test_client::TestClientBuilder;
    use crate::{RpcContext, RpcServer};
    use http::Method;
    use jsonrpsee::core::error::Error;
    use jsonrpsee::types::error::{CallError, METHOD_NOT_FOUND_CODE};
    use rstest::rstest;
    use serde_json::json;

    // In an unintentional way OFC: if a method is INTENDED to be available
    // on many paths then this is absolutely allowed.
    #[tokio::test]
    async fn api_versions_dont_leak_between_each_other() {
        let context = RpcContext::for_tests();
        let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
            .run()
            .await
            .unwrap();

        let not_in_v03 = method_names::PATHFINDER_ONLY
            .into_iter()
            .chain(method_names::V04_ONLY.into_iter())
            .collect::<Vec<_>>();
        let not_in_v04 = method_names::PATHFINDER_ONLY
            .into_iter()
            .chain(method_names::V03_ONLY.into_iter())
            .collect::<Vec<_>>();
        let not_in_pathfinder = method_names::COMMON_FOR_V03_V04
            .into_iter()
            .chain(method_names::V03_ONLY.into_iter())
            .chain(method_names::V04_ONLY.into_iter())
            .collect::<Vec<_>>();

        for (paths, methods) in vec![
            (paths::V03, not_in_v03),
            (paths::V04, not_in_v04),
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
                        Err(Error::Call(CallError::Custom(e)))
                            if e.code() == METHOD_NOT_FOUND_CODE =>
                        {
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

    #[rstest]
    // Root requires empty body to become health
    #[case("", "", 200, "")]
    #[case("/", "", 200, "")]
    #[tokio::test]
    async fn health_ignores_http_method(
        #[case] path: &str,
        #[case] body: &str,
        #[case] expected_code: u16,
        #[case] expected_body: &str,
        // We really care about these two but any is fine
        #[values(Method::POST, Method::GET)] http_method: Method,
    ) {
        let context = RpcContext::for_tests();
        let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
            .run()
            .await
            .unwrap();

        let url = format!("http://{address}{path}");

        let resp = reqwest::Client::new()
            .request(http_method, url)
            .body(body.to_owned())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status().as_u16(), expected_code);
        assert_eq!(resp.text().await.unwrap(), expected_body);
    }

    #[rstest]
    // Valid paths that accept POST only
    #[case("/", "body is not empty so this is not health", 405)]
    #[case("/rpc/v0.3/", "", 405)]
    #[case("/rpc/v0.3/", "a body", 405)]
    #[case("/rpc/pathfinder/v0.1/", "", 405)]
    #[case("/rpc/pathfinder/v0.1/", "a body", 405)]
    // Invalid paths
    #[case("/neither/health/nor/rpc", "", 404)]
    #[case("/neither/health/nor/rpc", "a body", 404)]
    #[tokio::test]
    async fn invalid_path_or_method(
        #[case] path: &str,
        #[case] body: &str,
        #[case] expected_status: u16,
        // Some unsupported http methods
        #[values(Method::GET, Method::PUT, Method::DELETE, Method::HEAD)] http_method: Method,
    ) {
        let context = RpcContext::for_tests();
        let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
            .run()
            .await
            .unwrap();

        let url = format!("http://{address}{path}");

        let resp = reqwest::Client::new()
            .request(http_method, url)
            .body(body.to_owned())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status().as_u16(), expected_status);
    }

    #[rstest]
    // Notification w/o params
    #[case(r#"{"jsonrpc":"2.0","method":"foo"}"#)]
    // Request, notification, w/o params
    #[case(r#"[{"jsonrpc":"2.0","method":"foo","id":0},{"jsonrpc":"2.0","method":"foo"}]"#)]
    // Notification w params
    #[case(r#"{"jsonrpc":"2.0","method":"foo","params":["bar"]}"#)]
    // Request, notification, w params
    #[case(r#"[{"jsonrpc":"2.0","method":"foo","params":[1],"id":0},{"jsonrpc":"2.0","method":"foo","params":[1,2]}]"#)]
    #[tokio::test]
    async fn disallow_notifications(#[case] body: &str) {
        let mut request = http::Request::new(hyper::Body::from(body.to_owned()));
        *request.method_mut() = http::Method::POST;
        let error = prefix_rpc_method_names_with_version(request, 1_000)
            .await
            .unwrap_err()
            .downcast::<super::VersioningError>()
            .unwrap();
        assert!(matches!(*error, super::VersioningError::Notification));
    }

    #[rstest]
    // Neither valid requests nor valid notifications but valid json
    #[case(r#"{"jsonrpc":"2.0"}"#)]
    #[case(r#"[{"jsonrpc":"2.0"},{"method":"foo"}]"#)]
    #[case(r#"{"id":0}"#)]
    #[case(r#"[{"id":0},{"method":"foo"}]"#)]
    #[case(r#"{"foo":"bar"}"#)]
    #[case(r#"["foo","bar"]"#)]
    // Valid requests
    #[case(r#"{"jsonrpc":"2.0","method":"foo","id":0,"params":[1]}"#)]
    #[case(r#"[{"jsonrpc":"2.0","method":"foo","id":0,"params":"bar"},{"jsonrpc":"2.0","method":"bar","id":0,"params":[1,2]}]"#)]
    #[tokio::test]
    async fn pass_non_notifications(#[case] body: &str) {
        let mut request = http::Request::new(hyper::Body::from(body.to_owned()));
        *request.method_mut() = http::Method::POST;
        let processed_body = prefix_rpc_method_names_with_version(request, 1_000)
            .await
            .unwrap()
            .into_body();
        let processed_body = serde_json::from_slice::<serde_json::Value>(
            &hyper::body::to_bytes(processed_body).await.unwrap(),
        )
        .unwrap();
        let expected = serde_json::from_str::<serde_json::Value>(body).unwrap();
        assert_eq!(processed_body, expected);
    }
}
