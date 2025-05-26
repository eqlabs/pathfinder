use starknet_gateway_types::error::KnownStarknetErrorCode;

/// Helper function which allows for easy creation of a response tuple
/// that contains a
/// [StarknetError](starknet_gateway_types::error::StarknetError) for a
/// given [KnownStarknetErrorCode].
///
/// The response tuple can then be used by the [setup] function.
///
/// The `message` field is always an empty string.
/// The HTTP status code for this response is always `500` (`Internal Server
/// Error`).
pub fn response_from(code: KnownStarknetErrorCode) -> (String, u16) {
    use starknet_gateway_types::error::StarknetError;

    let e = StarknetError {
        code: code.into(),
        message: "".to_string(),
    };
    (serde_json::to_string(&e).unwrap(), 500)
}

/// # Usage
///
/// Use to initialize a server that the gateway client can connect to.
pub fn setup<S1, S2, const N: usize>(
    url_paths_queries_and_response_fixtures: [(S1, (S2, u16)); N],
) -> (Option<tokio::task::JoinHandle<()>>, reqwest::Url)
where
    S1: std::convert::AsRef<str>
        + std::fmt::Display
        + std::fmt::Debug
        + std::cmp::PartialEq
        + Send
        + Sync
        + Clone
        + 'static,
    S2: std::string::ToString + Send + Sync + Clone + 'static,
{
    use warp::Filter;
    let opt_query_raw = warp::query::raw()
        .map(Some)
        .or_else(|_| async { Ok::<(Option<String>,), std::convert::Infallible>((None,)) });
    let path = warp::any().and(warp::path::full()).and(opt_query_raw).map(
        move |full_path: warp::path::FullPath, raw_query: Option<String>| {
            let actual_full_path_and_query = match raw_query {
                Some(some_raw_query) => {
                    format!("{}?{}", full_path.as_str(), some_raw_query.as_str())
                }
                None => full_path.as_str().to_owned(),
            };

            match url_paths_queries_and_response_fixtures
                .iter()
                .find(|x| x.0.as_ref() == actual_full_path_and_query)
            {
                Some((_, (body, status))) => warp::http::response::Builder::new()
                    .status(*status)
                    .body(body.to_string()),
                None => panic!(
                    "Actual url path and query {} not found in the expected {:?}",
                    actual_full_path_and_query,
                    url_paths_queries_and_response_fixtures
                        .iter()
                        .map(|(expected_path, _)| expected_path)
                        .collect::<Vec<_>>()
                ),
            }
        },
    );

    let (addr, serve_fut) = warp::serve(path).bind_ephemeral(([127, 0, 0, 1], 0));
    let server_handle = tokio::spawn(serve_fut);
    let url = reqwest::Url::parse(&format!("http://{addr}")).unwrap();
    (Some(server_handle), url)
}

/// # Usage
///
/// Use to initialize a server that the gateway client can connect to. The
/// function does one of the following things:
/// - initializes a local mock server instance with the given expected url paths
///   & queries and respective fixtures for replies
/// - replies for a particular path & query are consumed one at a time until
///   exhausted
///
/// # Panics
///
/// Panics if replies for a particular path & query have been exhausted and
/// the client still attempts to query the very same path.
pub fn setup_with_varied_responses<const M: usize, const N: usize>(
    url_paths_queries_and_response_fixtures: [(String, [(String, u16); M]); N],
) -> (Option<tokio::task::JoinHandle<()>>, reqwest::Url) {
    let url_paths_queries_and_response_fixtures = url_paths_queries_and_response_fixtures
        .into_iter()
        .map(|x| {
            (
                x.0.clone(),
                x.1.into_iter().collect::<std::collections::VecDeque<_>>(),
            )
        })
        .collect::<Vec<_>>();
    use std::sync::{Arc, Mutex};

    let url_paths_queries_and_response_fixtures =
        Arc::new(Mutex::new(url_paths_queries_and_response_fixtures));

    use warp::Filter;
    let opt_query_raw = warp::query::raw()
        .map(Some)
        .or_else(|_| async { Ok::<(Option<String>,), std::convert::Infallible>((None,)) });
    let path = warp::any().and(warp::path::full()).and(opt_query_raw).map(
        move |full_path: warp::path::FullPath, raw_query: Option<String>| {
            let actual_full_path_and_query = match raw_query {
                Some(some_raw_query) => {
                    format!("{}?{}", full_path.as_str(), some_raw_query.as_str())
                }
                None => full_path.as_str().to_owned(),
            };

            let mut url_paths_queries_and_response_fixtures =
                url_paths_queries_and_response_fixtures.lock().unwrap();

            match url_paths_queries_and_response_fixtures
                .iter_mut()
                .find(|x| x.0 == actual_full_path_and_query)
            {
                Some((_, responses)) => {
                    let (body, status) =
                        responses.pop_front().expect("more responses for this path");
                    warp::http::response::Builder::new()
                        .status(status)
                        .body(body)
                }
                None => panic!(
                    "Actual url path and query {} not found in the expected {:?}",
                    actual_full_path_and_query,
                    url_paths_queries_and_response_fixtures
                        .iter()
                        .map(|(expected_path, _)| expected_path)
                        .collect::<Vec<_>>()
                ),
            }
        },
    );

    let (addr, serve_fut) = warp::serve(path).bind_ephemeral(([127, 0, 0, 1], 0));
    let server_handle = tokio::spawn(serve_fut);
    let url = reqwest::Url::parse(&format!("http://{addr}")).unwrap();
    (Some(server_handle), url)
}
