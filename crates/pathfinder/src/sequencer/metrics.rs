//! Metrics related utilities
use super::{
    builder::{stage::Method, Request},
    SequencerError,
};
use crate::core::BlockId;
use futures::Future;

const METRIC_REQUESTS: &str = "sequencer_requests_total";
const METRIC_FAILED_REQUESTS: &str = "sequencer_requests_failed_total";
const METRIC_STARKNET_ERRORS: &str = "sequencer_requests_failed_starknet_total";
const METRIC_DECODE_ERRORS: &str = "sequencer_requests_failed_decode_total";
const METRIC_RATE_LIMITED: &str = "sequencer_requests_failed_rate_limited_total";
const METRICS: &[&str] = &[
    METRIC_REQUESTS,
    METRIC_FAILED_REQUESTS,
    METRIC_STARKNET_ERRORS,
    METRIC_DECODE_ERRORS,
    METRIC_RATE_LIMITED,
];

/// Register all sequencer related metrics
pub fn register() {
    // We also track `get_block`, `get_state_update` wrt `latest` and `pending` blocks
    let methods = ["get_block", "get_state_update"].into_iter();
    let tags = ["latest", "pending"].into_iter();

    // Register counters for all the methods
    METRICS.iter().for_each(|&name| {
        Request::<'_, Method>::METHODS.iter().for_each(|&method| {
            metrics::register_counter!(name, "method" => method);
        });

        methods.clone().for_each(|method| {
            tags.clone().for_each(|tag| {
                metrics::register_counter!(name, "method" => method, "tag" => tag);
            })
        })
    });
}

/// Used to mark methods that touch special block tags to avoid reparsing the url.
#[derive(Clone, Copy, Debug)]
pub enum BlockTag {
    None,
    Latest,
    Pending,
}

impl From<BlockId> for BlockTag {
    fn from(x: BlockId) -> Self {
        match x {
            BlockId::Number(_) | BlockId::Hash(_) => Self::None,
            BlockId::Latest => Self::Latest,
            BlockId::Pending => Self::Pending,
        }
    }
}

impl BlockTag {
    // Returns a `&'static str` representation of the tag, if it exists.
    pub fn as_str(self) -> Option<&'static str> {
        match self {
            BlockTag::None => None,
            BlockTag::Latest => Some("latest"),
            BlockTag::Pending => Some("pending"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// Carries metrics metadata while creating sequencer requests
pub struct RequestMetadata {
    pub method: &'static str,
    pub tag: BlockTag,
}

impl RequestMetadata {
    /// Create new instance with tag set to [`BlockTag::None`]
    pub fn new(method: &'static str) -> Self {
        Self {
            method,
            tag: BlockTag::None,
        }
    }
}

/// Awaits future `f` and increments the following counters for a particular method:
/// - `sequencer_requests_total`,
/// - `sequencer_requests_failed_total` if the future returns the `Err()` variant.
/// - `sequencer_requests_failed_starknet_total` if the future returns the `Err()` variant, which carries a
/// StarkNet specific error variant
/// - `sequencer_requests_failed_decode_total` counter for `method` if the future returns the `Err()` variant,
/// which carries a decode error variant
/// - `sequencer_requests_failed_rate_limited_total` if the future returns the `Err()` variant,
/// which carries the [`reqwest::StatusCode::TOO_MANY_REQUESTS`] status code
///
/// All the above counters are also duplicated for the special cases of:
/// `("get_block" | "get_state_update") AND ("latest" | "pending")`
pub async fn wrap_with_metrics<T>(
    meta: RequestMetadata,
    f: impl Future<Output = Result<T, SequencerError>>,
) -> Result<T, SequencerError> {
    /// Increments a counter and all its special flavors that record tag specific events
    fn increment_counter(counter_name: &'static str, meta: RequestMetadata) {
        let method = meta.method;
        let tag = meta.tag;
        metrics::increment_counter!(counter_name, "method" => method);
        if let ("get_block" | "get_state_update", Some(tag)) = (method, tag.as_str()) {
            metrics::increment_counter!(counter_name, "method" => method, "tag" => tag)
        }
    }

    increment_counter("sequencer_requests_total", meta);

    f.await.map_err(|e| {
        increment_counter("sequencer_requests_failed_total", meta);

        match &e {
            SequencerError::StarknetError(_) => {
                increment_counter("sequencer_requests_failed_starknet_total", meta);
            }
            SequencerError::ReqwestError(e) if e.is_decode() => {
                increment_counter("sequencer_requests_failed_decode_total", meta);
            }
            SequencerError::ReqwestError(e)
                if e.is_status()
                    && e.status().expect("error kind should be status")
                        == reqwest::StatusCode::TOO_MANY_REQUESTS =>
            {
                increment_counter("sequencer_requests_failed_rate_limited_total", meta);
            }
            SequencerError::ReqwestError(_) => {}
        }

        e
    })
}
