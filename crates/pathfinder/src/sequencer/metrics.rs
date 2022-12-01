//! Metrics related utilities
use super::{
    builder::{stage::Method, Request},
    SequencerError,
};
use futures::Future;
use pathfinder_common::BlockId;

const METRIC_REQUESTS: &str = "gateway_requests_total";
const METRIC_FAILED_REQUESTS: &str = "gateway_requests_failed_total";
const METRICS: [&str; 2] = [METRIC_REQUESTS, METRIC_FAILED_REQUESTS];
const TAG_LATEST: &str = "latest";
const TAG_PENDING: &str = "pending";
const TAGS: &[&str] = &[TAG_LATEST, TAG_PENDING];
const REASON_DECODE: &str = "decode";
const REASON_STARKNET: &str = "starknet";
const REASON_RATE_LIMITING: &str = "rate_limiting";
const REASONS: [&str; 3] = [REASON_DECODE, REASON_RATE_LIMITING, REASON_STARKNET];

/// Register all sequencer related metrics
pub fn register() {
    let methods_with_tags = ["get_block", "get_state_update"].into_iter();

    // Requests and failed requests
    METRICS.iter().for_each(|&name| {
        // For all methods
        Request::<'_, Method>::METHODS.iter().for_each(|&method| {
            metrics::register_counter!(name, "method" => method);
        });

        // For methods that support block tags in metrics
        methods_with_tags.clone().for_each(|method| {
            TAGS.iter().for_each(|&tag| {
                metrics::register_counter!(name, "method" => method, "tag" => tag);
            })
        })
    });

    // Failed requests for specific failure reasons
    REASONS.iter().for_each(|&reason| {
        // For all methods
        Request::<'_, Method>::METHODS.iter().for_each(|&method| {
            metrics::register_counter!(METRIC_FAILED_REQUESTS, "method" => method, "reason" => reason);
        });

        // For methods that support block tags in metrics
        methods_with_tags.clone().for_each(|method| {
            TAGS.iter().for_each(|&tag| {
                metrics::register_counter!(METRIC_FAILED_REQUESTS, "method" => method, "tag" => tag, "reason" => reason);
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
            BlockTag::Latest => Some(TAG_LATEST),
            BlockTag::Pending => Some(TAG_PENDING),
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

/// # Usage
///
///  Awaits future `f` and increments the following counters for a particular method:
/// - `gateway_requests_total`,
/// - `gateway_requests_failed_total` if the future returns the `Err()` variant.
///
/// # Additional counter labels
///
/// 1. All the above counters are also duplicated for the special cases of:
/// `("get_block" | "get_state_update") AND ("latest" | "pending")`.
///
/// 2. `gateway_requests_failed_total` is also duplicated for the specific failure reasons:
/// - `starknet`, if the future returns an `Err()` variant, which carries a StarkNet specific error variant
/// - `decode`, if the future returns an `Err()` variant, which carries a decode error variant
/// - `rate_limiting` if the future returns an `Err()` variant,
/// which carries the [`reqwest::StatusCode::TOO_MANY_REQUESTS`] status code
pub async fn with_metrics<T>(
    meta: RequestMetadata,
    f: impl Future<Output = Result<T, SequencerError>>,
) -> Result<T, SequencerError> {
    /// Increments a counter and its block tag specific variants if they exist
    fn increment(counter_name: &'static str, meta: RequestMetadata) {
        let method = meta.method;
        let tag = meta.tag;
        metrics::increment_counter!(counter_name, "method" => method);

        if let ("get_block" | "get_state_update", Some(tag)) = (method, tag.as_str()) {
            metrics::increment_counter!(counter_name, "method" => method, "tag" => tag);
        }
    }

    /// Increments the `gateway_requests_failed_total` counter for a given failure `reason`,
    /// includes block tag specific variants if they exist
    fn increment_failed(meta: RequestMetadata, reason: &'static str) {
        let method = meta.method;
        let tag = meta.tag;
        metrics::increment_counter!(METRIC_FAILED_REQUESTS, "method" => method, "reason" => reason);

        if let ("get_block" | "get_state_update", Some(tag)) = (method, tag.as_str()) {
            metrics::increment_counter!(METRIC_FAILED_REQUESTS, "method" => method, "tag" => tag, "reason" => reason);
        }
    }

    increment(METRIC_REQUESTS, meta);

    f.await.map_err(|e| {
        increment(METRIC_FAILED_REQUESTS, meta);

        match &e {
            SequencerError::StarknetError(_) => {
                increment_failed(meta, REASON_STARKNET);
            }
            SequencerError::InvalidStarknetErrorVariant => {
                increment_failed(meta, REASON_DECODE);
            }
            SequencerError::ReqwestError(e) if e.is_decode() => {
                increment_failed(meta, REASON_DECODE);
            }
            SequencerError::ReqwestError(e)
                if e.is_status()
                    && e.status().expect("error kind should be status")
                        == reqwest::StatusCode::TOO_MANY_REQUESTS =>
            {
                increment_failed(meta, REASON_RATE_LIMITING);
            }
            SequencerError::ReqwestError(_) => {}
        }

        e
    })
}
