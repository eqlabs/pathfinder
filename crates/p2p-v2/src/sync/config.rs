use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    /// Timeout for an entire stream in p2p-stream
    pub stream_timeout: Duration,
    /// Timeout for a single response in p2p-stream
    pub response_timeout: Duration,
    /// Applies to each of the p2p-stream protocols separately
    pub max_concurrent_streams: usize,
}
