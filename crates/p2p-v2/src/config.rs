use std::time::Duration;

use ipnet::IpNet;

/// P2P configuration options and limits.
#[derive(Debug, Clone)]
pub struct Config {
    /// A direct (not relayed) peer can only connect once in this period.
    pub direct_connection_timeout: Duration,
    /// A relayed peer can only connect once in this period.
    pub relay_connection_timeout: Duration,
    /// Maximum number of direct (non-relayed) inbound peers.
    pub max_inbound_direct_peers: usize,
    /// Maximum number of relayed inbound peers.
    pub max_inbound_relayed_peers: usize,
    /// Maximum number of outbound peers.
    pub max_outbound_peers: usize,
    /// How long to prevent evicted peers from reconnecting.
    pub eviction_timeout: Duration,
    pub ip_whitelist: Vec<IpNet>,
    /// If the number of peers is below the low watermark, the node will attempt
    /// periodic bootstrapping at this interval. If `None`, periodic bootstrap
    /// is disabled and only automatic bootstrap remains.
    pub bootstrap_period: Option<Duration>,
    pub inbound_connections_rate_limit: RateLimit,
    /// Custom protocol name for Kademlia
    pub kad_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    pub max: usize,
    pub interval: Duration,
}
