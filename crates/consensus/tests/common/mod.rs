use std::fmt::Display;
use std::time::Duration;

use pathfinder_consensus::{
    Consensus,
    ConsensusEvent,
    ProposerSelector,
    ValidatorAddress,
    ValuePayload,
};
use serde::{Deserialize, Serialize};
use tokio::time::advance;
use tracing_subscriber::EnvFilter;

/// A simple validator address type.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct NodeAddress(pub String);

impl Display for NodeAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<NodeAddress> for Vec<u8> {
    fn from(addr: NodeAddress) -> Self {
        addr.0.into_bytes()
    }
}

/// A simple consensus value type.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ConsensusValue(pub String);

impl Display for ConsensusValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Advances simulated time and polls `Consensus` until a matching event is seen
/// or max attempts are hit. Returns the matching event if found.
#[allow(dead_code)]
pub async fn drive_until<
    V: ValuePayload + 'static,
    A: ValidatorAddress + 'static,
    P: ProposerSelector<A> + Send + Sync + 'static,
    F,
>(
    consensus: &mut Consensus<V, A, P>,
    tick: Duration,
    max_attempts: usize,
    mut match_fn: F,
) -> Option<ConsensusEvent<V, A>>
where
    F: FnMut(&ConsensusEvent<V, A>) -> bool,
{
    for _ in 0..max_attempts {
        advance(tick).await;
        if let Some(event) = consensus.next_event().await {
            if match_fn(&event) {
                return Some(event);
            }
        }
    }
    None
}

/// Setup tracing for the tests.
/// This is just used for debugging purposes.
#[allow(dead_code)]
pub fn setup_tracing_full() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace"));

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_env_filter(filter)
        .with_target(true)
        .without_time()
        .try_init();
}
