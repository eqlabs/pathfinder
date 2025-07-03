use std::time::Duration;

use pathfinder_consensus::{Consensus, ConsensusEvent};
use tokio::time::advance;
use tracing_subscriber::EnvFilter;

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

/// Advances simulated time and polls `Consensus` until a matching event is seen
/// or max attempts are hit. Returns the matching event if found.
#[allow(dead_code)]
pub async fn drive_until<F>(
    consensus: &mut Consensus,
    tick: Duration,
    max_attempts: usize,
    mut match_fn: F,
) -> Option<ConsensusEvent>
where
    F: FnMut(&ConsensusEvent) -> bool,
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
