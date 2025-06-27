use std::time::Duration;

use pathfinder_consensus::{Consensus, ConsensusEvent};
use tokio::time::advance;

/// Advances simulated time and polls `Consensus` until a matching event is seen
/// or max attempts are hit. Returns the matching event if found.
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
