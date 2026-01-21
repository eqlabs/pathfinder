# Pathfinder Consensus

A Byzantine Fault Tolerant (BFT) consensus engine for Starknet nodes, built on top of the Malachite consensus engine.

[![Documentation](https://docs.rs/pathfinder-consensus/badge.svg)](https://docs.rs/pathfinder-consensus)

## Overview

Pathfinder Consensus provides a robust consensus engine for Starknet nodes that wraps the Malachite implementation of the Tendermint BFT consensus algorithm. It's designed to be generic over validator addresses and consensus values, making it suitable for Starknet's consensus requirements.

## Quick Start

```rust
use pathfinder_consensus::*;

// Create and start consensus
let config = Config::new(my_address);
let mut consensus: DefaultConsensus<MyValue, MyAddress> = Consensus::new(config);
consensus.handle_command(ConsensusCommand::StartHeight(1, validator_set));

// Main loop
loop {
    if let Some(event) = consensus.next_event().await {
        match event {
            ConsensusEvent::RequestProposal { height, round } => {
                // Build and submit proposal
                consensus.handle_command(ConsensusCommand::Propose(proposal));
            }
            ConsensusEvent::Decision { height, round, value } => {
                // Commit the decided value
            }
            ConsensusEvent::Gossip(msg) => {
                // Broadcast to peers
            }
            ConsensusEvent::Error(e) => {
                // Handle error
            }
        }
    }
}
```

## API Overview

### Commands (input via `handle_command`)

| Command | Description |
|---------|-------------|
| `StartHeight(height, validator_set)` | Begin consensus at a new height |
| `Propose(proposal)` | Submit your proposal (when you're the proposer) |
| `Proposal(signed_proposal)` | Inject a proposal received from the network |
| `Vote(signed_vote)` | Inject a vote received from the network |

For detailed information about commands, refer to the [API documentation](https://docs.rs/pathfinder-consensus/latest/pathfinder_consensus/enum.ConsensusCommand.html).

### Events (output via `next_event`)

| Event | Description |
|-------|-------------|
| `RequestProposal { height, round }` | You're requested to build a proposal |
| `Decision { height, round, value }` | Consensus reached |
| `Gossip(NetworkMessage)` | Broadcast this message to peers |
| `Error(ConsensusError)` | Internal error occurred |

For detailed information about events, refer to the [API documentation](https://docs.rs/pathfinder-consensus/latest/pathfinder_consensus/enum.ConsensusEvent.html).

## Configuration

```rust
let config = Config::new(my_address)
    .with_wal_dir("/path/to/wal")
    .with_history_depth(10)
    .with_timeouts(TimeoutValues {
        propose_timeout: Duration::from_secs(3),
        prevote_timeout: Duration::from_secs(1),
        precommit_timeout: Duration::from_secs(1),
        commit_timeout: Duration::from_secs(1),
    });
```

## Custom Proposer Selection

Implement [`ProposerSelector<A>`](https://docs.rs/pathfinder-consensus/latest/pathfinder_consensus/trait.ProposerSelector.html) to override round-robin selection:

```rust
#[derive(Clone)]
struct WeightedSelector;

impl<A: ValidatorAddress> ProposerSelector<A> for WeightedSelector {
    fn select_proposer<'a>(
        &self,
        validator_set: &'a ValidatorSet<A>,
        height: u64,
        round: u32,
    ) -> &'a Validator<A> {
        // Custom selection logic
        &validator_set.validators[round as usize % validator_set.count()]
    }
}

let consensus = Consensus::with_proposer_selector(config, WeightedSelector);
```

## Crash Recovery

Recover state from write-ahead log after restart:

```rust
let validator_sets = Arc::new(StaticValidatorSetProvider::new(validator_set));
let highest_committed = storage.get_highest_block()?; // Your storage layer
let consensus = Consensus::recover(config, validator_sets, highest_committed)?;
```

## Type Requirements

Your address type must implement [`ValidatorAddress`](https://docs.rs/pathfinder-consensus/latest/pathfinder_consensus/trait.ValidatorAddress.html) (auto-implemented for types with `Sync + Send + Ord + Display + Debug + Default + Clone + Into<Vec<u8>> + Serialize + DeserializeOwned`).

Your value type must implement [`ValuePayload`](https://docs.rs/pathfinder-consensus/latest/pathfinder_consensus/trait.ValuePayload.html) (auto-implemented for types with `Sync + Send + Ord + Display + Debug + Default + Clone + Serialize + DeserializeOwned`).
