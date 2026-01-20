# Pathfinder Consensus

A Byzantine Fault Tolerant (BFT) consensus engine for Starknet nodes, built on top of the Malachite consensus engine.

[![Documentation](https://docs.rs/pathfinder-consensus/badge.svg)](https://docs.rs/pathfinder-consensus)

## Overview

Pathfinder Consensus provides a robust consensus engine for Starknet nodes that wraps the Malachite implementation of the Tendermint BFT consensus algorithm. It's designed to be generic over validator addresses and consensus values, making it suitable for Starknet's consensus requirements.

## Quick Start

```rust
use pathfinder_consensus::*;
use serde::{Deserialize, Serialize};

// Define your validator address type
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct MyAddress(String);

impl std::fmt::Display for MyAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<MyAddress> for Vec<u8> {
    fn from(addr: MyAddress) -> Self {
        addr.0.into_bytes()
    }
}

// Define your consensus value type
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct BlockData(String);

impl std::fmt::Display for BlockData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[tokio::main]
async fn main() {
    // Create configuration
    let my_address = MyAddress("validator_1".to_string());
    let config = Config::new(my_address.clone());
    
    // Create consensus engine
    let mut consensus = Consensus::new(config);
    
    // Start consensus at height 1
    let validator_set = ValidatorSet::new(vec![
        Validator::new(my_address.clone(), PublicKey::from_bytes([0; 32]))
    ]);
    
    consensus.handle_command(ConsensusCommand::StartHeight(1, validator_set));
    
    // Poll for events
    while let Some(event) = consensus.next_event().await {
        match event {
            ConsensusEvent::RequestProposal { height, round } => {
                println!("Need to propose at height {}, round {}", height, round);
            }
            ConsensusEvent::Decision { height, round, value } => {
                println!("Consensus reached at height {}, round {}: {:?}", height, round, value);
            }
            ConsensusEvent::Gossip(message) => {
                println!("Need to gossip: {:?}", message);
            }
            ConsensusEvent::Error(error) => {
                eprintln!("Consensus error: {}", error);
            }
        }
    }
}
```

## Core Concepts

### ValidatorAddress Trait

Your validator address type must implement the `ValidatorAddress` trait:

```rust
pub trait ValidatorAddress:
    Sync + Send + Ord + Display + Debug + Default + Clone + Into<Vec<u8>> + Serialize + DeserializeOwned
{
}
```

### ValuePayload Trait

Your consensus value type must implement the `ValuePayload` trait:

```rust
pub trait ValuePayload:
    Sync + Send + Ord + Display + Debug + Default + Clone + Serialize + DeserializeOwned
{
}
```

### Consensus Engine

The main `Consensus<V, A>` struct is generic over:
- `V`: Your consensus value type (must implement `ValuePayload`)
- `A`: Your validator address type (must implement `ValidatorAddress`)

### Commands and Events

The consensus engine operates on a command/event model:

- **Commands**: Send commands to the consensus engine via `handle_command()`
- **Events**: Poll for events from the consensus engine via `next_event().await`

## Integration Contract

This crate is a consensus *engine*, not a networking or block-production implementation. The application integrating it is responsible for:

- **Proposal creation**: When you receive `ConsensusEvent::RequestProposal { height, round }`, build a proposal value and inject it back with `ConsensusCommand::Propose(Proposal<_, _>)`.
- **Signing and validation**:
  - Outbound messages produced by the engine come as `ConsensusEvent::Gossip(NetworkMessage<_, _>)`.
  - Inbound messages from peers should be validated (e.g., signature checks using the sender's `PublicKey`, basic sanity checks, and any application-level rules) before being injected with `ConsensusCommand::Proposal(SignedProposal<_, _>)` or `ConsensusCommand::Vote(SignedVote<_, _>)`.
- **Networking (gossip)**:
  - On `ConsensusEvent::Gossip(...)`, broadcast the message to peers.
  - On receiving a peer message, decode it and pass it into the engine via `handle_command(...)`.
  - Be prepared for **duplicates** and **out-of-order** delivery from the network.

## Configuration

The `Config` struct allows you to customize:

- **History Depth**: How many completed heights to keep in memory
- **WAL Directory**: Where to store write-ahead logs for crash recovery
- **Timeouts**: Customize consensus round timeouts

## Crash Recovery

The consensus engine supports crash recovery through write-ahead logging:

```rust
// Recover from a previous crash
let validator_sets = Arc::new(StaticValidatorSetProvider::new(validator_set));
let highest_committed = None;
let mut consensus = Consensus::recover(config, validator_sets, highest_committed)?;
```
