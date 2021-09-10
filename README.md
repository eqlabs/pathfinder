# StarkNet

A StarkNet full node written in Rust.

This project is in its infancy.

## Network Architecture

The StarkNet network consists of three entities with distinct responsibilities

1. L1 core contract
2. Sequencer nodes
3. L2 full nodes

### L1 Core Contract

It is the sole arbitrator of truth. It receives state updates from sequencer nodes along with ZK-SNARKS proofs of these updates. The contract verifies the proofs before storing the updated state on L1.

Since L1 is the only source of truth in the network, nodes must query L1 if they wish to verify any state updates.

### Sequencer nodes

These nodes are responsible for ordering and batching transactions in the network. They compute ZK-SNARKS proofs for these transaction rollups (ZK-rollup) and submit them to L1 for verification.

Currently, sequencer nodes are fully centralised and provided by StarkWare. This will eventually be changed to a decentralised model once development stabilises.

### L2 full nodes

This is what this project is implementing. These nodes act as StarkNet access points for users, providing an HTTP RPC interface to interact with StarkNet.

They form a p2p decentralised network, propagating network state and transactions between nodes.

Network state updates can be received from other L2 nodes, sequencer nodes or even queried from L1. Note, that only L1 can confirm the validity of a state update.

## Roadmap

The end goal is to have a node which can

- hold the full StarkNet state
- synchronise StarkNet state
- provides an API for interacting with StarkNet state
- participates in the L2 StarkNet network
  - propagating state
  - propagating transactions

The roadmap has been split into stages, with goals in the later stages being less certain and well-defined. This gives us a target to aim at while accommodating the evolving StarkNet requirements.

### Stage I

A simplistic node which has no p2p capabilities. It synchronises network state using L1 and the StarkNet gateway, and provides an HTTP RPC API.

#### Network State Sync

- [ ] get state root from L1
- [ ] get state updates from Starkware gateway

#### HTTP RPC API

Serve and implement the following API endpoints:

- [ ] `get_storage_at`
- [ ] `get_code`
- [ ] `call_transaction`
- [ ] `get_block`
- [ ] `get_tx`

#### State Storage

- [ ] store all StarkNet contracts (including code)
- [ ] store all StarkNet transactions
- [ ] store the ABI

### Stage II

Establish p2p network, state is now propagated between nodes.

Add support for syncing completely from L1.

### Stage III

Create a transaction mempool, transactions are now propagated between nodes.

Add contract calls to RPC API: `invoke` and `deploy`.