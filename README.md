# Welcome to Pathfinder

A [StarkNet](https://starkware.co/starknet/) full node written in Rust.

This project is a work-in-progress and is not yet usable.

A first release will be made with the completion of [Milestone I](#milestone-i).

## Table of Contents
- [Roadmap](#roadmap)
  - [Milestone I](#milestone-i)
  - [Milestone II](#milestone-ii)
  - [Milestone III](#milestone-iii)
- [Developers](#developers)
  - [Getting started](#getting-started)
  - [Building](#building)
  - [Testing](#testing)
- [License](#license)
- [Contribution](#contribution)

## Roadmap

The end goal is to have a node which

- holds the full StarkNet state
- synchronises StarkNet state from both L1 and L2 (p2p)
- verifies L2 state against L1
- provides an RPC API for interacting with StarkNet state
- participates in the L2 StarkNet network
  - propagating state
  - propagating transactions

The roadmap has been split into milestones, with goals in the later milestones being less certain and well-defined.

### Milestone I

A node which has no p2p capabilities. It synchronises network state using L1 and L2 (StarkNet gateway), and provides an HTTP RPC API.

- [x] retrieve state updates from L1
  - [x] state root
  - [x] contract deployments
  - [x] contract updates
- [x] retrieve state from StarkNet sequencer gateway
  - [x] blocks
  - [x] transactions
  - [x] contract code
- [x] serve RPC API
- [ ] storage
  - [ ] global state
  - [x] contract definitions
  - [x] transactions
  - [x] blocks
- [x] basic user configuration
- [ ] sync state from L1 and L2
- [ ] run `starknet_call` locally
- [ ] validate contract code against L1
- [ ] integrate various components
- [ ] documentation

### Milestone II

Establish p2p network, state is now propagated between nodes.

Add support for syncing completely from L1.

### Milestone III

Create a transaction mempool, transactions are now propagated between nodes.

Add contract calls to RPC API: `invoke` and `deploy`.

## Developers

Note that this project is currently only built on linux; but we do plan on supporting MacOs and Windows in the future.

### Getting started

Install Rust, by following the [official Rust instructions](https://www.rust-lang.org/tools/install).

`git clone` this project and you should be good to go.

### Building

Invoke `cargo build -p pathfinder` from the project root.

### Testing

Some of our tests require access to an archive Ethereum node. If you want to run these tests you will require setting the environment variable `STARKNET_ETHEREUM_WEBSOCKET_URL` to the websocket address of a Goerli full node. Infura provides such nodes for free (on Goerli testnet), and is what we currently use for our own CI.

Example with an Infura node:
```
export STARKNET_ETHEREUM_WEBSOCKET_URL=wss://goerli.infura.io/ws/v3/<project-id>
```

Run the tests (invoke from project root):
```
cargo test
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
