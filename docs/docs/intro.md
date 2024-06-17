---
sidebar_position: 1
title: Introduction
slug: /
---
# Welcome to Pathfinder

A [Starknet](https://www.starknet.io) full node giving you a safe view into Starknet.

Pathfinder is currently in alpha so expect some rough edges but it is already usable today!

## Features

- access the full Starknet state history
  - includes contract code and storage, and transactions
- verifies state using Ethereum
  - calculates the Starknet state's Patricia-Merkle Trie root on a block-by-block basis and confirms it against L1
  - this means the contract code and storage are now locally verified
- implements the [Starknet JSON-RPC API](#json-rpc-api)
  - Starknet APIs like [starknet.js](https://www.starknetjs.com/) or [starknet.py](https://github.com/software-mansion/starknet.py)
    full support using our JSON-RPC API for interacting with Starknet
- run Starknet functions without requiring a Starknet transaction
  - executed against the local state
- do fee estimation for transactions

## Feedback

We appreciate any feedback, especially during this alpha period.
This includes any documentation issues, feature requests and bugs that you may encounter.

For help or to submit bug reports or feature requests, please open an issue or alternatively visit the Starknet [discord channel](https://discord.com/invite/QypNMzkHbc).
