---
sidebar_position: 3
---

# Configuring your Setup

The `pathfinder` node options can be configured via the command line as well as environment variables.

The command line options are passed in after the `docker run` options, as follows:

```bash
sudo docker run --name pathfinder [...] eqlabs/pathfinder:latest <pathfinder options>
```

Using `--help` will display the `pathfinder` options, including their environment variable names:

```bash
sudo docker run --rm eqlabs/pathfinder:latest --help
```

## Pending Support

Block times on `mainnet` can be prohibitively long for certain applications. As a workaround, Starknet added the concept of a `pending` block which is the block currently under construction. This is supported by pathfinder, and usage is documented in the [JSON-RPC API](#json-rpc-api) with various methods accepting `"block_id"="pending"`.

## State trie pruning

Pathfinder allows you to control the number of blocks of state trie history to preserve. You can choose between archive:

```
--storage.state-tries = archive
```

which stores all of history, or to keep only the last `k+1` blocks:

```
--storage.state-tries = k
```

The latest block is always stored, though in the future we plan an option to disable this entirely. Currently at least
one block is required to trustlessly verify Starknet's state update.

State trie data consumes a massive amount of storage space. You can expect an overall storage reduction of ~75% when going
from archive to pruned mode.

The downside to pruning this data is that storage proofs are only available for blocks that are not pruned i.e. with
`--storage.state-tries = k` you can only serve storage proofs for the latest `k+1` blocks.

Note that this only impacts storage proofs - for all other considerations pathfinder is still an archive mode and no
data is dropped.

Also note that you cannot switch between archive and pruned modes. You may however change `k` between different runs of
pathfinder.

If you don't care about storage proofs, you can maximise storage savings by setting `--storage.state-tries = 0`, which
will only store the latest block's state trie.

## Logging

Logging can be configured using the `RUST_LOG` environment variable.
We recommend setting it when you start the container:

```bash
sudo docker run --name pathfinder [...] -e RUST_LOG=<log level> eqlabs/pathfinder:latest
```

The following log levels are supported, from most to least verbose:

```bash
trace
debug
info  # default
warn
error
```

## Network Selection

The Starknet network can be selected with the `--network` configuration option.

If `--network` is not specified, network selection will default to match your Ethereum endpoint:

- Starknet mainnet for Ethereum mainnet,
- Starknet testnet for Ethereum Sepolia

### Custom networks & gateway proxies

You can specify a custom network with `--network custom` and specifying the `--gateway-url`, `feeder-gateway-url` and `chain-id` options.
Note that `chain-id` should be specified as text e.g. `SN_SEPOLIA`.

This can be used to interact with a custom Starknet gateway, or to use a gateway proxy.
