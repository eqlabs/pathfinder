---
sidebar_position: 3
---

# Configuring Pathfinder

Pathfinder can be configured using the following methods in order of priority:

1. [Command line options](#command-line-options)
2. [Environment variables](#environment-variables)

## Command Line Options

Command-line options take the highest precedence. If an option is set both via environment variable and on the command line, the command-line value overrides.

When running Pathfinder via Docker, command-line arguments come after the Docker run options:

```bash
docker run \
  --name pathfinder \
  --detach \
  --restart unless-stopped \
  -p 9545:9545 \
  --user "$(id -u):$(id -g)" \
  -e RUST_LOG=info \
  -e PATHFINDER_ETHEREUM_API_URL="wss://sepolia.infura.io/ws/v3/<project-id>" \
  -v $HOME/pathfinder:/usr/share/pathfinder/data \
  eqlabs/pathfinder:latest \
  --network mainnet \
  --monitor-address=0.0.0.0:9000 \
  --rpc.websocket.enabled \
```

If you built Pathfinder from source, pass options after `--` so cargo doesn’t parse them:

```bash
cargo run --release --bin pathfinder -- \
    --network mainnet \
    --monitor-address=0.0.0.0:9000
```

:::tip
Use `--help` to view all available options, including their corresponding environment variable names.
:::

### Network Selection

By default, Pathfinder detects your Starknet network based on the Ethereum endpoint you provide. If the endpoint is on Ethereum mainnet, it uses the mainnet network; if the endpoint is on Sepolia, it uses the Sepolia testnet. 

However, you can explicitly override this detection using the `--network` option:

```bash
--network <mainnet|sepolia-testnet|sepolia-integration|custom>
```

For example, to force mainnet even if your Ethereum endpoint is ambiguous:

```bash
--network mainnet
```

### Custom Networks and Gateway Proxies

Pathfinder can be configured to use custom networks and gateway proxies by specifying:

* `--network custom`: Indicates a custom network configuration.
    
* `--gateway-url` and `--feeder-gateway-url`: Specify the URLs of the gateway and feeder gateway.
    
* `--chain-id`: The chain ID to use, specified as text (e.g., `SN_SEPOLIA`).
    

These options can be used to connect to a custom Starknet gateway or to use a proxy for the Starknet network:

```bash title="Sample source build with a custom network"
cargo run --release --bin pathfinder -- \
    --network custom \
    --gateway-url https://my-custom-network/gateway \
    --feeder-gateway-url https://my-custom-network/feeder \
    --chain-id SN_MYNETWORK
```


### Logging Configuration

Logging can be configured using the `RUST_LOG` environment variable.
We recommend setting it when you start the container:

```bash
docker run --name pathfinder [...] -e RUST_LOG=<log level> eqlabs/pathfinder:latest
```

The following log levels are supported, from most to least verbose:

```bash
trace
debug
info  # default
warn
error
```

### State Trie Pruning

Pathfinder allows you to control the number of blocks of state trie history to preserve using either archive or pruned mode. 

Archive mode keeps the entire history of state tries, which can be storage-intensive:

```bash
--storage.state-tries=archive
```

If you don’t require storage proofs for older blocks, you can prune the trie to preserve only recent states using the following option:

```bash
--storage.state-tries=<k>
```

Where `k` keeps only the last `k+1` blocks tries.

For example, if you’re using Docker and want to prune older state tries:

```bash
sudo docker run \
  --name pathfinder \
  --detach \
  -p 9545:9545 \
  -e RUST_LOG=info \
  eqlabs/pathfinder:latest \
  --network mainnet \
  --storage.state-tries=100
```
Here, Pathfinder keeps state tries for the latest 101 blocks.

Similarly, if you built Pathfinder from source and want to a prune state trie:

```bash
cargo run --release --bin pathfinder -- \
    --network testnet \
    --storage.state-tries=0
```

Setting `--storage.state-tries=0` keeps only the most recent block’s trie. This option maximizes space at the cost of older proofs.

:::note  
  - Pruning affects only storage proofs for older blocks. All transactions and blocks are still available.  
  - You cannot switch between archive and pruned mode mid-run. To switch from archive to pruned, you’ll need to either re-sync or use a pruned [Database Snapshot](/database-snapshots).  
:::

### Blockchain Pruning

:::warning

Blockchain Pruning is still an experimental feature and not recommended for production use.

:::

Similar to [State Trie Pruning](#state-trie-pruning), Pathfinder allows you to control the number of historical blocks to preserve using, again, either archive or pruned mode.

Archive mode keeps the entire blockchain history, which can be storage-intensive:

```bash
--storage.blockchain-history=archive
```

If you don’t require block, transaction, state update or event data for older blocks, you can enable pruning to preserve only recent blocks using the following option:

```bash
--storage.blockchain-history=<k>
```

Where `k` keeps only the last `k+1` blocks.

For example, if you’re using Docker and want to prune older blocks:

```bash
sudo docker run \
  --name pathfinder \
  --detach \
  -p 9545:9545 \
  -e RUST_LOG=info \
  eqlabs/pathfinder:latest \
  --network mainnet \
  --storage.blockchain-history=100
```

Here, Pathfinder keeps data for the latest 101 blocks.

Similarly, if you built Pathfinder from source and want to a prune older blocks:

```bash
cargo run --release --bin pathfinder -- \
    --network testnet \
    --storage.blockchain-history=0
```

Setting `--storage.blockchain-history=0` keeps only the most recent block’s data.

:::note

You cannot switch between archive and pruned mode mid-run. To switch from archive to pruned, you’ll need to either re-sync or use a pruned [Database Snapshot](/database-snapshots). It is, however, possible to change the number of stored blocks in pruned mode each time you run Pathfinder.

:::

### Native Execution

:::warning

Native execution (using [Cairo Native](https://github.com/lambdaclass/cairo_native)) is still an experimental feature that is beneficial for a few specific use-cases only.

:::

To improve Cairo execution performance, Pathfinder supports "native execution". Cairo Native works by compiling Cairo classes into platform-specific binaries. These binaries are then used to execute entry points directly, avoiding the overhead of running the Cairo VM interpreter. You can enable native execution by the following option:

```bash
--rpc.native-execution true
```

#### Limitations

- Only Sierra 1.7+ classes can be compiled. This practically makes native execution only available for classes that have been compiled with a recent version of the Cairo compiler.
- Compilation is performed on-demand. That is, the first execution attempt of a compatible class adds the class to the compiler queue. Since compilation might take up to a minute Pathfinder falls back to using the Cairo VM until compilation finishes to avoid delaying JSON-RPC responses. Compilation is performed on a single thread.
- Compiled native classes are transient. We keep the compiler artifacts in temporary files (under `/tmp`). The classes are _not_ persisted into Pathfinder's database. Restarting the node clears this cache and all classes will need to be re-compiled.
- The size of the native compiler class cache is configurable using `--rpc.native-execution-class-cache-size=<N>`. The default setting is 512, meaning that at most 512 native classes are kept in the cache.
- Each compiled class takes up some disk space. The actual disk space required depends on the size of the Cairo class. For estimation you can use a few megabytes per class.
- The optimization level used by the Cairo Native compiler can be set by the `--rpc.native-execution-compiler-optimization-level` CLI option. Valid values are 0 (no optimization), 1 (less optimization), 2 (default optimization), and 3 (aggressive optimization).


## Environment Variables

Pathfinder can also be configured via environment variables, which take second place in configuration precedence.

By convention, environment variables for Pathfinder begin with `PATHFINDER_` and are in SCREAMING_SNAKE_CASE. 

For instance, the `--ethereum-api-url` command-line option corresponds to `PATHFINDER_ETHEREUM_API_URL`, and `--network` to `PATHFINDER_NETWORK`, etc.

When using Docker, pass environment variables via the `-e` option:

```bash
sudo docker run \
  --name pathfinder \
  --restart unless-stopped \
  --detach \
  -p 9545:9545 \
  -v $HOME/pathfinder:/usr/share/pathfinder/data \
  -e "PATHFINDER_ETHEREUM_API_URL=wss://sepolia.infura.io/ws/v3/<project-id>" \
  -e "PATHFINDER_NETWORK=sepolia-testnet" \
  -e "RUST_LOG=debug" \
  eqlabs/pathfinder:latest
```

When running Pathfinder directly from source, set environment variables in this format:

```bash
RUST_LOG=debug PATHFINDER_NETWORK=sepolia-testnet cargo run --release --bin pathfinder
```

:::note
Command-line parameters will override environment variables if both are set.
:::
