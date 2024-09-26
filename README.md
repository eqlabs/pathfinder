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

## Database compatibility

**pathfinder 0.9.0 contains a change in our Merkle tree storage implementation that makes it impossible to use database files produced by earlier versions.**

This means that upgrading to 0.9.0 will require either a full re-sync _or_ downloading a [database snapshot](#database-snapshots).

## Running with Docker

The `pathfinder` node can be run in the provided Docker image.
Using the Docker image is the easiest way to start `pathfinder`. If for any reason you're interested in how to set up all the
dependencies yourself please check the [Installation from source](doc/install-from-source.md) guide.

The following assumes you have [Docker installed](https://docs.docker.com/get-docker/) and ready to go.
(In case of Ubuntu installing docker is as easy as running `sudo snap install docker`.)

The example below uses `$HOME/pathfinder` as the data directory where persistent files used by `pathfinder` will be stored.
It is easiest to create the volume directory as the user who is running the docker command.
If the directory gets created by docker upon startup, it might be unusable for creating files.

The following commands start the node in the background, also making sure that it starts automatically after reboot:

```bash
# Ensure the directory has been created before invoking docker
mkdir -p $HOME/pathfinder
# Start the pathfinder container instance running in the background
sudo docker run \
  --name pathfinder \
  --restart unless-stopped \
  --detach \
  -p 9545:9545 \
  --user "$(id -u):$(id -g)" \
  -e RUST_LOG=info \
  -e PATHFINDER_ETHEREUM_API_URL="https://sepolia.infura.io/v3/<project-id>" \
  -v $HOME/pathfinder:/usr/share/pathfinder/data \
  eqlabs/pathfinder
```

To check logs you can use:

```bash
sudo docker logs -f pathfinder
```

The node can be stopped using

```bash
sudo docker stop pathfinder
```


### Updating the Docker image

When pathfinder detects there has been a new release, it will log a message similar to:

```
WARN New pathfinder release available! Please consider updating your node! release=0.4.5
```

You can try pulling the latest docker image to update it:

```bash
sudo docker pull eqlabs/pathfinder
```

After pulling the updated image you should stop and remove the `pathfinder` container then re-create it with the exact same command
that was used above to start the node:

```bash
# This stops the running instance
sudo docker stop pathfinder
# This removes the current instance (using the old version of pathfinder)
sudo docker rm pathfinder
# This command re-creates the container instance with the latest version
sudo docker run \
  --name pathfinder \
  --restart unless-stopped \
  --detach \
  -p 9545:9545 \
  --user "$(id -u):$(id -g)" \
  -e RUST_LOG=info \
  -e PATHFINDER_ETHEREUM_API_URL="https://sepolia.infura.io/v3/<project-id>" \
  -v $HOME/pathfinder:/usr/share/pathfinder/data \
  eqlabs/pathfinder
```

### Available images

Our images are updated on every `pathfinder` release. This means that the `:latest` docker image does not track our `main` branch here, but instead matches the latest `pathfinder` [release](https://github.com/eqlabs/pathfinder/releases).

### Docker compose

You can also use `docker-compose` if you prefer that to just using Docker.

Create the folder `pathfinder` where your `docker-compose.yaml` is

```bash
mkdir -p pathfinder

# replace the value by of PATHFINDER_ETHEREUM_API_URL by the HTTP(s) URL pointing to your Ethereum node's endpoint
cp example.pathfinder-var.env pathfinder-var.env

docker-compose up -d
```

To check if it's running well use `docker-compose logs -f`.

## Database Snapshots

Re-syncing the whole history for either the mainnet or testnet networks might take a long time. To speed up the process you can use database snapshot files that contain the full state and history of the network up to a specific block.

The database files are hosted on Cloudflare R2. There are two ways to download the files:

* Using the [Rclone](https://rclone.org/) tool
* Via the HTTPS URL: we've found this to be less reliable in general

### Rclone setup

We recommend using RClone. Add the following to your RClone configuration file (`$HOME/.config/rclone/rclone.conf`):

```ini
[pathfinder-snapshots]
type = s3
provider = Cloudflare
env_auth = false
access_key_id = 7635ce5752c94f802d97a28186e0c96d
secret_access_key = 529f8db483aae4df4e2a781b9db0c8a3a7c75c82ff70787ba2620310791c7821
endpoint = https://cbf011119e7864a873158d83f3304e27.r2.cloudflarestorage.com
acl = private
```

You can then download a compressed database using the command:

```shell
rclone copy -P pathfinder-snapshots:pathfinder-snapshots/sepolia-testnet_0.11.0_47191.sqlite.zst .
```

### Uncompressing database snapshots

**To avoid issues please check that the SHA2-256 checksum of the compressed file you've downloaded matches the value we've published.**

We're storing database snapshots as SQLite database files compressed with [zstd](https://github.com/facebook/zstd). You can uncompress the files you've downloaded using the following command:

```shell
zstd -T0 -d sepolia-testnet_0.13.0_74494_pruned.sqlite.zst -o testnet-sepolia.sqlite
```

This produces uncompressed database file `testnet-sepolia.sqlite` that can then be used by pathfinder.

### Available database snapshots

| Network         | Block  | Pathfinder version required | Mode    | Filename                                           | Download URL                                                                                                     | Compressed size | SHA2-256 checksum of compressed file                               |
| --------------- | ------ | --------------------------- | ------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------- | ------------------------------------------------------------------ |
| Sepolia testnet | 74494  | >= 0.13.0                   | archive | `sepolia-testnet_0.13.0_74494_archive.sqlite.zst`  | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/sepolia-testnet_0.13.0_74494_archive.sqlite.zst)  | 5.83 GB         | `03faf036e24e31cad0d5bd6c32fdeb2d52329c86cb90eb1b3b1fef91173ca63c` |
| Sepolia testnet | 74494  | >= 0.13.0                   | pruned  | `sepolia-testnet_0.13.0_74494_pruned.sqlite.zst`   | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/sepolia-testnet_0.13.0_74494_pruned.sqlite.zst)   | 2.22 GB         | `0a74d47739939b43090f44f852ef14c48a8d4b303b03186d2e5ef74b1093b3f7` |
| Sepolia testnet | 121145 | >= 0.14.0                   | archive | `sepolia-testnet_0.14.0_121145_archive.sqlite.zst` | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/sepolia-testnet_0.14.0_121145_archive.sqlite.zst) | 11.98 GB        | `6ff4e1a3d6e91edaceac35c8b17c42d3f3d0a93bd29954bb0fafa250c6e74071` |
| Sepolia testnet | 121057 | >= 0.14.0                   | pruned  | `sepolia-testnet_0.14.0_121057_pruned.sqlite.zst`  | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/sepolia-testnet_0.14.0_121057_pruned.sqlite.zst)  | 4.05 GB         | `f38c486a76699250c21a3fd7e7bcb695a7bc094387903b4137094a68d9371065` |
| Mainnet         | 649680 | >= 0.13.0                   | archive | `mainnet_0.13.0_649680_archive.sqlite.zst`         | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/mainnet_0.13.0_649680_archive.sqlite.zst)         | 400.08 GB       | `d01766380fff47f3c08199d0e5c7039ea6fc412081bac026ca99d24f52e6a923` |
| Mainnet         | 649680 | >= 0.13.0                   | pruned  | `mainnet_0.13.0_649680_pruned.sqlite.zst`          | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/mainnet_0.13.0_649680_pruned.sqlite.zst)          | 64.85 GB        | `fd68a09672abcc37068ecf892ecd028e08456744a6e636027878f65bd801b991` |
| Mainnet         | 670000 | >= 0.14.0                   | pruned  | `mainnet_0.14.0_670000_pruned.sqlite.zst`          | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/mainnet_0.14.0_670000_pruned.sqlite.zst)          | 68.58 GB        | `b859ae1a7c6a996b3cf1666f7a13bec2fc0450829cdda5d3198e1ef2af4bc8e1` |

## Configuration

The `pathfinder` node options can be configured via the command line as well as environment variables.

The command line options are passed in after the `docker run` options, as follows:

```bash
sudo docker run --name pathfinder [...] eqlabs/pathfinder:latest <pathfinder options>
```

Using `--help` will display the `pathfinder` options, including their environment variable names:

```bash
sudo docker run --rm eqlabs/pathfinder:latest --help
```

### Pending Support

Block times on `mainnet` can be prohibitively long for certain applications. As a workaround, Starknet added the concept of a `pending` block which is the block currently under construction. This is supported by pathfinder, and usage is documented in the [JSON-RPC API](#json-rpc-api) with various methods accepting `"block_id"="pending"`.

### State trie pruning

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

### Logging

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

### Network Selection

The Starknet network can be selected with the `--network` configuration option.

If `--network` is not specified, network selection will default to match your Ethereum endpoint:

- Starknet mainnet for Ethereum mainnet,
- Starknet testnet for Ethereum Sepolia

#### Custom networks & gateway proxies

You can specify a custom network with `--network custom` and specifying the `--gateway-url`, `feeder-gateway-url` and `chain-id` options. 
Note that `chain-id` should be specified as text e.g. `SN_SEPOLIA`.

This can be used to interact with a custom Starknet gateway, or to use a gateway proxy.

## JSON-RPC API

You can interact with Starknet using the JSON-RPC API. Pathfinder supports the official Starknet RPC API and in addition supplements this with its own pathfinder specific extensions such as `pathfinder_getProof`.

Currently, pathfinder supports `v0.4`, `v0.5`, `v0.6` and `v0.7` versions of the Starknet JSON-RPC specification.
The `path` of the URL used to access the JSON-RPC server determines which version of the API is served:

- the `v0.4.0` API is exposed on the `/rpc/v0.4` and `/rpc/v0_4` path
- the `v0.5.1` API is exposed on the `/`, `/rpc/v0.5` and `/rpc/v0_5` path
- the `v0.6.0` API is exposed on the `/rpc/v0_6` path via HTTP and on `/ws/rpc/v0_6` via Websocket
- the `v0.7.0` API is exposed on the `/rpc/v0_7` path via HTTP and on `/ws/rpc/v0_7` via Websocket
- the pathfinder extension API is exposed on `/rpc/pathfinder/v0.1` and `/rpc/pathfinder/v0_1` via HTTP and `/ws/rpc/pathfinder/v0_1` via Websocket.

Version of the API, which is served on the root (`/`) path via HTTP and on `/ws` via Websocket, can be configured via the pathfinder parameter `--rpc.root-version` (or the `RPC_ROOT_VERSION` environment variable).

Note that the pathfinder extension is versioned separately from the Starknet specification itself.

### pathfinder extension API

Here are links to our [API extensions](doc/rpc/pathfinder_rpc_api.json) and [websocket API](doc/rpc/pathfinder_ws.json).

## Monitoring API

Pathfinder has a monitoring API which can be enabled with the `--monitor-address` configuration option.

### Health

`/health` provides a method to check the health status of your `pathfinder` node, and is commonly useful in Kubernetes docker setups. It returns a `200 OK` status if the node is healthy.

### Readiness

`pathfinder` does several things before it is ready to respond to RPC queries. In most cases this startup time is less than a second, however there are certain scenarios where this can be considerably longer. For example, applying an expensive database migration after an upgrade could take several minutes (or even longer) on testnet. Or perhaps our startup network checks fail many times due to connection issues.

`/ready` provides a way of checking whether the node's JSON-RPC API is ready to be queried. It returns a `503 Service Unavailable` status until all startup tasks complete, and then `200 OK` from then on.

### Synced

Similar to `/ready`, `/ready/synced` checks whether the node's JSON-RPC API is ready to be queried _and_ also checks if the node is synced (within 6 blocks of the current tip of the chain). It returns a `503 Service Unavailable` status if either check fails, and `200 OK` if they both pass.

This endpoint is useful for Docker nodes which only want to present themselves as ready after they have been synced.

### Metrics

`/metrics` provides a [Prometheus](https://prometheus.io/) metrics scrape endpoint. Currently the following metrics are available:

#### RPC related counters

- `rpc_method_calls_total`,
- `rpc_method_calls_failed_total`,

You __must__ use the label key `method` to retrieve a counter for a particular RPC method, for example:
```
rpc_method_calls_total{method="starknet_getStateUpdate"}
rpc_method_calls_failed_total{method="starknet_chainId"}
```
You may also use the label key `version` to specify a particular version of the RPC API, for example:
```
rpc_method_calls_total{method="starknet_getEvents", version="v0.3"}
```

#### Feeder Gateway and Gateway related counters

- `gateway_requests_total`
- `gateway_requests_failed_total`
- `gateway_request_duration_seconds`

Labels:
- `method`, to retrieve a counter for a particular sequencer request type
- `tag`
    - works with methods: `get_block`, `get_state_update`
    - valid values:
        - `pending`
        - `latest`
- `reason`
    - works with: `gateway_requests_failed_total`
    - valid values:
        - `decode`
        - `starknet`
        - `rate_limiting`
        - `timeout`

Valid examples:
```
gateway_requests_total{method="get_block"}
gateway_requests_total{method="get_block", tag="latest"}
gateway_requests_failed_total{method="get_state_update"}
gateway_requests_failed_total{method="get_state_update", tag="pending"}
gateway_requests_failed_total{method="get_state_update", tag="pending", reason="starknet"}
gateway_requests_failed_total{method="get_state_update", reason="rate_limiting"}
```

These __will not work__:
- `gateway_requests_total{method="get_transaction", tag="latest"}`, `tag` is not supported for that `method`
- `gateway_requests_total{method="get_transaction", reason="decode"}`, `reason` is only supported for failures.

### Sync related metrics

- `current_block` currently sync'd block height of the node
- `highest_block` height of the block chain
- `block_time` timestamp difference between the current block and its parent
- `block_latency` delay between current block being published and sync'd locally
- `block_download` time taken to download current block's data excluding classes
- `block_processing` time taken to process and store the current block
- `block_processing_duration_seconds` histogram of time taken to process and store a block

### Build info metrics

- `pathfinder_build_info` reports current version as a `version` property

## Build from source

See the [guide](https://github.com/eqlabs/pathfinder/blob/main/doc/install-from-source.md).

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
