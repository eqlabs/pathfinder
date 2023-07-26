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

## Running with Docker

The `pathfinder` node can be run in the provided Docker image.
Using the Docker image is the easiest way to start `pathfinder`. If for any reason you're interested in how to set up all the
dependencies and the Python environment yourself please check the [Installation from source](doc/install-from-source.md) guide.

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
  -e PATHFINDER_ETHEREUM_API_URL="https://goerli.infura.io/v3/<project-id>" \
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
  -e PATHFINDER_ETHEREUM_API_URL="https://goerli.infura.io/v3/<project-id>" \
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

Note that `pending` support is disabled by default and must be enabled by setting `poll-pending=true` in the configuration options.

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
- Starknet testnet for Ethereum Goerli

#### Custom networks & gateway proxies

You can specify a custom network with `--network custom` and specifying the `--gateway-url`, `feeder-gateway-url` and `chain-id` options. 
Note that `chain-id` should be specified as text e.g. `SN_GOERLI`.

This can be used to interact with a custom Starknet gateway, or to use a gateway proxy.

## JSON-RPC API

You can interact with Starknet using the JSON-RPC API. Pathfinder supports the official Starknet RPC API and in addition supplements this with its own pathfinder specific extensions such as `pathfinder_getProof`.

Currently pathfinder supports `v0.3` and `v0.4` versions of the Starknet JSON-RPC specification.
The `path` of the URL used to access the JSON-RPC server determines which version of the API is served:

- the `v0.3.0` API is exposed on the `/` and `/rpc/v0.3` path
- the `v0.4.0` API is exposed on the `/` and `/rpc/v0.4` path
- the pathfinder extension API is exposed on `/rpc/pathfinder/v0.1`

Note that the pathfinder extension is versioned separately from the Starknet specification itself.

### API `v0.4.0`

`starknet_simulateTransactions` currently always requires the `SKIP_FEE_CHARGE` flag until we upgrade to using starknet-in-rust as our execution engine.

### pathfinder extension API

You can find the API specification [here](doc/rpc/pathfinder_rpc_api.json).

## Monitoring API

Pathfinder has a monitoring API which can be enabled with the `--monitor-address` configuration option.

### Health

`/health` provides a method to check the health status of your `pathfinder` node, and is commonly useful in Kubernetes docker setups. It returns a `200 OK` status if the node is healthy.

### Readiness

`pathfinder` does several things before it is ready to respond to RPC queries. In most cases this startup time is less than a second, however there are certain scenarios where this can be considerably longer. For example, applying an expensive database migration after an upgrade could take several minutes (or even longer) on testnet. Or perhaps our startup network checks fail many times due to connection issues.

`/ready` provides a way of checking whether the node's JSON-RPC API is ready to be queried. It returns a `503 Service Unavailable` status until all startup tasks complete, and then `200 OK` from then on.

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

#### Python subprocess related counters

- `extpy_processes_launched_total` incremented each time python subprocess is launched
- `extpy_processes_exited_total` with labels, incremented each time python subprocess exits normally
- `extpy_processes_failed_total` incremented each time python subprocess exits abnormally

#### Feeder Gateway and Gateway related counters

- `gateway_requests_total`
- `gateway_requests_failed_total`

Labels:
- `method`, to retrieve a counter for a particular sequencer request type
- `tag`
    - works with: `get_block`, `get_state_update`
    - valid values:
        - `pending`
        - `latest`
- `reason`
    - works with: `gateway_requests_failed_total`
    - valid values:
        - `decode`
        - `starknet`
        - `rate_limiting`

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

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Questions / FAQ

Questions are welcome! If you have any questions regarding Pathfinder, feel free to ask them using [Newton](https://www.newton.so/view?tags=pathfinder).

### FAQ

* [How do I run a Pathfinder node?](https://www.newton.so/view/63a062c3620f9c99ad981fc6)

* [Why should I run a Pathfinder node?](https://www.newton.so/view/63a06374620f9c99ad981fc7)

* [What resources are required to run a Pathfinder node?](https://www.newton.so/view/63a063e1620f9c99ad981fc9)

* [Are there rewards for running a Pathfinder node?](https://www.newton.so/view/63a0643d620f9c99ad981fca)

* [How do I connect my wallet to my Pathfinder node?](https://www.newton.so/view/63a06484620f9c99ad981fcb)

* [How do I interact with my Pathfinder node?](https://www.newton.so/view/63a064bb407c7621270c0202)

* [My Alchemy dashboard usage is low?](https://www.newton.so/view/63a06558620f9c99ad981fce)

* [How to select the network my Pathfinder node runs on?](https://www.newton.so/view/63a0659a407c7621270c0204)

* [How do I see my Pathfinder logs?](https://www.newton.so/view/63a065da620f9c99ad981fd0)

* [How do I move my Pathfinder node to another server / disk?](https://www.newton.so/view/63a06611407c7621270c0206)

* [Error compiling Pathfinder (rust)](https://www.newton.so/view/63a066c2407c7621270c0208)

* [Python issues with Pathfinder](https://www.newton.so/view/63a06669620f9c99ad981fd1)


## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

If you would like to contribute to the `py/` parts, which interface with
[`cairo-lang`](https://github.com/starkware-libs/cairo-lang), please include a
mention that you agree to relicense the python parts as necessary to abide with
future `cairo-lang` license. See `contributing.md` for more information.
