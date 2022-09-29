# Welcome to Pathfinder

A StarkNet full node giving you a safe view into StarkNet.

Pathfinder is currently in alpha so expect some rough edges but it is already usable today!

## Features

- access the full StarkNet state history
  - includes contract code and storage, and transactions
- verifies state using L1
  - calculates the StarkNet state's Patricia-Merkle Trie root on a block-by-block basis and confirms it against L1
  - this means the contract code and storage are now locally verified
- Ethereum-like RPC API
- run StarkNet functions without requiring a StarkNet transaction
  - executed against the local state

## Feedback

We appreciate any feedback, especially during this alpha period.
This includes any documentation issues, feature requests and bugs that you may encounter.

For help or to submit bug reports or feature requests, please open an issue or alternatively visit the StarkNet [discord channel](https://discord.com/invite/QypNMzkHbc).

## Installation (from source)

If you'd like to just run and deploy a node, please consider skipping ahead to [docker instructions](#running-with-docker).
The following are instructions on how to build from source.

### Prerequisites

Currently only supports Linux. Windows and MacOS support is planned.
We need access to a full Ethereum node operating on the network matching the StarkNet network you wish to run. Currently this is either Goerli or Mainnet.

| :warning: | If using Infura as an L1 provider, you will need access to their archive node facilities. This is because `pathfinder` requires access to the full log history. |
| --------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------- |


Before you start, make sure your system is up to date with Curl and Git available:

```bash
sudo apt update
sudo apt upgrade
sudo apt install curl git
```

### Install Rust

`pathfinder` requires Rust version `1.63` or later.
The easiest way to install Rust is by following the [official instructions](https://www.rust-lang.org/tools/install).

If you already have Rust installed, verify the version:

```bash
cargo --version # must be 1.63 or higher
```

To update your Rust version, use the `rustup` tool that came with the official instructions:

```bash
rustup update
```

### Install Python

`pathfinder` requires Python version `3.8` (in particular, `cairo-lang` 0.7.1 seems incompatible with Python 3.10).

```bash
sudo apt install python3 python3-venv python3-dev
```

Verify the python version.
Some Linux distributions only supply an outdated python version, in which case you will need to lookup a guide for your distribution.

```bash
python3 --version # must be 3.8
```

### Install build dependencies

`pathfinder` compilation need additional libraries to be installed (C compiler, linker, other deps)

```bash
sudo apt install build-essential libgmp-dev pkg-config libssl-dev
```

### Clone `pathfinder`

Checkout the latest `pathfinder` release by cloning this repo and checking out the latest version tag.
Take care not to be on our `main` branch as we do actively develop in it.

The remainder of the installation documentation assumes you are in the checkout directory.

### Python setup

Create a python virtual environment in the `py` folder.

```bash
# Enter the `<repo>/py` directory
cd py
# Create the virtual environment and activate it
python3 -m venv .venv
source .venv/bin/activate
```

Next install the python tooling and dependencies

```bash
PIP_REQUIRE_VIRTUALENV=true pip install --upgrade pip
PIP_REQUIRE_VIRTUALENV=true pip install -r requirements-dev.txt
```

Finally, run our python tests to make sure you were succesful.

```bash
# This should run the tests (and they should pass).
pytest
```

### Compiling `pathfinder`

You should now be able to compile `pathfinder` by running (from within the `pathfinder` repo):

```bash
cargo build --release --bin pathfinder
```

## Updating `pathfinder`

Updating a `pathfinder` node from source is fairly straight forward and is a simpler variant of the installation and compilation described above.

#### `pathfinder` repository

Start by updating the `pathfinder` repository to the desired version. From within your `pathfinder` folder:

```bash
git fetch
git checkout <version-tag>
```

where `<version-tag>` is the desired pathfinder version. To display a list of all available versions, run

```
git tag
```

#### Python dependencies

Next, update the python dependencies. First enable your python virtual environment (if you are using one). For our example installation this would be:

```bash
source ./py/.venv/bin/activate
```

and then update:

```bash
PIP_REQUIRE_VIRTUALENV=true pip install -r requirements-dev.txt
```

#### Build and run `pathfinder`

Re-compile `pathfinder`:

```bash
cargo build --release --bin pathfinder
```

and you should now be able to run your `pathfinder` node as described in the [next section](#running-the-node).

## Running the node

Ensure you have activated the python virtual environment you created in the [python setup step](#python-setup).
For the `pathfinder` environment this is done by running:

```bash
source py/.venv/bin/activate
```

If you are already in another virtual environment, you can exit it by running `deactivate` and then activating the `pathfinder` one.

This step is always required when running `pathfinder`.

Finally, you can start the node:

```bash
cargo run --release --bin pathfinder -- <pathfinder options>
```

Note the extra "`--`" which separate the Rust `cargo` command options from the options for our node.
For more information on these options see the [Configuration](#configuration) section.

It may take a while to first compile the node on the first invocation if you didn't do the [compilation step](#compiling-pathfinder).

`pathfinder` runs relative to the current directory.
This means things like the database will be created and searched for within the current directory.

### Configuration

The `pathfinder` node options can be configured via the command line as well as a configuration file or environment variables.
The command line configuration overrides the options from the file.

The command line options are passed in after the after the `cargo run` options, as follows:

```bash
cargo run --release --bin pathfinder -- <pathfinder options>
```

Using `--help` will display the `pathfinder` options, including their environment variable names:

```bash
# with built from source
cargo run --release --bin pathfinder -- --help

# with docker images (0.2.0 onwards)
docker run --rm eqlabs/pathfinder
```

The configuration file uses the `toml` format:

```toml
# The address we will host the RPC API at. Defaults to "127.0.0.1:9545"
http-rpc = "127.0.0.1:1235"
# The directory the node will use to store its data. Defaults to the current directory.
data-directory = "..."
# Override the Sequencer gateway address with your own. This is can be useful if you
# have a caching proxy in front of the actual Sequencer gateway. If you're unsure
# of what this does, then you don't need it.
sequencer-url = "https://..."
# Set the number of Python subprocesses pathfinder starts. These processes are used
# to service the `starknet_call` JSON-RPC method and their number limits the maximal
# number of call requests that can be processed in parallel. Defaults to 2.
python-subprocesses = 2
# Whether to enable SQLite write-ahead logging. Defaults to true.
sqlite-wal = true
# Whether to enable pending support.
poll-pending = true
# The address to host the monitoring API at. Defaults to disabled.
monitor-address = "127.0.0.1:54321"

[ethereum]
# This is required and must be an HTTP(s) URL pointing to your Ethereum node's endpoint.
url      = "https://goerli.infura.io/v3/..." #
# The optional password for your Ethereum endpoint.
password = "..."
```

### Pending Support

Block times on `mainnet` can be prohibitively long for certain applications. As a work-around, StarkNet added the concept of a `pending` block which is the block currently under construction. This is supported by pathfinder, and usage is documented in the [JSON-RPC API](#json-rpc-api) with various methods accepting `"block_id"="pending"`.

Note that `pending` support is disabled by default and must be enabled by setting `poll-pending=true` in the configuration options.

### Logging

Logging can be configured using the `RUST_LOG` environment variable.
We recommend setting it when you invoke the run command:

```bash
RUST_LOG=<log level> cargo run --release --bin pathfinder ...
```

The following log levels are supported, from most to least verbose:

```bash
trace
debug
info  # default
warn
error
```

At the more verbose log levels (`trace`, `debug`), you may find the logs a bit noisy as our dependencies also add their own logging to the mix.
You can restrict the logs to only `pathfinder` specific ones using `RUST_LOG=pathfinder=<level>` instead. For example:

```bash
RUST_LOG=pathfinder=<log level> cargo run --release --bin pathfinder ...
```

### Network Selection

The StarkNet network is based on the provided Ethereum endpoint.
If the Ethereum endpoint is on the Goerli network, then the it will be the StarkNet testnet on Goerli.
If the Ethereum endpoint is on mainnet, then it will be StarkNet Mainnet.

## Running with Docker

The following assumes you have [docker installed](https://docs.docker.com/get-docker/) and ready to go.

The provided docker image embeds everything to run a node directly without any other installation. For example:

```sh
mkdir -p $HOME/pathfinder
docker run \
  --rm \
  -p 9545:9545 \
  --user "$(id -u):$(id -g)" \
  -e RUST_LOG=info \
  -e PATHFINDER_ETHEREUM_API_URL="<https://goerli.infura.io/v3/><project-id>" \
  -v $HOME/pathfinder:/usr/share/pathfinder/data \
  eqlabs/pathfinder
```

will run a Goerli node (see `PATHFINDER_ETHEREUM_API_URL` endpoint) on port `9545`, binding local folder `$HOME/pathfinder` to the node's sqlite db directory.

### Docker compose

The [docker-compose.yml](./docker-compose.yml) file embeds everything to run or deploy goerli and mainnet nodes in one command.
It uses env variables defined in the `.env` that you need to create from the `example.env` and populate with Ethereum RPC endpoints.

```bash
cp example.env .env
# replace the value(s) of PATHFINDER_ETHEREUM_API_URL by the HTTP URL(s) pointing to your Ethereum node's endpoint
```

By default, `docker compose up` will run both a mainnet and a goerli node. If you want to run only one service, you can specify it after the `up`:

```bash
docker compose up # run both mainnet and goerli
docker compose up starknet-mainnet # run mainnet only
docker compose up starknet-goerli # run goerli only
```

To check if it's running well use `docker-compose logs -f`.

The mainnet node runs on port 9546 while the goerli one runs on port 9545. You can check this by calling the `starknet_chainId` method:

```bash
curl '0.0.0.0:9545' \
  -H 'content-type: application/json' \
  --data-raw '{"method":"starknet_chainId","jsonrpc":"2.0","params":[],"id":0}' \
  --compressed
# {"jsonrpc":"2.0","result":"0x534e5f474f45524c49","id":0}
echo 0x534e5f474f45524c49 | xxd -rp
# SN_GOERLI
curl '0.0.0.0:9546' \
  -H 'content-type: application/json' \
  --data-raw '{"method":"starknet_chainId","jsonrpc":"2.0","params":[],"id":0}' \
  --compressed
# {"jsonrpc":"2.0","result":"0x534e5f4d41494e","id":0}
echo 0x534e5f4d41494e | xxd -rp
# SN_MAIN
```

### Cloud deployment

Docker has built-in integrations with [AWS](https://docs.docker.com/cloud/ecs-integration/) and [Azure](https://docs.docker.com/cloud/aci-integration/) using `docker context`.

More details are given in the dedicated pages:

- for AWS: [docs/aws/README.md](./docs/aws/README.md)
- for Azure: [docs/azure/README.md](./docs/azure/README.md)
- for GCP: [docs/gcp/README.md](./docs/gcp/README.md)

### Updating the docker image

When pathfinder detects there has been a new release, it will log a message similar to:

```log
WARN New pathfinder release available! Please consider updating your node! release=0.1.8-alpha
```

You can try pulling the latest docker image to update it:

```bash
docker pull eqlabs/pathfinder
```

There is a chance of seeing the release notification before a new docker image is available for download, so just wait a minutes and then retry.

### Available images

Our images are updated on every `pathfinder` release. This means that the `:latest` docker image does not track our `main` branch here, but instead matches the latest `pathfinder` [release](https://github.com/eqlabs/pathfinder/releases).

### Building the container image yourself

Building the container image from source code is necessary only in special cases or development.
You can build the image by running:

```bash
docker build -t pathfinder .
```

## JSON-RPC API

Pathfinder supports version `v0.1.0` of the StarkNet JSON-RPC [specification](https://github.com/starkware-libs/starknet-specs/blob/v0.1.0/api/starknet_api_openrpc.json), with the following changes:
- The `starknet_protocolVersion` method is not implemented. This method will be removed from the specification in its next version as its semantics and usage was questionable. We decided to not implement it.
- To be able to represent L1 handler transactions introduced in Starknet 0.10, we use the `L1_HANDLER_TXN` type from `0.2.0-rc1` of the JSON-RPC specification.
- Pathfinder supports submitting transactions by passing these requests on to the StarkNet gateway. See [here](#transaction-write-api) for more details.

When browsing the specification project, please be aware of the following pitfalls:
- It uses git tags for release versions. The link above should take you to the version supported by pathfinder.
- The `master` branch is an active development branch and may contain unreleased specification changes.
- The playground link listed there does not link to the specific version, but instead reflects the `master` branch. Here is a corrected [playground link](https://playground.open-rpc.org/?uiSchema[appBar][ui:splitView]=false&[appBar][ui:input]=false&uiSchema[appBar][ui:darkMode]=true&uiSchema[appBar][ui:examplesDropdown]=false&schemaUrl=https://raw.githubusercontent.com/starkware-libs/starknet-specs/v0.1.0/api/starknet_api_openrpc.json&uiSchema).

### Transaction write API

Pathfinder also support's submitting StarkNet transaction's to the StarkNet gateway. Here are links to the [specification](https://github.com/starkware-libs/starknet-specs/blob/v0.1.0/api/starknet_write_api.json) and the [playground](https://playground.open-rpc.org/?uiSchema[appBar][ui:splitView]=false&[appBar][ui:input]=false&uiSchema[appBar][ui:darkMode]=true&uiSchema[appBar][ui:examplesDropdown]=false&schemaUrl=https://gist.githubusercontent.com/Mirko-von-Leipzig/f4515d423775edee68ab08c3f4b6afec/raw/65ce9b3adfb97393152450b2f36d6d3572ee2354/StarkNet%2520Write%2520API%2520v0.1.0.json).

Note that:

- `mainnet` requires an additional `token` parameter to submit transactions
- `starknet_addDeployTransaction` and `starknet_addDeclareTransaction` allow an optional `abi` field

## Monitoring API

Pathfinder has a monitoring API which can be enabled with the `--monitor-address` configuration option.

### Health

`/health` provides a method to check the health status of your `pathfinder` node, and is commonly useful in Kubernetes docker setups. It returns a `200 OK` status if the node is healthy.

### Readyness

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

If you would like to contribute to the `py/` parts, which interface with
[`cairo-lang`](https://github.com/starkware-libs/cairo-lang), please include a
mention that you agree to relicense the python parts as necessary to abide with
future `cairo-lang` license. See `contributing.md` for more information.
