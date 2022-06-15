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

For help or to submit bug reports or feature requests, please open an issue or alternatively visit the StarkNet [discord channel](https://discord.com/invite/uJ9HZTUk2Y).

## Installation

If you'd like to just run the node, please consider skipping ahead to [docker instructions](#running-with-docker).
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

`pathfinder` requires Rust version `1.58` or later.
The easiest way to install Rust is by following the [official instructions](https://www.rust-lang.org/tools/install).

If you already have Rust installed, verify the version:

```bash
cargo --version # must be 1.58 or higher
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

[ethereum]
# This is required and must be an HTTP(s) URL pointing to your Ethereum node's endpoint.
url      = "https://goerli.infura.io/v3/..." #
# The optional password for your Ethereum endpoint.
password = "..."
# The optional user-agent for your Ethereum endpoint.
user-agent     = "..."
```

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

The `pathfinder` node can be run in the provided Docker image.
Docker image is the easiest way which does not involve a lot of python setup.
The following assumes you have [docker installed](https://docs.docker.com/get-docker/) and ready to go.

The example uses `$HOME/pathfinder` as the volume directory where persistent files used by `pathfinder` will be stored.
It is easiest to create the volume directory as the user who is running the docker command.
If the directory gets created by docker upon startup, it might be unusable for creating files.

```bash
# ensure the directory has been created before invoking docker
mkdir -p $HOME/pathfinder
docker run \
  --rm \
  -p 9545:9545 \
  -e RUST_LOG=info \
  -e PATHFINDER_ETHEREUM_API_URL="https://goerli.infura.io/v3/<project-id>" \
  -v $HOME/pathfinder:/usr/share/pathfinder/data \
  eqlabs/pathfinder
```

### Updating the docker image

When pathfinder detects there has been a new release, it will log a message similar to:

```
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

## API

The full specification is available [here](https://github.com/starkware-libs/starknet-specs).
Note that we currently only support a subset of these.
Here is an overview of the JSON-RPC calls which we support.

```bash
# Block information
starknet_getBlockByHash
starknet_getBlockByNumber
# Value of a storage at a given address and key
starknet_getStorageAt
# Transaction information
starknet_getTransactionByHash
starknet_getTransactionByBlockHashAndIndex
starknet_getTransactionByBlockNumberAndIndex
starknet_getTransactionReceipt
# Block transaction counts
starknet_getBlockTransactionCountByHash
starknet_getBlockTransactionCountByNumber
# The code of a class
starknet_getClass
# The class hash of a specific contract
starknet_getClassHashAt
# The code of a specific contract
starknet_getClassAt
# The old, now deprecated name for starknet_getClassAt is also supported
starknet_getCode
# Call a StarkNet function without creating a transaction
starknet_call
# The latest StarkNet block height
starknet_blockNumber
# The StarkNet chain this node is on
starknet_chainId
# The node's sync status
starknet_syncing
# Returns all events matching the given filter
starknet_getEvents
# Submit a new invoke contract transaction
starknet_addInvokeTransaction
# Submit a new deploy contract transaction
starknet_addDeployTransaction
# Submit a new declare contract transaction
starknet_addDeclareTransaction
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
