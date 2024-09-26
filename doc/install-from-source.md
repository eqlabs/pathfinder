# Installation from source

## Prerequisites

Currently only supports Linux. Windows and MacOS support is planned.
We need access to a full Ethereum node operating on the network matching the Starknet network you wish to run. Currently this is either Sepolia or Mainnet.

| :warning: | If using Infura as an L1 provider, you will need access to their archive node facilities. This is because `pathfinder` requires access to the full log history. |
| --------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------- |


Before you start, make sure your system is up to date with Curl and Git available:

```bash
sudo apt update
sudo apt upgrade
sudo apt install curl git
```

## Install Rust

`pathfinder` requires Rust version `1.80` or later.
The easiest way to install Rust is by following the [official instructions](https://www.rust-lang.org/tools/install).

If you already have Rust installed, verify the version:

```bash
cargo --version # must be 1.80 or higher
```

To update your Rust version, use the `rustup` tool that came with the official instructions:

```bash
rustup update
```

## Install build dependencies

`pathfinder` compilation needs additional libraries to be installed (C compiler, linker, other deps)

```bash
sudo apt install build-essential pkg-config libssl-dev protobuf-compiler libzstd-dev
```

Make sure `protoc` version is at least `3.15`
```bash
protoc --version # must be >= 3.15
```

Alternatively you can grab the latest `protoc` from the [releases page](https://github.com/protocolbuffers/protobuf/releases).

## Clone `pathfinder`

Checkout the latest `pathfinder` release by cloning this repo and checking out the latest version tag.
Take care not to be on our `main` branch as we do actively develop in it.

The remainder of the installation documentation assumes you are in the checkout directory.

### Compiling `pathfinder`

You should now be able to compile `pathfinder` by running (from within the `pathfinder` repo):

```bash
cargo build --release --bin pathfinder
```

## Updating `pathfinder`

Updating a `pathfinder` node from source is fairly straightforward and is a simpler variant of the installation and compilation described above.

### `pathfinder` repository

Start by updating the `pathfinder` repository to the desired version. From within your `pathfinder` folder:

```bash
git fetch
git checkout <version-tag>
```

where `<version-tag>` is the desired pathfinder version. To display a list of all available versions, run

```
git tag
```

### Build and run `pathfinder`

Re-compile `pathfinder`:

```bash
cargo build --release --bin pathfinder
```

and you should now be able to run your `pathfinder` node as described in the [next section](#running-the-node).


## Running the node

```bash
cargo run --release --bin pathfinder -- <pathfinder options>
```

Note the extra "`--`" which separates the Rust `cargo` command options from the configuration options for our node.
You can list these configuration options using `--help`:
```bash
cargo run --release --bin pathfinder -- --help
```

It may take a while to first compile the node on the first invocation if you didn't do the [compilation step](#compiling-pathfinder).

`pathfinder` runs relative to the current directory.
This means things like the database will be created and searched for within the current directory.
