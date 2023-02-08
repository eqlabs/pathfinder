# Installation from source

## Prerequisites

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

## Install Rust

`pathfinder` requires Rust version `1.64` or later.
The easiest way to install Rust is by following the [official instructions](https://www.rust-lang.org/tools/install).

If you already have Rust installed, verify the version:

```bash
cargo --version # must be 1.64 or higher
```

To update your Rust version, use the `rustup` tool that came with the official instructions:

```bash
rustup update
```

## Install Python

`pathfinder` requires Python version `3.8` (in particular, `cairo-lang` 0.10.2a0 seems incompatible with Python 3.10).

```bash
sudo apt install python3 python3-venv python3-dev
```

Verify the python version.
Some Linux distributions only supply an outdated python version, in which case you will need to lookup a guide for your distribution.

```bash
python3 --version # must be 3.8
```

## Install build dependencies

`pathfinder` compilation need additional libraries to be installed (C compiler, linker, other deps)

```bash
sudo apt install build-essential libgmp-dev pkg-config libssl-dev
```

## Clone `pathfinder`

Checkout the latest `pathfinder` release by cloning this repo and checking out the latest version tag.
Take care not to be on our `main` branch as we do actively develop in it.

The remainder of the installation documentation assumes you are in the checkout directory.

## Python setup

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
PIP_REQUIRE_VIRTUALENV=true pip install -e .[dev]
```

Finally, run our python tests to make sure you were successful.

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

### Python dependencies

Next, update the python dependencies. First enable your python virtual environment (if you are using one). For our example installation this would be:

```bash
source ./py/.venv/bin/activate
```

and then update:

```bash
PIP_REQUIRE_VIRTUALENV=true pip install -e py/.[dev]
```

### Build and run `pathfinder`

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

Note the extra "`--`" which separates the Rust `cargo` command options from the configuration options for our node.
You can list these configuration options using `--help`:
```bash
cargo run --release --bin pathfinder -- --help
```

It may take a while to first compile the node on the first invocation if you didn't do the [compilation step](#compiling-pathfinder).

`pathfinder` runs relative to the current directory.
This means things like the database will be created and searched for within the current directory.
