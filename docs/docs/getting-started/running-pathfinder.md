---
sidebar_position: 2
---

# Setting up Pathfinder

Pathfinder can be set up using one of the following methods:

* [Docker container](#docker-setup)  
* [Building from source](#building-from-source)
        

## Docker Container

The simplest way to run Pathfinder is using Docker. This method is recommended for beginners as it requires minimal setup and configuration.  

### Installing Docker

Follow the official [Docker installation guide](https://docs.docker.com/get-docker/) for your operating system. 

### Setting Up the Ethereum API URL

Pathfinder requires an Ethereum Websocket API URL to verify Starknet state proofs by communicating with the Ethereum blockchain. You can obtain this URL from services like [Infura](https://www.infura.io/) or [Alchemy](https://www.alchemy.com/). After signing up, create a new project on your desired Ethereum network to receive your WebSocket (wss://) endpoint.

### Running Pathfinder with Docker

With Docker installed and your endpoint ready, you can run Pathfinder using the following commands:

```bash
mkdir -p $HOME/pathfinder
docker run \
  --name pathfinder \
  --restart unless-stopped \
  --detach \
  -p 9545:9545 \
  --user "$(id -u):$(id -g)" \
  -e RUST_LOG=info \
  -e PATHFINDER_ETHEREUM_API_URL="wss://sepolia.infura.io/ws/v3/<project-id>" \
  -v $HOME/pathfinder:/usr/share/pathfinder/data \
  eqlabs/pathfinder
```

:::tip
Always ensure your `$HOME/pathfinder` directory exists and is writable by your user before starting the container.
:::

To check the logs of the running container:

```bash
docker logs -f pathfinder
```

To stop the Pathfinder container:

```bash
docker stop pathfinder
```



### Docker Compose Setup

If you prefer using Docker Compose, create a `pathfinder` folder where your `docker-compose.yaml` file is located:

```bash
mkdir -p pathfinder

# Replace the value of PATHFINDER_ETHEREUM_API_URL with the URL of your Ethereum node's endpoint
cp example.pathfinder-var.env pathfinder-var.env

docker-compose up -d
```

To check if it's running correctly, use:

```bash
docker-compose logs -f
```

## Building From Source

Building Pathfinder from source gives you more control over the build and is ideal if you need a specific version or configuration.

### Prerequisites

To build Pathfinder from source, you need to have the following prerequisites:

* **Operating System**: Linux (Windows and macOS support is planned)
* **Ethereum Node Access**: You need access to a full Ethereum node (e.g., Infura) operating on the same network as Starknet.

To set up the required tools, make sure your system is up to date and install Curl and Git:

```bash
sudo apt update
sudo apt upgrade
sudo apt install curl git
```

### Install Rust

Pathfinder requires Rust version 1.80 or later. Install Rust by following the [official instructions](https://www.rust-lang.org/tools/install). If you already have Rust installed, verify the version:

```bash
cargo --version # must be 1.80 or higher
```

To update Rust, use:

```bash
rustup update
```

### Install Build Dependencies

Pathfinder requires additional libraries for compilation:

```bash
sudo apt install build-essential pkg-config libssl-dev protobuf-compiler libzstd-dev
```

Ensure `protoc` is version 3.15 or higher:

```bash
protoc --version # must be >= 3.15
```

If needed, you can get the latest `protoc` from the [releases page](https://github.com/protocolbuffers/protobuf/releases).

### Cloning Pathfinder

Clone the Pathfinder repository and check out the latest release:

```bash
git clone https://github.com/eqlabs/pathfinder.git
cd pathfinder
git checkout <latest-version-tag>
```

To see all available versions:

```bash
git tag
```

### Compiling Pathfinder

From within the `pathfinder` repository, compile the project:

```bash
cargo build --release --bin pathfinder
```

### Running the Node

After building Pathfinder, you can run the node:

```bash
cargo run --release --bin pathfinder -- <pathfinder options>
```

Note: The `--` separates Rust `cargo` options from Pathfinder configuration options. To list available options:

```bash
cargo run --release --bin pathfinder -- --help
```