---
sidebar_position: 4
---

# Updating Pathfinder

When a new version of Pathfinder is released, you'll need to update your node to stay compatible with the Starknet network and access new features. Here's how to update your Pathfinder node, depending on how you installed it:

- [Updating Docker image](#updating-docker-images)
- [Updating from source](#updating-from-source)


## Updating Docker Image

When Pathfinder detects a new release, it will log a message similar to:

```plaintext
WARN New pathfinder release available! Please consider updating your node! release=0.14.3
```

To update to the latest version:

1. Pull the latest Docker image:
    
    ```bash
    docker pull eqlabs/pathfinder
    ```
    
2. Stop and remove the current Pathfinder container:
    
    ```bash
    docker stop pathfinder
    docker rm pathfinder
    ```
    
3. Re-create the container with the updated image:
    
    ```bash
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
Your node should now run the latest version without losing any stored data.

## Updating From Source

If you built Pathfinder from source, follow these steps to update:

1. Pull the latest changes from the repository: 
   ```bash
   git pull
   ```
2. Rebuild your pathfinder node:
   ```bash
   cargo build --release --bin pathfinder
   ```
3. Restart the node:
   ```bash
   cargo run --release --bin pathfinder -- <pathfinder options>
   ```
   The existing data in your `pathfinder` directory will be retained.
