---
sidebar_position: 4
---

# Database Snapshots

Database snapshots let you quickly start your node without having to download all blocks from the very beginning. Instead, you use a pre-made version of the database that’s already in sync up to a certain block. This saves you a lot of time, especially if the network has many blocks.

## Available Snapshots

Please check our [snapshot download page](https://rpc.pathfinder.swmansion.com/snapshots/latest) for the list of latest snapshots.

## How Snapshots Are Made

Snapshots are created once a week from the databases of our public Pathfinder nodes. For each network we take an online copy of the live database with SQLite's `VACUUM INTO`, compress it with `zstd` and compute its SHA2-256 checksum. The snapshot download page lists each snapshot's block height, sizes and checksum.

### Retention

Older snapshots are removed automatically after each weekly run. For each network we keep the two newest snapshots of each of the three newest Pathfinder minor versions, including all their patch releases. This way a compatible snapshot stays available for a while after a Pathfinder upgrade.

## Downloading via HTTPS

Snapshots are large files, so use a client that can resume an interrupted download. For example:

```bash
wget --continue -O mainnet.sqlite.zst https://rpc.pathfinder.swmansion.com/snapshots/latest/mainnet
```

Replace `mainnet` with `testnet-sepolia` or `integration-sepolia` for the other networks. The link redirects to the latest snapshot for that network.

## Extracting Snapshots and Checksums

Snapshots come as zstd-compressed SQLite files. Once the download completes, follow these steps:

1. Compare the file’s checksum against the published value to ensure data integrity:
   ```bash
   sha256sum mainnet.sqlite.zst
   # Compare with the hash listed on the snapshot download page
   ```
2. Use `zstd` (version 1.5 or later) to extract:
   ```bash
   zstd -T0 -d mainnet.sqlite.zst -o mainnet.sqlite
   ```
   This produces an uncompressed file, e.g., `mainnet.sqlite`.

3. If you intend to replace your existing database, **stop** the Pathfinder process, rename or remove your old database, and move the new file into place. For example:
   ```bash
   mv mainnet.sqlite /path/to/your/pathfinder/data/mainnet.sqlite
   ```
   Ensure your file names and paths match the network you’re running.
