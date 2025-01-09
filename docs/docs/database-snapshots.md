---
sidebar_position: 4
---

# Database Snapshots

Database snapshots let you quickly start your node without having to download all blocks from the very beginning. Instead, you use a pre-made version of the database that’s already in sync up to a certain block. This saves you a lot of time, especially if the network has many blocks.

There are two main ways to download and use a snapshot with Pathfinder:

* [Using Rclone](#using-rclone-for-snapshots)
* [Using a direct HTTPS link](#downloading-via-https)

## Using Rclone for Snapshots

[**Rclone**](https://rclone.org/) is a command-line program to manage files on cloud storage. It is highly recommended for Pathfinder snapshots due to its reliability and support for resumable downloads.

### Rclone Configuration

1. Follow the [official installation guide](https://rclone.org/install/) for your operating system.
2. Open or create your Rclone configuration file (`$HOME/.config/rclone/rclone.conf`) and add:
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
3. Use `rclone` to copy the compressed SQLite file to your local directory:
   ```bash
   rclone copy -P pathfinder-snapshots:pathfinder-snapshots/sepolia-testnet_0.14.0_209745_pruned.sqlite.zst .
   ```

:::tip 
Add `-P` to get a progress display that helps you track the download status.
:::

## Downloading via HTTPS

While HTTPS URLs are also provided, direct HTTPS downloads can sometimes be less reliable for very large files. If you must use HTTPS, verify you can resume downloads or maintain a stable connection. For example:

```bash
wget --continue https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/mainnet_0.14.0_751397_pruned.sqlite.zst
```

## Extracting Snapshots and Checksums

Snapshots come as zstd-compressed SQLite files. Once the download completes, follow these steps:

1. Compare the file’s checksum against the published value to ensure data integrity:
   ```bash
   sha256sum sepolia-testnet_0.14.0_209745_pruned.sqlite.zst
   # Compare with the listed hash in the documentation
   ```
2. Use `zstd` (version 1.5 or later) to extract:
   ```bash
   zstd -T0 -d sepolia-testnet_0.14.0_209745_pruned.sqlite.zst -o testnet-sepolia.sqlite
   ```
   This produces an uncompressed file, e.g., `testnet-sepolia.sqlite`.

3. If you intend to replace your existing database, **stop** the Pathfinder process, rename or remove your old database, and move the new file into place. For example:
   ```bash
   mv testnet-sepolia.sqlite /path/to/your/pathfinder/data/mainnet.sqlite
   ```
   Ensure your file names and paths match the network you’re running.

## Available Snapshots

The table below lists currently available snapshots, their block heights, and corresponding checksums. Refer to the [official release page](https://github.com/eqlabs/pathfinder/releases) or the snapshot hosting platform for the latest files.

| **Network**     | **Block** | **Pathfinder Version** | **Mode** | **Filename**                                       | **Download URL**                                                                                                 | **Size**  | **Checksum (SHA2-256)**                                            |
| --------------- | --------- | ---------------------- | -------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------ |
| Mainnet         | 751397    | >= 0.14.0              | pruned   | `mainnet_0.14.0_751397_pruned.sqlite.zst`          | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/mainnet_0.14.0_751397_pruned.sqlite.zst)          | 71.03 GB  | `2f9aa8b98086c12a1ce14e89ddfe02ebf320a7ba47e63829056a405866568113` |
| Mainnet         | 751250    | >= 0.14.0              | archive  | `mainnet_0.14.0_751250_archive.sqlite.zst`         | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/mainnet_0.14.0_751250_archive.sqlite.zst)         | 433.13 GB | `3540087b326b58437fd12bcf427eaeb6323f3efc3def56816b7e5fc06d2633ae` |
| Sepolia testnet | 209745    | >= 0.14.0              | pruned   | `sepolia-testnet_0.14.0_209745_pruned.sqlite.zst`  | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/sepolia-testnet_0.14.0_209745_pruned.sqlite.zst)  | 5.71 GB   | `5cc9a13079a36ee09c04824f6b30b5ce16cd2d26039b23c7c7937f57a76ba19b` |
| Sepolia testnet | 209758    | >= 0.14.0              | archive  | `sepolia-testnet_0.14.0_209758_archive.sqlite.zst` | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/sepolia-testnet_0.14.0_209758_archive.sqlite.zst) | 18.93 GB  | `3c24a6e9e5294d738f5976e2c949ebac42ed3fc4865a21893df44897fe803686` |

:::info
**Pruned** mode retains limited historical state tries, reducing storage size but limiting storage-proof queries. **Archive** mode is fully historic, storing all state tries since genesis.
:::