---
sidebar_position: 4
---

# Database Snapshots

Re-syncing the whole history for either the mainnet or testnet networks might take a long time. To speed up the process you can use database snapshot files that contain the full state and history of the network up to a specific block.

The database files are hosted on Cloudflare R2. There are two ways to download the files:

* Using the [Rclone](https://rclone.org/) tool
* Via the HTTPS URL: we've found this to be less reliable in general

## Rclone setup

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

## Uncompressing database snapshots

**To avoid issues please check that the SHA2-256 checksum of the compressed file you've downloaded matches the value we've published.**

We're storing database snapshots as SQLite database files compressed with [zstd](https://github.com/facebook/zstd). You can uncompress the files you've downloaded using the following command:

```shell
zstd -T0 -d sepolia-testnet_0.11.0_47191.sqlite.zst -o testnet-sepolia.sqlite
```

This produces uncompressed database file `testnet-sepolia.sqlite` that can then be used by pathfinder.

## Available database snapshots

| Network         | Block  | Pathfinder version required | Mode    | Filename                                          | Download URL                                                                                                    | Compressed size | SHA2-256 checksum of compressed file                               |
| --------------- | ------ | --------------------------- | ------- | ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | --------------- | ------------------------------------------------------------------ |
| Sepolia testnet | 47191  | >= 0.11.0                   | archive | `sepolia-testnet_0.11.0_47191.sqlite.zst`         | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/sepolia-testnet_0.11.0_47191.sqlite.zst)         | 1.91 GB         | `82704d8382bac460550c3d31dd3c1f4397c4c43a90fb0e38110b0cd07cd94831` |
| Sepolia testnet | 61322  | >= 0.12.0                   | archive | `sepolia-testnet_0.12.0_61322_archive.sqlite.zst` | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/sepolia-testnet_0.12.0_61322_archive.sqlite.zst) | 3.56 GB         | `d25aa259ce62bb4b2e3ff49d243217799c99cd8b7e594a7bb24d4c091d980828` |
| Sepolia testnet | 61322  | >= 0.12.0                   | pruned  | `sepolia-testnet_0.12.0_61322_pruned.sqlite.zst`  | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/sepolia-testnet_0.12.0_61322_pruned.sqlite.zst)  | 1.26 GB         | `f2da766a8f8be93170997b3e5f268c0146aec1147c8ec569d0d6fdd5cd9bc3f1` |
| Mainnet         | 595424 | >= 0.11.0                   | archive | `mainnet_0.11.0_595424.sqlite.zst`                | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/mainnet_0.11.0_595424.sqlite.zst)                | 469.63 GB       | `e42bae71c97c1a403116a7362f15f5180b19e8cc647efb1357f1ae8924dce654` |
| Mainnet         | 635054 | >= 0.12.0                   | archive | `mainnet_0.12.0_635054_archive.sqlite.zst`        | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/mainnet_0.12.0_635054_archive.sqlite.zst)        | 383.86 GB       | `d401902684cecaae4a88d6c0219498a0da1bbdb3334ea5b91e3a16212db9ee43` |
| Mainnet         | 635054 | >= 0.12.0                   | pruned  | `mainnet_0.12.0_635054_pruned.sqlite.zst`         | [Download](https://pub-1fac64c3c0334cda85b45bcc02635c32.r2.dev/mainnet_0.12.0_635054_pruned.sqlite.zst)         | 59.89 GB        | `1d854423278611b414130ac05f486c66ef475f47a1c930c2af5296c9906f9ae0` |
