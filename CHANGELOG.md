# Changelog

All notable changes to this project will be documented in this file.

More expansive patch notes and explanations may be found in the specific [pathfinder release notes](https://github.com/eqlabs/pathfinder/releases).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.5] - 2023-05-18

### Added

- `cairo-lang` upgraded to 0.11.1.1

### Fixed

- RPC emits connection logs and warnings
- Fee estimate mismatch between gateway and pathfinder
  - Gateway uses a new gas price sampling algorithm which was incompatible with pathfinders.
- Fee estimate returns error when submitting Cairo 1.0.0-rc0 classes.
- Historic L1 handler transactions are served as Invoke V0
  - Older databases contain L1 handler transactions from before L1 handler was a specific transaction type. These were
    stored as Invoke V0. These are now correctly identified as being L1 Handler transactions.

### Fixed

- RPC emits connection logs and warnings
- Fee estimate mismatch between gateway and pathfinder
  - Gateway uses a new gas price sampling algorithm which was incompatible with pathfinders.
- Historic L1 handler transactions are served as Invoke V0
  - Older databases contain L1 handler transactions from before L1 handler was a specific transaction type. These were
    stored as Invoke V0. These are now correctly identified as being L1 Handler transactions.

## [0.5.4] - 2023-05-09

### Added

- Starknet v0.11.1 support
  - Sierra compiler v1.0.0.rc0 (while keeping previous compiler for older contracts)
  - new block hash calculation
  - new L1 contract
- CORS support for the RPC server, enabled via the `rpc.cors-domains` command line argument
- transaction hash verification, excluding older L1 handler transactions, i.e. in blocks older than
  - 4400 for mainnet
  - 306008 for testnet

### Fixed

- rpc server panic for unprefixed unregistered method names
- remove a small time window where data which is transitioning from pending to latest block was not available for RPC queries.
  - this was commonly seen when rapidly monitoring a new transaction, which would go from `PENDING` to `TXN_HASH_NOT_FOUND` to `ACCEPTED_ON_L2`.

## [0.5.3] - 2023-04-12

### Added

- `max-rpc-connections` command-line argument
- `cairo-lang` upgraded to 0.11.0.2

### Fixed

- `starknet_simulateTransaction` data model inconsistency
- `poll-pending` default value restored to `false`
- handling of invalid JSON-RPC requests

### Removed

- support for `BROADCASTED` transactions version 0

## [0.5.2] - 2023-03-28

### Added

- support `starknet_estimateFee` in the JSON-RPC v0.3 API
  - supports estimating multiple transactions
  - this includes declaring and immediately using a class (not currently possible via the gateway)
- support `starknet_simulateTransaction` for JSON-RPC v0.3
  - supports simulating multiple transactions
  - this includes declaring and immediately using a class (not currently possible via the gateway)
- support `pathfinder_getTransactionStatus` which is exposed on all RPC routes
  - this enables querying a transactions current status, including whether the gateway has received or rejected it

### Fixed

- RPC returns int for entrypoint offsets instead of hex
- RPC rejects Fee values with more than 32 digits
- RPC does not expose `pathfinder_getProof` on v0.3 route

## [0.5.1] - 2023-03-23

### Fixed

- pathfinder can spam nethermind L1 nodes
- pathfinder stops syncing testnet2 at block 95220 due to a Sierra class compilation issue

## [0.5.0] - 2023-03-20

### Added

- support for state commitment and class commitment in pathfinder_getProof
- support for starknet v0.11
- partial support for RPC specification v0.3
  - exposed on `/rpc/v0.3/` route
  - missing support for `starknet_estimateFee` and `starknet_simulate`

### Changed

- `starknet_call` and `starknet_estimateFee` JSON-RPC methods return more detailed error messages
- `python` version requirement has changed to `3.9` or `3.10` (was `3.8` or `3.9`)

### Fixed

- RPC accepts hex inputs for Felt without '0x' prefix. This led to confusion especially when passing in a decimal string which would get silently interpretted as hex.
- using a Nethermind Ethereum endpoint occasionally causes errors such as `<block-number> could not be found` to be logged.
- sync can miss new block events by getting stuck waiting for pending data.

### Removed

- `--config` configuration option (deprecated in [v0.4.1](https://github.com/eqlabs/pathfinder/releases/tag/v0.4.1))
- `--integration` configuration option (deprecated in [v0.4.1](https://github.com/eqlabs/pathfinder/releases/tag/v0.4.1))
- `--sequencer-url` configuration option (deprecated in [v0.4.1](https://github.com/eqlabs/pathfinder/releases/tag/v0.4.1))
- `--testnet2` configuration option (deprecated in [v0.4.1](https://github.com/eqlabs/pathfinder/releases/tag/v0.4.1))
- `starknet_addDeployTransaction` as this is no longer an allowed transaction
- RPC api version `0.1`, which used to be served on path `/rpc/v0.1`

## [0.4.5] - 2022-12-21

### Added

- added Newton FAQ links to readme (thanks @SecurityQQ)

### Fixed

- node fails to sync really old blocks

## [0.4.4] - 2022-12-20

### Added

- storage proofs via pathfinder_getProof by @pscott

### Changed

- improved performance for starknet_call and starknet_estimateFee by caching classes
- improved performance for starknet_call and starknet_estimateFee by using Rust for hashing

### Fixed

- starknet_getEvents returns all events when from_block="latest"
- v0.1 starknet_getStateUpdate does not contain nonces

## [0.4.3] - 2022-12-7

### Changed

- updated to cairo-lang 0.10.3

### Fixed

- testnet2 and integration flags are ignored
- starknet_estimateFee uses wrong chain ID for testnet2

## [0.4.2] - 2022-12-2

### Added

- document that --chain-id expects text as input

### Fixed

- testnet2 and integration L1 addresses are swopped (bug introduced in v0.4.1)
- proxy network setups can't sync historical blocks (bug introduced in v0.4.1)
- ABI serialization for starknet_estimateFee for declare transactions

## [0.4.1] - 2022-11-30

### Added

- custom Starknet support (see above for details)
- pathfinder specific RPC extensions hosted at <rpc-url>/rpc/pathfinder/v0.1. Currently this only contains pathfinder_version which returns the pathfinder version of the node.

### Changed

- The following configuration options are now marked as deprecated: --testnet2, --integration, --config, --sequencer-url
- Optimised starknet_events for queries with both a block range and a from address

### Fixed

- block timestamps for pending in starknet_call and starknet_estimateFee were using the latest timestamp instead of the pending one. This meant contracts relying on accurate timestamps could sometimes fail unexpectedly.

## [0.4.0] - 2022-11-30

### Added

- support for Starknet v0.10.2

### Changed

- default RPC API version changed from v0.1 to v0.2

## Ancient History

Older history may be found in the [pathfinder release notes](https://github.com/eqlabs/pathfinder/releases).
