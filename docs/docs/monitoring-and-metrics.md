---
sidebar_position: 5
---


# Monitoring API

Pathfinder has a monitoring API which can be enabled with the `--monitor-address` configuration option.

## Health

`/health` provides a method to check the health status of your `pathfinder` node, and is commonly useful in Kubernetes docker setups. It returns a `200 OK` status if the node is healthy.

## Readiness

`pathfinder` does several things before it is ready to respond to RPC queries. In most cases this startup time is less than a second, however there are certain scenarios where this can be considerably longer. For example, applying an expensive database migration after an upgrade could take several minutes (or even longer) on testnet. Or perhaps our startup network checks fail many times due to connection issues.

`/ready` provides a way of checking whether the node's JSON-RPC API is ready to be queried. It returns a `503 Service Unavailable` status until all startup tasks complete, and then `200 OK` from then on.

## Synced

Similar to `/ready`, `/ready/synced` checks whether the node's JSON-RPC API is ready to be queried _and_ also checks if the node is synced (within 6 blocks of the current tip of the chain). It returns a `503 Service Unavailable` status if either check fails, and `200 OK` if they both pass.

This endpoint is useful for Docker nodes which only want to present themselves as ready after they have been synced.

## Metrics

`/metrics` provides a [Prometheus](https://prometheus.io/) metrics scrape endpoint. Currently the following metrics are available:

### RPC related counters

- `rpc_method_calls_total`,
- `rpc_method_calls_failed_total`,

You __must__ use the label key `method` to retrieve a counter for a particular RPC method, for example:

```
rpc_method_calls_total{method="starknet_getStateUpdate"}
rpc_method_calls_failed_total{method="starknet_chainId"}
```

You may also use the label key `version` to specify a particular version of the RPC API, for example:

```
rpc_method_calls_total{method="starknet_getEvents", version="v0.3"}
```

### Feeder Gateway and Gateway related counters

- `gateway_requests_total`
- `gateway_requests_failed_total`
- `gateway_request_duration_seconds`

Labels:

- `method`, to retrieve a counter for a particular sequencer request type
- `tag`
  - works with methods: `get_block`, `get_state_update`
  - valid values:
    - `pending`
    - `latest`
- `reason`
  - works with: `gateway_requests_failed_total`
  - valid values:
    - `decode`
    - `starknet`
    - `rate_limiting`
    - `timeout`

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

## Sync related metrics

- `current_block` currently sync'd block height of the node
- `highest_block` height of the block chain
- `block_time` timestamp difference between the current block and its parent
- `block_latency` delay between current block being published and sync'd locally
- `block_download` time taken to download current block's data excluding classes
- `block_processing` time taken to process and store the current block
- `block_processing_duration_seconds` histogram of time taken to process and store a block

## Build info metrics

- `pathfinder_build_info` reports current version as a `version` property
