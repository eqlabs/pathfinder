---
sidebar_position: 2
---

# WebSocket API

The WebSocket interface serves the same API versions and extension endpoints as HTTP, but in a stateful, two-way communication channel. This can be especially useful for real-time notifications, subscription-based events, or building interactive dashboards.
 
## Supported Versions
- **Starknet v0.6.0**  
  Accessible at `/ws/rpc/v0_6`.
- **Starknet v0.7.0**  
  Accessible at `/ws/rpc/v0_7`.
- **Starknet v0.8.0-rc1**  
  Accessible at `/ws/rpc/v0_8`.
- **Pathfinder Extension**  
  Exposed via `/ws/rpc/pathfinder/v0_1`

You can configure the default root endpoint (i.e., `/ws`) with the `--rpc.root-version` parameter.

## WebSocket Endpoints and Usage
A typical WebSocket connection can be opened using libraries like `ws`, `websockets`, or the native browser WebSocket API. The RPC payload structure remains the same (JSON-RPC 2.0), but it is sent over a persistent socket connection:

```js title="WebSocket Connection Example in Node.js"
const ws = new WebSocket("ws://127.0.0.1:9545/ws/rpc/v0_8");

ws.onopen = () => {
  const message = JSON.stringify({
    jsonrpc: "2.0",
    method: "starknet_chainId",
    params: [],
    id: 1
  });
  ws.send(message);
};

ws.onmessage = (event) => {
  console.log("Received response:", event.data);
};
```

## Pathfinder WebSocket Extensions

As with the [JSON extensions](interacting-with-pathfinder/json-rpc-api#pathfinder-json-extensions), Pathfinder provides Websocket equivalents of their custom endpoints. They are served under:
```
/ws/rpc/pathfinder/v0_1
```

You can find the complete list of WebSocket extensions in the [Pathfinder repository](https://github.com/eqlabs/pathfinder/blob/main/doc/rpc/pathfinder_ws.json).
