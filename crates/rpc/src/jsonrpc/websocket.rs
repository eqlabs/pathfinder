//! A websocket subscription service, inspired by [Ethereum](https://ethereum.org/en/developers/tutorials/using-websockets/)
//! See also the [Infura Ethereum API spec](https://docs.infura.io/networks/ethereum/json-rpc-methods/subscription-methods/eth_subscribe)
//! as well as the [Alchemy subscription API doc](https://docs.alchemy.com/reference/subscription-api)
//!
//! Requires the `--rpc.websocket.enabled` cli option.
//!
//! Manual testing can be performed using `wscat`:
//! ```bash
//! > pierre:~/pathfinder$ wscat -c ws://localhost:9545/ws
//! Connected (press CTRL+C to quit)
//! > {"jsonrpc":"2.0", "id": 1, "method": "pathfinder_subscribe", "params": ["newHeads"]}
//! < {"jsonrpc":"2.0","result":0,"id":1}
//! < {"jsonrpc":"2.0","method":"pathfinder_subscription","result":{"truncated":""}}
//! ```
mod data;
mod logic;

pub use data::*;
pub use logic::*;
