//! A websocket subscription service, inspired by [Ethereum](https://ethereum.org/en/developers/tutorials/using-websockets/)
//! See also the [Infura Ethereum API spec](https://docs.infura.io/networks/ethereum/json-rpc-methods/subscription-methods/eth_subscribe)
//! as well as the [Alchemy subscription API doc](https://docs.alchemy.com/reference/subscription-api)
//!
//! Requires the `--rpc.websocket.enabled` cli option.
//!
//! Manual testing can be performed using `wscat`:
//! ```
//! > pierre:~/pathfinder$ wscat -c ws://localhost:9545/ws
//! Connected (press CTRL+C to quit)
//! > {"jsonrpc":"2.0", "id": 1, "method": "pathfinder_subscribe", "params": ["newHeads"]}
//! < {"jsonrpc":"2.0","result":0,"id":1}
//! < {"jsonrpc":"2.0","method":"pathfinder_subscription","result":{"subscription":0,"result":{"block_hash":"0x383d92f0136b3c345b71348a08d424434c9e0ba009001740d6bba2b1404118f","block_number":907613,"gas_price":"0x3b9aca0c","parent_block_hash":"0x798f79f86d483e04322e305f14a5c1889b12d1bea4e7b0e403754f5acd3204b","sequencer_address":"0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8","starknet_version":"0.12.3","state_commitment":"0x23e851c43f40e51dfa78872ecf87c2763aef34cd48142db6e1004e1fe5d7a22","status":"ACCEPTED_ON_L2","timestamp":1700733281}}}
//! ```
//!
//! Subscriptions may lag behind because of a slow network or slow client and result in an error:
//! ```
//! > pierre:~/pathfinder$ wscat -c ws://localhost:9545/ws
//! Connected (press CTRL+C to quit)
//! > {"jsonrpc":"2.0", "id": 1, "method": "pathfinder_subscribe", "params": ["newHeads"]}
//! < {"jsonrpc":"2.0","result":0,"id":1}
//! < {"jsonrpc":"2.0","error":{"code":-32099,"message":"Websocket subscription closed","data":{"id":0,"reason":"Lagging stream, some headers were skipped. Closing subscription."}},"id":null}
//! ```

mod data;
mod logic;

pub use data::*;
pub use logic::*;
