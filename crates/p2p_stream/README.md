# Introduction

This crate is a derivative of Parity Technologies' [`libp2p request/response`](https://docs.rs/libp2p-request-response/latest/libp2p_request_response/) crate, which provides a generic **"single request - stream of responses"** protocol, similar to [gRPC's server streaming RPC](https://grpc.io/docs/what-is-grpc/core-concepts/#server-streaming-rpc).

# Feature comparison with request/response

|  | p2p-stream | libp2p-request-response |
| ----------- | ----------- | ----------- |
| libp2p compatibility | [≥ libp2p-v0.53.2](https://github.com/libp2p/rust-libp2p/releases/tag/libp2p-v0.53.2) | ✔ |
| sending request opens new libp2p stream | ✔ | ✔ |
| sending request | `Behavior::send_request` | `Behavior::send_request` |
| receiving request | `InboundRequest` event | `Message::Request` in `Message` event |
| sending response(s) | into a channel obtained from `InboundRequest` event | call `Behaviour` method after receiving `Message::Request` event |
| receiving response(s) | from a channel obtained from `OutboundRequestSentAwaitingResponses` event | `Message::Response` in `Message` event |
| number of responses per request | ≥ 0 | 1 |
| user defined R & W protocol codec | ✔ | ✔ |
| response codec should delimit messages | ✔ | n/a |
| partial protocol support<br>(ie. only upstream or downstream) | * | ✔ |
| out of the box cbor and json codecs | * | ✔ |

<br>

*): [`pathfinder`](https://github.com/eqlabs/pathfinder) uses this crate with its own [Starknet](https://www.starknet.io/) specific [protocol](https://github.com/starknet-io/starknet-p2p-specs) and decided to drop unnecessary features

# Acknowledgements

Thanks to the [rust-libp2p contributors](https://github.com/libp2p/rust-libp2p/graphs/contributors) and [Parity Technologies](https://www.parity.io/) for making [`rust-libp2p`](https://github.com/libp2p/rust-libp2p) possible.

# FAQ

1. Q: I'd like to see the scope of changes compared to the original crate.<br>
   A: Please diff with [`libp2p-v0.53.2`](https://github.com/libp2p/rust-libp2p/tree/libp2p-v0.53.2)
