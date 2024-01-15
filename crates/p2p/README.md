# Intro

See also the [docker-compose setup for P2P](../../nodes/).

This crate is a PoC for using Kademlia for bootstrap and capability lookup for nodes.

The library exports a few useful things:

- A Behaviour implementing both Kademlia and Gossipsub. The Behaviour also supports announcing support for a list of capabilities.
- A Transport using Tokio for TCP and DNS.
- An executor using Tokio.
- Some utility functions.

The `peer` example can be used with the `p2p_bootstrap` crate to connect to a bootstrap node, discover other peers and join a Gossipsub channel:

`identity.json` should have a libp2p private key in a JSON config file:

```json
{
    "private_key": "Base64 encoded private key"
}
```

The `generate_key` example can be used to output a private key in the proper format for inclusion in the config file:

```shell
cargo run -p p2p --example generate_key
```

Starting up the bootstrap node:

```shell
RUST_LOG=info cargo run -p p2p --bin bootstrap -- --identity-config-file ./identity1.json --listen-on /ip4/127.0.0.1/tcp/4000 --bootstrap-interval-seconds 3
````

And then starting three peers that initially connect to the bootstrap node:

```shell
RUST_LOG=debug cargo run -p pathfinder --features p2p -- --network goerli-testnet --ethereum.url <infura or alchemy testnet url> --p2p.listen-on /ip4/127.0.0.1/tcp/4001 --p2p.bootstrap-addresses /ip4/127.0.0.1/tcp/4000/p2p/<pubkey from identity.json>
RUST_LOG=debug cargo run -p pathfinder --features p2p -- --network goerli-testnet --ethereum.url <infura or alchemy testnet url> --p2p.listen-on /ip4/127.0.0.1/tcp/4002 --p2p.bootstrap-addresses /ip4/127.0.0.1/tcp/4000/p2p/<pubkey from identity.json>
RUST_LOG=debug cargo run -p pathfinder --features p2p -- --network goerli-testnet --ethereum.url <infura or alchemy testnet url> --p2p.listen-on /ip4/127.0.0.1/tcp/4003 --p2p.bootstrap-addresses /ip4/127.0.0.1/tcp/4000/p2p/<pubkey from identity.json>
```

(Note that the last part is the peer ID of the bootstrap node that's derived from the private key in the configuration. The bootstrap node prints its peer id when starting up, change the peer id to the appropriate one in the commands above.)
