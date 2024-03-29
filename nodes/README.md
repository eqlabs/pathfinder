This is a docker-compose setup connecting multiple (different) nodes together.

Before starting any of the nodes, you must first create a `pathfinder-var.env` file with your testnet Ethereum node URL:

```
PATHFINDER_ETHEREUM_API_URL=<infura or alchemy URL>
```

To start the P2P network, do the following:

1. `docker-compose up -d pathfinder-proxy` to start the pathfinder proxy node, which connects to
the sequencer gateway, fetches blocks, and stores them.
2. `docker-compose up -d pathfinder-p2p` to start the pathfinder P2P node, which will connect to the
pathfinder proxy node and sync blocks over a P2P connection.
3. `docker-compose up -d juno` to start a juno P2P node which will connect to both of the pathfinder nodes
above.

Step 3. is optional. If you wish to have two pathfinder nodes communicating between each other, the first
two steps are sufficient.
