#! /usr/bin/env bash
set -e;
set -o pipefail;

echo "starknet_blockNumber"

curl -X POST \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":"1","method":"starknet_blockNumber"}' \
     http://localhost:9545

printf "\n\nstarknet_getBlockBy[Hash|Number]\n"

curl -X POST \
     -H 'Content-Type: application/json' \
     -d '[{"jsonrpc":"2.0","id":"1","method":"starknet_blockNumber"},
     {"jsonrpc":"2.0","id":"2","method":"starknet_getBlockByHash","params":["0x1000"]},
     {"jsonrpc":"2.0","id":"3","method":"starknet_getBlockByHash","params":["latest"]},
     {"jsonrpc":"2.0","id":"4","method":"starknet_getBlockByNumber","params":["0x1000"]},
     {"jsonrpc":"2.0","id":"5","method":"starknet_getBlockByNumber","params":["latest"]}]' \
     http://localhost:9545

printf "\n\nstarknet_getTransactionByBlock[Hash|Number]AndIndex\n"

curl -X POST \
     -H 'Content-Type: application/json' \
     -d '[{"jsonrpc":"2.0","id":"6","method":"starknet_getTransactionByBlockHashAndIndex","params":["0x1000", 0]},
     {"jsonrpc":"2.0","id":"7","method":"starknet_getTransactionByBlockHashAndIndex","params":["latest", 0]},
     {"jsonrpc":"2.0","id":"8","method":"starknet_getTransactionByBlockNumberAndIndex","params":["0x1000", 0]},
     {"jsonrpc":"2.0","id":"9","method":"starknet_getTransactionByBlockNumberAndIndex","params":["latest", 0]}]' \
     http://localhost:9545

printf "\n\nstarknet_getStorage\n"

curl -X POST \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":"10","method":"starknet_getStorage","params":["0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc", "0x206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091"]}' \
     http://localhost:9545

printf "\n\nstarknet_getCode\n"

curl -X POST \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":"11","method":"starknet_getCode","params":["0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc"]}' \
     http://localhost:9545

printf "\n\nstarknet_call\n"

curl -X POST \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":"12","method":"starknet_call","params":["0x0399d3cf2405e997b1cda8c45f5ba919a6499f3d3b00998d5a91d6d9bcbc9128",[],"0x039e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695"]}' \
     http://localhost:9545

echo
