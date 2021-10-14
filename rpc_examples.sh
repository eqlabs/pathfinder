#! /usr/bin/env bash
set -e;
set -o pipefail;

function rpc_call() {
     printf "Request:\n${1}\nReply:\n"
     curl -s -X POST \
          -H 'Content-Type: application/json' \
          -d "${1}" \
          http://localhost:9545
     printf "\n\n"
}

rpc_call '{"jsonrpc":"2.0","id":"1","method":"starknet_blockNumber"}'

rpc_call '[{"jsonrpc":"2.0","id":"2","method":"starknet_getBlockByHash","params":["latest"]},
{"jsonrpc":"2.0","id":"3","method":"starknet_getBlockByNumber","params":["0x1000"]},
{"jsonrpc":"2.0","id":"4","method":"starknet_getBlockByNumber","params":["latest"]}]'

rpc_call '{"jsonrpc":"2.0","id":"5","method":"starknet_getTransactionByNumber","params":["0x23c86"]}'
     
rpc_call '[{"jsonrpc":"2.0","id":"6","method":"starknet_getTransactionByBlockHashAndIndex","params":["latest", 0]},
{"jsonrpc":"2.0","id":"7","method":"starknet_getTransactionByBlockNumberAndIndex","params":["0x1000", 0]},
{"jsonrpc":"2.0","id":"8","method":"starknet_getTransactionByBlockNumberAndIndex","params":["latest", 0]}]'

rpc_call '{"jsonrpc":"2.0","id":"9","method":"starknet_getStorage","params":["0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc", "0x206f38f7e4f15e87567361213c28f235cccdaa1d7fd34c9db1dfe9489c6a091"]}'

rpc_call '{"jsonrpc":"2.0","id":"10","method":"starknet_getCode","params":["0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc"]}'

rpc_call '{"jsonrpc":"2.0","id":"11","method":"starknet_call","params":["0x0399d3cf2405e997b1cda8c45f5ba919a6499f3d3b00998d5a91d6d9bcbc9128",[],"0x039e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695"]}'
