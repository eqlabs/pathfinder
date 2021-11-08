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

rpc_call '[{"jsonrpc":"2.0","id":"2","method":"starknet_getBlockByHash","params":["latest"]},
{"jsonrpc":"2.0","id":"3","method":"starknet_getBlockByNumber","params":[4069]},
{"jsonrpc":"2.0","id":"4","method":"starknet_getBlockByNumber","params":["latest"]}]'

rpc_call '{"jsonrpc":"2.0","id":"5","method":"starknet_getStorageAt","params":["0x4c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78", "0x206f38f7e4f15e87567361213c28f235cccdaa1d7fd34c9db1dfe9489c6a091", "latest"]}'

rpc_call '[{"jsonrpc":"2.0","id":"6","method":"starknet_getStorageAtByBlockNumber","params":["0x4c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78", "0x206f38f7e4f15e87567361213c28f235cccdaa1d7fd34c9db1dfe9489c6a091", "latest"]},
{"jsonrpc":"2.0","id":"7","method":"starknet_getStorageAtByBlockNumber","params":["0x4c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78", "0x206f38f7e4f15e87567361213c28f235cccdaa1d7fd34c9db1dfe9489c6a091", 5272]}]'

rpc_call '{"jsonrpc":"2.0","id":"8","method":"starknet_getTransactionByHash","params":["0x0285b9a272dd72769789d06400bf0da86ed80555b98ca8a6df0cc888c694e3f1"]}'

rpc_call '[{"jsonrpc":"2.0","id":"9","method":"starknet_getTransactionByBlockHashAndIndex","params":["latest", 0]},
{"jsonrpc":"2.0","id":"10","method":"starknet_getTransactionByBlockNumberAndIndex","params":[5272, 0]},
{"jsonrpc":"2.0","id":"11","method":"starknet_getTransactionByBlockNumberAndIndex","params":["latest", 0]}]'

rpc_call '{"jsonrpc":"2.0","id":"12","method":"starknet_getTransactionReceipt","params":["0x0285b9a272dd72769789d06400bf0da86ed80555b98ca8a6df0cc888c694e3f1"]}'

rpc_call '{"jsonrpc":"2.0","id":"13","method":"starknet_getCode","params":["0x4c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78"]}'

rpc_call '[{"jsonrpc":"2.0","id":"14","method":"starknet_getBlockTransactionCountByHash","params":["latest"]},
{"jsonrpc":"2.0","id":"15","method":"starknet_getBlockTransactionCountByNumber","params":["latest"]},
{"jsonrpc":"2.0","id":"16","method":"starknet_getBlockTransactionCountByNumber","params":[5272]}]'

rpc_call '{"jsonrpc":"2.0","id":"17","method":"starknet_call","params":[{"calldata":[1234],"contract_address":"0x4c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78",
"entry_point_selector":"0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320","signature":[]}, "latest"]}'

rpc_call '{"jsonrpc":"2.0","id":"18","method":"starknet_blockNumber"}'
