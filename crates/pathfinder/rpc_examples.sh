#! /usr/bin/env bash
set -e;
set -o pipefail;

function rpc_call() {
     printf "Request:\n${1}\nReply:\n"
     curl -s -X POST \
          -H 'Content-Type: application/json' \
          -d "${1}" \
          http://127.0.0.1:9545
     printf "\n\n"
}

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockByHash","params":["pending"]}'
rpc_call '{"jsonrpc":"2.0","id":"1","method":"starknet_getBlockByNumber","params":["pending"]}'

rpc_call '{"jsonrpc":"2.0","id":"2","method":"starknet_getBlockByHash","params":["pending","TXN_HASH"]}'
rpc_call '{"jsonrpc":"2.0","id":"3","method":"starknet_getBlockByNumber","params":["pending","TXN_HASH"]}'

rpc_call '{"jsonrpc":"2.0","id":"4","method":"starknet_getBlockByHash","params":["latest"]}'
rpc_call '{"jsonrpc":"2.0","id":"5","method":"starknet_getBlockByNumber","params":["latest"]}'

rpc_call '{"jsonrpc":"2.0","id":"6","method":"starknet_getBlockByHash","params":["latest","TXN_HASH"]}'
rpc_call '{"jsonrpc":"2.0","id":"7","method":"starknet_getBlockByNumber","params":["latest","TXN_HASH"]}'

rpc_call '{"jsonrpc":"2.0","id":"8","method":"starknet_getBlockByHash","params":["latest","FULL_TXNS"]}'
rpc_call '{"jsonrpc":"2.0","id":"9","method":"starknet_getBlockByNumber","params":["latest","FULL_TXNS"]}'

rpc_call '{"jsonrpc":"2.0","id":"10","method":"starknet_getBlockByHash","params":["latest","FULL_TXN_AND_RECEIPTS"]}'
rpc_call '{"jsonrpc":"2.0","id":"11","method":"starknet_getBlockByNumber","params":["latest","FULL_TXN_AND_RECEIPTS"]}'

# At the moment causes HTTP 504
# rpc_call '{"jsonrpc":"2.0","id":"12","method":"starknet_getBlockByHash","params":["0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"]}'

rpc_call '{"jsonrpc":"2.0","id":"13","method":"starknet_getBlockByNumber","params":[41000]}'

# TODO not implemented yet
# rpc_call '[{"jsonrpc":"2.0","id":"14","method":"starknet_getStateUpdateByHash","params":["latest"]},
# {"jsonrpc":"2.0","id":"15","method":"starknet_getStateUpdateByHash","params":["0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"]}]'

rpc_call '[{"jsonrpc":"2.0","id":"16","method":"starknet_getStorageAt","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39", "0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091", "latest"]},
{"jsonrpc":"2.0","id":"17","method":"starknet_getStorageAt","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39", "0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091", "pending"]},
{"jsonrpc":"2.0","id":"18","method":"starknet_getStorageAt","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39", "0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091", "0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"]}]'

rpc_call '{"jsonrpc":"2.0","id":"19","method":"starknet_getTransactionByHash","params":["0x74ec6667e6057becd3faff77d9ab14aecf5dde46edb7c599ee771f70f9e80ba"]}'

rpc_call '[{"jsonrpc":"2.0","id":"20","method":"starknet_getTransactionByBlockHashAndIndex","params":["latest", 0]},
{"jsonrpc":"2.0","id":"21","method":"starknet_getTransactionByBlockNumberAndIndex","params":["latest", 0]},
{"jsonrpc":"2.0","id":"22","method":"starknet_getTransactionByBlockHashAndIndex","params":["pending", 0]},
{"jsonrpc":"2.0","id":"23","method":"starknet_getTransactionByBlockNumberAndIndex","params":["pending", 0]},
{"jsonrpc":"2.0","id":"24","method":"starknet_getTransactionByBlockHashAndIndex","params":["0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27", 4]},
{"jsonrpc":"2.0","id":"25","method":"starknet_getTransactionByBlockNumberAndIndex","params":[21348, 4]}]'

rpc_call '{"jsonrpc":"2.0","id":"26","method":"starknet_getTransactionReceipt","params":["0x74ec6667e6057becd3faff77d9ab14aecf5dde46edb7c599ee771f70f9e80ba"]}'

rpc_call '{"jsonrpc":"2.0","id":"27","method":"starknet_getCode","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"]}'

rpc_call '[{"jsonrpc":"2.0","id":"28","method":"starknet_getBlockTransactionCountByHash","params":["latest"]},
{"jsonrpc":"2.0","id":"29","method":"starknet_getBlockTransactionCountByNumber","params":["latest"]},
{"jsonrpc":"2.0","id":"30","method":"starknet_getBlockTransactionCountByHash","params":["pending"]},
{"jsonrpc":"2.0","id":"31","method":"starknet_getBlockTransactionCountByNumber","params":["pending"]},
{"jsonrpc":"2.0","id":"32","method":"starknet_getBlockTransactionCountByHash","params":["0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"]},
{"jsonrpc":"2.0","id":"33","method":"starknet_getBlockTransactionCountByNumber","params":[21348]}]'

rpc_call '[{"jsonrpc":"2.0","id":"34","method":"starknet_call","params":[{"calldata":["0x1234"],"contract_address":"0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39",
"entry_point_selector":"0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"}, "latest"]},
{"jsonrpc":"2.0","id":"35","method":"starknet_call","params":[{"calldata":["0x1234"],"contract_address":"0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39",
"entry_point_selector":"0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"}, "pending"]}]'

rpc_call '{"jsonrpc":"2.0","id":"36","method":"starknet_blockNumber"}'

rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_getEvents",
    "params": [
        {"fromBlock": 800, "toBlock": 1701, "page_size": 1000, "page_number": 0}
    ],
    "id": 0
}'

rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_addInvokeTransaction",
    "params": [
        {
            "contract_address": "0x23371b227eaecd8e8920cd429d2cd0f3fee6abaacca08d3ab82a7cdd",
            "calldata": [
                "1",
                "2925423296824367013529965983412166292018955438053992527907701360681569823649",
                "1530486729947006463063166157847785599120665941190480211966374137237989315360",
                "0",
                "1",
                "1",
                "43",
                "0"
            ],
            "entry_point_selector": "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
        },
        [
            "3557065757165699682249469970267166698995647077461960906176449260016084767701",
            "3202126414680946801789588986259466145787792017299869598314522555275920413944"
        ],
        "0x4f388496839",
        "0x0"
    ],
    "id": 0
}'

# TODO not implemented yet
# rpc_call '{"jsonrpc":"2.0","id":"37","method":"starknet_chainId"}'
# rpc_call '{"jsonrpc":"2.0","id":"38","method":"starknet_pendingTransactions"}'
# rpc_call '{"jsonrpc":"2.0","id":"39","method":"starknet_protocolVersion"}'
# rpc_call '{"jsonrpc":"2.0","id":"40","method":"starknet_syncing"}'
