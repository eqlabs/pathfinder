#! /usr/bin/env bash
set -e;
set -o pipefail;

function rpc_call() {
     printf "Request:\n${1}\nReply:\n"
     curl -s -X POST \
          -H 'Content-Type: application/json' \
          -d "${1}" \
          http://127.0.0.1:9545/rpc/v0.2
     printf "\n\n"
}

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxs","params":["pending"]}'
rpc_call '{"jsonrpc":"2.0","id":"2","method":"starknet_getBlockWithTxHashes","params":["pending"]}'

rpc_call '{"jsonrpc":"2.0","id":"4","method":"starknet_getBlockWithTxs","params":["latest"]}'
rpc_call '{"jsonrpc":"2.0","id":"6","method":"starknet_getBlockWithTxHashes","params":["latest"]}'

rpc_call '{"jsonrpc":"2.0","id":"12","method":"starknet_getBlockWithTxs","params":[{"block_hash": "0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"}]}'
rpc_call '{"jsonrpc":"2.0","id":"13","method":"starknet_getBlockWithTxs","params":[{"block_number": 41000}]}'

rpc_call '[{"jsonrpc":"2.0","id":"0","method":"starknet_getStateUpdate","params":["latest"]},
{"jsonrpc":"2.0","id":"1","method":"starknet_getStateUpdate","params":[{"block_number":0}]},
{"jsonrpc":"2.0","id":"2","method":"starknet_getStateUpdate","params":[{"block_hash":"0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"}]}]'

rpc_call '[{"jsonrpc":"2.0","id":"16","method":"starknet_getStorageAt","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39", "0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091", "latest"]},
{"jsonrpc":"2.0","id":"17","method":"starknet_getStorageAt","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39", "0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091", "pending"]},
{"jsonrpc":"2.0","id":"18","method":"starknet_getStorageAt","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39", "0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091", {"block_hash": "0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"}]}]'

rpc_call '{"jsonrpc":"2.0","id":"19","method":"starknet_getTransactionByHash","params":["0x74ec6667e6057becd3faff77d9ab14aecf5dde46edb7c599ee771f70f9e80ba"]}'

rpc_call '[{"jsonrpc":"2.0","id":"20","method":"starknet_getTransactionByBlockIdAndIndex","params":["latest", 0]},
{"jsonrpc":"2.0","id":"22","method":"starknet_getTransactionByBlockIdAndIndex","params":["pending", 0]},
{"jsonrpc":"2.0","id":"24","method":"starknet_getTransactionByBlockIdAndIndex","params":[{"block_hash": "0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"}, 4]},
{"jsonrpc":"2.0","id":"25","method":"starknet_getTransactionByBlockNumberAndIndex","params":[{"block_number": 21348}, 4]}]'

rpc_call '{"jsonrpc":"2.0","id":"26","method":"starknet_getTransactionReceipt","params":["0x74ec6667e6057becd3faff77d9ab14aecf5dde46edb7c599ee771f70f9e80ba"]}'

rpc_call '{"jsonrpc":"2.0","id":"27","method":"starknet_getClass","params":["latest", "0x21a7f43387573b68666669a0ed764252ce5367708e696e31967764a90b429c2"]}'

rpc_call '{"jsonrpc":"2.0","id":"27","method":"starknet_getClassHashAt","params":["latest", "0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"]}'

rpc_call '{"jsonrpc":"2.0","id":"27","method":"starknet_getClassAt","params":["latest", "0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"]}'

rpc_call '[{"jsonrpc":"2.0","id":"28","method":"starknet_getBlockTransactionCount","params":["latest"]},
{"jsonrpc":"2.0","id":"30","method":"starknet_getBlockTransactionCount","params":["pending"]},
{"jsonrpc":"2.0","id":"32","method":"starknet_getBlockTransactionCount","params":[{"block_hash": "0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"}]},
{"jsonrpc":"2.0","id":"33","method":"starknet_getBlockTransactionCount","params":[{"block_number": 21348}]}]'

rpc_call '[{"jsonrpc":"2.0","id":"34","method":"starknet_call","params":[{"calldata":["0x1234"],"contract_address":"0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39",
"entry_point_selector":"0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"}, "latest"]},
{"jsonrpc":"2.0","id":"35","method":"starknet_call","params":[{"calldata":["0x1234"],"contract_address":"0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39",
"entry_point_selector":"0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"}, "pending"]}]'

# smoke test call on first block of goerli, should return 0x22b; same as examples/call_against_sequencer.rs example.
rpc_call '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "starknet_call",
    "params": {
        "request": {
            "calldata": ["0x5"],
            "contract_address": "0x019245f0f49d23f2379d3e3f20d1f3f46207d1c4a1d09cac8dd50e8d528aabe1",
            "entry_point_selector": "0x026813d396fdb198e9ead934e4f7a592a8b88a059e45ab0eb6ee53494e8d45b0"
        },
        "block_id": {
            "block_hash": "0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"
        }
    }
}'

# mainnet transaction 0xccb3808126726235eee5818e6298e5cc2c9db3731442d66ad63f7e3f7d396d
rpc_call '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "starknet_call",
    "params": {
        "request": {
            "contract_address": "0x0019fcae2482de8fb3afaf8d4b219449bec93a5928f02f58eef645cc071767f4",
            "calldata": [
                "0x0000000000000000000000000000000000000000000000000000000000000001",
                "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                "0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000000000000000000000000000003",
                "0x04681402a7ab16c41f7e5d091f32fe9b78de096e0bd5962ce5bd7aaa4a441f64",
                "0x000000000000000000000000000000000000000000000000001d41f6331e6800",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ],
            "entry_point_selector": "0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
            "signature": [
                "0x10E400D046147777C2AC5645024E1EE81C86D90B52D76AB8A8125E5F49612F9",
                "0x0ADB92739205B4626FEFB533B38D0071EB018E6FF096C98C17A6826B536817B"
            ],
            "max_fee": "0x12C72866EFA9B",
            "version": "0x0"
        },
        "block_id": {
            "block_hash": "0x0147c4b0f702079384e26d9d34a15e7758881e32b219fc68c076b09d0be13f8c"
        }
    }
}'

# mainnet transaction 0xccb3808126726235eee5818e6298e5cc2c9db3731442d66ad63f7e3f7d396d again
# because this specifies a block hash to estimate on, this will use that blocks recorded historic gas price
# try with "block_id": "latest" for current "eth_gasPrice".
rpc_call '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "starknet_estimateFee",
    "params": {
        "request": {
            "type": "INVOKE",
            "max_fee": "0x12C72866EFA9B",
            "version": "0x0",
            "signature": [
                "0x10E400D046147777C2AC5645024E1EE81C86D90B52D76AB8A8125E5F49612F9",
                "0x0ADB92739205B4626FEFB533B38D0071EB018E6FF096C98C17A6826B536817B"
            ],
            "contract_address": "0x0019fcae2482de8fb3afaf8d4b219449bec93a5928f02f58eef645cc071767f4",
            "calldata": [
                "0x0000000000000000000000000000000000000000000000000000000000000001",
                "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                "0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000000000000000000000000000003",
                "0x04681402a7ab16c41f7e5d091f32fe9b78de096e0bd5962ce5bd7aaa4a441f64",
                "0x000000000000000000000000000000000000000000000000001d41f6331e6800",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ],
            "entry_point_selector": "0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
        },
        "block_id": {
            "block_hash": "0x0147c4b0f702079384e26d9d34a15e7758881e32b219fc68c076b09d0be13f8c"
        }
    }
}'

rpc_call '{"jsonrpc":"2.0","id":"36","method":"starknet_blockNumber"}'

rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_getEvents",
    "params": {
        "filter": {"from_block": {"block_number": 800}, "to_block": {"block_number": 1701}, "chunk_size": 1000}
    },
    "id": 0
}'

rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_getEvents",
    "params": {
        "filter": {"from_block": {"block_number": 800}, "to_block": {"block_number": 1701}, "chunk_size": 1000, "continuation_token": "1000"}
    },
    "id": 1
}'

rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_addInvokeTransaction",
    "params": {
        "invoke_transaction": {
            "type": "INVOKE",
            "max_fee": "0x4f388496839",
            "version": "0x0",
            "signature": [
                "0x7dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5",
                "0x71456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
            ],
            "contract_address": "0x23371b227eaecd8e8920cd429d2cd0f3fee6abaacca08d3ab82a7cdd",
            "calldata": [
                "0x1",
                "0x677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1",
                "0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
                "0x0",
                "0x1",
                "0x1",
                "0x2b",
                "0x0"
            ],
            "entry_point_selector": "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
        }
    },
    "id": 0
}'

rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_addDeployTransaction",
    "params": {
        "deploy_transaction": {
            "type": "DEPLOY",
            "version": "0x0",
            "contract_address_salt": "0x0",
            "constructor_calldata": [],
            "contract_class": {
                "program": "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",
                "entry_points_by_type": {
                    "CONSTRUCTOR": [],
                    "EXTERNAL": [
                        {
                            "offset": "0x3a",
                            "selector": "0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                        },
                        {
                            "offset": "0x5b",
                            "selector": "0x39e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695"
                        }
                    ],
                    "L1_HANDLER": []
                }
            }
        }
    },
    "id": 0
}'

rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_addDeclareTransaction",
    "params": {
        "declare_transaction": {
            "type": "DECLARE",
            "max_fee": "0x0",
            "version": "0x0",
            "signature": [],
            "nonce": "0x0",
            "contract_class": {
                "program": "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",
                "entry_points_by_type": {
                    "CONSTRUCTOR": [],
                    "EXTERNAL": [
                        {
                            "offset": "0x3a",
                            "selector": "0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                        },
                        {
                            "offset": "0x5b",
                            "selector": "0x39e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695"
                        }
                    ],
                    "L1_HANDLER": []
                }
            },
            "sender_address": "0x1"
        }
    },
    "id": 0
}'

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_chainId"}'
rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getNonce","params":["latest", "0x019245f0f49d23f2379d3e3f20d1f3f46207d1c4a1d09cac8dd50e8d528aabe1"]}'
rpc_call '{"jsonrpc":"2.0","id":"40","method":"starknet_syncing"}'
rpc_call '{"jsonrpc":"2.0","id":"40","method":"starknet_pendingTransaction"}'
