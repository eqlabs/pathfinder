#! /usr/bin/env bash
set -e;
set -o pipefail;

function rpc_call() {
     printf "Request:\n${1}\nReply:\n"
     curl -s -X POST \
          -H 'Content-Type: application/json' \
          -d "${1}" \
          http://127.0.0.1:9545/rpc/v0.3
     printf "\n\n"
}

# Uncommented examples refer to testnet

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxs","params":["pending"]}'
rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxHashes","params":["pending"]}'

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxs","params":["latest"]}'
rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxHashes","params":["latest"]}'

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxs","params":[{"block_hash": "0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"}]}'
rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxs","params":[{"block_number": 41000}]}'

rpc_call '[{"jsonrpc":"2.0","id":"0","method":"starknet_getStateUpdate","params":["latest"]},
{"jsonrpc":"2.0","id":"1","method":"starknet_getStateUpdate","params":[{"block_number":0}]},
{"jsonrpc":"2.0","id":"2","method":"starknet_getStateUpdate","params":[{"block_hash":"0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"}]}]'

rpc_call '[{"jsonrpc":"2.0","id":"0","method":"starknet_getStorageAt","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39", "0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091", "latest"]},
{"jsonrpc":"2.0","id":"1","method":"starknet_getStorageAt","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39", "0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091", "pending"]},
{"jsonrpc":"2.0","id":"2","method":"starknet_getStorageAt","params":["0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39", "0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091", {"block_hash": "0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"}]}]'

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getTransactionByHash","params":["0x74ec6667e6057becd3faff77d9ab14aecf5dde46edb7c599ee771f70f9e80ba"]}'

rpc_call '[{"jsonrpc":"2.0","id":"0","method":"starknet_getTransactionByBlockIdAndIndex","params":["latest", 0]},
{"jsonrpc":"2.0","id":"1","method":"starknet_getTransactionByBlockIdAndIndex","params":["pending", 0]},
{"jsonrpc":"2.0","id":"2","method":"starknet_getTransactionByBlockIdAndIndex","params":[{"block_hash": "0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"}, 4]},
{"jsonrpc":"2.0","id":"3","method":"starknet_getTransactionByBlockIdAndIndex","params":[{"block_number": 21348}, 4]}]'

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getTransactionReceipt","params":["0x74ec6667e6057becd3faff77d9ab14aecf5dde46edb7c599ee771f70f9e80ba"]}'

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getClass","params":["latest", "0x21a7f43387573b68666669a0ed764252ce5367708e696e31967764a90b429c2"]}'

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getClassHashAt","params":["latest", "0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"]}'

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getClassAt","params":["latest", "0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"]}'

rpc_call '[{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockTransactionCount","params":["latest"]},
{"jsonrpc":"2.0","id":"1","method":"starknet_getBlockTransactionCount","params":["pending"]},
{"jsonrpc":"2.0","id":"2","method":"starknet_getBlockTransactionCount","params":[{"block_hash": "0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"}]},
{"jsonrpc":"2.0","id":"3","method":"starknet_getBlockTransactionCount","params":[{"block_number": 21348}]}]'

rpc_call '[{"jsonrpc":"2.0","id":"0","method":"starknet_call","params":[{"calldata":["0x1234"],"contract_address":"0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39",
"entry_point_selector":"0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"}, "latest"]},
{"jsonrpc":"2.0","id":"1","method":"starknet_call","params":[{"calldata":["0x1234"],"contract_address":"0x6fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39",
"entry_point_selector":"0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"}, "pending"]}]'

# smoke test call on first block of goerli, should return 0x22b; same as examples/call_against_sequencer.rs example.
rpc_call '{
    "jsonrpc": "2.0",
    "id": "0",
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
    "id": "0",
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
    "id": "0",
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

# mainnet
rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_getEvents",
    "params": {
        "filter": {
            "from_block": {"block_number": 800}, "to_block": {"block_number": 1701}, "chunk_size": 1,
            "keys": [
                ["0x32152e6067d0b8e3ff1aea0749afa5a823e4646d1663a7167c0a92d21d256eb", "0xb83f204dcb21221bd5ef3d70b06988cd4beaa4d48ff498a1a0c9e1e49e2804"],
                [],
                ["0x599573a0023b0ce23bb8537d2c5f3e9b72ebd4f008d033b4c0a1475a68338ac","0x47a4c36c2932f213e7b054c9573e49a6681d5b710d1b25a96ea6346f5689929"]
            ]
        }
    },
    "id": 0
}'

# mainnet
rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_getEvents",
    "params": {
        "filter": {
            "from_block": {"block_number": 800}, "to_block": {"block_number": 1701}, "chunk_size": 1,
            "keys": [
                ["0x32152e6067d0b8e3ff1aea0749afa5a823e4646d1663a7167c0a92d21d256eb", "0xb83f204dcb21221bd5ef3d70b06988cd4beaa4d48ff498a1a0c9e1e49e2804"],
                [],
                ["0x599573a0023b0ce23bb8537d2c5f3e9b72ebd4f008d033b4c0a1475a68338ac","0x47a4c36c2932f213e7b054c9573e49a6681d5b710d1b25a96ea6346f5689929"]
            ],
            "continuation_token": "1"
        }
    },
    "id": 0
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

# testnet, declare v1, Cairo 0.x class
rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_addDeclareTransaction",
    "params": {
        "declare_transaction": {
            "type": "DECLARE",
            "max_fee": "0x4f388496839",
            "version": "0x1",
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

# testnet, declare v2, Cairo 1.x class (Sierra)
rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_addDeclareTransaction",
    "params": {
        "declare_transaction": {
            "type": "DECLARE",
            "version": "0x2",
            "max_fee": "0xffffffffffffffff",
            "signature": [],
            "contract_class": {
                "sierra_program": "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",
            "contract_class_version": "0.1.0",
            "entry_points_by_type": {
                "CONSTRUCTOR": [],
                "EXTERNAL": [
                    {
                    "selector": "0x22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658",
                    "function_idx": 0
                    },
                    {
                    "selector": "0x1fc3f77ebc090777f567969ad9823cf6334ab888acb385ca72668ec5adbde80",
                    "function_idx": 1
                    },
                    {
                    "selector": "0x3d778356014c91effae9863ee4a8c2663d8fa2e9f0c4145c1e01f5435ced0be",
                    "function_idx": 2
                    }
                ],
                "L1_HANDLER": []
            },
            "abi": "[\n  {\n    \"type\": \"function\",\n    \"name\": \"test\",\n    \"inputs\": [\n      {\n        \"name\": \"arg\",\n        \"ty\": \"core::felt\"\n      },\n      {\n        \"name\": \"arg1\",\n        \"ty\": \"core::felt\"\n      },\n      {\n        \"name\": \"arg2\",\n        \"ty\": \"core::felt\"\n      }\n    ],\n    \"output_ty\": \"core::felt\",\n    \"state_mutability\": \"external\"\n  },\n  {\n    \"type\": \"function\",\n    \"name\": \"empty\",\n    \"inputs\": [],\n    \"output_ty\": \"()\",\n    \"state_mutability\": \"external\"\n  },\n  {\n    \"type\": \"function\",\n    \"name\": \"call_foo\",\n    \"inputs\": [\n      {\n        \"name\": \"a\",\n        \"ty\": \"core::integer::u128\"\n      }\n    ],\n    \"output_ty\": \"core::integer::u128\",\n    \"state_mutability\": \"external\"\n  }\n]"
        },
        "sender_address": "0x1",
        "nonce": "0x0",
        "compiled_class_hash": "0x711c0c3e56863e29d3158804aac47f424241eda64db33e2cc2999d60ee5105"
    },
    "id": 0
}'

rpc_call '{
    "jsonrpc": "2.0",
    "method": "starknet_addDeployAccountTransaction",
    "params": {
        "deploy_account_transaction": {
            "type": "DEPLOY_ACCOUNT",
            "max_fee": "0x4f388496839",
            "version": "0x1",
            "signature": [
                "0x7dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5",
                "0x71456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
            ],
            "nonce": "0x0",
            "contract_address_salt": "0x6d44a6aecb4339e23a9619355f101cf3cb9baec289fcd9fd51486655c1bb8a8",
            "constructor_calldata": ["0x677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"],
            "class_hash": "0x1fac3074c9d5282f0acc5c69a4781a1c711efea5e73c550c5d9fb253cf7fd3d"
        }
    },
    "id": 0
}'

rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_chainId"}'
rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_getNonce","params":["latest", "0x019245f0f49d23f2379d3e3f20d1f3f46207d1c4a1d09cac8dd50e8d528aabe1"]}'
rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_syncing"}'
rpc_call '{"jsonrpc":"2.0","id":"0","method":"starknet_pendingTransactions"}'
