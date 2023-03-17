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

rpc_call '{"jsonrpc":"2.0","id":"0","method":"pathfinder_version"}'

rpc_call '{
    "jsonrpc": "2.0",
    "method": "pathfinder_getProof",
    "params": {
        "block_id": "latest",
        "contract_address": "0x23371b227eaecd8e8920cd429d2cd0f3fee6abaacca08d3ab82a7cdd",
        "keys": [
            "0x1",
            "0xfffffffff"
        ]
    },
    "id": 0
}'