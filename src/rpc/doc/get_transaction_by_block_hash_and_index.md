Returns information about a transaction by block hash and transaction index position.
`block_hash` should either be a 32 byte value encoded as 0x-prefixed hex string or
one of special tag values:
- `latest`, which means the most recent block,
- `earliest`, which means the genesis block.
`transaction_index` should either be a 0x-prefixed hex-encoded unsigned integer.

This call is the equivalent of `eth_getTransactionByBlockHashAndIndex` in [eth1.0 API](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/eth1.0-apis/assembled-spec/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=true&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false).
