Executes a new call immediately without creating a transaction on the block chain.
`contract_address` and `entry_point` should be a 32 byte value encoded as 0x-prefixed hex string.
`call_data` should be an array of 32 byte values encoded as 0x-prefixed hex strings.

This call is the equivalent of `eth_call` in [eth1.0 API](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/eth1.0-apis/assembled-spec/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=true&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false).
