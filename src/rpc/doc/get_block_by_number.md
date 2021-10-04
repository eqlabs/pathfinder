Returns information about a block by number. `block_number` should either be
a 0x-prefixed hex-encoded unsigned integer or one of special tag values
- `latest`, which means the most recent block,
- `earliest`, which means the genesis block.

This call is the equivalent of `eth_getBlockByNumber` in [eth1.0 API](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/eth1.0-apis/assembled-spec/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=true&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false).
