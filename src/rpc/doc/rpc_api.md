Describes the RPC API methods.
The methods are trying to follow the `eth1.0 API` covention. For comparison:
- [eth1.0 API spec repo](https://github.com/ethereum/execution-apis)
- [eth1.0 API spec viewer on openrpc playground](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/eth1.0-apis/assembled-spec/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=true&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false)

__TODO__ At the moment the `latest` special tag value means the _most recent pending_,
while later on we should make a distinction between _the most recent accepted on chain_ and _the most recent pending_.
