# Node RPC

## node_network

Returns the network the node is connected to.

**Parameters**

None

**Returns**

`network` - string, network name (e.g., "mainnet", "testnet")

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"node_network","params":{},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "network": "testnet"
  }
}
```
