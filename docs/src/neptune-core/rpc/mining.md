# Mining RPC

Block template and submission for miners.

---

## mining_getBlockTemplate

Returns a block template for mining.

**Parameters**

1. `guesserAddress` - string, address to receive mining rewards

**Returns**

`template` - object or null, block template for mining

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"mining_getBlockTemplate","params":["xntnwm1..."],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "template": {
      "block": { ... },
      "metadata": { ... }
    }
  }
}
```

---

## mining_submitBlock

Submits a mined block.

**Parameters**

1. `template` - object, block with solved proof-of-work
2. `pow` - object, proof-of-work solution with nonce

**Returns**

`success` - boolean, true if block was accepted

**Errors**

- `InvalidBlock` - block validation failed
- `InsufficientWork` - proof-of-work doesn't meet target

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"mining_submitBlock","params":{"template": { ... }, "pow": { ... }},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "success": true
  }
}
```
