# Chain RPC

Blockchain state and tip information.

---

## chain_height

Returns the current block height.

**Parameters**

None

**Returns**

`height` - number, current block height

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"chain_height","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "height": 12345
  }
}
```

---

## chain_tipDigest

Returns the hash of the current tip block.

**Parameters**

None

**Returns**

`digest` - string, 40-char hex block hash

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"chain_tipDigest","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "digest": "04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52"
  }
}
```

---

## chain_tip

Returns the full tip block.

**Parameters**

None

**Returns**

`block` - object, full block data including kernel and proof

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"chain_tip","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "block": { ... }
  }
}
```

---

## chain_tipProof

Returns the proof of the tip block.

**Parameters**

None

**Returns**

`proof` - object, block proof data

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"chain_tipProof","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "proof": { ... }
  }
}
```

---

## chain_tipKernel

Returns the kernel of the tip block.

**Parameters**

None

**Returns**

`kernel` - object, block kernel containing header and body

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"chain_tipKernel","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "kernel": { ... }
  }
}
```

---

## chain_tipHeader

Returns the header of the tip block.

**Parameters**

None

**Returns**

`header` - object, block header data

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"chain_tipHeader","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "header": { ... }
  }
}
```

---

## chain_tipBody

Returns the body of the tip block.

**Parameters**

None

**Returns**

`body` - object, block body data

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"chain_tipBody","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "body": { ... }
  }
}
```

---

## chain_tipTransactionKernel

Returns the transaction kernel of the tip block.

**Parameters**

None

**Returns**

`kernel` - object, transaction kernel with inputs, outputs, fee

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"chain_tipTransactionKernel","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "kernel": {
      "inputs": [...],
      "outputs": [...],
      "fee": "1.0",
      "timestamp": 1703500000000
    }
  }
}
```

---

## chain_tipAnnouncements

Returns the announcements from the tip block.

**Parameters**

None

**Returns**

`announcements` - array, list of announcements

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"chain_tipAnnouncements","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "announcements": []
  }
}
```
