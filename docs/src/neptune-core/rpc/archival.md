# Archival RPC

Historical block and UTXO data. Requires archival node.

---

## archival_getBlockDigest

Returns the hash of a block by selector.

**Parameters**

1. `selector` - SELECTOR, block selector

SELECTOR can be:
- `{"height": 100}` - by height
- `{"digest": "04e19a9adf..."}` - by hash (hex string)
- `"tip"` - latest block
- `"genesis"` - first block

**Returns**

`digest` - string or null, 40-char hex block hash

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getBlockDigest","params":[100],"id":1}'

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

## archival_getBlockDigests

Returns all block hashes at a height (handles forks).

**Parameters**

1. `height` - number, block height

**Returns**

`digests` - array of strings, list of hex block hashes at that height

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getBlockDigests","params":[100],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "digests": ["04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52"]
  }
}
```

---

## archival_getBlock

Returns a full block by selector.

**Parameters**

1. `selector` - SELECTOR, block selector

**Returns**

`block` - object or null, full block data

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getBlock","params":[100],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "block": {
      "kernel": {
        "header": { ... },
        "body": { ... },
        "appendix": { ... }
      },
      "proof": { ... }
    }
  }
}
```

---

## archival_getBlockProof

Returns block proof by selector.

**Parameters**

1. `selector` - SELECTOR, block selector

**Returns**

`proof` - object or null, block proof

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getBlockProof","params":[100],"id":1}'

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

## archival_getBlockKernel

Returns block kernel by selector.

**Parameters**

1. `selector` - SELECTOR, block selector

**Returns**

`kernel` - object or null, block kernel

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getBlockKernel","params":[100],"id":1}'

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

## archival_getBlockHeader

Returns block header by selector.

**Parameters**

1. `selector` - SELECTOR, block selector

**Returns**

`header` - object or null, block header

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getBlockHeader","params":[100],"id":1}'

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

## archival_getBlockBody

Returns block body by selector.

**Parameters**

1. `selector` - SELECTOR, block selector

**Returns**

`body` - object or null, block body

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getBlockBody","params":[100],"id":1}'

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

## archival_getBlockTransactionKernel

Returns transaction kernel from a block.

**Parameters**

1. `selector` - SELECTOR, block selector

**Returns**

`kernel` - object or null, transaction kernel

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getBlockTransactionKernel","params":[100],"id":1}'

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

## archival_getBlockAnnouncements

Returns announcements from a block.

**Parameters**

1. `selector` - SELECTOR, block selector

**Returns**

`announcements` - array or null, announcements

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getBlockAnnouncements","params":[100],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "announcements": []
  }
}
```

---

## archival_isBlockCanonical

Checks if a block is part of the canonical chain.

**Parameters**

1. `digest` - string, 40-char hex block hash

**Returns**

`canonical` - boolean, true if block is canonical

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_isBlockCanonical","params":["04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52"],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "canonical": true
  }
}
```

---

## archival_getUtxoDigest

Returns UTXO hash by AOCL leaf index.

**Parameters**

1. `leafIndex` - number, AOCL leaf index

**Returns**

`digest` - string or null, 40-char hex UTXO hash

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_getUtxoDigest","params":[12345],"id":1}'

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

## archival_findUtxoLeafIndex

Finds UTXO leaf index by hash. Also checks mempool.

**Parameters**

1. `utxoDigest` - string, 40-char hex UTXO hash to find
2. `fromLeafIndex` - number, optional, start of search range
3. `toLeafIndex` - number, optional, end of search range

**Returns**

- `leafIndex` - number, AOCL leaf index (if confirmed)
- `mempool` - boolean, true if in mempool (not yet confirmed)
- `blockHeight` - number, block height where confirmed
- `blockDigest` - string, hex block hash where confirmed

Fields are omitted when null.

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_findUtxoLeafIndex","params":{"utxoDigest":"04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52"},"id":1}'

// Result - in mempool
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "mempool": true
  }
}

// Result - confirmed
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "leafIndex": 54321,
    "blockHeight": 1000,
    "blockDigest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
  }
}
```

---

## archival_findUtxoOrigin

Finds which block created a UTXO.

**Parameters**

1. `additionRecord` - string, 40-char hex UTXO hash (canonical commitment)
2. `searchDepth` - number, optional, blocks to search back (default 100)

**Returns**

`block` - string or null, hex block hash where UTXO was created

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"archival_findUtxoOrigin","params":["04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52",100],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "block": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
  }
}
```
