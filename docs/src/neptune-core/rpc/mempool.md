# Mempool RPC

Pending transaction methods.

---

## mempool_transactions

Returns all transaction IDs in the mempool.

**Parameters**

None

**Returns**

`transactions` - array of strings, list of hex transaction kernel IDs

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"mempool_transactions","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "transactions": [
      "04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52"
    ]
  }
}
```

---

## mempool_getTransactionKernel

Returns transaction kernel by ID.

**Parameters**

1. `id` - string, hex transaction kernel ID

**Returns**

`kernel` - object or null, transaction kernel containing:
- `inputs` - array, removal records (spent UTXOs)
- `outputs` - array of strings, hex UTXO commitments
- `fee` - string, transaction fee
- `coinbase` - string or null, coinbase amount
- `timestamp` - number, transaction timestamp in milliseconds
- `mutatorSetHash` - string, hex mutator set state hash

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"mempool_getTransactionKernel","params":["04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52"],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "kernel": {
      "inputs": [...],
      "outputs": ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"],
      "fee": "1.0",
      "coinbase": null,
      "timestamp": 1703500000000,
      "mutatorSetHash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
    }
  }
}
```

---

## mempool_getTransactionProof

Returns transaction proof by ID.

**Parameters**

1. `id` - string, hex transaction kernel ID

**Returns**

`proof` - object or null, transaction proof

Note: Proofs for witness-backed transactions are not exposed for privacy.

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"mempool_getTransactionProof","params":["04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52"],"id":1}'

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

## mempool_submitTransaction

Submits a proven transaction to the mempool for broadcast.

**Parameters**

1. `transaction` - object, full transaction with proof:
   - `kernel` - object, transaction kernel
   - `proof` - object, transaction proof (SingleProof or ProofCollection)

**Returns**

`success` - boolean, true if transaction was accepted

**Errors**

- `InvalidTransaction` - validation failed
- `CoinbaseTransaction` - coinbase not allowed
- `FeeNegative` - negative fee
- `FutureDated` - timestamp too far in future
- `NotConfirmable` - invalid mutator set state

**Example**

```json
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"mempool_submitTransaction","params":[{"kernel":{...},"proof":{...}}],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "success": true
  }
}
```

---

## mempool_getMempoolEvents

Returns a paginated, filterable log of mempool state changes (transaction adds and removes). The node keeps the last 128 block-height batches in memory. Events are grouped by the block height at which they occurred.

**Parameters**

An object with optional fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fromHeight` | number | none | Only include batches at or above this block height |
| `toHeight` | number | none | Only include batches at or below this block height |
| `txid` | string | none | Filter to events matching this hex transaction kernel ID |
| `commitment` | string | none | Filter to events whose kernel outputs contain this hex UTXO commitment digest |
| `reason` | string | none | Filter to events matching this reason string (see tables below) |
| `limit` | number | 50 | Maximum number of batches per page |
| `page` | number | 0 | Zero-based page index |

**Add reasons**

| Reason | Description |
|--------|-------------|
| `submitted` | Submitted by the local wallet |
| `from_peer` | Received from a peer |
| `restored` | Restored from merge input cache after a new block |
| `updated` | Re-inserted after mutator set update |
| `upgraded` | Proof upgraded (e.g. ProofCollection to SingleProof, or merge) |

**Remove reasons**

| Reason | Description |
|--------|-------------|
| `merged` | Consumed by a new block being mined |
| `abandoned` | ProofCollection from peer with no primitive witness — cannot update |
| `empty_inputs` | Transaction had empty inputs |
| `mempool_full` | Mempool full, lowest fee-density transaction evicted |
| `orphaned` | Chain reorganization, mempool cleared |
| `pruned` | Transaction too old |
| `replaced` | Replaced by a transaction with higher fee density or better proof |
| `updated` | Replaced by updated version (same logical tx, new mutator set data) |
| `explicit` | Explicit removal (e.g. by RPC call) |

**Returns**

| Field | Type | Description |
|-------|------|-------------|
| `total` | number | Total number of matching batches (before pagination) |
| `page` | number | Current page index |
| `limit` | number | Page size used |
| `events` | array | Array of event batches |

Each batch in `events`:

| Field | Type | Description |
|-------|------|-------------|
| `blockHeight` | number | Block height when these events occurred |
| `events` | array | Array of event objects |

Each event object is tagged by `type`:

**`add` event:**

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `"add"` |
| `txid` | string | Hex transaction kernel ID |
| `kernel` | object | Full transaction kernel |
| `reason` | string | One of the add reasons above |

**`remove` event:**

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `"remove"` |
| `txid` | string | Hex transaction kernel ID |
| `kernel` | object | Full transaction kernel |
| `reason` | string | One of the remove reasons above |

**Example**

```
// Request — get all events, default pagination
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"mempool_getMempoolEvents","params":{},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "total": 2,
    "page": 0,
    "limit": 50,
    "events": [
      {
        "blockHeight": 1023,
        "events": [
          {
            "type": "remove",
            "txid": "04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52",
            "kernel": { ... },
            "reason": "merged"
          }
        ]
      },
      {
        "blockHeight": 1024,
        "events": [
          {
            "type": "add",
            "txid": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
            "kernel": { ... },
            "reason": "from_peer"
          }
        ]
      }
    ]
  }
}
```

```
// Request — filter by txid
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"mempool_getMempoolEvents","params":{"txid":"04e19a9adfefa811f68d8de45da6412d0d73368159a119af97cfd38da6cfc55ae7c6ba403b9c8b52"},"id":2}'
```

```
// Request — filter by reason and height range
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"mempool_getMempoolEvents","params":{"reason":"merged","fromHeight":1000,"toHeight":1100},"id":3}'
```

---

## Tracking Transactions

Transaction IDs can change when merged. Use `outputs` (UTXO commitments) for tracking:

1. Get `outputs[].utxoDigest` from `wallet_sendTx` response
2. Use `archival_findUtxoLeafIndex` to check status:
   - `mempool: true` = pending
   - `leafIndex` present = confirmed
