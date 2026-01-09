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

## Tracking Transactions

Transaction IDs can change when merged. Use `outputs` (UTXO commitments) for tracking:

1. Get `outputs[].utxoDigest` from `wallet_sendTx` response
2. Use `archival_findUtxoLeafIndex` to check status:
   - `mempool: true` = pending
   - `leafIndex` present = confirmed
