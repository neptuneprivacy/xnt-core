# Exchange Integration Guide

This guide covers integrating Neptune Core for cryptocurrency exchanges.

---

## Overview

Neptune is a privacy-focused cryptocurrency using zero-knowledge proofs. Key concepts:

- **UTXOs**: Unspent transaction outputs, the fundamental unit of value
- **UTXO Digest**: Unique 40-char hex identifier for each output (use for tracking)
- **Leaf Index**: Position in the append-only commitment log (AOCL)
- **Archival Node**: Required for exchange operations (stores full history)

---

## Node Setup

### Requirements

- Archival node mode
- RPC enabled with authentication
- Adequate storage for blockchain data

### Configuration

```bash
neptune-core --listen-rpc 127.0.0.1:9897 --rpc-modules Node,Chain,Wallet,Archival
```

### Health Check

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"node_network","params":[],"id":1}' \
  http://localhost:9799
```

---

## Deposits

### 1. Generate Deposit Address

Generate a unique address for each user/deposit:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"wallet_generateAddress","params":{},"id":1}' \
  http://localhost:9799
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "xntnwm1..."
  }
}
```

Store the address mapped to the user in your database.

### 2. Monitor for Deposits

Poll new blocks using `wallet_blockInfo` and check for deposits to your addresses:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"wallet_blockInfo","params":{"selector":{"height":1000}},"id":1}' \
  http://localhost:9799
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "height": 1000,
    "digest": "04e19a9adfefa811...",
    "timestamp": 1703500000000,
    "outputs": [
      {
        "utxoDigest": "a1b2c3d4e5f6...",
        "receivingAddress": "xntnwm1...",
        "utxo": {
          "lockScriptHash": "...",
          "amount": "100.0"
        }
      }
    ]
  }
}
```

**Key fields:**

- `height` - Block height for calculating confirmations
- `utxoDigest` - Unique identifier for this deposit
- `receivingAddress` - Match against your deposit addresses
- `amount` - Deposit amount

### 3. Check Confirmations

Get current chain height and calculate confirmations:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"chain_height","params":{},"id":1}' \
  http://localhost:9799
```

```text
confirmations = current_height - block_height + 1
```

**Recommended confirmations:** 10+ for deposits

---

## Withdrawals

### 1. Validate User Input

Always validate address and amount before sending:

```bash
# Validate address
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"wallet_validateAddress","params":{"addressString":"npt1qxyz..."},"id":1}' \
  http://localhost:9799

# Validate amount
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"wallet_validateAmount","params":{"amountString":"10.5"},"id":1}' \
  http://localhost:9799
```

Returns normalized value if valid, `null` if invalid.

### 2. Check Balance

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"wallet_getBalance","params":{},"id":1}' \
  http://localhost:9799
```

### 3. Send Transaction

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"wallet_sendTx","params":{"amount":"10.0","fee":"0.1","toAddress":"npt1qxyz..."},"id":1}' \
  http://localhost:9799
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "timestamp": 1703500000000,
    "tipWhenSent": "04e19a9adfefa811...",
    "inputs": [...],
    "outputs": [
      {
        "utxo": {
          "lockScriptHash": "...",
          "amount": "10.0"
        },
        "utxoDigest": "d4e5f6a1b2c3...",
        "senderRandomness": "e5f6a1b2c3d4...",
        "isOwned": false,
        "isChange": false
      }
    ]
  }
}
```

**Important:** Store the `utxoDigest` from the non-change output for tracking. The `tipWhenSent` is the block digest at the time the transaction was sent, useful for tracking confirmation progress.

### 4. Track Withdrawal Status

Poll new blocks using `wallet_blockInfo` and check for your withdrawal's `utxoDigest`:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"wallet_blockInfo","params":{"selector":{"height":1000}},"id":1}' \
  http://localhost:9799
```

Check the block's `outputs` array for your `utxoDigest`. Once found, calculate confirmations:

```text
confirmations = current_height - block_height + 1
```

**Withdrawal states:**

- **Pending**: Not yet in any block (check mempool)
- **Confirmed**: Found in block outputs, calculate confirmations
- **Complete**: Sufficient confirmations reached (10+ recommended)

### 4.1. Alternative: Find by UTXO Digest

Use `archival_findUtxoLeafIndex` to find a specific UTXO's confirmation status:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"archival_findUtxoLeafIndex","params":{"utxoDigest":"d4e5f6a1b2c3..."},"id":1}' \
  http://localhost:9799
```

**Optional parameters:**

- `fromLeafIndex` - Start of search range (for faster lookups)
- `toLeafIndex` - End of search range

**Results:**

- `mempool: true` - Transaction pending in mempool
- `leafIndex`, `blockHeight`, `blockDigest` - Confirmed in block
- Empty result - Not found

### 4.2. Verify Block Canonicity

If a confirmed transaction hasn't gained confirmations for a long time, check if its block is still canonical:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"archival_isBlockCanonical","params":["a1b2c3d4..."],"id":1}' \
  http://localhost:9799
```

Use the `blockDigest` returned from `archival_findUtxoLeafIndex` or stored when the transaction was first confirmed.

**Results:**

- `canonical: true` - Block is on the main chain, transaction is valid
- `canonical: false` - Block was reorged out, transaction moved to a different canonical block

If non-canonical, re-query `archival_findUtxoLeafIndex` to find the new block containing your transaction.

---

## Transaction Tracking

### Why Use utxoDigest?

Transaction IDs can change when transactions are merged in the mempool. The `utxoDigest` (UTXO commitment hash) is stable and unique for each output.

### Tracking Flow

```text
1. wallet_sendTx
   └── Save outputs[].utxoDigest (non-change output)

2. Poll wallet_blockInfo for new blocks
   ├── utxoDigest in outputs → Confirmed (note block height)
   └── not found             → Still pending (check mempool)

3. Calculate confirmations
   └── current_height - block_height + 1
```

### Mempool Monitoring

List pending transactions:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"mempool_transactions","params":{},"id":1}' \
  http://localhost:9799
```

Get transaction details:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"mempool_getTransactionKernel","params":["04e19a9adf..."],"id":1}' \
  http://localhost:9799
```

---

## Handling Reorgs

### Detection

Monitor `chain_tipDigest` for changes:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"chain_tipDigest","params":{},"id":1}' \
  http://localhost:9799
```

If the tip changes unexpectedly (not the next sequential block), a reorg may have occurred.

### Verification

Check if a previously confirmed block is still canonical:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"archival_isBlockCanonical","params":["04e19a9adf..."],"id":1}' \
  http://localhost:9799
```

### Recovery

If a deposit's block is no longer canonical:

1. Mark the deposit as unconfirmed
2. Re-check `wallet_blockInfo` for new blocks containing the `utxoDigest`
3. If found in a new block, update confirmation status
4. If not found, the transaction may return to mempool or be lost

**Recommendation:** Wait for 10+ confirmations before crediting deposits.

---

### Excluding Recent UTXOs

To avoid spending UTXOs that might be reorged:

```bash
# Exclude UTXOs from last 10 blocks
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"wallet_sendTx","params":{"amount":"10.0","fee":"0.1","toAddress":"npt1qxyz...","excludeRecentBlocks":10},"id":1}' \
  http://localhost:9799
```

---

## Security Considerations

### RPC Security

- Use authentication for RPC endpoints
- Bind RPC to localhost only (`127.0.0.1`)
- Use TLS for remote connections
- Implement rate limiting

### Wallet Security

- Use separate hot/cold wallets
- Keep minimal balance in hot wallet
- Regular backups of wallet data
- Monitor for unusual activity

### Input Validation

Always validate:

- Addresses before sending
- Amounts before sending
- Transaction responses before storing

### Monitoring

- Track mempool size for congestion
- Monitor confirmation times
- Alert on large withdrawals
- Log all RPC calls

---

## Error Handling

### Common Errors

| Error | Cause | Action |
| ----- | ----- | ------ |
| `InvalidTransaction` | Validation failed | Check inputs/outputs |
| `InsufficientBalance` | Not enough funds | Wait for deposits or consolidate |
| `FeeNegative` | Invalid fee | Use positive fee value |
| `AddressInvalid` | Bad address format | Validate before sending |

### Retry Logic

- Network errors: Retry with exponential backoff
- RPC timeout: Increase timeout, retry
- Transaction not found: Wait and retry (may be in mempool)

---

## API Reference

| Category | Methods |
| -------- | ------- |
| [Wallet](rpc/wallet.md) | `generateAddress`, `getBalance`, `sendTx`, `blockInfo`, `getBlocks`, `validateAddress`, `validateAmount` |
| [Chain](rpc/chain.md) | `height`, `tipDigest`, `tip` |
| [Archival](rpc/archival.md) | `findUtxoLeafIndex`, `isBlockCanonical`, `getBlock` |
| [Mempool](rpc/mempool.md) | `transactions`, `getTransactionKernel` |

See [RPC Documentation](rpc.md) for complete API reference.
