# Wallet RPC

Wallet operations for managing funds and transactions.

## Authentication

**Authentication is required** for all Wallet RPC methods. When starting the node with `--rpc-modules` including `Wallet`, you must provide credentials:

```bash
neptune-core --listen-rpc 127.0.0.1:9897 --rpc-modules Node,Chain,Wallet --rpc-username <username> --rpc-password <password>
```

All requests must include HTTP Basic Authentication:

```bash
curl -X POST -H "Content-Type: application/json" \
  -u "<username>:<password>" \
  --data '{"jsonrpc":"2.0","method":"wallet_getBalance","params":{},"id":1}' \
  http://localhost:9897
```

---

## wallet_generateAddress

Generates a new receiving address.

**Parameters**

None

**Returns**

`address` - string, bech32-encoded address

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_generateAddress","params":{},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "xntnwm1..."
  }
}
```

---

## wallet_generateSubaddress

Generates a subaddress from the current wallet's base address with a specified payment ID. Subaddresses allow receiving payments that can be identified by payment ID while sharing the same underlying spending key.

**Parameters**

1. `paymentId` - number, non-zero payment identifier (must be > 0)

**Returns**

- `address` - string, bech32-encoded subaddress
- `paymentId` - number, the payment ID used
- `baseAddress` - string, the base address this subaddress derives from

**Errors**

- Payment ID 0 is not allowed (use `wallet_generateAddress` for base address)
- Only Generation addresses support subaddresses

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_generateSubaddress","params":{"paymentId":42},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "xntnsm1...",
    "paymentId": 42,
    "baseAddress": "xntnwm1..."
  }
}
```

**Use Cases**

- **Payment tracking**: Generate unique subaddresses per customer/invoice to identify payments
- **Privacy**: Subaddresses are unlinkable to the base address without the spending key
- **Organization**: Use payment IDs as invoice numbers, customer IDs, or order references

---

## wallet_getBalance

Returns total wallet balance.

**Parameters**

None

**Returns**

`balance` - string, balance as decimal

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_getBalance","params":{},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "balance": "100.5"
  }
}
```

---

## wallet_sendTx

Sends a transaction.

**Parameters**

1. `amount` - string, amount to send as decimal
2. `fee` - string, transaction fee as decimal
3. `toAddress` - string, recipient address
4. `excludeRecentBlocks` - number, optional, exclude UTXOs from recent blocks

**Returns**

- `timestamp` - number, transaction timestamp in milliseconds
- `tipWhenSent` - string, hex block digest at time of sending
- `inputs` - array, spent UTXOs
- `outputs` - array, created UTXOs

Each input contains:
- `leafIndex` - number, AOCL leaf index
- `utxoDigest` - string, hex UTXO commitment
- `utxo.lockScriptHash` - string, hex lock script hash
- `utxo.amount` - string, amount

Each output contains:
- `utxo.lockScriptHash` - string, hex lock script hash
- `utxo.amount` - string, amount
- `utxoDigest` - string, hex UTXO commitment (use for tracking)
- `senderRandomness` - string, hex randomness
- `isOwned` - boolean, wallet owns this output
- `isChange` - boolean, change output

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_sendTx","params":{"amount":"10.0","fee":"0.1","toAddress":"xntnwm1..."},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "timestamp": 1703500000000,
    "tipWhenSent": "04e19a9adfefa811a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
    "inputs": [
      {
        "leafIndex": 12345,
        "utxoDigest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "utxo": {
          "lockScriptHash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
          "amount": "50.0"
        }
      }
    ],
    "outputs": [
      {
        "utxo": {
          "lockScriptHash": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
          "amount": "10.0"
        },
        "utxoDigest": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
        "senderRandomness": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
        "isOwned": false,
        "isChange": false
      }
    ]
  }
}
```

---

## wallet_validateAmount

Validates an amount string.

**Parameters**

1. `amountString` - string, amount to validate

**Returns**

`amount` - string or null, normalized amount if valid

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_validateAmount","params":{"amountString":"10.5"},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "amount": "10.5"
  }
}
```

---

## wallet_validateAddress

Validates an address string and returns address details.

**Parameters**

1. `addressString` - string, address to validate

**Returns**

- `address` - string or null, normalized address if valid
- `addressType` - string or null, one of: `"generation"`, `"symmetric"`, `"generation_subaddress"`
- `receiverIdentifier` - number or null, receiver identifier value
- `baseAddress` - string or null, base address (only for subaddresses)
- `paymentId` - number or null, payment ID (only for subaddresses)

**Example (base address)**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_validateAddress","params":{"addressString":"xntnwm1..."},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "xntnwm1...",
    "addressType": "generation",
    "receiverIdentifier": 12345678901234567890,
    "baseAddress": null,
    "paymentId": null
  }
}
```

**Example (subaddress)**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_validateAddress","params":{"addressString":"xntnsm1..."},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "xntnsm1...",
    "addressType": "generation_subaddress",
    "receiverIdentifier": 98765432109876543210,
    "baseAddress": "xntnwm1...",
    "paymentId": 42
  }
}
```

---

## wallet_unspentUtxos

Returns all unspent UTXOs.

**Parameters**

1. `excludeRecentBlocks` - number, optional, exclude recent blocks

**Returns**

Array of:
- `leafIndex` - number, AOCL leaf index
- `lockScriptHash` - string, hex lock script hash
- `amount` - string, amount

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_unspentUtxos","params":{},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    {
      "leafIndex": 12345,
      "lockScriptHash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
      "amount": "100.0"
    }
  ]
}
```

---

## wallet_selectSpendableInputs

Selects UTXOs to cover an amount.

**Parameters**

1. `amount` - string, target amount
2. `fee` - string, transaction fee
3. `excludeRecentBlocks` - number, optional, exclude recent blocks

**Returns**

- `selectedUtxos` - array, selected UTXOs
- `totalSelectedAmount` - string, total of selected

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_selectSpendableInputs","params":{"amount":"50.0","fee":"0.1"},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "selectedUtxos": [
      {
        "leafIndex": 12345,
        "lockScriptHash": "a1b2c3d4...",
        "amount": "100.0"
      }
    ],
    "totalSelectedAmount": "100.0"
  }
}
```

---

## wallet_history

Returns wallet transaction history.

**Parameters**

All optional:
1. `leafIndex` - number, filter by leaf index
2. `utxoDigest` - string, filter by hex UTXO hash
3. `receivingAddress` - string, filter by address
4. `senderRandomness` - string, filter by hex randomness
5. `confirmedHeight` - number, filter by confirmation height
6. `spentHeight` - number, filter by spent height

**Returns**

Array of:
- `leafIndex` - number, AOCL leaf index
- `utxoDigest` - string, hex UTXO hash
- `senderRandomness` - string, hex sender randomness
- `confirmedHeight` - number, block height when confirmed
- `spentHeight` - number or null, block height when spent
- `timestamp` - number, timestamp in milliseconds
- `receivingAddress` - string or null, address if known
- `utxo` - object, UTXO details

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_history","params":{},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    {
      "leafIndex": 12345,
      "utxoDigest": "a1b2c3d4...",
      "senderRandomness": "b2c3d4e5...",
      "confirmedHeight": 100,
      "spentHeight": null,
      "timestamp": 1703500000000,
      "receivingAddress": "xntnwm1...",
      "utxo": { ... }
    }
  ]
}
```

---

## wallet_sentTransaction

Returns sent transaction details.

**Parameters**

All optional:
1. `senderRandomness` - string, filter by hex randomness
2. `receiverDigest` - string, filter by hex receiver
3. `lockScriptHash` - string, filter by hex lock script
4. `utxoDigest` - string, filter by hex UTXO hash
5. `timestamp` - number, filter by timestamp
6. `limit` - number, max results
7. `page` - number, page number

**Returns**

Array of sent transactions with inputs, outputs, fee, timestamp.

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_sentTransaction","params":{"limit":10},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    {
      "txInputs": [...],
      "txOutputs": [...],
      "fee": "0.1",
      "timestamp": 1703500000000,
      "tipWhenSent": "a1b2c3d4..."
    }
  ]
}
```

---

## wallet_blockInfo

Returns block info with wallet-known details.

**Parameters**

1. `selector` - SELECTOR, block selector

**Returns**

- `height` - number, block height
- `digest` - string, hex block hash
- `timestamp` - number, block timestamp in milliseconds
- `difficulty` - string, block difficulty
- `size` - number, block size in bytes
- `fee` - string, total fees
- `inputs` - array, block inputs with wallet info
- `outputs` - array, block outputs with wallet info

For wallet-known outputs, includes: `senderRandomness`, `receivingAddress`, `receiverDigest`, `utxo`

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_blockInfo","params":{"selector":100},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "height": 100,
    "digest": "04e19a9adfefa811...",
    "timestamp": 1703500000000,
    "difficulty": "1000000",
    "size": 4096,
    "fee": "1.5",
    "inputs": [...],
    "outputs": [...]
  }
}
```

---

## wallet_getBlocks

Returns blocks in a height range.

**Parameters**

1. `fromHeight` - number, start height
2. `toHeight` - number, end height

**Returns**

`blocks` - array, list of wallet blocks

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_getBlocks","params":[0,10],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "blocks": [...]
  }
}
```

---

## wallet_countSentTransactionsAtBlock

Counts sent transactions at a block.

**Parameters**

1. `block` - SELECTOR, block selector

**Returns**

`count` - number, number of sent transactions

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"wallet_countSentTransactionsAtBlock","params":{"block":{"height":100}},"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "count": 5
  }
}
```
