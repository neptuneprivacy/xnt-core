# Exchange Integration Guide

NAPI SDK integration guide for exchanges and non-custodial wallets.

**Reference:** See full working example at `xnt-sdk/examples/xnt-sdk-test.ts`

---

## Node Setup

Start xnt-core with UTXO indexer enabled for block scanning:

```bash
xnt-core --network main --utxo-indexer --rpc-modules Node,Chain,Wallet,Archival,Mempool --listen-rpc 0.0.0.0:9897
```

---

## SDK Setup

Build the SDK:

```bash
cd xnt-sdk
npm install
npm run build
```

---

## Imports

```typescript
import {
  XntNetwork,
  XntWalletEntropy,
  XntAddress,
  XntRpcClient,
  XntTransactionBuilder,
  XntMembershipProof,
  XntDecryptedUtxo,
  XntPendingUtxo,
  xntVersion,
  xntTimestampNow,
  xntFetchUtxos,
  xntCheckSpent,
  xntGetAoclIndices,
  xntGetMutatorSet,
  xntGetMembershipProofs,
  xntDecryptIndexedUtxo,
  xntComputeCommitment,
  xntComputeAbsoluteIndexSetHash,
  xntRandomSenderRandomness,
  xntSelectInputs,
  xntMempoolSpending,
  xntMempoolIncoming,
  xntComputeCommitmentForOutput,
} from "../src/napi/output";
```

---

## Seed

Generate and manage wallet seeds using BIP39 mnemonics.

```typescript
// Generate new wallet (18 words)
const wallet = XntWalletEntropy.generate();
const mnemonic = wallet.toMnemonic();

// Import existing wallet
const imported = new XntWalletEntropy(mnemonic);

// Derive spending key at index 0
const key = wallet.deriveKey(0);

// Key methods
key.receiverIdHex();        // receiver ID hex
key.receiverIdHashHex();    // receiver ID hash hex (for UTXO queries)
key.receiverPreimageHex();  // receiver preimage hex (for decryption)
key.toAddress();            // returns XntAddress
```

---

## Address

### Base Address

```typescript
const key = wallet.deriveKey(0);
const addr = key.toAddress();

// Encode to bech32
const bech32 = addr.toBech32(XntNetwork.Main);
// "xntnwm1..."

// Decode from bech32
const decoded = XntAddress.fromBech32(bech32, XntNetwork.Main);

// Address methods
addr.toReceivingAddress();  // for transaction outputs
addr.privacyDigestHex();    // for pending incoming display
```

### Subaddress with Payment ID

Generate unique deposit addresses per customer using payment IDs:

```typescript
// Create subaddress (payment_id must be > 0)
const customerId = 12345;
const sub = addr.withPaymentId(customerId);
const depositAddr = sub.toBech32(XntNetwork.Main);
// "xntnsm1..." (subaddress prefix)

// Get payment ID
sub.paymentId(); // 12345

// payment_id=0 is rejected
try { addr.withPaymentId(0); } catch { /* rejected */ }
```

---

## RPC

Connect to Neptune node:

```typescript
const client = new XntRpcClient("http://localhost:9897/");

// Health check
client.ping();

// Get current block height
const height = client.chainHeight(); // negative if failed
```

---

## Sync

Block scanning and UTXO queries with range filter.

### Interfaces

```typescript
interface UnspentUtxo {
  decrypted: XntDecryptedUtxo;
  aoclIndex: number;
  absHash: string;
}

interface SyncResult {
  unspent: UnspentUtxo[];
  pendingSpending: number[];        // indices into unspent
  pendingIncoming: XntPendingUtxo[];
}
```

### Sync Wallet Function

```typescript
function syncWallet(
  client: XntRpcClient,
  key: ReturnType<XntWalletEntropy["deriveKey"]>
): SyncResult | null {
  const ridHashHex = key.receiverIdHashHex();
  const receiverPreimageHex = key.receiverPreimageHex();

  const height = client.chainHeight();
  if (height < 0) return null;

  // Fetch & decrypt UTXOs in 1000-block ranges
  const decrypted: XntDecryptedUtxo[] = [];
  for (let from = 0; from <= height; from += 1000) {
    const indexed = xntFetchUtxos(client, ridHashHex, from, Math.min(from + 999, height));
    for (const u of indexed) {
      try {
        decrypted.push(xntDecryptIndexedUtxo(key, u.ciphertext, u.blockHeight, u.blockDigestHex));
      } catch { /* not ours */ }
    }
  }
  if (decrypted.length === 0) return { unspent: [], pendingSpending: [], pendingIncoming: [] };

  // Compute commitments and get AOCL indices
  const commitments = decrypted.map(u =>
    xntComputeCommitment(u.utxo.hashHex(), u.senderRandomnessHex, receiverPreimageHex)
  );
  const aoclIndices = xntGetAoclIndices(client, commitments);

  // Build valid UTXOs with absolute hashes
  const validUtxos: { idx: number; aocl: number; absHash: string }[] = [];
  aoclIndices.forEach((aocl, i) => {
    if (aocl >= 0) {
      const u = decrypted[i];
      const absHash = xntComputeAbsoluteIndexSetHash(
        u.utxo.hashHex(), u.senderRandomnessHex, receiverPreimageHex, aocl
      );
      validUtxos.push({ idx: i, aocl, absHash });
    }
  });

  // Check spent status
  const spentStatus = xntCheckSpent(client, validUtxos.map(v => v.absHash));
  const now = BigInt(Date.now());

  // Filter unspent and spendable (not timelocked)
  const unspent = validUtxos
    .filter((_, j) => spentStatus[j] < 0)
    .map(v => ({ decrypted: decrypted[v.idx], aoclIndex: v.aocl, absHash: v.absHash }))
    .filter(u => u.decrypted.utxo.canSpendAt(now));

  // Check mempool for pending spending
  const absHashes = unspent.map(u => u.absHash);
  let pendingSpending: number[] = [];
  try {
    pendingSpending = xntMempoolSpending(client, absHashes);
  } catch { /* mempool check failed */ }

  // Check mempool for pending incoming
  let pendingIncoming: XntPendingUtxo[] = [];
  try {
    pendingIncoming = xntMempoolIncoming(client, key);
  } catch { /* mempool check failed */ }

  return { unspent, pendingSpending, pendingIncoming };
}
```

### Decrypted UTXO Properties

```typescript
decrypted.amount              // bigint (in NAU)
decrypted.blockHeight         // number
decrypted.senderRandomnessHex // string
decrypted.paymentId           // number (0 for base address)
decrypted.utxo.hashHex()      // UTXO hash
decrypted.utxo.canSpendAt(ts) // boolean
```

### Pending UTXO Properties

```typescript
pending.amount              // bigint
pending.utxo.hashHex()      // string
pending.senderRandomnessHex // string
pending.paymentId           // number
```

---

## TX

Full transaction build, prove, and submit.

### Amount Helpers

```typescript
const CONVERSION_FACTOR = 4n * 10n ** 30n; // 1 XNT = 4 * 10^30 NAU

const toNau = (xnt: number) =>
  BigInt(Math.round(xnt * 1e8)) * CONVERSION_FACTOR / 100000000n;

const formatAmount = (nau: bigint) => {
  const abs = nau < 0n ? -nau : nau;
  const sign = nau < 0n ? "-" : "";
  return `${sign}${abs / CONVERSION_FACTOR}.${((abs % CONVERSION_FACTOR) * 100000000n / CONVERSION_FACTOR).toString().padStart(8, "0")} XNT`;
};
```

### Build Transaction

```typescript
// Sync wallet and filter available UTXOs
const result = syncWallet(client, key);
const available = result.unspent.filter((_, i) => !result.pendingSpending.includes(i));

// Select inputs
const fee = toNau(0.005);
const sendAmount = toNau(10.0);
const totalAmount = sendAmount + fee;

const amounts = available.map(u => u.decrypted.amount);
const selected = xntSelectInputs(amounts, totalAmount, 10); // max 10 inputs
const selectedUtxos = selected.map(i => available[i]);

// Get membership proofs
const proofBuffers = xntGetMembershipProofs(
  client,
  selectedUtxos.map(u => u.decrypted.utxo.hashHex()),
  selectedUtxos.map(u => u.decrypted.senderRandomnessHex),
  key.receiverPreimageHex(),
  selectedUtxos.map(u => u.aoclIndex)
);

// Get mutator set
const mutatorSet = xntGetMutatorSet(client);

// Build transaction
const builder = new XntTransactionBuilder();

// Add inputs
for (let i = 0; i < selected.length; i++) {
  const proof = XntMembershipProof.fromBytes(proofBuffers[i]);
  builder.addInput(selectedUtxos[i].decrypted.utxo, key, proof);
}

// Add output (recipient)
const recipient = XntAddress.fromBech32(recipientBech32, XntNetwork.Main);
builder.addOutput(recipient.toReceivingAddress(), sendAmount, xntRandomSenderRandomness());

// Set fee and change
builder.setFee(fee);
builder.setChange(addr, xntRandomSenderRandomness());

// Build
const builtTx = builder.build(mutatorSet, xntTimestampNow(), XntNetwork.Main);
```

### Built Transaction Info

```typescript
// Get inputs info
const inputs = builtTx.inputs();
for (const inp of inputs) {
  console.log(inp.amount, inp.commitmentHex);
}

// Get outputs info
const outputs = builtTx.outputs();
for (const out of outputs) {
  console.log(out.amount, out.commitmentHex, out.isChange, out.paymentId);
}

// Serialize
const txBytes = builtTx.toBytes();
```

### Prove Transaction

Requires prover binary and ~16GB RAM:

```bash
export TRITON_VM_PROVER_PATH=/path/to/xnt-core/target/release/triton-vm-prover
```

```typescript
// WARNING: ~16GB RAM, several minutes
const provenTx = builtTx.prove();
provenTx.hasProofCollection(); // boolean
```

### Submit Transaction

```typescript
try {
  provenTx.submit(client);
} catch (e) {
  console.log(`submit error: ${e}`);
}
```

---

## Utils

```typescript
xntVersion();                  // version string
xntTimestampNow();             // current timestamp (bigint ms)
xntRandomSenderRandomness();   // random sender randomness hex

// For pending incoming display
xntComputeCommitmentForOutput(
  utxoHashHex,
  senderRandomnessHex,
  addr.privacyDigestHex()
);
```

---

## Exchange Workflow

### Deposit Tracking

1. Generate subaddress per customer: `addr.withPaymentId(customerId)`
2. Scan new blocks: `xntFetchUtxos(client, receiverIdHashHex, fromHeight, toHeight)`
3. Match `paymentId` to customer
4. Wait for confirmations

### Withdrawal

1. `syncWallet()` to get available UTXOs
2. Filter out `pendingSpending` indices
3. `xntSelectInputs()` to select UTXOs
4. Build, prove, submit transaction
5. Track `commitmentHex` for confirmation

---

## Storage Suggestion

For exchanges handling large volumes, use LevelDB or SQL database to persist UTXO scan results and spent status instead of re-scanning the full chain on every request. Track last scanned block height and only scan new blocks incrementally.
