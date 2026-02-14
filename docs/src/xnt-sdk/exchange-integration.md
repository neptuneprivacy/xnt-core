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

## Quick Start with Example CLI

The SDK ships with a ready-to-use CLI tool at `xnt-sdk/examples/xnt-sdk-test.ts`. After building the SDK:

```bash
cd xnt-sdk
npx ts-node examples/xnt-sdk-test.ts
```

This prints all available commands:

```
Usage: npx ts-node examples/xnt-sdk-test.ts [command] [arg]

Commands:
  version
  seed
  address [payment-id]
  shortaddress [payment-id]
  utils
  rpc
  sync
  tx <recipient> <amount> <fee>
```

### Try Offline Commands

These work without a running node:

```bash
# Check SDK version
npx ts-node examples/xnt-sdk-test.ts version

# Generate a new wallet seed
npx ts-node examples/xnt-sdk-test.ts seed

# Show Generation address (long)
XNT_TEST_MNEMONIC="your 18 word mnemonic" npx ts-node examples/xnt-sdk-test.ts address

# Show Generation subaddress with payment ID
XNT_TEST_MNEMONIC="your 18 word mnemonic" npx ts-node examples/xnt-sdk-test.ts address 12345

# Show dCTIDH address (short)
XNT_TEST_MNEMONIC="your 18 word mnemonic" npx ts-node examples/xnt-sdk-test.ts shortaddress

# Show dCTIDH subaddress with payment ID
XNT_TEST_MNEMONIC="your 18 word mnemonic" npx ts-node examples/xnt-sdk-test.ts shortaddress 12345
```

### Try Online Commands

These require a running xnt-core node:

```bash
export XNT_TEST_MNEMONIC="your 18 word mnemonic"
export XNT_RPC_URL="http://localhost:9897/"

# Test RPC connection
npx ts-node examples/xnt-sdk-test.ts rpc

# Sync wallet and show balance
npx ts-node examples/xnt-sdk-test.ts sync

# Send transaction (recipient can be any address type)
npx ts-node examples/xnt-sdk-test.ts tx xntctm1... 0.575 0.005
```

### Output Format

All commands output structured JSON, one line per event:

```json
{"ts":"2025-01-01T00:00:00.000Z","level":"ok","msg":"version","data":{"version":"0.5.0"}}
```

Pipe through `jq` for readability:

```bash
npx ts-node examples/xnt-sdk-test.ts version | jq
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

// Derive Generation spending key at index 0 (long address)
const genKey = wallet.deriveKey(0);

// Derive dCTIDH spending key at index 0 (short address)
const key = wallet.derivedCTIDHKey(0);

// Key methods (same for both key types)
key.receiverIdHex();        // receiver ID hex
key.receiverIdHashHex();    // receiver ID hash hex (for UTXO queries)
key.receiverPreimageHex();  // receiver preimage hex (for decryption)
key.toAddress();            // returns XntAddress
key.isDCTIDH();             // true for dCTIDH keys
key.isGeneration();         // true for Generation keys
```

---

## Address

Two address families are supported. Both can receive funds and create subaddresses with payment IDs.

> **Recommendation:** Use **dCTIDH (short address)** for new integrations. dCTIDH addresses are ~130 characters vs ~4000 for Generation, making them far more practical for QR codes, user display, and API payloads.

### Generation Address (Long Address)

```typescript
const genKey = wallet.deriveKey(0);
const genAddr = genKey.toAddress();

// Encode to bech32
const bech32 = genAddr.toBech32(XntNetwork.Main);
// "xntnwm1..."

// Decode from bech32
const decoded = XntAddress.fromBech32(bech32, XntNetwork.Main);

// Subaddress with payment ID
const sub = genAddr.withPaymentId(12345); // returns XntSubAddress
sub.toBech32(XntNetwork.Main);            // "xntnsm1..."
sub.paymentId();                          // 12345
sub.toReceivingAddress();                 // for addOutput()
```

### dCTIDH Address (Short Address)

Recommended for new integrations.

```typescript
const key = wallet.derivedCTIDHKey(0);
const addr = key.toAddress();

// Encode to bech32
const bech32 = addr.toBech32(XntNetwork.Main);
// "xntctm1..."

// Decode from bech32
const decoded = XntAddress.fromBech32(bech32, XntNetwork.Main);

// Subaddress with payment ID
const sub = addr.dCTIDHSubaddress(12345); // returns XntReceivingAddress
sub.toBech32(XntNetwork.Main);            // "xntctam1..."
sub.paymentId();                          // 12345

// Address methods
addr.toReceivingAddress();  // for transaction outputs
addr.privacyDigestHex();    // for pending incoming display
```

> **Note:** `withPaymentId()` returns `XntSubAddress` (Generation), while `dCTIDHSubaddress()` returns `XntReceivingAddress` (dCTIDH). Both work with `builder.addOutput()`.

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

Block scanning and UTXO queries with range filter. Works with both Generation and dCTIDH keys.

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
  key: ReturnType<XntWalletEntropy["derivedCTIDHKey"]>
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
const FACTOR = 4n * 10n ** 30n; // 1 XNT = 4 * 10^30 NAU

function toNau(xnt: number): bigint {
  return BigInt(Math.round(xnt * 1e8)) * FACTOR / 100000000n;
}

function formatAmount(nau: bigint): string {
  const abs = nau < 0n ? -nau : nau;
  const sign = nau < 0n ? "-" : "";
  return `${sign}${abs / FACTOR}.${((abs % FACTOR) * 100000000n / FACTOR).toString().padStart(8, "0")} XNT`;
}
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

// Add output — accepts any address type (Generation or dCTIDH)
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

1. Generate subaddress per user:
   - Generation (long): `genAddr.withPaymentId(userId)`
   - dCTIDH (short): `addr.dCTIDHSubaddress(userId)`
2. Scan new blocks: `xntFetchUtxos(client, receiverIdHashHex, fromHeight, toHeight)`
3. Match `paymentId` to user
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
