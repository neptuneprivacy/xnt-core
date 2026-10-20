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
  xntFetchUtxosWithSkipped,
  xntDecryptIndexedUtxoForNetwork,
  xntLegacyDctidhCutoff,
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
key.receiverPreimageHex();  // receiver preimage hex (for commitments and membership proofs)
key.lockScriptHashHex();    // hash of the lock script this key can satisfy
key.toAddress();            // returns XntAddress
key.isDCTIDH();             // true for dCTIDH keys
key.isGeneration();         // true for Generation keys
key.isLegacy();             // true for legacy-format dCTIDH keys, see Migration
```

> **Spending secrets:** for dCTIDH keys `receiverPreimageHex()` is also the
> unlock preimage of the key's lock script: anyone who has it can spend the
> key's UTXOs. The same holds for the witness of a built transaction
> (`builtTx.witnessBytes()`, `builtTx.toBytes()`), which carries the unlock data
> of its inputs. Keep both in the process that holds the seed: do not log them,
> send them to a server or store them unencrypted. The helpers that take the
> preimage as a loose argument (`xntComputeCommitment`,
> `xntComputeAbsoluteIndexSetHash`, `xntGetMembershipProofs`) use it locally and
> do not send it to the node, so a component that calls them for a dCTIDH key
> holds spending authority for that key.

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
    const { utxos, skipped } =
      xntFetchUtxosWithSkipped(client, ridHashHex, from, Math.min(from + 999, height));
    if (skipped > 0) console.warn(`skipped ${skipped} malformed indexer entries`);
    for (const u of utxos) {
      try {
        decrypted.push(xntDecryptIndexedUtxoForNetwork(
          key, u.ciphertext, u.blockHeight, u.blockDigestHex, XntNetwork.Main));
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

Malformed indexer entries (oversized ciphertext, values that are not field
elements, no block height) are skipped instead of failing the range;
`xntFetchUtxosWithSkipped` reports how many, `xntFetchUtxos` only returns the
valid entries.

`xntDecryptIndexedUtxoForNetwork` applies the legacy cutoff of the given network
(see [Migration](#migration-legacy-format-dctidh-addresses-v03)).
`xntDecryptIndexedUtxo` applies the main-net cutoff whatever the network.

### Decrypted UTXO Properties

```typescript
decrypted.amount              // bigint (in NAU)
decrypted.blockHeight         // number
decrypted.senderRandomnessHex // string
decrypted.paymentId           // number (0 for base address)
decrypted.isLegacy            // true: legacy-format lock, sweep-only (see Migration)
decrypted.lockScriptHashHex   // lock script hash of the UTXO
decrypted.utxo.hashHex()      // UTXO hash
decrypted.utxo.canSpendAt(ts) // boolean
```

### Pending UTXO Properties

```typescript
pending.amount              // bigint
pending.utxo.hashHex()      // string
pending.senderRandomnessHex // string
pending.paymentId           // number
pending.isLegacy            // true: legacy-format lock, sweep-only
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

// Get mutator set, and the height of its tip: submit only while that is still
// the tip, see Avoiding Stale Proof Collections
const mutatorSet = xntGetMutatorSet(client);
const buildTip = mutatorSet.tipHeight();

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

`build()` throws for:

- more than 200 inputs: nodes relay ProofCollection-backed transactions only up
  to that many inputs (`xntSelectInputs` never selects more);
- a fee below 0.0005 XNT per input, including a zero fee, the default
  `--min-relay-pctx-fee-per-input` of the node. Call `builder.setAllowLowFee(true)`
  only for a node configured to accept lower fees;
- a recipient that cannot receive a UTXO notification (legacy-format dCTIDH
  address, invalid dCTIDH public key).

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
// Proves for the block after the tip whose mutator set the transaction was
// built on (xntGetMutatorSet records that tip's height).
const provenTx = builtTx.prove();
provenTx.hasProofCollection(); // boolean

// Cold signing, or a mutator set restored with XntMutatorSet.fromBytes (which
// has no tip height): pass the height of the tip the mutator set belongs to.
const provenForTip = builtTx.proveForTip(tipHeight);
```

`prove()` throws if the tip height is unknown; give it with
`mutatorSet.withTipHeight(tipHeight)` before building, or use
`proveForTip(tipHeight)`. See [Before the Hard Fork at Block 95,000](#before-the-hard-fork-at-block-95000)
for what changes around the fork.

### Submit Transaction

`submit()` returns the node's `success` field. `true` only means the
transaction passed the node's validity and confirmability checks and was queued
for its mempool: the node can still drop it, for example when the fee is below
its relay minimum or the mempool is full. Confirm a withdrawal by finding the
transaction in the mempool or its outputs on chain, not by the return value.
`false` means the node did not queue it. When the node rejects a transaction it
does so via a JSON-RPC error whose `data` carries the reason (e.g.
`{"SubmitTransaction":"NotConfirmable"}`), surfaced in the thrown message;
`submit()` also throws on RPC/transport errors.

```typescript
// Submit only while the tip the transaction was built on (buildTip, the
// tipHeight() of the mutator set passed to build()) is still the tip, see
// Avoiding Stale Proof Collections. Confirmability mirrors the node's submit
// gate; check against the current tip BEFORE submit.
const current = xntGetMutatorSet(client);
if (current.tipHeight() !== buildTip || !provenTx.isConfirmable(current)) {
  // stale — re-prove (see below)
}

try {
  const success = provenTx.submit(client);
  console.log(`submitted: ${success}`); // true = queued, confirm on chain
} catch (e) {
  console.log(`submit error: ${e}`);    // e.g. ... (data: {"SubmitTransaction":"NotConfirmable"})
}
```

### Re-proving on Staleness

Proving takes several minutes. While you prove, the chain can advance (a new
block lands, or one of your inputs gets spent), which makes the proof's mutator
set snapshot **stale** — the node then rejects it with `NotConfirmable`.

A transaction proof is only valid against the tip it was built on, so the fix is
to **rebuild from a fresh sync and re-prove**. Wrap build → prove → submit in a
retry loop and re-prove whenever the result is stale:

```typescript
const MAX_ATTEMPTS = 5;

const synced = (provenTx: XntTransaction, buildTip: number | null) => {
  const current = xntGetMutatorSet(client);
  return current.tipHeight() === buildTip && provenTx.isConfirmable(current);
};

for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
  // Rebuild from a CURRENT sync each attempt (fresh UTXOs, proofs, mutator set)
  const mutatorSet = xntGetMutatorSet(client);
  const buildTip = mutatorSet.tipHeight(); // the tip the transaction is built on
  const builtTx = buildTransaction(client, key, mutatorSet, recipientBech32, sendAmount, fee);
  const provenTx = builtTx.prove();

  // Pre-flight: did the chain advance during proving?
  if (!synced(provenTx, buildTip)) {
    console.log(`attempt ${attempt}: stale, re-proving...`);
    continue; // re-prove against the new tip
  }

  try {
    const success = provenTx.submit(client);
    console.log(`submitted: ${success}`);
    break; // now watch its inputs, see Avoiding Stale Proof Collections
  } catch (e) {
    // A block landing mid-submit is also staleness (retryable); anything else
    // is a real rejection (stop).
    if (!synced(provenTx, buildTip)) {
      console.log(`attempt ${attempt}: went stale on submit, re-proving...`);
      continue;
    }
    throw e; // genuine rejection — do not retry
  }
}
```

> **Caveat:** each retry re-proves from scratch (minutes). If blocks arrive
> faster than your prove time, every attempt goes stale and the loop exhausts
> `MAX_ATTEMPTS`. Provision enough CPU/RAM that prove time stays well under the
> block interval.

The bundled example (`examples/xnt-sdk-test.ts`, `tx` command) implements this
loop; cap the attempts via `XNT_TX_MAX_ATTEMPTS` (default `5`).

### Avoiding Stale Proof Collections

Before the hard fork at block 95,000, the nodes that upgrade a proof collection
to a single proof, which is how it gets mined, take only one built on the
mutator set of their own tip: they cannot update someone else's proof
collection to a new block. A proof collection built on tip `h` and submitted
after block `h + 1` is often still confirmable, as its removal records are
still valid, so nodes accept it into their mempools; but none upgrades or mines
it, and nodes drop it with the next block. `isConfirmable` alone does not tell.

1. Remember the height of the tip the transaction is built on: the
   `tipHeight()` of the mutator set passed to `build()` (Rust
   `built.tip_height()`, C `xnt_mutator_set_tip_height`), or `plan.tipHeight()`
   of a migration plan (Rust `plan.tip_height`).
2. After proving, right before `submit()`, fetch the current mutator set
   (`xntGetMutatorSet`, which records the height of its tip) and submit only if
   its tip height equals the build tip and the transaction is confirmable
   against it. Otherwise do not submit: build again from a fresh sync, a
   bounded number of times.
3. After `submit()`, watch the inputs by their absolute index set hashes and
   classify each poll, polling again after RPC errors:
   - *confirmed*: all inputs spent on chain at one height (`xntCheckSpent`);
   - *pending*: an input is spent by a mempool transaction
     (`xntMempoolSpending`), or no block arrived since the build tip;
   - *dropped*: the tip is past the build tip, and the inputs are neither spent
     on chain nor by a mempool transaction: build again and resend, a bounded
     number of times. For a payment, spend the same inputs again, so that the
     dropped transaction and the resent one cannot both be mined;
   - *conflicted*: some inputs are spent on chain otherwise: stop and look into
     it.

   Read the mempool before the spent status, so that a transaction mined
   between the two calls is seen as confirmed, not as dropped. The examples
   take a transaction for dropped only on two polls in a row.

`examples/xnt-sdk-test.ts` (`tx`), `examples/xnt-sdk-test.rs` (`tx`,
`tx-dctidh`), `examples/migrate.ts` and `examples/migrate.rs` implement this, as
does `migrateLegacyFunds` in `src/ts/helpers.ts` (used by
`examples/migrate-legacy.ts` and the `migrate` command of
`examples/xnt-sdk-test.ts`): its report counts the dropped transactions in
`dropped` and gives the last state of each input in `inputs[].status`.

### Before the Hard Fork at Block 95,000

Main net follows the `UpgradeVMv7` consensus rule set until block 95,000, and
`UpgradeVMv8` from then on. A transaction is proven for the rule set of the
block that follows the tip it was built on:

- `prove()` takes that tip from the mutator set: `xntGetMutatorSet(client)`
  (Rust `get_mutator_set`, C `xnt_sync_get_mutator_set`) records the height of
  the tip it belongs to. Up to tip 94,998 the result is a v7 proof collection,
  which the nodes of the previous release relay, upgrade and mine; from tip
  94,999 on, a v8 one. Releases of the SDK before this one always made a v8
  proof, which main-net nodes refuse before block 95,000.
- `proveForTip(tipHeight)` (Rust `prove_for_tip`, C
  `xnt_built_transaction_prove_for_tip`) does the same for a given tip height:
  for cold signing, or for a mutator set restored from bytes, which carries no
  height (`XntMutatorSet.tipHeight()` is `null`; set it with `withTipHeight`).
  `prove()` throws rather than guessing the era.

Before the fork, the nodes that upgrade and mine transactions run the previous
release, and take a v7 proof collection only on their terms. Proving fails if a
transaction does not meet them:

- a fee of at least 0.017 XNT, and at least 0.0005 XNT per input;
- at most 10 inputs, 11 if no input or output carries a time lock;
- outputs with native currency and time locks only.

No new transaction is made within 10 blocks of the fork: from tip 94,990 to
94,998, proving fails, since the transaction might not be mined before block
95,000; build and prove again from tip 94,999 on, for v8. A v7 transaction that
is not mined by block 95,000 can no longer be mined; its inputs are free to be
spent again.

A proof collection is valid only against the mutator set it was built on, and
nodes take it only if it is synced to their tip: submit right after proving,
only while the tip it was built on is still the tip, and rebuild and prove
again after every block until it is mined (see
[Avoiding Stale Proof Collections](#avoiding-stale-proof-collections)).

Nodes of this release answer a transaction made for the other side of the fork
with the JSON-RPC error data `{"SubmitTransaction":"OtherEra"}` (prove again for
the current tip), and a v7 proof collection that does not meet the terms above
with `{"SubmitTransaction":"BelowLegacyEraTerms"}`.

The indexer serves at most 10,000 blocks per `archival_getUtxosByReceiver`
request and answers longer ranges with `{"BlockRangeExceedsLimit":10000}`. The
SDK's UTXO fetch (`xntFetchUtxos`, `xntFetchUtxosWithSkipped`, Rust
`fetch_utxos_with_skipped` and `collect_spendable_inputs`, C
`xnt_sync_fetch_utxos[_with_skipped]`) splits longer ranges into requests of
that size and merges the results.

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
2. Scan new blocks: `xntFetchUtxosWithSkipped(client, receiverIdHashHex, fromHeight, toHeight)`
   and decrypt with `xntDecryptIndexedUtxoForNetwork`
3. Match `paymentId` to user
4. Wait for confirmations
5. Never credit a deposit with `isLegacy` set, see [Crediting Deposits](#crediting-deposits)

### Withdrawal

1. `syncWallet()` to get available UTXOs
2. Filter out `pendingSpending` indices
3. `xntSelectInputs()` to select UTXOs
4. Build, prove, submit transaction — re-prove on staleness, and resend when
   dropped (see [Re-proving on Staleness](#re-proving-on-staleness) and
   [Avoiding Stale Proof Collections](#avoiding-stale-proof-collections))
5. Track `commitmentHex` for confirmation: a successful `submit()` only means the
   node queued the transaction

---

## Migration: Legacy-Format dCTIDH Addresses (v0.3)

dCTIDH addresses created by releases before v0.3 use a legacy lock format. v0.3
refuses such addresses as recipients (decoding fails), and the node and the SDK
recognize UTXOs at legacy-format locks only if they were confirmed in a block
below the legacy cutoff height:

```typescript
xntLegacyDctidhCutoff(XntNetwork.Main);    // UpgradeVMv8 activation height
xntLegacyDctidhCutoff(XntNetwork.RegTest); // null: no cutoff on test networks
```

UTXOs at legacy-format locks are **sweep-only**: move them to a current-format
address and never count them towards the available balance.

### Before Upgrading

Moving the funds with the old release is no longer needed: the v0.3 SDK moves
them, before and after the hard fork at block 95,000, see
[Migrating in One Call](#migrating-in-one-call). Funds at legacy-format locks
are recognized only if they were confirmed below block 95,000; move them soon.

After upgrading, create new dCTIDH deposit addresses with the v0.3 SDK and
replace every legacy-format address you have handed out.

### Migrating in One Call

`xntBuildMigration` (Rust `build_migration`, C `xnt_build_migration`) scans the
legacy keys of the given indices and builds the transactions that move every
legacy UTXO that can be spent now to one current-format address: at most 10
inputs per transaction, the largest first, each paying the fee the node uses for
its own migration (0.1 XNT), with one output and no change. Nothing is proven or
submitted. The scans and the mutator set the transactions are built on belong to
the same tip.

A proof collection is valid only for the mutator set it was built on: prove,
check and submit each transaction right away, one after the other, and once the
submitted ones are mined, build the remaining ones again.

```typescript
const destination = wallet.derivedCTIDHKey(0).toAddress().toBech32(XntNetwork.Main);

for (;;) {
  const plan = xntBuildMigration(client, wallet, [0, 1, 2], destination, XntNetwork.Main);
  const transactions = plan.takeTransactions();
  if (transactions.length === 0) break; // nothing (left) to move
  console.log(`moving ${plan.total()} nau for ${plan.fees()} nau in fees`);

  const watched: string[] = [];
  for (let i = 0; i < transactions.length; i++) {
    const provenTx = transactions[i].prove(); // the era of the block after plan.tipHeight()
    const current = xntGetMutatorSet(client);
    if (current.tipHeight() !== plan.tipHeight() || !provenTx.isConfirmable(current)) break; // a block arrived: build again
    provenTx.submit(client);
    watched.push(...plan.inputHashes(i));
  }

  // Wait until the submitted transactions are mined (their inputs are spent on
  // chain) or dropped, see Avoiding Stale Proof Collections; then build again.
  await waitUntilMinedOrDropped(client, watched, plan.tipHeight());
}
```

`xntBuildMigrationWith` takes the fee per transaction, the most inputs per
transaction and the heights to scan. The plan also reports inputs left out:
`dustInputs()` (batches holding no more than their fee), `timeLocked()` (time
lock not released yet) and `skipped()` (indexer entries the scans could not
use). `examples/migrate.ts` and `examples/migrate.rs` implement the loop above.

`migrateLegacyFunds` in `src/ts/helpers.ts` runs the whole loop, by default as
a dry run that only builds and reports the transactions; pass `dryRun: false`
to prove and submit them:

```typescript
const report = await migrateLegacyFunds(client, wallet, { indices: [0, 1, 2] });                 // dry run
const final = await migrateLegacyFunds(client, wallet, { indices: [0, 1, 2], dryRun: false }); // submit
```

The examples take the parameter `dry_run=yes|no`, default `yes`:

```bash
npx ts-node examples/migrate-legacy.ts                  # dry run, report per payment id
npx ts-node examples/migrate-legacy.ts dry_run=no       # prove and submit
npx ts-node examples/migrate.ts dry_run=no
cargo run --release -p xnt-sdk --example migrate -- dry_run=no
npx ts-node examples/xnt-sdk-test.ts migrate dry_run=no
```

### Reconciling Payment IDs

All payment ids (subaddresses) of a base address share its key and lock, and a
migration transaction merges the UTXOs of many payment ids into one output: the
output does not tell whose deposits it holds. The payment id of each input comes
from its decrypted notification, so the plan reports it per input, with the
legacy key index it was found with:

```typescript
const plan = xntBuildMigration(client, wallet, [0, 1], destination, XntNetwork.Main);

// Per transaction and input: keyIndex, paymentId (0 for the base address),
// amount (nau, before fees), blockHeight, aoclIndex, absoluteIndexSetHashHex.
for (let i = 0; i < plan.numTransactions(); i++) {
  for (const input of plan.inputs(i)) record(i, input);
}

// Summed per legacy key index and payment id, sorted by both.
for (const { keyIndex, paymentId, amount } of plan.totalsByPaymentId()) {
  console.log(`key ${keyIndex}, payment id ${paymentId}: ${amount} nau`);
}

// Inputs left out, with the same details.
plan.dustInputInfo();   // batches holding no more than their fee
plan.timeLockedInfo();  // time lock not released yet
```

`migrateLegacyFunds` reports the same: `report.inputs` lists every input of the
transactions it built, with `round`, `txIndex`, `submitted` and `status`
(`"confirmed"`, `"dropped"`, ...), and `report.byPaymentId` sums them as
`{ keyIndex, paymentId, amount, inputs }`: in a dry run over the planned inputs,
otherwise over the inputs of the submitted transactions that were neither
dropped nor conflicted. `examples/migrate-legacy.ts` prints it as a table.

In Rust the plan has `swept_inputs`, `dust_inputs`, `time_locked_inputs`
(`MigrationInput`) and `totals_by_payment_id()`; in C,
`xnt_migration_input_info`, `xnt_migration_dust_input_info` and
`xnt_migration_time_locked_info` fill an `XntMigrationInputInfo`.

1. Before submitting, record the amount per payment id of each transaction
   (`inputs(i)`, or the report's `inputs`). Amounts are before fees: the fee is
   taken from the merged output, so decide how to share it.
2. Keep these deposits pending, not available: legacy-format deposits are not
   final balance until the transaction moving them is confirmed, i.e. its
   inputs (`absoluteIndexSetHashHex`) are spent on chain (`xntCheckSpent`).
3. Then credit the recorded amounts per payment id. The merged output is a
   deposit to the destination address, not of any user: do not credit it again.

### Finding Legacy UTXOs

The legacy key of an index is the key the pre-v0.3 release derived for that
index. It has its own secret key and receiver identifier, different from those
of the current-format key of the same index, so query the indexer once per key
and decrypt each result with the key it was queried for.

```typescript
const key = wallet.derivedCTIDHKey(i);             // current format
const legacyKey = wallet.deriveLegacydCTIDHKey(i); // legacy format, same index
const network = XntNetwork.Main;

for (const k of [key, legacyKey]) {
  const { utxos } = xntFetchUtxosWithSkipped(client, k.receiverIdHashHex(), from, to);
  for (const u of utxos) {
    try {
      const d = xntDecryptIndexedUtxoForNetwork(
        k, u.ciphertext, u.blockHeight, u.blockDigestHex, network);
      if (d.isLegacy) sweepQueue.push(d); else credit(d);
    } catch { /* not decryptable, or a legacy UTXO at or above the cutoff */ }
  }
}
```

Derive legacy keys only for the indices you used before the upgrade; indices
first used with v0.3 have no legacy funds. `legacyKey.toAddress()` throws: a
legacy key has no receiving address. Pending incoming funds of a legacy key
(`xntMempoolIncoming`) are not reported once the next block is at or above the
main-net cutoff.

### Sweeping by Hand

Instead of `xntBuildMigration`, spend the legacy UTXOs with the legacy key and
send them to a current-format address of your wallet (Generation, or a dCTIDH
address from the v0.3 SDK).
Membership proofs must be built with the legacy key's preimage, which
`buildMixedProofs` / `addMultiTypeInputs` in `src/ts/helpers.ts` do for inputs
of kind `"legacy-dctidh"`:

```typescript
const selected = sweepQueue.map(d => ({ kind: "legacy-dctidh", u: { decrypted: d, aoclIndex: aocl(d) } }));
const proofs = buildMixedProofs(client, genKey, key, selected, legacyKey);
addMultiTypeInputs(builder, selected, genKey, key,
  proofs.genProofBuffers, proofs.dCTIDHProofBuffers,
  proofs.genSelected, proofs.dCTIDHSelected,
  legacyKey, proofs.legacyProofBuffers, proofs.legacySelected);
builder.addOutput(genAddr.toReceivingAddress(), total - fee, xntRandomSenderRandomness());
builder.setFee(fee);
```

Before the hard fork at block 95,000, a transaction may have at most 10 inputs
(11 if none carries a time lock) and must pay at least 0.017 XNT, 0.1 XNT by
default, see [Before the Hard Fork at Block 95,000](#before-the-hard-fork-at-block-95000);
after it, the usual limits apply: at most 200 inputs and at least 0.0005 XNT fee
per input. Sweep large numbers of UTXOs in batches. A node can also do this for
its own wallet, see `--migrate-dctidh`.

### Crediting Deposits

- Never credit a deposit at a legacy-format lock (`isLegacy`) as final or
  available. Show it as pending until the sweep that moves it to a
  current-format address has confirmed, and credit the swept output.
- Do not count legacy UTXOs in balances, withdrawal input selection or proofs of
  reserve; keep them in a separate sweep queue.
- Watch the `skipped` count of `xntFetchUtxosWithSkipped`: a non-zero count
  means the indexer returned entries the SDK could not use.

---

## Storage Suggestion

For exchanges handling large volumes, use LevelDB or SQL database to persist UTXO scan results and spent status instead of re-scanning the full chain on every request. Track last scanned block height and only scan new blocks incrementally.
