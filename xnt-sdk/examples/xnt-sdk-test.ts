/**
 * XNT-SDK TypeScript Test
 *
 * Usage: npx ts-node examples/xnt-sdk-test.ts [command] [arg]
 * Commands: version, seed, address [payment-id], shortaddress [payment-id], rpc, sync, utils, tx <recipient> <amount> <fee>, migrate [dry_run=yes|no]
 */

import * as fs from "fs";
import * as path from "path";
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
import { migrateLegacyFunds } from "../src/ts/helpers";

// ── Types ──────────────────────────────────────────────────────────────────

interface UnspentUtxo {
  decrypted: XntDecryptedUtxo;
  aoclIndex: number;
  absHash: string;
}

interface SyncResult {
  unspent: UnspentUtxo[];
  pendingSpending: number[];
  pendingIncoming: XntPendingUtxo[];
}

// Outcome of a single tx build→prove→submit attempt. "stale" is retryable
// (re-prove); everything else is terminal.
type AttemptResult =
  | { status: "submitted"; success: boolean }
  | { status: "stale"; where: "preflight" | "submit" }
  | { status: "empty" }
  | { status: "insufficient"; need: bigint; have: bigint }
  | { status: "rejected"; error: string };

// ── Logger ─────────────────────────────────────────────────────────────────

class Logger {
  skipCount = 0;
  failCount = 0;

  private write(level: string, msg: string, data?: Record<string, unknown>) {
    const entry: Record<string, unknown> = { ts: new Date().toISOString(), level, msg };
    if (data !== undefined) entry.data = data;
    console.log(JSON.stringify(entry));
  }

  info(msg: string, data?: Record<string, unknown>) { this.write("info", msg, data); }
  ok(msg: string, data?: Record<string, unknown>) { this.write("ok", msg, data); }

  fail(msg: string, data?: Record<string, unknown>): false {
    this.failCount++;
    this.write("fail", msg, data);
    return false;
  }

  skip(msg: string, data?: Record<string, unknown>): false {
    this.skipCount++;
    this.write("skip", msg, data);
    return false;
  }
}

// ── Prover path ──────────────────────────────────────────────────────────────

// The NAPI prover spawns an external `triton-vm-prover` binary. When run via
// node it would look next to the node executable, so point it at the repo build.
// Respects TRITON_VM_PROVER_PATH if already set; otherwise picks the repo's
// release build (falling back to debug).
function ensureProverPath(log: Logger): void {
  if (process.env.TRITON_VM_PROVER_PATH) return;
  const candidates = [
    path.resolve(__dirname, "../../target/release/triton-vm-prover"),
    path.resolve(__dirname, "../../target/debug/triton-vm-prover"),
  ];
  const found = candidates.find(p => fs.existsSync(p));
  if (found) {
    process.env.TRITON_VM_PROVER_PATH = found;
    log.info("prover", { path: found });
  } else {
    log.info("prover not found in target/, relying on PATH/TRITON_VM_PROVER_PATH", {
      looked: candidates,
    });
  }
}

// ── AmountUtil ─────────────────────────────────────────────────────────────

class AmountUtil {
  private static readonly FACTOR = 4n * 10n ** 30n;

  static toNau(xnt: number): bigint {
    return BigInt(Math.round(xnt * 1e8)) * this.FACTOR / 100000000n;
  }

  static format(nau: bigint): string {
    const abs = nau < 0n ? -nau : nau;
    const sign = nau < 0n ? "-" : "";
    return `${sign}${abs / this.FACTOR}.${((abs % this.FACTOR) * 100000000n / this.FACTOR).toString().padStart(8, "0")} XNT`;
  }
}

// ── WalletHelper ───────────────────────────────────────────────────────────

class WalletHelper {
  constructor(private log: Logger) {}

  connectRpc(): XntRpcClient | null {
    const url = process.env.XNT_RPC_URL;
    if (!url) { this.log.skip("XNT_RPC_URL not set"); return null; }
    try {
      const client = new XntRpcClient(url);
      client.ping();
      return client;
    } catch {
      this.log.skip("no server");
      return null;
    }
  }

  loadTestWallet(index = 0) {
    const mnemonic = process.env.XNT_TEST_MNEMONIC;
    if (!mnemonic) throw new Error("XNT_TEST_MNEMONIC required");
    const wallet = new XntWalletEntropy(mnemonic);
    const genKey = wallet.deriveKey(index);
    const genAddr = genKey.toAddress();
    const key = wallet.derivedCTIDHKey(index);
    const addr = key.toAddress();
    // The key the pre-v0.3 release derived for this index; its UTXOs sit at
    // legacy-format locks and are only moved, never counted as balance.
    const legacyKey = wallet.deriveLegacydCTIDHKey(index);
    return { wallet, genKey, genAddr, key, addr, legacyKey };
  }

  sync(client: XntRpcClient, key: ReturnType<XntWalletEntropy["derivedCTIDHKey"]>): SyncResult | null {
    const ridHashHex = key.receiverIdHashHex();
    const receiverPreimageHex = key.receiverPreimageHex();
    const height = client.chainHeight();
    if (height < 0) return null;

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

    const commitments = decrypted.map(u =>
      xntComputeCommitment(u.utxo.hashHex(), u.senderRandomnessHex, receiverPreimageHex)
    );
    const aoclIndices = xntGetAoclIndices(client, commitments);

    const validUtxos: { idx: number; aocl: number; absHash: string }[] = [];
    aoclIndices.forEach((aocl, i) => {
      if (aocl >= 0) {
        const u = decrypted[i];
        const absHash = xntComputeAbsoluteIndexSetHash(u.utxo.hashHex(), u.senderRandomnessHex, receiverPreimageHex, aocl);
        validUtxos.push({ idx: i, aocl, absHash });
      }
    });

    const spentStatus = xntCheckSpent(client, validUtxos.map(v => v.absHash));
    const now = BigInt(Date.now());

    const unspent = validUtxos
      .filter((_, j) => spentStatus[j] < 0)
      .map(v => ({ decrypted: decrypted[v.idx], aoclIndex: v.aocl, absHash: v.absHash }))
      .filter(u => u.decrypted.utxo.canSpendAt(now));

    const absHashes = unspent.map(u => u.absHash);
    let pendingSpending: number[] = [];
    try { pendingSpending = xntMempoolSpending(client, absHashes); } catch { /* mempool check failed */ }

    let pendingIncoming: XntPendingUtxo[] = [];
    try { pendingIncoming = xntMempoolIncoming(client, key); } catch { /* mempool check failed */ }

    return { unspent, pendingSpending, pendingIncoming };
  }

  availableUtxos(result: SyncResult): UnspentUtxo[] {
    return result.unspent.filter((_, i) => !result.pendingSpending.includes(i));
  }
}

// ── TestRunner ─────────────────────────────────────────────────────────────

class TestRunner {
  private log = new Logger();
  private wallet = new WalletHelper(this.log);
  private tests: Map<string, (args: string[]) => boolean | Promise<boolean>>;

  constructor() {
    this.tests = new Map<string, (args: string[]) => boolean | Promise<boolean>>([
      ["version", (_) => this.testVersion()],
      ["seed", (_) => this.testSeed()],
      ["address", (a) => this.testAddress(a)],
      ["shortaddress", (a) => this.testShortAddress(a)],
      ["utils", (_) => this.testUtils()],
      ["rpc", (_) => this.testRpc()],
      ["sync", (_) => this.testSync()],
      ["tx", (a) => this.testTx(a)],
      ["migrate", (a) => this.testMigrate(a)],
    ]);
  }

  run(command: string, args: string[]) {
    if (command === "help") {
      console.log("Usage: npx ts-node examples/xnt-sdk-test.ts [command] [arg]\n");
      console.log("Commands:");
      const argHints: Record<string, string> = {
        address: "[payment-id]",
        shortaddress: "[payment-id]",
        tx: "<recipient> <amount> <fee>",
        migrate: "[dry_run=yes|no]",
      };
      for (const name of this.tests.keys()) {
        const hint = argHints[name];
        console.log(`  ${name}${hint ? " " + hint : ""}`);
      }
      console.log("\nExamples:");
      console.log("  npx ts-node examples/xnt-sdk-test.ts version");
      console.log("  npx ts-node examples/xnt-sdk-test.ts address 111");
      return;
    }

    const fn = this.tests.get(command);
    if (!fn) {
      this.log.fail(`unknown command: ${command}`);
      process.exit(1);
    }
    fn(args);
  }

  // ── Tests ────────────────────────────────────────────────────────────────

  private testVersion(): boolean {
    this.log.ok("version", { version: xntVersion() });
    return true;
  }

  private testSeed(): boolean {
    const wallet = XntWalletEntropy.generate();
    const mnemonic = wallet.toMnemonic();
    this.log.ok("mnemonic generated", { mnemonic });

    const restored = new XntWalletEntropy(mnemonic);
    if (restored.toMnemonic() !== mnemonic) return this.log.fail("mnemonic roundtrip");

    const key = wallet.derivedCTIDHKey(0);
    this.log.ok("dCTIDH key derived", { receiverId: key.receiverIdHex() });
    return true;
  }

  private testAddress(args: string[]): boolean {
    const paymentId = args[0] ? parseInt(args[0], 10) : undefined;
    const { genAddr } = this.wallet.loadTestWallet();

    const bech32 = genAddr.toBech32(XntNetwork.Main);
    this.log.ok("Generation address", { bech32 });
    const decoded = XntAddress.fromBech32(bech32, XntNetwork.Main);
    if (decoded.toBech32(XntNetwork.Main) !== bech32) return this.log.fail("Generation roundtrip");

    if (paymentId !== undefined) {
      const sub = genAddr.withPaymentId(paymentId);
      this.log.ok("Generation subaddress", { pid: paymentId, bech32: sub.toBech32(XntNetwork.Main) });
    }

    return true;
  }

  private testShortAddress(args: string[]): boolean {
    const paymentId = args[0] ? parseInt(args[0], 10) : undefined;
    const { addr } = this.wallet.loadTestWallet();

    const bech32 = addr.toBech32(XntNetwork.Main);
    this.log.ok("dCTIDH address", { bech32 });
    const decoded = XntAddress.fromBech32(bech32, XntNetwork.Main);
    if (decoded.toBech32(XntNetwork.Main) !== bech32) return this.log.fail("dCTIDH roundtrip");

    if (paymentId !== undefined) {
      const sub = addr.dCTIDHSubaddress(paymentId);
      this.log.ok("dCTIDH subaddress", { pid: paymentId, bech32: sub.toBech32(XntNetwork.Main) });
    }

    return true;
  }

  private testUtils(): boolean {
    this.log.ok("timestamp", { value: xntTimestampNow() });
    this.log.ok("random sender_randomness", { hex: xntRandomSenderRandomness().slice(0, 16) });
    return true;
  }

  private testRpc(): boolean {
    const client = this.wallet.connectRpc();
    if (!client) return false;
    this.log.ok("ping");
    this.log.ok("height", { height: client.chainHeight() });
    return true;
  }

  private testSync(): boolean {
    const client = this.wallet.connectRpc();
    if (!client) return false;

    const { genKey, genAddr, key, addr, legacyKey } = this.wallet.loadTestWallet();
    // Funds can land on either the Generation or the dCTIDH address; scan both.
    const accounts = [
      { kind: "generation", key: genKey, addr: genAddr },
      { kind: "dctidh", key, addr },
    ];

    let total = 0n;
    let incomingTotal = 0n;
    let spendingTotal = 0n;
    let unspentCount = 0;

    for (const acct of accounts) {
      const result = this.wallet.sync(client, acct.key);
      if (!result) return this.log.skip("sync failed");

      unspentCount += result.unspent.length;
      this.log.ok("synced", { kind: acct.kind, unspent: result.unspent.length });

      const receiverPreimage = acct.key.receiverPreimageHex();
      const privacyDigest = acct.addr.privacyDigestHex();

      for (let i = 0; i < result.unspent.length; i++) {
        const u = result.unspent[i];
        const d = u.decrypted;
        total += d.amount;
        const pending = result.pendingSpending.includes(i);
        const c = xntComputeCommitment(d.utxo.hashHex(), d.senderRandomnessHex, receiverPreimage);
        this.log.info("utxo", {
          kind: acct.kind,
          aocl: u.aoclIndex, height: d.blockHeight,
          amount: AmountUtil.format(d.amount),
          ...(d.paymentId ? { pid: d.paymentId } : {}),
          ...(pending ? { pendingSpend: true } : {}),
          commitment: c,
        });
      }

      for (const p of result.pendingIncoming) {
        incomingTotal += p.amount;
        const c = xntComputeCommitmentForOutput(p.utxo.hashHex(), p.senderRandomnessHex, privacyDigest);
        this.log.info("pending-incoming", {
          kind: acct.kind,
          amount: AmountUtil.format(p.amount),
          ...(p.paymentId > 0 ? { pid: p.paymentId } : {}),
          commitment: c,
        });
      }

      for (const idx of result.pendingSpending) {
        spendingTotal += result.unspent[idx].decrypted.amount;
      }
    }

    // Funds at legacy-format dCTIDH locks (sent to a pre-v0.3 address) are
    // reported apart: they are only moved, see the migrate command.
    let legacyTotal = 0n;
    const legacy = this.wallet.sync(client, legacyKey);
    for (const u of legacy?.unspent ?? []) {
      legacyTotal += u.decrypted.amount;
      this.log.info("utxo", {
        kind: "legacy-dctidh",
        aocl: u.aoclIndex, height: u.decrypted.blockHeight,
        amount: AmountUtil.format(u.decrypted.amount),
        ...(u.decrypted.paymentId ? { pid: u.decrypted.paymentId } : {}),
        legacy: u.decrypted.isLegacy,
      });
    }

    const available = total - spendingTotal;
    const unconfirmed = available + incomingTotal;
    this.log.ok("balance", {
      unspent: unspentCount,
      confirmed: AmountUtil.format(total),
      ...(incomingTotal > 0n || spendingTotal > 0n ? { unconfirmed: AmountUtil.format(unconfirmed) } : {}),
      ...(legacyTotal > 0n ? { legacyToMigrate: AmountUtil.format(legacyTotal) } : {}),
    });
    return true;
  }

  // Move the funds at legacy-format dCTIDH locks of index 0 to the wallet's
  // current-format dCTIDH address 0. A dry run, which only builds and lists
  // the transactions, unless "dry_run=no".
  private async testMigrate(args: string[]): Promise<boolean> {
    const dryRunArg = args[0] ?? "dry_run=yes";
    if (dryRunArg !== "dry_run=yes" && dryRunArg !== "dry_run=no") {
      return this.log.fail("migrate takes dry_run=yes or dry_run=no", { arg: dryRunArg });
    }
    const dryRun = dryRunArg === "dry_run=yes";
    const client = this.wallet.connectRpc();
    if (!client) return false;
    const { wallet } = this.wallet.loadTestWallet();
    try {
      const report = await migrateLegacyFunds(client, wallet, {
        indices: [0],
        dryRun,
        log: (message) => this.log.info("migrate", { message }),
      });
      this.log.ok("migrate", {
        submitted: report.submitted,
        moved: AmountUtil.format(report.moved),
        fees: AmountUtil.format(report.fees),
        dustInputs: report.dustInputs,
        timeLocked: report.timeLocked,
        remaining: report.remaining,
        // Before fees; over the plan in a dry run, else over the submitted
        // transactions. Record these per payment id before crediting.
        byPaymentId: report.byPaymentId.map(total => ({
          keyIndex: total.keyIndex,
          paymentId: total.paymentId,
          amount: AmountUtil.format(total.amount),
          inputs: total.inputs,
        })),
        ...(dryRun ? { note: "dry run; pass dry_run=no to prove and submit" } : {}),
      });
      return true;
    } catch (e) {
      return this.log.fail("migrate failed", { error: String(e) });
    }
  }

  private testTx(args: string[]): boolean {
    const [recipientBech32, amountStr, feeStr] = args;
    if (!recipientBech32 || !amountStr || !feeStr) {
      return this.log.fail("tx requires: recipient amount fee");
    }

    const client = this.wallet.connectRpc();
    if (!client) return false;

    const fee = AmountUtil.toNau(parseFloat(feeStr));
    const sendAmount = AmountUtil.toNau(parseFloat(amountStr));

    // Proving takes minutes, so the chain can advance and make the proof stale.
    // Auto re-prove: rebuild from a fresh sync + proofs and retry. Override the
    // attempt cap via XNT_TX_MAX_ATTEMPTS (default 5).
    const maxAttempts = Math.max(1, parseInt(process.env.XNT_TX_MAX_ATTEMPTS ?? "5", 10));
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      if (attempt > 1) this.log.info("re-proving (previous attempt went stale)", { attempt, maxAttempts });

      const r = this.attemptTx(client, recipientBech32, sendAmount, fee);
      switch (r.status) {
        case "submitted":
          this.log.ok("submit result", { success: r.success, attempt, note: "accepted + queued by node" });
          return r.success;
        case "empty":
          return this.log.skip("no spendable UTXOs");
        case "insufficient":
          return this.log.fail("insufficient funds", {
            need: AmountUtil.format(r.need),
            have: AmountUtil.format(r.have),
          });
        case "rejected":
          return this.log.fail("submit rejected", { reason: "node rejected — see error", error: r.error });
        case "stale":
          if (attempt === maxAttempts) {
            return this.log.fail("stale after max attempts — chain advancing faster than proving", {
              attempts: maxAttempts,
              where: r.where,
            });
          }
          // loop and re-prove
          break;
      }
    }
    return false;
  }

  // One build→prove→submit attempt. Returns a status the caller uses to decide
  // whether to re-prove (on "stale") or stop.
  private attemptTx(
    client: XntRpcClient,
    recipientBech32: string,
    sendAmount: bigint,
    fee: bigint,
  ): AttemptResult {
    const { genKey, genAddr, key, addr } = this.wallet.loadTestWallet();
    // Spend across both account types; tag each UTXO with its owning key so we
    // add inputs and restore membership proofs with the correct receiver_preimage.
    const accounts = [
      { kind: "generation", key: genKey, addr: genAddr },
      { kind: "dctidh", key, addr },
    ];

    type OwnedUtxo = { u: UnspentUtxo; key: typeof genKey; receiverPreimage: string };
    const available: OwnedUtxo[] = [];
    for (const acct of accounts) {
      const result = this.wallet.sync(client, acct.key);
      if (!result) continue;
      const avail = this.wallet.availableUtxos(result);
      const receiverPreimage = acct.key.receiverPreimageHex();
      for (const u of avail) available.push({ u, key: acct.key, receiverPreimage });
    }
    if (available.length === 0) return { status: "empty" };
    this.log.ok("synced", { available: available.length });

    const totalAmount = sendAmount + fee;
    const amounts = available.map(o => o.u.decrypted.amount);
    const selected = xntSelectInputs(amounts, totalAmount, 10);
    if (selected.length === 0) {
      return { status: "insufficient", need: totalAmount, have: amounts.reduce((s, a) => s + a, 0n) };
    }
    this.log.ok("inputs selected", { count: selected.length, total: AmountUtil.format(totalAmount) });

    const selectedUtxos = selected.map(i => available[i]);

    // Restore membership proofs per receiver_preimage group (one RPC batch per owning key).
    const proofBuffers: Buffer[] = new Array(selectedUtxos.length);
    const groups = new Map<string, number[]>();
    selectedUtxos.forEach((o, i) => {
      const g = groups.get(o.receiverPreimage) ?? [];
      g.push(i);
      groups.set(o.receiverPreimage, g);
    });
    for (const [receiverPreimage, idxs] of groups) {
      const bufs = xntGetMembershipProofs(
        client,
        idxs.map(i => selectedUtxos[i].u.decrypted.utxo.hashHex()),
        idxs.map(i => selectedUtxos[i].u.decrypted.senderRandomnessHex),
        receiverPreimage,
        idxs.map(i => selectedUtxos[i].u.aoclIndex),
      );
      idxs.forEach((origIdx, j) => { proofBuffers[origIdx] = bufs[j]; });
    }
    this.log.ok("membership proofs", { count: proofBuffers.length });

    const mutatorSet = xntGetMutatorSet(client);
    const builder = new XntTransactionBuilder();

    for (let i = 0; i < selectedUtxos.length; i++) {
      const proof = XntMembershipProof.fromBytes(proofBuffers[i]);
      builder.addInput(selectedUtxos[i].u.decrypted.utxo, selectedUtxos[i].key, proof);
    }

    const recipient = XntAddress.fromBech32(recipientBech32, XntNetwork.Main).toReceivingAddress();
    builder.addOutput(recipient, sendAmount, xntRandomSenderRandomness());
    builder.setFee(fee);
    builder.setChange(genAddr, xntRandomSenderRandomness());

    const builtTx = builder.build(mutatorSet, xntTimestampNow(), XntNetwork.Main);

    const inputs = builtTx.inputs();
    const outputs = builtTx.outputs();
    for (const inp of inputs) {
      this.log.info("tx-input", { amount: AmountUtil.format(inp.amount), commitment: inp.commitmentHex });
    }
    for (const out of outputs) {
      this.log.info("tx-output", {
        amount: AmountUtil.format(out.amount),
        ...(out.isChange ? { change: true } : {}),
        ...(out.paymentId ? { pid: out.paymentId } : {}),
        commitment: out.commitmentHex,
      });
    }
    this.log.ok("built", { bytes: builtTx.toBytes().length, fee: AmountUtil.format(fee) });

    this.log.info("proving (this takes several minutes)");
    const start = Date.now();
    let provenTx: ReturnType<typeof builtTx.prove>;
    try {
      // Picks the rule set from the tip the mutator set belongs to; before the
      // UpgradeVMv8 fork it refuses terms that nodes of that era do not relay
      // (fee below 0.017 XNT, more than 10 inputs, within 10 blocks of the fork).
      provenTx = builtTx.prove();
    } catch (e) {
      return { status: "rejected", error: `prove: ${e}` };
    }
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    this.log.ok("proven", { seconds: elapsed, hasProofCollection: provenTx.hasProofCollection() });

    // Confirmable check against the current tip — proving can take minutes, so a
    // block may have landed (or an input got spent) meanwhile, making it stale.
    if (!provenTx.isConfirmable(xntGetMutatorSet(client))) {
      this.log.info("tx not confirmable (stale) — chain advanced while proving");
      return { status: "stale", where: "preflight" };
    }

    // NOTE: the node rejects a tx via a JSON-RPC *error* (carrying the reason in
    // error.data), not via success:false — so submit() returns true on accept and
    // throws on rejection. We diagnose the throw below.
    this.log.info("submitting");
    try {
      const success = provenTx.submit(client);
      return { status: "submitted", success };
    } catch (e) {
      // Re-check against the current tip: a block landing mid-submit is stale
      // (retryable); anything else is a real rejection (stop).
      if (!provenTx.isConfirmable(xntGetMutatorSet(client))) {
        this.log.info("submit went stale — chain advanced", { error: String(e) });
        return { status: "stale", where: "submit" };
      }
      return { status: "rejected", error: String(e) };
    }
  }

}

// ── Entry Point ────────────────────────────────────────────────────────────

const command = process.argv[2] || "help";
// Resolve the prover binary up-front for the commands that prove.
if (command === "tx" || command === "migrate") ensureProverPath(new Logger());
const runner = new TestRunner();
runner.run(command, process.argv.slice(3));
