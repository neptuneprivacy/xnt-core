/**
 * XNT-SDK TypeScript Test
 *
 * Usage: npx ts-node examples/xnt-sdk-test.ts [command]
 * Commands: version, seed, address, rpc, sync, utils, tx, utxos-pid, full
 */

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
    const key = wallet.derivedCTIDHKey(index);
    const addr = key.toAddress();
    return { wallet, key, addr };
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
  private tests: Map<string, () => boolean>;

  constructor() {
    this.tests = new Map([
      ["version", () => this.testVersion()],
      ["seed", () => this.testSeed()],
      ["address", () => this.testAddress()],
      ["utils", () => this.testUtils()],
      ["rpc", () => this.testRpc()],
      ["sync", () => this.testSync()],
      ["tx", () => this.testTx()],
      ["utxos-pid", () => this.testUtxosPid()],
    ]);
  }

  run(command: string) {
    if (command === "full") {
      this.log.info("XNT-SDK TypeScript Test");
      let pass = 0, fail = 0, skip = 0;

      for (const [name, fn] of this.tests) {
        this.log.info(`test: ${name}`);
        const beforeSkip = this.log.skipCount;
        const result = fn();
        if (result) pass++;
        else if (this.log.skipCount > beforeSkip) skip++;
        else fail++;
      }

      this.log.info("summary", { pass, fail, skip, total: this.tests.size });
      process.exit(fail === 0 ? 0 : 1);
    }

    const fn = this.tests.get(command);
    if (!fn) {
      this.log.fail(`unknown command: ${command}`);
      process.exit(1);
    }
    fn();
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
    this.log.ok("mnemonic roundtrip");

    const key = wallet.derivedCTIDHKey(0);
    this.log.ok("dCTIDH key derived", { receiverId: key.receiverIdHex() });
    return true;
  }

  private testAddress(): boolean {
    const { addr } = this.wallet.loadTestWallet();
    const bech32 = addr.toBech32(XntNetwork.Main);
    this.log.ok("dCTIDH address", { bech32 });

    const decoded = XntAddress.fromBech32(bech32, XntNetwork.Main);
    if (decoded.toBech32(XntNetwork.Main) !== bech32) return this.log.fail("dCTIDH roundtrip");
    this.log.ok("dCTIDH roundtrip");

    const sub = addr.dCTIDHSubaddress(111);
    this.log.ok("dCTIDH subaddress", { pid: 111, bech32: sub.toBech32(XntNetwork.Main) });
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

    const { key, addr } = this.wallet.loadTestWallet();
    const result = this.wallet.sync(client, key);
    if (!result) return this.log.skip("sync failed");

    this.log.ok("synced", { unspent: result.unspent.length });

    let total = 0n;
    const receiverPreimage = key.receiverPreimageHex();
    const privacyDigest = addr.privacyDigestHex();

    for (let i = 0; i < result.unspent.length; i++) {
      const u = result.unspent[i];
      const d = u.decrypted;
      total += d.amount;
      const pending = result.pendingSpending.includes(i);
      const c = xntComputeCommitment(d.utxo.hashHex(), d.senderRandomnessHex, receiverPreimage);
      this.log.info("utxo", {
        aocl: u.aoclIndex, height: d.blockHeight,
        amount: AmountUtil.format(d.amount),
        ...(d.paymentId ? { pid: d.paymentId } : {}),
        ...(pending ? { pendingSpend: true } : {}),
        commitment: c,
      });
    }

    let incomingTotal = 0n;
    for (const p of result.pendingIncoming) {
      incomingTotal += p.amount;
      const c = xntComputeCommitmentForOutput(p.utxo.hashHex(), p.senderRandomnessHex, privacyDigest);
      this.log.info("pending-incoming", {
        amount: AmountUtil.format(p.amount),
        ...(p.paymentId > 0 ? { pid: p.paymentId } : {}),
        commitment: c,
      });
    }

    let spendingTotal = 0n;
    for (const idx of result.pendingSpending) {
      spendingTotal += result.unspent[idx].decrypted.amount;
    }

    const available = total - spendingTotal;
    const unconfirmed = available + incomingTotal;
    this.log.ok("balance", {
      confirmed: AmountUtil.format(total),
      ...(incomingTotal > 0n || spendingTotal > 0n ? { unconfirmed: AmountUtil.format(unconfirmed) } : {}),
    });
    return true;
  }

  private testTx(): boolean {
    const client = this.wallet.connectRpc();
    if (!client) return false;

    const { key, addr } = this.wallet.loadTestWallet();
    const result = this.wallet.sync(client, key);
    if (!result || result.unspent.length === 0) return this.log.skip("no unspent UTXOs");
    this.log.ok("synced", { unspent: result.unspent.length });

    const available = this.wallet.availableUtxos(result);
    if (available.length === 0) return this.log.skip("all UTXOs pending spend");
    if (available.length < result.unspent.length) {
      this.log.info("filtered pending", {
        available: available.length,
        pendingSpend: result.unspent.length - available.length,
      });
    }

    const fee = AmountUtil.toNau(0.005);
    const sendAmount = AmountUtil.toNau(0.575);
    const totalAmount = sendAmount + fee;

    const amounts = available.map(u => u.decrypted.amount);
    const selected = xntSelectInputs(amounts, totalAmount, 10);
    if (selected.length === 0) {
      return this.log.fail("insufficient funds", {
        need: AmountUtil.format(totalAmount),
        have: AmountUtil.format(amounts.reduce((s, a) => s + a, 0n)),
      });
    }
    this.log.ok("inputs selected", { count: selected.length, total: AmountUtil.format(totalAmount) });

    const selectedUtxos = selected.map(i => available[i]);
    const proofBuffers = xntGetMembershipProofs(
      client,
      selectedUtxos.map(u => u.decrypted.utxo.hashHex()),
      selectedUtxos.map(u => u.decrypted.senderRandomnessHex),
      key.receiverPreimageHex(),
      selectedUtxos.map(u => u.aoclIndex),
    );
    this.log.ok("membership proofs", { count: proofBuffers.length });

    const mutatorSet = xntGetMutatorSet(client);
    const builder = new XntTransactionBuilder();

    for (let i = 0; i < selected.length; i++) {
      const proof = XntMembershipProof.fromBytes(proofBuffers[i]);
      builder.addInput(selectedUtxos[i].decrypted.utxo, key, proof);
    }

    const recipient = addr.dCTIDHSubaddress(33354);
    builder.addOutput(recipient, sendAmount, xntRandomSenderRandomness());
    builder.setFee(fee);
    builder.setChange(addr, xntRandomSenderRandomness());

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
    const provenTx = builtTx.prove();
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    this.log.ok("proven", { seconds: elapsed, hasProofCollection: provenTx.hasProofCollection() });

    this.log.info("submitting");
    try {
      provenTx.submit(client);
      this.log.ok("submitted");
    } catch (e) {
      this.log.fail("submit failed", { error: String(e) });
    }

    return true;
  }

  private testUtxosPid(): boolean {
    const client = this.wallet.connectRpc();
    if (!client) return false;

    const { key, addr } = this.wallet.loadTestWallet();
    this.log.info("addresses", {
      dCTIDH: addr.toBech32(XntNetwork.Main),
      subaddress: addr.dCTIDHSubaddress(61002).toBech32(XntNetwork.Main),
    });

    const result = this.wallet.sync(client, key);
    if (!result) return this.log.skip("sync failed");

    for (const u of result.unspent) {
      const d = u.decrypted;
      this.log.info("unspent", {
        amount: AmountUtil.format(d.amount),
        ...(d.paymentId ? { pid: d.paymentId } : {}),
        aocl: u.aoclIndex, height: d.blockHeight,
      });
    }

    for (const p of result.pendingIncoming) {
      this.log.info("pending-incoming", {
        amount: AmountUtil.format(p.amount),
        ...(p.paymentId > 0 ? { pid: p.paymentId } : {}),
      });
    }

    const total = result.unspent.length + result.pendingIncoming.length;
    if (total === 0) return this.log.skip("no dCTIDH UTXOs");
    this.log.ok("utxos", { unspent: result.unspent.length, pending: result.pendingIncoming.length });
    return true;
  }
}

// ── Entry Point ────────────────────────────────────────────────────────────

const runner = new TestRunner();
runner.run(process.argv[2] || "full");
