import {
  XntNetwork,
  XntRpcClient,
  XntWalletEntropy,
  XntTransactionBuilder,
  XntMembershipProof,
  XntDecryptedUtxo,
  XntTransaction,
  xntBuildMigration,
  xntCheckSpent,
  xntGetMembershipProofs,
  xntGetMutatorSet,
  xntMempoolSpending,
} from "../napi/output";

/**
 * An unspent UTXO with its decrypted data and AOCL index.
 */
export type UnspentUtxo = {
  decrypted: XntDecryptedUtxo;
  aoclIndex: number;
};

/**
 * Selected input for mixed Generation + dCTIDH transactions.
 *
 * `"legacy-dctidh"` is a UTXO of a legacy-format dCTIDH key
 * (`wallet.deriveLegacydCTIDHKey(i)`, `decrypted.isLegacy`). Such UTXOs are
 * sweep-only: move them to a current-format key and never count them towards
 * the available balance.
 */
export type MixedSelectedInput = {
  kind: "gen" | "dctidh" | "legacy-dctidh";
  u: UnspentUtxo;
};

export type IndexedSelected = {
  s: MixedSelectedInput;
  idx: number;
};

/**
 * The key for the kind of a selected input. Throws if there is none, or if
 * the key and the UTXO disagree on being legacy-format: the membership proof
 * and the unlock data must come from the key the UTXO is locked to.
 */
function keyForKind(item: MixedSelectedInput, genKey: any, dCTIDHKey: any, legacyKey: any): any {
  const key = item.kind === "gen" ? genKey : item.kind === "dctidh" ? dCTIDHKey : legacyKey;
  if (!key) {
    throw new Error(`no key for selected input of kind "${item.kind}"`);
  }
  if (key.isLegacy() !== item.u.decrypted.isLegacy) {
    throw new Error(
      `selected input of kind "${item.kind}" has isLegacy=${item.u.decrypted.isLegacy}, its key has isLegacy=${key.isLegacy()}`,
    );
  }
  return key;
}

/**
 * Add heterogeneous inputs (Generation + dCTIDH, and optionally legacy-format
 * dCTIDH) to a `XntTransactionBuilder` using the correct membership proof for
 * each key type.
 */
export function addMultiTypeInputs(
  builder: XntTransactionBuilder,
  selected: MixedSelectedInput[],
  genKey: any,
  dCTIDHKey: any,
  genProofBuffers: Buffer[],
  dCTIDHProofBuffers: Buffer[],
  genSelected: IndexedSelected[],
  dCTIDHSelected: IndexedSelected[],
  legacyKey?: any,
  legacyProofBuffers: Buffer[] = [],
  legacySelected: IndexedSelected[] = [],
): void {
  for (let i = 0; i < selected.length; i++) {
    const item = selected[i];
    keyForKind(item, genKey, dCTIDHKey, legacyKey);

    if (item.kind === "gen") {
      const pos = genSelected.findIndex(x => x.idx === i);
      if (pos < 0) continue;
      const proof = XntMembershipProof.fromBytes(genProofBuffers[pos]);
      builder.addInput(item.u.decrypted.utxo, genKey, proof);
    } else if (item.kind === "dctidh") {
      const pos = dCTIDHSelected.findIndex(x => x.idx === i);
      if (pos < 0) continue;
      const proof = XntMembershipProof.fromBytes(dCTIDHProofBuffers[pos]);
      builder.addInput(item.u.decrypted.utxo, dCTIDHKey, proof);
    } else {
      const pos = legacySelected.findIndex(x => x.idx === i);
      if (pos < 0) continue;
      const proof = XntMembershipProof.fromBytes(legacyProofBuffers[pos]);
      builder.addInput(item.u.decrypted.utxo, legacyKey, proof);
    }
  }
}

/**
 * Build membership proofs for a mixed set of selected inputs (Generation +
 * dCTIDH, and optionally legacy-format dCTIDH).
 *
 * Returns the partitioned selections plus the raw proof buffers so callers can
 * log counts or inspect them before adding inputs to a transaction.
 */
export function buildMixedProofs(
  client: any,
  genKey: any,
  dCTIDHKey: any,
  selected: MixedSelectedInput[],
  legacyKey?: any,
): {
  genSelected: IndexedSelected[];
  dCTIDHSelected: IndexedSelected[];
  legacySelected: IndexedSelected[];
  genProofBuffers: Buffer[];
  dCTIDHProofBuffers: Buffer[];
  legacyProofBuffers: Buffer[];
} {
  selected.forEach(item => keyForKind(item, genKey, dCTIDHKey, legacyKey));

  const genSelected: IndexedSelected[] = selected
    .map((s, idx) => ({ s, idx }))
    .filter(x => x.s.kind === "gen");
  const dCTIDHSelected: IndexedSelected[] = selected
    .map((s, idx) => ({ s, idx }))
    .filter(x => x.s.kind === "dctidh");
  const legacySelected: IndexedSelected[] = selected
    .map((s, idx) => ({ s, idx }))
    .filter(x => x.s.kind === "legacy-dctidh");

  const genProofBuffers: Buffer[] = genSelected.length > 0
    ? xntGetMembershipProofs(
        client,
        genSelected.map(x => x.s.u.decrypted.utxo.hashHex()),
        genSelected.map(x => x.s.u.decrypted.senderRandomnessHex),
        genKey.receiverPreimageHex(),
        genSelected.map(x => x.s.u.aoclIndex),
      )
    : [];

  const dCTIDHProofBuffers: Buffer[] = dCTIDHSelected.length > 0
    ? xntGetMembershipProofs(
        client,
        dCTIDHSelected.map(x => x.s.u.decrypted.utxo.hashHex()),
        dCTIDHSelected.map(x => x.s.u.decrypted.senderRandomnessHex),
        dCTIDHKey.receiverPreimageHex(),
        dCTIDHSelected.map(x => x.s.u.aoclIndex),
      )
    : [];

  const legacyProofBuffers: Buffer[] = legacySelected.length > 0
    ? xntGetMembershipProofs(
        client,
        legacySelected.map(x => x.s.u.decrypted.utxo.hashHex()),
        legacySelected.map(x => x.s.u.decrypted.senderRandomnessHex),
        legacyKey.receiverPreimageHex(),
        legacySelected.map(x => x.s.u.aoclIndex),
      )
    : [];

  return {
    genSelected,
    dCTIDHSelected,
    legacySelected,
    genProofBuffers,
    dCTIDHProofBuffers,
    legacyProofBuffers,
  };
}

/**
 * Options of `migrateLegacyFunds`.
 */
export type MigrationOptions = {
  /**
   * Key indices whose legacy dCTIDH key is swept, i.e. the base addresses
   * handed out before v0.3; default [0]. These are not payment ids: every
   * payment id of a base address shares its key, so one index covers all of
   * them.
   */
  indices?: number[];
  /** Destination bech32m address; default: the current-format dCTIDH address of index 0. */
  destination?: string;
  network?: XntNetwork;
  /**
   * Only build the transactions and report them, without proving or
   * submitting anything; default true. Set to false to prove and submit.
   */
  dryRun?: boolean;
  /**
   * Build rounds before giving up; a new round after the submitted
   * transactions are confirmed, after a block that made a proof stale before
   * it was submitted, and after a submitted transaction was dropped.
   */
  maxRounds?: number;
  watchIntervalMs?: number;
  watchTimeoutMs?: number;
  log?: (message: string) => void;
};

/**
 * An input of a transaction built by `migrateLegacyFunds`, with the legacy
 * key index and the payment id (0 for the base address) it was received
 * with, and its amount in nau before fees.
 *
 * `round` and `txIndex` name the plan and the transaction in it. `submitted`
 * is true if that transaction was submitted, i.e. queued by the node; it is
 * confirmed once `absoluteIndexSetHashHex` is spent on chain (`xntCheckSpent`).
 * `status` is what was last seen of that transaction, see
 * `MigratedInputStatus`, and `confirmedAt` the height of the block it was
 * mined in.
 */
export type MigratedInput = {
  round: number;
  txIndex: number;
  keyIndex: number;
  paymentId: number;
  amount: bigint;
  blockHeight: number;
  absoluteIndexSetHashHex: string;
  submitted: boolean;
  status: MigratedInputStatus;
  confirmedAt?: number;
};

/**
 * What was last seen of the transaction of a `MigratedInput`:
 * - `"planned"`: not submitted (a dry run, or the tip moved before it was);
 * - `"submitted"`: submitted, not watched yet;
 * - `"pending"`: in a mempool, or submitted and no block since;
 * - `"confirmed"`: mined, all its inputs are spent on chain;
 * - `"dropped"`: not mined, and after a block no longer in the mempool; its
 *   UTXOs are moved by a later round;
 * - `"conflicted"`: some of its inputs were spent on chain by another
 *   transaction, so it cannot be mined; `migrateLegacyFunds` stops.
 */
export type MigratedInputStatus = "planned" | "submitted" | "pending" | "confirmed" | "dropped" | "conflicted";

/** The inputs of one legacy key index and payment id, see `MigrationReport.byPaymentId`. */
export type PaymentIdTotal = {
  keyIndex: number;
  paymentId: number;
  /** In nau, before fees. */
  amount: bigint;
  /** Number of inputs. */
  inputs: number;
};

/**
 * Outcome of `migrateLegacyFunds`: the transactions submitted, the amount
 * they send to the destination and their fees (in nau). `remaining` is true
 * if funds are left at legacy-format locks, for example because the rounds or
 * the watch time ran out, or in a dry run that found funds to move; run it
 * again. It is also true if a transaction conflicted (see
 * `MigratedInputStatus`); look at the inputs with that status first.
 *
 * `submitted`, `moved` and `fees` cover the submitted transactions that were
 * neither dropped nor conflicted, see `MigratedInputStatus`. `dropped` counts
 * the submitted transactions that were dropped; their UTXOs are built into the
 * transactions of the next round.
 *
 * A migration transaction merges the UTXOs of many payment ids into one
 * output. `inputs` lists every input of the transactions of every plan built,
 * one plan per round, with `submitted` true for those of the transactions
 * submitted; in a dry run all are `submitted` false. A UTXO whose transaction
 * was not submitted or was dropped in a round is listed again in the next.
 * `byPaymentId` sums them per legacy key index and payment id, sorted by both:
 * in a dry run over the inputs of the plan, otherwise over the inputs of the
 * submitted transactions that were neither dropped nor conflicted. Record
 * these per payment id before crediting the moved funds.
 */
export type MigrationReport = {
  submitted: number;
  moved: bigint;
  fees: bigint;
  dropped: number;
  dustInputs: number;
  timeLocked: number;
  remaining: boolean;
  inputs: MigratedInput[];
  byPaymentId: PaymentIdTotal[];
};

/** Sum `inputs` per legacy key index and payment id, sorted by both. */
function totalsByPaymentId(inputs: MigratedInput[]): PaymentIdTotal[] {
  const totals = new Map<string, PaymentIdTotal>();
  for (const input of inputs) {
    const key = `${input.keyIndex}:${input.paymentId}`;
    const total = totals.get(key) ?? { keyIndex: input.keyIndex, paymentId: input.paymentId, amount: 0n, inputs: 0 };
    total.amount += input.amount;
    total.inputs += 1;
    totals.set(key, total);
  }
  return Array.from(totals.values()).sort((a, b) => a.keyIndex - b.keyIndex || a.paymentId - b.paymentId);
}

const sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

const NAU_PER_COIN = 4n * 10n ** 30n;

/** An amount in nau as coins with 8 decimals, e.g. "3.90000000 XNT". */
export function formatCoins(nau: bigint): string {
  const sign = nau < 0n ? "-" : "";
  const abs = nau < 0n ? -nau : nau;
  const frac = ((abs % NAU_PER_COIN) * 100_000_000n) / NAU_PER_COIN;
  return `${sign}${abs / NAU_PER_COIN}.${frac.toString().padStart(8, "0")} XNT`;
}

/** Retry a call that talks to the node; public endpoints time out now and then. */
async function withRetry<T>(f: () => T, attempts = 5, delayMs = 3000): Promise<T> {
  let last: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return f();
    } catch (e) {
      last = e;
      if (attempt < attempts) await sleep(delayMs);
    }
  }
  throw last;
}

/**
 * Whether `proven`, built on the mutator set of the tip at `buildTip`, may be
 * submitted now: only while that tip is still the tip and the transaction is
 * confirmable.
 *
 * Confirmability alone is not enough. Before the UpgradeVMv8 fork, the nodes
 * that upgrade proof collections to single proofs, which is how they get
 * mined, take only those built on the mutator set of their own tip: they
 * cannot update someone else's proof collection to a new block. A proof
 * collection built on an earlier tip is often still confirmable, so nodes
 * accept it into their mempools, but none upgrades or mines it.
 */
async function syncedToTip(client: XntRpcClient, proven: XntTransaction, buildTip: number): Promise<boolean> {
  try {
    const current = await withRetry(() => xntGetMutatorSet(client), 3);
    return current.tipHeight() === buildTip && proven.isConfirmable(current);
  } catch {
    return false; // the tip is not known: do not submit
  }
}

/** What one poll tells of a submitted transaction, see `pollTransaction`. */
type TransactionPoll =
  | { status: "confirmed"; height: number }
  | { status: "pending" }
  | { status: "dropped" }
  | { status: "conflicted" };

/**
 * Classify a submitted transaction built on the tip at `buildTip`, from the
 * current tip, the heights its inputs are spent at (`xntCheckSpent`, -1 if
 * unspent) and the number of its inputs spent by a mempool transaction
 * (`xntMempoolSpending`).
 */
function pollTransaction(tip: number, buildTip: number, spentAt: number[], inMempool: number): TransactionPoll {
  const onChain = spentAt.filter(height => height >= 0);
  if (onChain.length > 0) {
    // A transaction is mined in one block, so all its inputs are spent at one height.
    const height = onChain[0];
    if (onChain.length === spentAt.length && onChain.every(h => h === height)) return { status: "confirmed", height };
    return { status: "conflicted" };
  }
  if (inMempool > 0 || tip <= buildTip) return { status: "pending" };
  // A block came, and the transaction is neither mined nor in the mempool:
  // nodes drop the proof collections they cannot update to the new block.
  return { status: "dropped" };
}

/** Polls in a row that must find the transactions dropped before they are built again. */
const DROPPED_POLLS = 2;

/**
 * Move the funds at legacy-format dCTIDH locks of `options.indices` to a
 * current-format address.
 *
 * Builds the transactions with `xntBuildMigration` (at most 10 inputs each,
 * one output to the destination, the default migration fee). By default this
 * is a dry run, which only reports them; with `dryRun: false` it proves and
 * submits them one by one. `prove()` picks the rule set from the tip the
 * transactions were built on, a v7 proof collection before the UpgradeVMv8
 * fork. A proof collection is valid only for the mutator set it was built on,
 * so each transaction is submitted only while the tip it was built on is still
 * the tip (see `syncedToTip`); after a new block the rest are built again.
 * After submitting, it watches the inputs of the submitted transactions until
 * each transaction is confirmed (its inputs are spent on chain) or dropped
 * (after a block, neither mined nor in the mempool); the UTXOs of the dropped
 * ones are built into the transactions of the next round. It stops if an input
 * was spent on chain by another transaction.
 */
export async function migrateLegacyFunds(
  client: XntRpcClient,
  wallet: XntWalletEntropy,
  options: MigrationOptions,
): Promise<MigrationReport> {
  const network = options.network ?? XntNetwork.Main;
  const destination = options.destination ?? wallet.derivedCTIDHKey(0).toAddress().toBech32(network);
  const maxRounds = options.maxRounds ?? 5;
  const watchIntervalMs = options.watchIntervalMs ?? 30_000;
  const watchTimeoutMs = options.watchTimeoutMs ?? 60 * 60 * 1000;
  const log = options.log ?? (() => {});
  const dryRun = options.dryRun ?? true;
  const indices = [...new Set(options.indices ?? [0])];
  if (indices.length === 0) throw new Error("no legacy key indices given");
  if (indices.some(i => !Number.isSafeInteger(i) || i < 0)) throw new Error("key indices must be non-negative integers");

  const report: MigrationReport = {
    submitted: 0,
    moved: 0n,
    fees: 0n,
    dropped: 0,
    dustInputs: 0,
    timeLocked: 0,
    remaining: false,
    inputs: [],
    byPaymentId: [],
  };
  const finish = (): MigrationReport => {
    report.byPaymentId = totalsByPaymentId(
      report.inputs.filter(
        input => dryRun || (input.submitted && input.status !== "dropped" && input.status !== "conflicted"),
      ),
    );
    return report;
  };
  for (let round = 1; round <= maxRounds; round++) {
    const plan = await withRetry(() => xntBuildMigration(client, wallet, indices, destination, network), 3);
    const transactions = plan.takeTransactions();
    const buildTip = plan.tipHeight();
    report.dustInputs = plan.dustInputs();
    report.timeLocked = plan.timeLocked();
    const planned: MigratedInput[][] = transactions.map((_, txIndex) =>
      plan.inputs(txIndex).map(input => ({
        round,
        txIndex,
        keyIndex: input.keyIndex,
        paymentId: input.paymentId,
        amount: input.amount,
        blockHeight: input.blockHeight,
        absoluteIndexSetHashHex: input.absoluteIndexSetHashHex,
        submitted: false,
        status: "planned" as MigratedInputStatus,
      })),
    );
    report.inputs.push(...planned.flat());
    log(
      `round ${round}, tip ${buildTip}: ${transactions.length} transaction(s), ` +
        `${formatCoins(plan.total())} for ${formatCoins(plan.fees())} in fees`,
    );
    if (transactions.length === 0) return finish();
    if (dryRun) {
      report.remaining = true;
      return finish();
    }

    type Sent = { txIndex: number; hashes: string[]; amount: bigint; fee: bigint };
    const sent: Sent[] = [];
    for (let i = 0; i < transactions.length; i++) {
      const amount = transactions[i].outputs().reduce((sum, o) => sum + o.amount, 0n);
      const fee = transactions[i].inputs().reduce((sum, x) => sum + x.amount, 0n) - amount;
      const proven = transactions[i].prove();
      if (!(await syncedToTip(client, proven, buildTip))) {
        log(`transaction ${i}: the tip moved past ${buildTip} while proving; building again`);
        break;
      }
      let queued: boolean;
      try {
        queued = proven.submit(client);
      } catch (e) {
        if (await syncedToTip(client, proven, buildTip)) throw e;
        log(`transaction ${i}: a block arrived while submitting; building again`);
        break;
      }
      if (!queued) {
        log(`transaction ${i} was not queued by the node; building again`);
        break;
      }
      const hashes = plan.inputHashes(i);
      log(`transaction ${i} submitted, ${hashes.length} input(s)`);
      sent.push({ txIndex: i, hashes, amount, fee });
      for (const input of planned[i]) {
        input.submitted = true;
        input.status = "submitted";
      }
      report.submitted += 1;
      report.moved += amount;
      report.fees += fee;
    }
    if (sent.length === 0) continue;

    // A dropped or conflicted transaction moves nothing.
    const retract = (tx: Sent, status: "dropped" | "conflicted") => {
      for (const input of planned[tx.txIndex]) input.status = status;
      report.submitted -= 1;
      report.moved -= tx.amount;
      report.fees -= tx.fee;
    };
    const watched = sent.flatMap(tx => tx.hashes);
    const started = Date.now();
    let droppedPolls = 0;
    for (;;) {
      await sleep(watchIntervalMs);
      let polls: TransactionPoll[] | undefined;
      try {
        // The mempool is read before the spent status: a transaction mined
        // in between is then seen as confirmed, not as dropped.
        const tip = client.chainHeight();
        const inMempool = new Set(xntMempoolSpending(client, watched));
        const spentAt = xntCheckSpent(client, watched);
        let offset = 0;
        polls = sent.map(tx => {
          const positions = tx.hashes.map((_, j) => offset + j);
          offset += tx.hashes.length;
          return pollTransaction(
            tip,
            buildTip,
            positions.map(k => spentAt[k]),
            positions.filter(k => inMempool.has(k)).length,
          );
        });
      } catch (e) {
        log(`watch: ${e}; trying again`);
      }
      if (polls) {
        const count = { confirmed: 0, pending: 0, dropped: 0, conflicted: 0 };
        for (const p of polls) count[p.status] += 1;
        polls.forEach((p, n) => {
          for (const input of planned[sent[n].txIndex]) {
            if (p.status === "confirmed") {
              input.status = "confirmed";
              input.confirmedAt = p.height;
            } else if (p.status === "pending") {
              input.status = "pending";
            }
          }
        });
        log(
          `${count.confirmed} of ${sent.length} submitted transaction(s) confirmed, ` +
            `${count.pending} pending, ${count.dropped} dropped`,
        );
        if (count.conflicted > 0) {
          polls.forEach((p, n) => {
            if (p.status !== "conflicted") return;
            retract(sent[n], "conflicted");
            log(`transaction ${sent[n].txIndex}: an input was spent on chain by another transaction; stopping`);
          });
          report.remaining = true;
          return finish();
        }
        if (count.confirmed === sent.length) break;
        if (count.pending > 0) {
          droppedPolls = 0;
        } else if (++droppedPolls >= DROPPED_POLLS) {
          // Every transaction is confirmed or dropped: build the dropped ones again.
          polls.forEach((p, n) => {
            if (p.status !== "dropped") return;
            retract(sent[n], "dropped");
            report.dropped += 1;
            log(
              `transaction ${sent[n].txIndex} was dropped: after block ${buildTip + 1} neither mined nor ` +
                `in the mempool; building it again`,
            );
          });
          break;
        }
      }
      if (Date.now() - started > watchTimeoutMs) {
        report.remaining = true;
        return finish();
      }
    }
  }
  report.remaining = true;
  return finish();
}
