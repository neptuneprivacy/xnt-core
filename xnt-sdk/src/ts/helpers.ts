import {
  XntNetwork,
  XntRpcClient,
  XntWalletEntropy,
  XntTransactionBuilder,
  XntMembershipProof,
  XntDecryptedUtxo,
  xntBuildMigration,
  xntCheckSpent,
  xntGetMembershipProofs,
  xntGetMutatorSet,
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
  /** Build rounds before giving up, a new round after each block that made a proof stale. */
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
};

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
 * again.
 *
 * A migration transaction merges the UTXOs of many payment ids into one
 * output. `inputs` lists every input of the transactions of every plan built,
 * one plan per round, with `submitted` true for those of the transactions
 * submitted; in a dry run all are `submitted` false. A UTXO whose transaction
 * was not submitted in a round is listed again in the next.
 * `byPaymentId` sums them per legacy key index and payment id, sorted by both:
 * in a dry run over the inputs of the plan, otherwise over the inputs of the
 * submitted transactions only. Record these per payment id before crediting
 * the moved funds.
 */
export type MigrationReport = {
  submitted: number;
  moved: bigint;
  fees: bigint;
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
 * Move the funds at legacy-format dCTIDH locks of `options.indices` to a
 * current-format address.
 *
 * Builds the transactions with `xntBuildMigration` (at most 10 inputs each,
 * one output to the destination, the default migration fee). By default this
 * is a dry run, which only reports them; with `dryRun: false` it proves and
 * submits them one by one. `prove()` picks the rule set from the tip the
 * transactions were built on, a v7 proof collection before the UpgradeVMv8
 * fork. A proof collection is valid only for the mutator set it was built on,
 * so each transaction is checked right before it is submitted; after a new
 * block the rest are built again. After submitting, it waits until the inputs
 * of the submitted transactions are spent on chain.
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
    dustInputs: 0,
    timeLocked: 0,
    remaining: false,
    inputs: [],
    byPaymentId: [],
  };
  const finish = (): MigrationReport => {
    report.byPaymentId = totalsByPaymentId(report.inputs.filter(input => dryRun || input.submitted));
    return report;
  };
  for (let round = 1; round <= maxRounds; round++) {
    const plan = await withRetry(() => xntBuildMigration(client, wallet, indices, destination, network), 3);
    const transactions = plan.takeTransactions();
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
      })),
    );
    report.inputs.push(...planned.flat());
    log(
      `round ${round}, tip ${plan.tipHeight()}: ${transactions.length} transaction(s), ` +
        `${formatCoins(plan.total())} for ${formatCoins(plan.fees())} in fees`,
    );
    if (transactions.length === 0) return finish();
    if (dryRun) {
      report.remaining = true;
      return finish();
    }

    const watched: string[] = [];
    for (let i = 0; i < transactions.length; i++) {
      const sent = transactions[i].outputs().reduce((sum, o) => sum + o.amount, 0n);
      const spentAmount = transactions[i].inputs().reduce((sum, x) => sum + x.amount, 0n);
      const proven = transactions[i].prove();
      const tip = await withRetry(() => xntGetMutatorSet(client));
      if (!proven.isConfirmable(tip)) {
        log(`transaction ${i} went stale while proving; building again`);
        break;
      }
      if (!proven.submit(client)) {
        log(`transaction ${i} was not queued by the node; building again`);
        break;
      }
      const inputs = plan.inputHashes(i);
      log(`transaction ${i} submitted, ${inputs.length} input(s)`);
      watched.push(...inputs);
      for (const input of planned[i]) input.submitted = true;
      report.submitted += 1;
      report.moved += sent;
      report.fees += spentAmount - sent;
    }
    if (watched.length === 0) continue;

    const started = Date.now();
    for (;;) {
      await sleep(watchIntervalMs);
      let spent: number[];
      try {
        spent = xntCheckSpent(client, watched);
      } catch {
        continue;
      }
      const done = spent.filter(height => height >= 0).length;
      log(`${done} of ${watched.length} submitted input(s) spent on chain`);
      if (done === watched.length) break;
      if (Date.now() - started > watchTimeoutMs) {
        report.remaining = true;
        return finish();
      }
    }
  }
  report.remaining = true;
  return finish();
}
