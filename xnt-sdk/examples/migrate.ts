/**
 * Move the funds at legacy-format dCTIDH locks to a current-format address.
 *
 * Usage: npx ts-node examples/migrate.ts [dry_run=yes|no]
 *
 * Parameter:
 * - dry_run=yes (default): only build the transactions and list them, with
 *   the legacy key index and payment id of each input
 * - dry_run=no: prove and submit them
 *
 * Environment:
 * - XNT_MNEMONIC_FILE: file holding the wallet's mnemonic (required)
 * - XNT_RPC_URL: JSON-RPC endpoint of an archival node with the UTXO indexer (required)
 * - XNT_LEGACY_INDICES: comma-separated legacy dCTIDH key indices (default "0")
 * - XNT_DESTINATION: bech32m address to move the funds to (default: the
 *   wallet's current-format dCTIDH address 0)
 *
 * A proof collection is valid only for the mutator set it was built on, so each
 * transaction is proven and submitted only while the tip it was built on is
 * still the tip (see `syncedToTip`). After the submissions, the example watches
 * the inputs of the submitted transactions until each is confirmed (spent on
 * chain) or dropped (after a block, neither mined nor in the mempool), then
 * builds the remaining transactions, and those dropped, again. It stops if an
 * input was spent on chain by another transaction.
 */

import * as fs from "fs";
import {
  XntNetwork,
  XntWalletEntropy,
  XntRpcClient,
  XntTransaction,
  xntBuildMigration,
  xntCheckSpent,
  xntGetMutatorSet,
  xntMempoolSpending,
} from "../src/napi/output";

const WATCH_TIMEOUT_MS = 60 * 60 * 1000;
const WATCH_INTERVAL_MS = 30 * 1000;
/** Rounds in a row that confirm nothing (stale before submitting, or dropped) before giving up. */
const MAX_ATTEMPTS = 5;
/** Polls in a row that must find the transactions dropped before they are built again. */
const DROPPED_POLLS = 2;
const FACTOR = 4n * 10n ** 30n; // 1 XNT = 4 * 10^30 nau

function coins(nau: bigint): string {
  const sign = nau < 0n ? "-" : "";
  const abs = nau < 0n ? -nau : nau;
  return `${sign}${abs / FACTOR}.${((abs % FACTOR) * 100000000n / FACTOR).toString().padStart(8, "0")} XNT`;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} required`);
  return value;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Whether `proven`, built on the mutator set of the tip at `buildTip`, may be
 * submitted now: only while that tip is still the tip and the transaction is
 * confirmable.
 *
 * Confirmability alone is not enough. Before the UpgradeVMv8 fork, the nodes
 * that upgrade proof collections to single proofs, which is how they get mined,
 * take only those built on the mutator set of their own tip: they cannot update
 * someone else's proof collection to a new block. A proof collection built on
 * an earlier tip is often still confirmable, so nodes accept it into their
 * mempools, but none upgrades or mines it.
 */
function syncedToTip(client: XntRpcClient, proven: XntTransaction, buildTip: number): boolean {
  try {
    const current = xntGetMutatorSet(client);
    return current.tipHeight() === buildTip && proven.isConfirmable(current);
  } catch (e) {
    console.log(`mutator set: ${e}`);
    return false; // the tip is not known: do not submit
  }
}

/**
 * Watch the inputs of the transactions submitted on the tip at `buildTip`
 * (absolute index set hashes, one list per transaction) until each is
 * confirmed or dropped; returns how many were confirmed. Throws if an input was
 * spent on chain by another transaction, or on timeout.
 */
async function watch(client: XntRpcClient, submitted: string[][], buildTip: number): Promise<number> {
  const watched = submitted.flat();
  const start = Date.now();
  let droppedPolls = 0;
  for (;;) {
    await sleep(WATCH_INTERVAL_MS);
    if (Date.now() - start > WATCH_TIMEOUT_MS) throw new Error("the submitted transactions were not mined in time");
    let tip: number;
    let inMempool: Set<number>;
    let spentAt: number[];
    try {
      // The mempool is read before the spent status: a transaction mined in
      // between is then seen as confirmed, not as dropped.
      tip = client.chainHeight();
      inMempool = new Set(xntMempoolSpending(client, watched));
      spentAt = xntCheckSpent(client, watched);
    } catch (e) {
      console.log(`watch: ${e}; trying again`);
      continue;
    }

    let confirmed = 0;
    let pending = 0;
    let offset = 0;
    for (const inputs of submitted) {
      const positions = inputs.map((_, j) => offset + j);
      offset += inputs.length;
      const onChain = positions.map((k) => spentAt[k]).filter((height) => height >= 0);
      if (onChain.length > 0) {
        // A transaction is mined in one block: all its inputs at one height.
        if (onChain.length < inputs.length || onChain.some((height) => height !== onChain[0])) {
          throw new Error("an input was spent on chain by another transaction");
        }
        confirmed++;
      } else if (positions.some((k) => inMempool.has(k)) || tip <= buildTip) {
        pending++;
      }
      // Otherwise dropped: after a block, neither mined nor in the mempool, as
      // nodes drop the proof collections they cannot update to the new block.
    }
    const dropped = submitted.length - confirmed - pending;
    console.log(`${confirmed} of ${submitted.length} submitted transactions confirmed, ${pending} pending, ${dropped} dropped`);
    if (pending > 0) {
      droppedPolls = 0;
    } else if (dropped === 0 || ++droppedPolls >= DROPPED_POLLS) {
      return confirmed;
    }
  }
}

/** The dry_run=yes|no parameter, default yes. */
function dryRunParameter(args: string[]): boolean {
  if (args.length > 1) throw new Error("usage: npx ts-node examples/migrate.ts [dry_run=yes|no]");
  const arg = args[0] ?? "dry_run=yes";
  if (arg === "dry_run=yes") return true;
  if (arg === "dry_run=no") return false;
  throw new Error(`unknown parameter ${arg}: expected dry_run=yes or dry_run=no`);
}

async function main(): Promise<void> {
  const dryRun = dryRunParameter(process.argv.slice(2));
  const mnemonic = fs.readFileSync(required("XNT_MNEMONIC_FILE"), "utf8").trim();
  const wallet = new XntWalletEntropy(mnemonic);
  const client = new XntRpcClient(required("XNT_RPC_URL"));
  const network = XntNetwork.Main;
  const indices = (process.env.XNT_LEGACY_INDICES || "0").split(",").map((index) => Number(index.trim()));
  const destination =
    process.env.XNT_DESTINATION || wallet.derivedCTIDHKey(0).toAddress().toBech32(network);
  console.log(`legacy key indices ${indices.join(",")}, destination ${destination}`);

  let attempts = 0;
  for (;;) {
    const plan = xntBuildMigration(client, wallet, indices, destination, network);
    const transactions = plan.takeTransactions();
    const buildTip = plan.tipHeight();
    console.log(
      `tip ${buildTip}: ${transactions.length} transactions moving ${coins(plan.total())} ` +
        `for ${coins(plan.fees())} in fees; ${plan.dustInputs()} dust inputs, ` +
        `${plan.timeLocked()} time-locked, ${plan.skipped()} skipped entries`,
    );
    // The transactions merge the UTXOs of all payment ids into one output:
    // record what each moves per legacy key index and payment id.
    for (let i = 0; i < transactions.length; i++) {
      for (const input of plan.inputs(i)) {
        console.log(
          `  transaction ${i}: legacy key ${input.keyIndex}, payment id ${input.paymentId}, ` +
            `${coins(input.amount)} from block ${input.blockHeight}`,
        );
      }
    }
    for (const total of plan.totalsByPaymentId()) {
      console.log(`  legacy key ${total.keyIndex}, payment id ${total.paymentId}: ${coins(total.amount)} before fees`);
    }
    if (transactions.length === 0) {
      console.log("nothing to move");
      return;
    }
    if (dryRun) {
      console.log("dry run; pass dry_run=no to prove and submit");
      return;
    }
    if (++attempts > MAX_ATTEMPTS) throw new Error(`nothing confirmed in ${MAX_ATTEMPTS} rounds; run again later`);

    // Prove and submit the transactions one after the other, while the tip
    // they were built on is still the tip; watch the inputs of those submitted.
    const submitted: string[][] = [];
    for (let i = 0; i < transactions.length; i++) {
      const start = Date.now();
      const proven = transactions[i].prove();
      console.log(`proven in ${((Date.now() - start) / 1000).toFixed(1)} s`);
      if (!syncedToTip(client, proven, buildTip)) {
        console.log(`the tip moved past ${buildTip} while proving; building again`);
        break;
      }
      try {
        if (!proven.submit(client)) throw new Error("the node did not queue the transaction");
      } catch (e) {
        if (syncedToTip(client, proven, buildTip)) throw e;
        console.log("a block arrived while submitting; building again");
        break;
      }
      console.log("submitted");
      submitted.push(plan.inputHashes(i));
    }
    if (submitted.length === 0) continue;

    // Build the remaining transactions, and those dropped, again.
    if ((await watch(client, submitted, buildTip)) > 0) attempts = 0;
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
