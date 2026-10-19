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
 * transaction is proven and checked right before it is submitted. After a
 * submission, the example waits until the inputs of the transaction are spent on
 * chain, then builds the remaining transactions again.
 */

import * as fs from "fs";
import {
  XntNetwork,
  XntWalletEntropy,
  XntRpcClient,
  xntBuildMigration,
  xntCheckSpent,
  xntGetMutatorSet,
} from "../src/napi/output";

const WATCH_TIMEOUT_MS = 60 * 60 * 1000;
const WATCH_INTERVAL_MS = 30 * 1000;
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

  for (;;) {
    const plan = xntBuildMigration(client, wallet, indices, destination, network);
    const transactions = plan.takeTransactions();
    console.log(
      `tip ${plan.tipHeight()}: ${transactions.length} transactions moving ${coins(plan.total())} ` +
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

    // Prove and submit the transactions one after the other, while they are
    // still confirmable; watch the inputs of those submitted.
    const watched: string[] = [];
    for (let i = 0; i < transactions.length; i++) {
      const start = Date.now();
      const proven = transactions[i].prove();
      console.log(`proven in ${((Date.now() - start) / 1000).toFixed(1)} s`);
      if (!proven.isConfirmable(xntGetMutatorSet(client))) {
        console.log("a block arrived while proving; building again");
        break;
      }
      if (!proven.submit(client)) throw new Error("the node did not queue the transaction");
      console.log("submitted");
      watched.push(...plan.inputHashes(i));
    }
    if (watched.length === 0) continue;

    const start = Date.now();
    for (;;) {
      const spent = xntCheckSpent(client, watched).filter((height) => height >= 0).length;
      console.log(`${spent} of ${watched.length} submitted inputs spent`);
      if (spent === watched.length) break;
      if (Date.now() - start > WATCH_TIMEOUT_MS) throw new Error("the submitted transactions were not mined in time");
      await sleep(WATCH_INTERVAL_MS);
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
