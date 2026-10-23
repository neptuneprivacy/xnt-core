/**
 * Move the funds at legacy-format dCTIDH locks to a current-format address
 * with `migrateLegacyFunds`, and report what is moved per payment id.
 *
 * Usage: npx ts-node examples/migrate-legacy.ts [dry_run=yes|no]
 *
 * Parameter:
 * - dry_run=yes (default): only build the transactions and report them;
 *   nothing is proven or submitted
 * - dry_run=no: prove and submit them, then wait until they are mined
 *
 * Environment:
 * - XNT_MNEMONIC_FILE: file holding the wallet's mnemonic (required)
 * - XNT_RPC_URL: JSON-RPC endpoint of an archival node with the UTXO indexer
 *   (default https://api.xntscan.io)
 * - XNT_LEGACY_INDICES: comma-separated legacy dCTIDH key indices, the base
 *   addresses handed out before v0.3 (default "0"). These are not payment
 *   ids: one index covers every payment id of its base address.
 * - XNT_DESTINATION: bech32m address to move the funds to (default: the
 *   wallet's current-format dCTIDH address 0)
 *
 * Reconciliation: an exchange hands each user a subaddress, i.e. a payment id
 * of one base address. All payment ids of a base address share its key, and a
 * migration transaction merges the UTXOs of many payment ids into one output,
 * so that output does not tell whose funds it holds. Before crediting
 * anything, record the report's `byPaymentId` (and `inputs`, per UTXO): how
 * much each legacy key index and payment id contributes, before fees. Deposits
 * at legacy-format locks are sweep-only, not final balance: keep them pending
 * until the transaction moving them is confirmed (its inputs are spent on
 * chain), then credit the recorded amounts per payment id. The fees are taken
 * from the merged output; decide how to share them.
 */

import * as fs from "fs";
import { XntNetwork, XntRpcClient, XntWalletEntropy } from "../src/napi/output";
import { formatCoins, migrateLegacyFunds } from "../src/ts/helpers";

const DEFAULT_RPC_URL = "https://api.xntscan.io";

/** The dry_run=yes|no parameter, default yes. */
function dryRunParameter(args: string[]): boolean {
  if (args.length > 1) throw new Error("usage: npx ts-node examples/migrate-legacy.ts [dry_run=yes|no]");
  const arg = args[0] ?? "dry_run=yes";
  if (arg === "dry_run=yes") return true;
  if (arg === "dry_run=no") return false;
  throw new Error(`unknown parameter ${arg}: expected dry_run=yes or dry_run=no`);
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} required`);
  return value;
}

async function main(): Promise<void> {
  const dryRun = dryRunParameter(process.argv.slice(2));
  // The mnemonic is only read from its file, never printed.
  const mnemonic = fs.readFileSync(required("XNT_MNEMONIC_FILE"), "utf8").trim();
  const wallet = new XntWalletEntropy(mnemonic);
  const client = new XntRpcClient(process.env.XNT_RPC_URL || DEFAULT_RPC_URL);
  const network = XntNetwork.Main;
  const indices = (process.env.XNT_LEGACY_INDICES || "0").split(",").map((index) => Number(index.trim()));
  const destination =
    process.env.XNT_DESTINATION || wallet.derivedCTIDHKey(0).toAddress().toBech32(network);
  console.log(
    `${dryRun ? "dry run" : "migration"}: legacy key indices ${indices.join(",")}, destination ${destination}`,
  );

  const report = await migrateLegacyFunds(client, wallet, {
    indices,
    destination,
    network,
    dryRun,
    log: (message) => console.log(message),
  });

  // What the transactions move per legacy key index and payment id, before
  // fees: in a dry run all planned inputs, otherwise those of the submitted
  // transactions. Record these per payment id before crediting the moved
  // funds; the legacy-format deposits are not final balance until then.
  console.log(`\n${dryRun ? "planned" : "submitted"}, per legacy key index and payment id (before fees):`);
  if (report.byPaymentId.length === 0) {
    console.log("  nothing");
  } else {
    console.log(`  ${"key index".padStart(9)}  ${"payment id".padStart(20)}  ${"amount".padStart(22)}  inputs`);
    for (const total of report.byPaymentId) {
      console.log(
        `  ${String(total.keyIndex).padStart(9)}  ${String(total.paymentId).padStart(20)}  ` +
          `${formatCoins(total.amount).padStart(22)}  ${String(total.inputs).padStart(6)}`,
      );
    }
  }

  console.log("\nreport:");
  console.log(
    JSON.stringify(report, (_key, value) => (typeof value === "bigint" ? formatCoins(value) : value), 2),
  );
  if (dryRun && report.remaining) console.log("\ndry run; pass dry_run=no to prove and submit");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
