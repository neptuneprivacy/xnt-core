//! Move the funds at legacy-format dCTIDH locks to a current-format address.
//!
//! Usage: cargo run --release -p xnt-sdk --example migrate -- [dry_run=yes|no]
//!
//! Parameter:
//! - dry_run=yes (default): only build the transactions and list them, with
//!   the legacy key index and payment id of each input
//! - dry_run=no: prove and submit them
//!
//! Environment:
//! - XNT_MNEMONIC_FILE: file holding the wallet's mnemonic (required)
//! - XNT_RPC_URL: JSON-RPC endpoint of an archival node with the UTXO indexer
//!   (required)
//! - XNT_LEGACY_INDICES: comma-separated legacy dCTIDH key indices (default
//!   "0")
//! - XNT_DESTINATION: bech32m address to move the funds to (default: the
//!   wallet's current-format dCTIDH address 0)
//! - XNT_NETWORK: main, testnet, regtest or testnet-mock (default main)
//!
//! A proof collection is valid only for the mutator set it was built on, so
//! each transaction is proven and submitted only while the tip it was built
//! on is still the tip (see `synced_to_tip`). After the submissions, the
//! example watches the inputs of the submitted transactions until each is
//! confirmed (spent on chain) or dropped (after a block, neither mined nor in
//! the mempool), then builds the remaining transactions, and those dropped,
//! again. It stops if an input was spent on chain by another transaction.

use std::time::{Duration, Instant};

use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use xnt_sdk::core::{
    build_migration, check_spent, get_mutator_set, mempool_spending, Digest, Network, RpcClient, Transaction,
    WalletEntropy,
};

/// How long to wait for the inputs of a submitted transaction to be spent.
const WATCH_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const WATCH_INTERVAL: Duration = Duration::from_secs(30);
/// Rounds in a row that confirm nothing (stale before submitting, or
/// dropped) before giving up.
const MAX_ATTEMPTS: usize = 5;
/// Polls in a row that must find the transactions dropped before they are
/// built again.
const DROPPED_POLLS: usize = 2;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn coins(nau: i128) -> String {
    NativeCurrencyAmount::from_nau(nau).to_string()
}

fn network() -> Network {
    match env("XNT_NETWORK").as_deref() {
        None | Some("main") => Network::Main,
        Some("testnet") => Network::Testnet,
        Some("regtest") => Network::RegTest,
        Some("testnet-mock") => Network::TestnetMock,
        Some(other) => panic!("unknown network {other}"),
    }
}

/// Whether `transaction`, built on the mutator set of the tip at `build_tip`,
/// may be submitted now: only while that tip is still the tip and the
/// transaction is confirmable.
///
/// Confirmability alone is not enough. Before the UpgradeVMv8 fork, the nodes
/// that upgrade proof collections to single proofs, which is how they get
/// mined, take only those built on the mutator set of their own tip: they
/// cannot update someone else's proof collection to a new block. A proof
/// collection built on an earlier tip is often still confirmable, so nodes
/// accept it into their mempools, but none upgrades or mines it.
fn synced_to_tip(client: &RpcClient, transaction: &Transaction, build_tip: u64) -> bool {
    match get_mutator_set(client) {
        Ok(mutator_set) => {
            mutator_set.tip_height() == Some(build_tip) && transaction.is_confirmable(&mutator_set)
        }
        Err(e) => {
            // The tip is not known: do not submit.
            println!("mutator set: {e}");
            false
        }
    }
}

/// Watch the inputs of the transactions submitted on the tip at `build_tip`,
/// one list per transaction, until each is confirmed or dropped; returns how
/// many were confirmed. Panics if an input was spent on chain by another
/// transaction, or on timeout.
fn watch(client: &RpcClient, submitted: &[Vec<Digest>], build_tip: u64) -> usize {
    let watched: Vec<Digest> = submitted.iter().flatten().copied().collect();
    let start = Instant::now();
    let mut dropped_polls = 0;
    loop {
        std::thread::sleep(WATCH_INTERVAL);
        if start.elapsed() > WATCH_TIMEOUT {
            panic!("the submitted transactions were not mined in time");
        }
        // The mempool is read before the spent status: a transaction mined in
        // between is then seen as confirmed, not as dropped.
        let poll = client.chain_height().and_then(|tip| {
            let in_mempool = mempool_spending(client, &watched)?;
            let spent_at = check_spent(client, &watched)?;
            Ok((tip, in_mempool, spent_at))
        });
        let (tip, in_mempool, spent_at) = match poll {
            Ok(poll) if poll.2.len() == watched.len() => poll,
            Ok(_) => {
                println!("watch: the spent status does not match the inputs; trying again");
                continue;
            }
            Err(e) => {
                println!("watch: {e}; trying again");
                continue;
            }
        };

        let (mut confirmed, mut pending, mut offset) = (0, 0, 0);
        for inputs in submitted {
            let positions = offset..offset + inputs.len();
            offset += inputs.len();
            let on_chain: Vec<i64> = spent_at[positions.clone()]
                .iter()
                .copied()
                .filter(|&height| height >= 0)
                .collect();
            if !on_chain.is_empty() {
                // A transaction is mined in one block: all its inputs at one
                // height.
                if on_chain.len() < inputs.len() || on_chain.iter().any(|&height| height != on_chain[0]) {
                    panic!("an input was spent on chain by another transaction");
                }
                confirmed += 1;
            } else if positions.into_iter().any(|k| in_mempool.contains(&k)) || tip <= build_tip {
                pending += 1;
            }
            // Otherwise dropped: after a block, neither mined nor in the
            // mempool, as nodes drop the proof collections they cannot update
            // to the new block.
        }
        let dropped = submitted.len() - confirmed - pending;
        println!(
            "{confirmed} of {} submitted transactions confirmed, {pending} pending, {dropped} dropped",
            submitted.len()
        );
        if pending > 0 {
            dropped_polls = 0;
            continue;
        }
        dropped_polls += 1;
        if dropped == 0 || dropped_polls >= DROPPED_POLLS {
            return confirmed;
        }
    }
}

/// The dry_run=yes|no parameter, default yes.
fn dry_run_parameter() -> bool {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => true,
        [arg] if arg == "dry_run=yes" => true,
        [arg] if arg == "dry_run=no" => false,
        _ => panic!("usage: migrate [dry_run=yes|no], got {args:?}"),
    }
}

fn main() {
    let dry_run = dry_run_parameter();
    let mnemonic_file = env("XNT_MNEMONIC_FILE").expect("XNT_MNEMONIC_FILE required");
    let mnemonic = std::fs::read_to_string(&mnemonic_file).expect("read the mnemonic file");
    let wallet = WalletEntropy::from_mnemonic(mnemonic.trim()).expect("wallet");
    let url = env("XNT_RPC_URL").expect("XNT_RPC_URL required");
    let client = RpcClient::new(&url).expect("rpc client");
    let network = network();
    let indices: Vec<u64> = env("XNT_LEGACY_INDICES")
        .unwrap_or_else(|| "0".to_string())
        .split(',')
        .map(|index| index.trim().parse().expect("legacy key index"))
        .collect();
    let destination = env("XNT_DESTINATION").unwrap_or_else(|| {
        wallet
            .derive_dctidh_spending_key(0)
            .to_address()
            .and_then(|address| address.to_bech32(network))
            .expect("destination address")
    });
    println!("legacy key indices {indices:?}, destination {destination}");

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let mut attempts = 0;
    loop {
        let mut plan =
            build_migration(&client, &wallet, &indices, &destination, network).expect("build migration");
        let build_tip = plan.tip_height;
        println!(
            "tip {}: {} transactions moving {} for {} in fees; {} dust inputs, {} time-locked, {} skipped entries",
            build_tip,
            plan.transactions.len(),
            coins(plan.total),
            coins(plan.fees),
            plan.dust.iter().map(Vec::len).sum::<usize>(),
            plan.time_locked.len(),
            plan.skipped.total(),
        );
        // The transactions merge the UTXOs of all payment ids into one
        // output: record what each moves per legacy key index and payment id.
        for (i, (built, inputs)) in plan.transactions.iter().zip(&plan.swept_inputs).enumerate() {
            let amount: i128 = built.outputs().iter().map(|output| output.utxo.amount()).sum();
            println!("  transaction {i}: {} inputs, {} to the destination", inputs.len(), coins(amount));
            for input in inputs {
                println!(
                    "    legacy key {}, payment id {}, {} from block {}",
                    input.key_index,
                    input.payment_id,
                    coins(input.amount),
                    input.block_height
                );
            }
        }
        for (key_index, payment_id, amount) in plan.totals_by_payment_id() {
            println!("  legacy key {key_index}, payment id {payment_id}: {} before fees", coins(amount));
        }
        if plan.transactions.is_empty() {
            println!("nothing to move");
            return;
        }
        if dry_run {
            println!("dry run; pass dry_run=no to prove and submit");
            return;
        }
        attempts += 1;
        if attempts > MAX_ATTEMPTS {
            panic!("nothing confirmed in {MAX_ATTEMPTS} rounds; run again later");
        }

        // Prove and submit the transactions one after the other, while the
        // tip they were built on is still the tip; watch the inputs of those
        // submitted.
        let mut submitted = Vec::new();
        for (built, inputs) in plan.transactions.drain(..).zip(plan.swept.drain(..)) {
            let start = Instant::now();
            let transaction = runtime.block_on(built.prove()).expect("prove");
            println!("proven in {:.1} s", start.elapsed().as_secs_f64());
            if !synced_to_tip(&client, &transaction, build_tip) {
                println!("the tip moved past {build_tip} while proving; building again");
                break;
            }
            match transaction.submit(&client) {
                Ok(true) => println!("submitted"),
                Ok(false) => panic!("the node did not queue the transaction"),
                Err(e) => {
                    if synced_to_tip(&client, &transaction, build_tip) {
                        panic!("submit: {e}");
                    }
                    println!("a block arrived while submitting ({e}); building again");
                    break;
                }
            }
            submitted.push(inputs.iter().map(|input| input.absolute_index_set_hash()).collect::<Vec<_>>());
        }
        if submitted.is_empty() {
            continue;
        }

        // Build the remaining transactions, and those dropped, again.
        if watch(&client, &submitted, build_tip) > 0 {
            attempts = 0;
        }
    }
}
