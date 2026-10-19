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
//! each transaction is proven and checked right before it is submitted. After
//! a submission, the example waits until the inputs of the transaction are
//! spent on chain, then builds the remaining transactions again.

use std::time::{Duration, Instant};

use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use xnt_sdk::core::{build_migration, check_spent, get_mutator_set, Network, RpcClient, WalletEntropy};

/// How long to wait for the inputs of a submitted transaction to be spent.
const WATCH_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const WATCH_INTERVAL: Duration = Duration::from_secs(30);

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
    loop {
        let mut plan =
            build_migration(&client, &wallet, &indices, &destination, network).expect("build migration");
        println!(
            "tip {}: {} transactions moving {} for {} in fees; {} dust inputs, {} time-locked, {} skipped entries",
            plan.tip_height,
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

        // Prove and submit the transactions one after the other, while they
        // are still confirmable; watch the inputs of those submitted.
        let mut submitted = Vec::new();
        for (built, inputs) in plan.transactions.drain(..).zip(plan.swept.drain(..)) {
            let start = Instant::now();
            let transaction = runtime.block_on(built.prove()).expect("prove");
            println!("proven in {:.1} s", start.elapsed().as_secs_f64());
            let mutator_set = get_mutator_set(&client).expect("mutator set");
            if !transaction.is_confirmable(&mutator_set) {
                println!("a block arrived while proving; building again");
                break;
            }
            match transaction.submit(&client) {
                Ok(true) => println!("submitted"),
                Ok(false) => panic!("the node did not queue the transaction"),
                Err(e) => panic!("submit: {e}"),
            }
            submitted.push(inputs);
        }
        if submitted.is_empty() {
            continue;
        }

        let hashes: Vec<_> = submitted
            .iter()
            .flatten()
            .map(|input| input.absolute_index_set_hash())
            .collect();
        let start = Instant::now();
        loop {
            let spent = check_spent(&client, &hashes).expect("check spent");
            let num_spent = spent.iter().filter(|&&height| height >= 0).count();
            println!("{num_spent} of {} submitted inputs spent", hashes.len());
            if num_spent == hashes.len() {
                break;
            }
            if start.elapsed() > WATCH_TIMEOUT {
                panic!("the submitted transactions were not mined in time");
            }
            std::thread::sleep(WATCH_INTERVAL);
        }
    }
}
