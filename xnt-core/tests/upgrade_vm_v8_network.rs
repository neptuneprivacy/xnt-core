//! End-to-end scenarios on a connected regtest cluster under the
//! `UpgradeVMv8` rule set, with mock proofs so that no real proving is needed.
//!
//! Regtest follows `UpgradeVMv8` from genesis: every block these scenarios
//! mine is a post-fork block, and every transaction is validated by the
//! post-fork rules.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_privacy::api::export::ConsensusRuleSet;
use neptune_privacy::api::export::KeyType;
use neptune_privacy::api::export::NativeCurrencyAmount;
use neptune_privacy::api::export::Network;
use neptune_privacy::api::export::Timestamp;
use neptune_privacy::api::export::TransactionKernelId;
use neptune_privacy::api::export::TxProvingCapability;
use neptune_privacy::api::tx_initiation::consolidate::CONSOLIDATION_FEE_SP;
use neptune_privacy::application::config::cli_args::Args;
use tasm_lib::prelude::Digest;

/// Assert that the node's tip and the block that follows it are both under
/// `UpgradeVMv8`, the rule set that carries transaction chaining.
async fn assert_follows_upgrade_vm_v8(node: &GenesisNode) {
    let tip_height = node
        .gsl
        .lock_guard()
        .await
        .chain
        .light_state()
        .header()
        .height;
    for height in [tip_height, tip_height.next()] {
        let consensus_rule_set = ConsensusRuleSet::infer_from(Network::RegTest, height);
        assert_eq!(ConsensusRuleSet::UpgradeVMv8, consensus_rule_set);
        assert!(consensus_rule_set.has_chain_branches());
    }
}

async fn tip_digest(node: &GenesisNode) -> Digest {
    node.gsl.lock_guard().await.chain.light_state().hash()
}

/// Arguments for `num_nodes` single-proof capable nodes. Each node gets its
/// own ports from the OS, and dials the nodes before it.
async fn cluster_args(num_nodes: usize) -> Vec<Args> {
    let mut all_args: Vec<Args> = vec![];
    for _ in 0..num_nodes {
        let mut args = GenesisNode::default_args().await;
        args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
        args.peers = all_args
            .iter()
            .map(|peer| SocketAddr::new(peer.peer_listen_addr, peer.peer_port).into())
            .collect();
        all_args.push(args);
    }
    all_args
}

async fn start_connected_nodes<const N: usize>(
    all_args: Vec<Args>,
    timeout_secs: u16,
) -> anyhow::Result<[GenesisNode; N]> {
    let nodes: [GenesisNode; N] = GenesisNode::start_nodes(all_args).await?;
    GenesisNode::wait_until_all_peers_connected(&nodes, timeout_secs).await?;
    Ok(nodes)
}

/// test: a chained payment spends the unconfirmed output of another chained
/// payment, and one block confirms the whole chain.
///
/// scenario:
/// 1. alice, bob, and charlie run a connected 3-node regtest network, all
///    single-proof capable.
/// 2. alice mines 3 blocks and pays bob 5 coins.
/// 3. before any block confirms it, bob pays 3 of those coins to charlie via a
///    chained send.
/// 4. before any block confirms that, charlie pays 1 of his coins back to bob
///    via a chained send onto bob's chained transaction.
/// 5. each chained transaction replaces its predecessor in every mempool, so
///    a single transaction carries all three payments.
/// 6. the next block confirms all three payments at once.
#[tokio::test(flavor = "multi_thread")]
pub async fn chained_payment_spends_a_chained_payment_before_any_block() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;

    let [mut alice, mut bob, mut charlie] =
        start_connected_nodes(cluster_args(3).await, timeout_secs).await?;

    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;
    let bob_second_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;
    let charlie_address = charlie
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;
    bob.wait_until_block_height(3, timeout_secs).await?;
    charlie.wait_until_block_height(3, timeout_secs).await?;
    assert_follows_upgrade_vm_v8(&alice).await;

    let fee = NativeCurrencyAmount::coins(1);
    let alice_txid = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_address, NativeCurrencyAmount::coins(5))],
            Default::default(),
            fee,
            Timestamp::now(),
            0,
            None,
        )
        .await?
        .transaction()
        .txid();
    bob.wait_until_tx_in_mempool_has_single_proof(alice_txid, timeout_secs)
        .await?;
    bob.wait_until_unconfirmed_balance(timeout_secs).await?;

    // ## bob pays charlie from the unconfirmed funds.
    let bob_txid = bob
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send_chained(
            vec![(charlie_address, NativeCurrencyAmount::coins(3))],
            Default::default(),
            fee,
            Timestamp::now(),
        )
        .await?
        .transaction()
        .txid();
    charlie
        .wait_until_tx_in_mempool_has_single_proof(bob_txid, timeout_secs)
        .await?;
    charlie.wait_until_unconfirmed_balance(timeout_secs).await?;

    // ## charlie pays bob from the unconfirmed output of bob's chained
    // transaction.
    let charlie_txid = charlie
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send_chained(
            vec![(bob_second_address, NativeCurrencyAmount::coins(1))],
            Default::default(),
            fee,
            Timestamp::now(),
        )
        .await?
        .transaction()
        .txid();

    for node in [&alice, &bob, &charlie] {
        node.wait_until_tx_in_mempool(charlie_txid, timeout_secs)
            .await?;
        let state = node.gsl.lock_guard().await;
        assert!(!state.mempool.contains(alice_txid));
        assert!(!state.mempool.contains(bob_txid));
        assert_eq!(1, state.mempool.len());
    }

    // ## the next block confirms the whole chain.
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, true)
        .await?;
    bob.wait_until_block_height(4, timeout_secs).await?;
    charlie.wait_until_block_height(4, timeout_secs).await?;
    bob.wait_until_confirmed_balance(timeout_secs).await?;
    charlie.wait_until_confirmed_balance(timeout_secs).await?;

    // bob holds 1 coin of change and the 1 coin from charlie; charlie holds 1
    // coin of change.
    assert_eq!(
        NativeCurrencyAmount::coins(2),
        bob.gsl
            .api()
            .wallet()
            .balances(Timestamp::now())
            .await
            .confirmed_available
    );
    assert_eq!(
        NativeCurrencyAmount::coins(1),
        charlie
            .gsl
            .api()
            .wallet()
            .balances(Timestamp::now())
            .await
            .confirmed_available
    );
    let alice_tip = tip_digest(&alice).await;
    for node in [&alice, &bob, &charlie] {
        assert_eq!(alice_tip, tip_digest(node).await);
        assert!(node.gsl.lock_guard().await.mempool.is_empty());
    }

    Ok(())
}

/// test: a wallet consolidates its UTXOs, and a peer's block confirms it.
///
/// scenario:
/// 1. alice and bob run a connected 2-node regtest network, both single-proof
///    capable.
/// 2. alice mines 15 blocks, so that her oldest UTXOs have enough
///    confirmations for consolidation.
/// 3. alice consolidates 4 UTXOs into one; her node upgrades the transaction
///    to a single proof, and it reaches bob's mempool.
/// 4. bob mines the next block, which confirms the consolidation: alice holds
///    3 UTXOs fewer, and her balance is down by the fee only.
#[tokio::test(flavor = "multi_thread")]
pub async fn consolidation_is_relayed_and_confirmed() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;
    // the proof upgrader ticks every ten seconds.
    let upgrade_timeout_secs = 30;

    let [mut alice, mut bob] = start_connected_nodes(cluster_args(2).await, timeout_secs).await?;

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(15, false)
        .await?;
    bob.wait_until_block_height(15, timeout_secs).await?;
    assert_follows_upgrade_vm_v8(&alice).await;

    let num_utxos_before = alice
        .gsl
        .api()
        .wallet()
        .spendable_inputs(Timestamp::now(), 0)
        .await
        .len();
    let balance_before = alice
        .gsl
        .api()
        .wallet()
        .balances(Timestamp::now())
        .await
        .confirmed_available;

    let num_inputs = 4;
    let num_consolidated = alice
        .gsl
        .api_mut()
        .tx_initiator_mut()
        .consolidate(num_inputs, None, Timestamp::now())
        .await?;
    assert_eq!(num_inputs, num_consolidated);

    // the consolidation transaction is the only transaction in the network.
    // Wait until bob holds it with a single proof, so that it can be mined.
    let txid = {
        let state = alice.gsl.lock_guard().await;
        assert_eq!(1, state.mempool.len());
        state.mempool.fee_density_iter().next().unwrap().0
    };
    bob.wait_until_tx_in_mempool_has_single_proof(txid, upgrade_timeout_secs)
        .await?;

    bob.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, true)
        .await?;
    alice.wait_until_block_height(16, timeout_secs).await?;
    alice.wait_until_confirmed_balance(timeout_secs).await?;

    let num_utxos_after = alice
        .gsl
        .api()
        .wallet()
        .spendable_inputs(Timestamp::now(), 0)
        .await
        .len();
    assert_eq!(num_utxos_before - num_inputs + 1, num_utxos_after);
    let balance_after = alice
        .gsl
        .api()
        .wallet()
        .balances(Timestamp::now())
        .await
        .confirmed_available;
    assert_eq!(balance_before, balance_after + CONSOLIDATION_FEE_SP);
    for node in [&alice, &bob] {
        assert!(node.gsl.lock_guard().await.mempool.is_empty());
    }

    Ok(())
}

/// test: a node that joins after blocks carrying a chained transaction syncs
/// to the tip, and then takes part in chaining.
///
/// scenario:
/// 1. alice and bob run a connected regtest network, single-proof capable and
///    running the proof upgrader.
/// 2. alice mines 3 blocks and pays bob 5 coins; bob pays 3 of those
///    unconfirmed coins back to alice via a chained send; alice mines the
///    block that confirms both, and 2 more.
/// 3. charlie starts and connects; he syncs to the tip, and so validates the
///    block carrying the chained transaction.
/// 4. alice pays charlie 4 coins; before any block confirms them, charlie pays
///    2 of them on to bob in a link transaction, which reaches every mempool.
/// 5. a proof upgrader fixes the link transaction, and the next block
///    confirms it.
#[tokio::test(flavor = "multi_thread")]
pub async fn late_node_syncs_and_sends_a_link_transaction() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;
    // the proof upgrader ticks every ten seconds.
    let upgrade_timeout_secs = 30;

    // Charlie dials alice and bob once he starts.
    let mut all_args = cluster_args(3).await;
    for args in &mut all_args {
        args.tx_proof_upgrading = true;
    }
    let charlie_args = all_args.pop().unwrap();
    let [mut alice, mut bob] = start_connected_nodes(all_args, timeout_secs).await?;

    let alice_address = alice
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;
    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;
    bob.wait_until_block_height(3, timeout_secs).await?;

    let fee = NativeCurrencyAmount::coins(1);
    let alice_txid = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_address.clone(), NativeCurrencyAmount::coins(5))],
            Default::default(),
            fee,
            Timestamp::now(),
            0,
            None,
        )
        .await?
        .transaction()
        .txid();
    bob.wait_until_tx_in_mempool_has_single_proof(alice_txid, timeout_secs)
        .await?;
    bob.wait_until_unconfirmed_balance(timeout_secs).await?;

    let bob_txid = bob
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send_chained(
            vec![(alice_address, NativeCurrencyAmount::coins(3))],
            Default::default(),
            fee,
            Timestamp::now(),
        )
        .await?
        .transaction()
        .txid();
    alice
        .wait_until_tx_in_mempool_has_single_proof(bob_txid, timeout_secs)
        .await?;

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, true)
        .await?;
    bob.wait_until_block_height(4, timeout_secs).await?;
    bob.wait_until_confirmed_balance(timeout_secs).await?;
    assert_eq!(
        NativeCurrencyAmount::coins(1),
        bob.gsl
            .api()
            .wallet()
            .balances(Timestamp::now())
            .await
            .confirmed_available
    );
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(2, false)
        .await?;
    bob.wait_until_block_height(6, timeout_secs).await?;

    // ## charlie joins, and syncs to the tip.
    let mut charlie = GenesisNode::start_node(charlie_args).await?;
    charlie.wait_until_peers_connected(2, timeout_secs).await?;
    charlie.wait_until_block_height(6, timeout_secs).await?;
    assert_eq!(tip_digest(&alice).await, tip_digest(&charlie).await);
    assert_follows_upgrade_vm_v8(&charlie).await;

    let charlie_address = charlie
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;
    let alice_to_charlie_txid = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(charlie_address, NativeCurrencyAmount::coins(4))],
            Default::default(),
            fee,
            Timestamp::now(),
            0,
            None,
        )
        .await?
        .transaction()
        .txid();
    charlie
        .wait_until_tx_in_mempool_has_single_proof(alice_to_charlie_txid, timeout_secs)
        .await?;
    charlie.wait_until_unconfirmed_balance(timeout_secs).await?;

    // ## charlie pays bob from the unconfirmed funds in a link transaction.
    let link_txid = charlie
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send_chained_link(
            vec![(bob_address, NativeCurrencyAmount::coins(2))],
            Default::default(),
            fee,
            Timestamp::now(),
        )
        .await?
        .link_tx()
        .txid();
    for node in [&alice, &bob, &charlie] {
        node.wait_until_chained_tx_in_mempool(link_txid, timeout_secs)
            .await?;
        assert!(!node
            .gsl
            .lock_guard()
            .await
            .mempool
            .contains(alice_to_charlie_txid));
    }

    // a proof upgrader fixes the link transaction into a single-proof
    // transaction under the same txid, and the next block confirms it.
    alice
        .wait_until_tx_in_mempool_has_single_proof(link_txid, upgrade_timeout_secs)
        .await?;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, true)
        .await?;
    bob.wait_until_block_height(7, timeout_secs).await?;
    charlie.wait_until_block_height(7, timeout_secs).await?;
    bob.wait_until_confirmed_balance(timeout_secs).await?;
    charlie.wait_until_confirmed_balance(timeout_secs).await?;

    assert_eq!(
        NativeCurrencyAmount::coins(3),
        bob.gsl
            .api()
            .wallet()
            .balances(Timestamp::now())
            .await
            .confirmed_available
    );
    assert_eq!(
        NativeCurrencyAmount::coins(1),
        charlie
            .gsl
            .api()
            .wallet()
            .balances(Timestamp::now())
            .await
            .confirmed_available
    );
    let alice_tip = tip_digest(&alice).await;
    for node in [&alice, &bob, &charlie] {
        assert_eq!(alice_tip, tip_digest(node).await);
        assert!(node.gsl.lock_guard().await.mempool.is_empty());
    }

    Ok(())
}

/// Wait until the node's mempool holds exactly one transaction, and return its
/// txid.
async fn wait_until_only_mempool_tx(
    node: &GenesisNode,
    timeout_secs: u16,
) -> anyhow::Result<TransactionKernelId> {
    let start = std::time::Instant::now();
    loop {
        {
            let state = node.gsl.lock_guard().await;
            if let Some((txid, _)) = state.mempool.fee_density_iter().next() {
                anyhow::ensure!(1 == state.mempool.len(), "more than one transaction");
                return Ok(txid);
            }
        }
        if start.elapsed() > Duration::from_secs(timeout_secs.into()) {
            anyhow::bail!("no transaction in mempool after {timeout_secs} seconds");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// test: a node with auto-consolidation consolidates on its own when a block
/// arrives from a peer, and the network confirms the consolidation.
///
/// scenario:
/// 1. alice runs with `--auto-consolidate --num-consolidation-inputs 3`, bob
///    without; both are single-proof capable.
/// 2. alice mines 12 blocks, so that her oldest UTXOs have enough
///    confirmations. Her own blocks do not start a consolidation.
/// 3. bob mines a block; when it reaches alice, she consolidates 3 UTXOs, and
///    her node upgrades the transaction to a single proof.
/// 4. the consolidation reaches bob, and his next block confirms it.
#[tokio::test(flavor = "multi_thread")]
pub async fn auto_consolidation_runs_on_a_block_from_a_peer() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;
    // the proof upgrader ticks every ten seconds.
    let upgrade_timeout_secs = 30;

    let num_inputs = 3;
    let mut alice_args = Args::try_parse_from([
        "xnt-core".to_string(),
        "--auto-consolidate".to_string(),
        "--num-consolidation-inputs".to_string(),
        num_inputs.to_string(),
    ])?;
    let defaults = GenesisNode::default_args().await;
    alice_args.network = defaults.network;
    alice_args.peer_listen_addr = defaults.peer_listen_addr;
    alice_args.peer_port = defaults.peer_port;
    alice_args.rpc_port = defaults.rpc_port;
    alice_args.quic_port = defaults.quic_port;
    alice_args.tcp_port = defaults.tcp_port;
    alice_args.data_dir = defaults.data_dir;
    alice_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
    alice_args
        .validate_auto_consolidation()
        .map_err(anyhow::Error::msg)?;

    let mut bob_args = GenesisNode::default_args().await;
    bob_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
    bob_args.peers =
        vec![SocketAddr::new(alice_args.peer_listen_addr, alice_args.peer_port).into()];

    let [mut alice, mut bob] =
        start_connected_nodes(vec![alice_args, bob_args], timeout_secs).await?;

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(12, false)
        .await?;
    bob.wait_until_block_height(12, timeout_secs).await?;
    assert!(alice.gsl.lock_guard().await.mempool.is_empty());
    assert_follows_upgrade_vm_v8(&alice).await;

    // ## a block from bob starts alice's consolidation.
    bob.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, false)
        .await?;
    alice.wait_until_block_height(13, timeout_secs).await?;
    let txid = wait_until_only_mempool_tx(&alice, timeout_secs).await?;
    let kernel = alice
        .gsl
        .lock_guard()
        .await
        .mempool
        .get(txid)
        .unwrap()
        .kernel
        .clone();
    assert_eq!(num_inputs, kernel.inputs.len());
    assert_eq!(1, kernel.outputs.len());
    assert_eq!(CONSOLIDATION_FEE_SP, kernel.fee);

    // ## the consolidation reaches bob, and his next block confirms it.
    bob.wait_until_tx_in_mempool_has_single_proof(txid, upgrade_timeout_secs)
        .await?;
    bob.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, true)
        .await?;
    alice.wait_until_block_height(14, timeout_secs).await?;

    let block_kernel = bob
        .gsl
        .lock_guard()
        .await
        .chain
        .light_state()
        .body()
        .transaction_kernel
        .clone();
    // The block stores its inputs packed, so compare their index sets.
    for input in &kernel.inputs {
        assert!(block_kernel
            .inputs
            .iter()
            .any(|rr| rr.absolute_indices == input.absolute_indices));
    }
    assert!(block_kernel.outputs.contains(&kernel.outputs[0]));
    assert!(!alice.gsl.lock_guard().await.mempool.contains(txid));
    assert!(!bob.gsl.lock_guard().await.mempool.contains(txid));

    Ok(())
}
