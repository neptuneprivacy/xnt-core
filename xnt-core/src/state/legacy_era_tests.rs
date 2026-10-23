//! How the global state holds transactions around the `UpgradeVMv8` fork:
//! for the rule set of the next block, those of the legacy era in the legacy
//! relay pool, all others in the mempool.

use macro_rules_attr::apply;
use tracing_test::traced_test;

use super::*;
use crate::api::tx_initiation::migrate_dctidh::tests::main_net_placeholder_block;
use crate::application::config::network::Network;
use crate::protocol::consensus::block::BlockProof;
use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::state::wallet::wallet_entropy::WalletEntropy;
use crate::tests::shared::globalstate::mock_genesis_global_state;
use crate::tests::shared::mock_tx::invalid_empty_single_proof_transaction;
use crate::tests::shared::mock_tx::testrunning::make_plenty_mock_transaction_supported_by_primitive_witness;
use crate::tests::shared_tokio_runtime;

/// The fork height, `UpgradeVMv8`'s first block on main net.
fn fork() -> u64 {
    BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET.value()
}

/// A main-net node, and the placeholder block at the given height that it
/// takes as its tip.
async fn main_net_state_at(height: u64) -> (GlobalStateLock, Block) {
    let cli = cli_args::Args::default_with_network(Network::Main);
    let mut state = mock_genesis_global_state(0, WalletEntropy::new_random(), cli).await;
    let genesis = state.lock_guard().await.chain.light_state().clone();
    let tip = main_net_placeholder_block(&genesis, height.into());
    state.set_new_tip(tip.clone()).await.unwrap();

    (state, tip)
}

/// Extend the tip by a placeholder block at the next height.
async fn extend(state: &mut GlobalStateLock, tip: &Block) -> (Block, Vec<MempoolUpdateJob>) {
    let block = main_net_placeholder_block(tip, tip.header().height.next());
    let jobs = state.set_new_tip(block.clone()).await.unwrap();

    (block, jobs)
}

async fn insert(state: &mut GlobalStateLock, transaction: &Transaction) {
    state
        .lock_guard_mut()
        .await
        .mempool_insert(
            transaction.clone(),
            UpgradePriority::Critical,
            AddReason::Submitted,
        )
        .await;
}

/// A v7 transaction is never held in the mempool, and a v8 one never in the
/// legacy relay pool: a tip at 96,998 is followed by a v7 block, a tip at
/// 96,999 by the fork block.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn transactions_are_held_for_the_rule_set_of_the_next_block() {
    let transaction = invalid_empty_single_proof_transaction();
    for (tip_height, legacy) in [(fork() - 2, true), (fork() - 1, false), (fork(), false)] {
        let (mut state, _) = main_net_state_at(tip_height).await;
        insert(&mut state, &transaction).await;

        let state = state.lock_guard().await;
        assert_eq!(
            legacy,
            state.next_block_consensus_rule_set().is_legacy_era(),
            "tip {tip_height}"
        );
        assert_eq!(
            legacy,
            state.legacy_relay_pool.contains(transaction.txid()),
            "tip {tip_height}"
        );
        assert_eq!(
            !legacy,
            state.mempool.contains(transaction.txid()),
            "tip {tip_height}"
        );
        assert!(state
            .mempool_or_legacy_pool_get(transaction.txid())
            .is_some());
    }
}

/// A transaction verified under one rule set is not held once the next block
/// follows another, as when a block arrives between a submission's check and
/// its insertion.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn a_transaction_is_held_only_for_the_rule_set_it_was_verified_under() {
    let transaction = invalid_empty_single_proof_transaction();
    let (mut state, _) = main_net_state_at(fork() - 100).await;
    let mut state = state.lock_guard_mut().await;

    assert!(
        !state
            .mempool_insert_for_rule_set(
                transaction.clone(),
                ConsensusRuleSet::UpgradeVMv8,
                UpgradePriority::Critical,
                AddReason::Submitted,
            )
            .await
    );
    assert!(state.mempool.is_empty());
    assert!(state.legacy_relay_pool.is_empty());

    assert!(
        state
            .mempool_insert_for_rule_set(
                transaction.clone(),
                ConsensusRuleSet::UpgradeVMv7,
                UpgradePriority::Critical,
                AddReason::Submitted,
            )
            .await
    );
    assert!(state.mempool.is_empty());
    assert!(state.legacy_relay_pool.contains(transaction.txid()));
}

/// While the next block is a v7 block, this node's own v7 transactions are
/// proven again on every block, and foreign ones dropped. When the next block
/// is the fork block, the legacy relay pool is cleared, and the own ones are
/// parked: held in the mempool with their primitive witnesses, and proven for
/// v8 on every block until the mempool holds them with a proof.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn the_fork_clears_the_legacy_pool_and_proves_own_transactions_for_v8() {
    let (mut state, tip) = main_net_state_at(fork() - 3).await;
    let own = make_plenty_mock_transaction_supported_by_primitive_witness(1)
        .pop()
        .unwrap();
    let TransactionProof::Witness(own_witness) = own.proof.clone() else {
        unreachable!()
    };
    let foreign = invalid_empty_single_proof_transaction();
    insert(&mut state, &own).await;
    insert(&mut state, &foreign).await;
    assert_eq!(2, state.lock_guard().await.legacy_relay_pool.len());

    // The tip at 96,998: the next block is still a v7 block.
    let (tip, jobs) = extend(&mut state, &tip).await;
    {
        let state = state.lock_guard().await;
        assert_eq!(1, state.legacy_relay_pool.len());
        assert!(state.legacy_relay_pool.contains(own.txid()));
        assert!(state.parked_own_witnesses.is_empty());
    }
    assert!(jobs.iter().any(|job| job.txid() == own.txid()));

    // The tip at 96,999: the next block is the fork block. The own
    // transaction is parked, held in the mempool backed by its witness, and
    // handed to the updater to be proven for the fork block.
    let (tip, switch_jobs) = extend(&mut state, &tip).await;
    {
        let state = state.lock_guard().await;
        assert!(state.legacy_relay_pool.is_empty());
        assert_eq!(1, state.parked_own_witnesses.len());
        assert_eq!(
            own_witness.kernel,
            state.parked_own_witnesses[0].primitive_witness.kernel
        );
        assert_eq!(vec![(own.txid(), 1)], state.parked_own_transactions());
        assert_eq!(1, state.mempool.len());
        assert!(state.mempool.get(own.txid()).unwrap().proof.is_witness());
        assert!(!state.mempool.contains(foreign.txid()));
    }
    let parked_switch_jobs = switch_jobs
        .iter()
        .filter(|job| job.txid() == own.txid())
        .collect_vec();
    assert_eq!(1, parked_switch_jobs.len());
    assert!(matches!(
        parked_switch_jobs[0],
        MempoolUpdateJob::ProofCollection(_)
    ));

    // The fork block: not proven yet, as when the jobs of the last block were
    // skipped, so it is handed over again, and only once.
    let (_, fork_block_jobs) = extend(&mut state, &tip).await;
    assert_eq!(
        vec![(own.txid(), 2)],
        state.lock_guard().await.parked_own_transactions()
    );
    let parked_fork_block_jobs = fork_block_jobs
        .iter()
        .filter(|job| job.txid() == own.txid())
        .collect_vec();
    assert_eq!(1, parked_fork_block_jobs.len());
    assert!(matches!(
        parked_fork_block_jobs[0],
        MempoolUpdateJob::ProofCollection(_)
    ));
}

/// Back across the fork, as by a reorganization to a shorter chain with more
/// work: the mempool's v8 transactions cannot be mined before the fork, so
/// none stays, in either pool.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn a_reorganization_back_across_the_fork_drops_v8_transactions() {
    let (mut state, before) = main_net_state_at(fork() - 3).await;
    let (last_v7_parent, _) = extend(&mut state, &before).await;
    let (_, _) = extend(&mut state, &last_v7_parent).await;
    assert!(!state
        .lock_guard()
        .await
        .next_block_consensus_rule_set()
        .is_legacy_era());

    let transaction = invalid_empty_single_proof_transaction();
    insert(&mut state, &transaction).await;
    assert!(state
        .lock_guard()
        .await
        .mempool
        .contains(transaction.txid()));

    // A sibling of the tip's parent, at 96,998: the next block is a v7 block.
    let mut sibling = main_net_placeholder_block(&before, last_v7_parent.header().height);
    let mut header = *sibling.header();
    header.timestamp += Timestamp::minutes(1);
    sibling = Block::new(
        header,
        sibling.body().clone(),
        sibling.appendix().clone(),
        BlockProof::Invalid,
    );
    assert_ne!(last_v7_parent.hash(), sibling.hash());
    let jobs = state.set_new_tip(sibling).await.unwrap();

    let state = state.lock_guard().await;
    assert!(state.next_block_consensus_rule_set().is_legacy_era());
    assert!(state.mempool.is_empty());
    assert!(!state.legacy_relay_pool.contains(transaction.txid()));
    assert!(jobs.is_empty());
}
