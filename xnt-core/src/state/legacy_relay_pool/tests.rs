use itertools::Itertools;

use super::*;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::tests::shared::blocks::invalid_block_with_kernel_and_mutator_set;
use crate::tests::shared::blocks::invalid_empty_block;
use crate::tests::shared::mock_tx::testrunning::make_plenty_mock_transaction_supported_by_primitive_witness;

const MAX_SIZE: usize = 1 << 30;

fn genesis() -> Block {
    Block::genesis(Network::Main)
}

/// Transactions of this node: backed by their primitive witnesses, with
/// pairwise disjoint inputs.
fn own_transactions(count: usize) -> Vec<Transaction> {
    make_plenty_mock_transaction_supported_by_primitive_witness(count)
}

/// The same transaction as relayed by a peer: the kernel with a proof
/// collection.
fn as_proof_collection(transaction: &Transaction) -> Transaction {
    let TransactionProof::Witness(primitive_witness) = &transaction.proof else {
        panic!("expected a witness-backed transaction");
    };
    Transaction {
        kernel: transaction.kernel.clone(),
        proof: TransactionProof::ProofCollection(
            ProofCollection::produce_mock(primitive_witness, true).into(),
        ),
    }
}

/// The same transaction with a single proof, as an upgrader of the era before
/// the fork makes it.
fn as_single_proof(transaction: &Transaction) -> Transaction {
    Transaction {
        kernel: transaction.kernel.clone(),
        proof: TransactionProof::invalid(),
    }
}

/// A foreign transaction spending the same inputs, with a different fee and
/// so a different id.
fn with_fee(transaction: &Transaction, coins: u32) -> Transaction {
    Transaction {
        kernel: TransactionKernelModifier::default()
            .fee(NativeCurrencyAmount::coins(coins))
            .modify(transaction.kernel.clone()),
        proof: TransactionProof::invalid(),
    }
}

fn now(transaction: &Transaction) -> Timestamp {
    transaction.kernel.timestamp + Timestamp::minutes(1)
}

fn num_removals(events: &[MempoolEvent], reason: RemovalReason) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, MempoolEvent::RemoveTx(_, r) if *r == reason))
        .count()
}

fn num_additions(events: &[MempoolEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, MempoolEvent::AddTx(..)))
        .count()
}

#[test]
fn insert_takes_a_transaction_once_and_upgrades_its_proof() {
    let mut pool = LegacyRelayPool::new(MAX_SIZE, &genesis());
    let own = own_transactions(1).pop().unwrap();
    let txid = own.txid();
    let now = now(&own);

    let events = pool.insert(own.clone(), None, AddReason::Submitted, now);
    assert_eq!(1, num_additions(&events));
    assert_eq!(1, pool.len());
    assert_eq!(1, pool.num_own());

    // The same transaction again is taken once.
    assert!(pool
        .insert(own.clone(), None, AddReason::Submitted, now)
        .is_empty());
    assert_eq!(1, pool.len());

    // Its proof collection replaces the witness, and keeps it. The kernel
    // stays the same, so the wallet is told of no change.
    let proof_collection = as_proof_collection(&own);
    let upgrade_events = pool.insert(proof_collection.clone(), None, AddReason::Upgraded, now);
    assert!(upgrade_events.is_empty());
    assert_eq!(Some(&proof_collection), pool.get(txid));
    assert!(pool.primitive_witness(txid).is_some());
    assert_eq!(1, pool.num_own());

    // A worse proof under the same id is refused, a better one taken.
    assert!(pool
        .insert(own.clone(), None, AddReason::FromPeer, now)
        .is_empty());
    let single_proof = as_single_proof(&own);
    pool.insert(single_proof.clone(), None, AddReason::Upgraded, now);
    assert_eq!(Some(&single_proof), pool.get(txid));
    assert!(pool.primitive_witness(txid).is_some());
}

#[test]
fn own_transactions_are_not_displaced_by_foreign_ones() {
    let mut pool = LegacyRelayPool::new(MAX_SIZE, &genesis());
    let own = own_transactions(1).pop().unwrap();
    let now = now(&own);
    pool.insert(own.clone(), None, AddReason::Submitted, now);

    // A foreign transaction spending the same inputs is refused, even with a
    // higher fee and a single proof.
    let foreign = with_fee(&own, 1000);
    assert!(pool
        .insert(foreign.clone(), None, AddReason::FromPeer, now)
        .is_empty());
    assert!(pool.contains(own.txid()));
    assert!(!pool.contains(foreign.txid()));

    // An own transaction replaces whatever it conflicts with, like the
    // re-proven version of an own transaction does.
    let TransactionProof::Witness(witness) = own.proof.clone() else {
        unreachable!()
    };
    let reproven = with_fee(&own, 2);
    let events = pool.insert(reproven.clone(), Some(witness), AddReason::Updated, now);
    assert_eq!(1, num_removals(&events, RemovalReason::Replaced));
    assert!(pool.contains(reproven.txid()));
    assert!(!pool.contains(own.txid()));
    assert_eq!(1, pool.num_own());
}

#[test]
fn foreign_conflicts_are_decided_by_proof_quality_then_fee_density() {
    let mut pool = LegacyRelayPool::new(MAX_SIZE, &genesis());
    let base = own_transactions(1).pop().unwrap();
    let now = now(&base);

    let low_fee = with_fee(&base, 1);
    let high_fee = with_fee(&base, 5);
    pool.insert(low_fee.clone(), None, AddReason::FromPeer, now);
    let events = pool.insert(high_fee.clone(), None, AddReason::FromPeer, now);
    assert_eq!(1, num_removals(&events, RemovalReason::Replaced));
    assert_eq!(vec![high_fee.txid()], pool.txids_by_fee_density());

    // A lower fee density at the same proof quality is refused.
    assert!(pool
        .insert(low_fee.clone(), None, AddReason::FromPeer, now)
        .is_empty());

    // A proof collection never replaces a single proof.
    let mut low_fee_pc = as_proof_collection(&base);
    low_fee_pc.kernel = low_fee.kernel.clone();
    assert!(pool
        .insert(low_fee_pc, None, AddReason::FromPeer, now)
        .is_empty());
    assert_eq!(vec![high_fee.txid()], pool.txids_by_fee_density());
}

#[test]
fn foreign_transactions_of_the_lowest_fee_density_are_evicted_first() {
    let mut pool = LegacyRelayPool::new(MAX_SIZE, &genesis());
    pool.max_num_transactions = 3;
    let transactions = own_transactions(5);
    let now = now(&transactions[0]);

    let own = transactions[0].clone();
    pool.insert(own.clone(), None, AddReason::Submitted, now);
    let foreign = transactions[1..]
        .iter()
        .zip([4, 1, 3, 2])
        .map(|(transaction, coins)| with_fee(transaction, coins))
        .collect_vec();
    let mut events = vec![];
    for transaction in &foreign {
        events.extend(pool.insert(transaction.clone(), None, AddReason::FromPeer, now));
    }

    // The two foreign transactions of the lowest fees went, the own one stays.
    // The last arrival was evicted at once, which leaves no event.
    assert_eq!(3, pool.len());
    assert_eq!(1, num_removals(&events, RemovalReason::MempoolFull));
    assert!(pool.contains(own.txid()));
    assert!(pool.contains(foreign[0].txid()));
    assert!(pool.contains(foreign[2].txid()));
    assert!(!pool.contains(foreign[1].txid()));
    assert!(!pool.contains(foreign[3].txid()));

    // The size bound evicts too, but never the own transaction.
    pool.max_total_size = 1;
    let shrink_events = pool.shrink_to_bounds();
    assert_eq!(2, num_removals(&shrink_events, RemovalReason::MempoolFull));
    assert_eq!(1, pool.len());
    assert!(pool.contains(own.txid()));
}

#[test]
fn a_new_block_drops_spent_and_foreign_transactions_and_reproves_own_ones() {
    let genesis = genesis();
    let mut pool = LegacyRelayPool::new(MAX_SIZE, &genesis);
    let transactions = own_transactions(5);
    let now = now(&transactions[0]);

    // Own: one backed by its witness, one by a proof collection, one by a
    // single proof, one that the block mines. Foreign: one.
    let own_witness = transactions[0].clone();
    let own_proof_collection = as_proof_collection(&transactions[1]);
    let own_single_proof = as_single_proof(&transactions[4]);
    let own_mined = transactions[2].clone();
    let foreign = with_fee(&transactions[3], 3);
    pool.insert(own_witness.clone(), None, AddReason::Submitted, now);
    pool.insert(transactions[1].clone(), None, AddReason::Submitted, now);
    pool.insert(own_proof_collection.clone(), None, AddReason::Upgraded, now);
    pool.insert(transactions[4].clone(), None, AddReason::Submitted, now);
    pool.insert(own_single_proof.clone(), None, AddReason::Upgraded, now);
    pool.insert(own_mined.clone(), None, AddReason::Submitted, now);
    pool.insert(foreign.clone(), None, AddReason::FromPeer, now);
    assert_eq!(5, pool.len());

    let TransactionProof::Witness(mined_witness) = &own_mined.proof else {
        unreachable!()
    };
    let block = invalid_block_with_kernel_and_mutator_set(
        own_mined.kernel.clone(),
        mined_witness.mutator_set_accumulator.clone(),
    );
    pool.tip_digest = block.header().prev_block_digest;
    let (events, jobs) = pool.update_with_block(&block).unwrap();
    assert_eq!(1, num_removals(&events, RemovalReason::Merged));
    assert_eq!(1, num_removals(&events, RemovalReason::Abandoned));
    assert_eq!(3, pool.len());
    assert!(pool.contains(own_witness.txid()));
    assert!(pool.contains(own_proof_collection.txid()));
    assert!(pool.contains(own_single_proof.txid()));

    // The transactions backed by their witness or a proof collection are
    // proven as proof collections, also the one whose first proof did not
    // complete. Of the one backed by a single proof, only the witness is
    // updated.
    assert_eq!(3, jobs.len());
    for job in &jobs {
        match job {
            MempoolUpdateJob::ProofCollection(_) => assert!(
                [own_witness.txid(), own_proof_collection.txid()].contains(&job.txid()),
                "unexpected proof collection job"
            ),
            MempoolUpdateJob::PrimitiveWitness(_) => {
                assert_eq!(own_single_proof.txid(), job.txid())
            }
            other => panic!("unexpected job {other:?}"),
        }
    }

    // A block that does not extend the pool's tip removes the foreign
    // transactions, and this node's own ones stay, to be proven again.
    pool.insert(foreign.clone(), None, AddReason::FromPeer, now);
    assert_eq!(4, pool.len());
    let sibling = invalid_empty_block(&genesis, Network::Main);
    let (reorg_events, reorg_jobs) = pool.update_with_block(&sibling).unwrap();
    assert_eq!(1, num_removals(&reorg_events, RemovalReason::Orphaned));
    assert!(!pool.contains(foreign.txid()));
    assert_eq!(3, pool.len());
    assert_eq!(3, reorg_jobs.len());
}

#[test]
fn stale_transactions_are_pruned() {
    let mut pool = LegacyRelayPool::new(MAX_SIZE, &genesis());
    let transactions = own_transactions(2);
    let inserted_at = now(&transactions[0]);
    let own = transactions[0].clone();
    let foreign = with_fee(&transactions[1], 1);
    pool.insert(own.clone(), None, AddReason::Submitted, inserted_at);
    pool.insert(foreign.clone(), None, AddReason::FromPeer, inserted_at);

    // Within the time to live, nothing goes.
    let events = pool.prune_stale_transactions(inserted_at + Timestamp::minutes(29));
    assert!(events.is_empty());

    // After it, the foreign transaction goes, the own one stays.
    let ttl_events = pool.prune_stale_transactions(inserted_at + Timestamp::minutes(31));
    assert_eq!(1, num_removals(&ttl_events, RemovalReason::Pruned));
    assert!(pool.contains(own.txid()));
    assert!(!pool.contains(foreign.txid()));

    // The own one goes once its timestamp is too old for any node to take it.
    let too_late = own.kernel.timestamp
        + Timestamp::seconds(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS)
        + Timestamp::minutes(1);
    let age_events = pool.prune_stale_transactions(too_late);
    assert_eq!(1, num_removals(&age_events, RemovalReason::Pruned));
    assert!(pool.is_empty());
}

#[test]
fn clearing_returns_the_witnesses_of_own_transactions() {
    let mut pool = LegacyRelayPool::new(MAX_SIZE, &genesis());
    let transactions = own_transactions(3);
    let now = now(&transactions[0]);
    pool.insert(transactions[0].clone(), None, AddReason::Submitted, now);
    pool.insert(
        as_proof_collection(&transactions[1]),
        None,
        AddReason::FromPeer,
        now,
    );
    pool.insert(
        with_fee(&transactions[2], 1),
        None,
        AddReason::FromPeer,
        now,
    );

    let (events, witnesses) = pool.clear_and_take_own_witnesses(RemovalReason::Abandoned);
    assert_eq!(3, num_removals(&events, RemovalReason::Abandoned));
    assert_eq!(1, witnesses.len());
    assert_eq!(transactions[0].kernel, witnesses[0].kernel);
    assert!(pool.is_empty());
}

#[test]
fn accept_transaction_follows_proof_quality_and_sync_status() {
    let genesis = genesis();
    let tip_mutator_set_hash = genesis.mutator_set_accumulator_after().unwrap().hash();
    let mut pool = LegacyRelayPool::new(MAX_SIZE, &genesis);
    let own = own_transactions(1).pop().unwrap();
    let txid = own.txid();
    let unsynced = own.kernel.mutator_set_hash;
    assert_ne!(tip_mutator_set_hash, unsynced);

    assert!(pool.accept_transaction(txid, TransactionProofQuality::ProofCollection, unsynced));
    pool.insert(
        as_proof_collection(&own),
        None,
        AddReason::FromPeer,
        now(&own),
    );
    assert!(!pool.accept_transaction(txid, TransactionProofQuality::ProofCollection, unsynced));
    assert!(pool.accept_transaction(
        txid,
        TransactionProofQuality::ProofCollection,
        tip_mutator_set_hash
    ));
    assert!(pool.accept_transaction(txid, TransactionProofQuality::SingleProof, unsynced));
}
