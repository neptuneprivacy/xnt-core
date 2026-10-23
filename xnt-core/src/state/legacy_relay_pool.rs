//! A pool for the transactions of the era before the next hard fork.
//!
//! Main net follows the `UpgradeVMv7` consensus rule set until the
//! `UpgradeVMv8` hard fork, see
//! [`ConsensusRuleSet::is_legacy_era`](crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet::is_legacy_era).
//! While the next block belongs to that era, this node creates, verifies and
//! relays v7 transactions, but it neither composes blocks of that era nor
//! updates or merges v7 proofs: the nodes of the previous release do. So v7
//! transactions are held here, apart from the [`Mempool`], whose composer and
//! proof upgrader never see them.
//!
//! The pool holds two kinds of transactions:
//!
//!  - foreign ones, held for relaying until the next block, as the nodes of
//!    the previous release hold foreign proof collections: their mutator set
//!    data goes stale with every block, and this node cannot update it;
//!  - this node's own ones, together with their primitive witnesses, from
//!    which they are proven again on every block (see
//!    [`LegacyRelayPool::update_with_block`]).
//!
//! The pool is bounded in the number and total size of its transactions,
//! evicting the foreign transactions of the lowest fee density first, and it
//! holds no two transactions spending the same input. Foreign transactions
//! expire after [`FOREIGN_TRANSACTION_TTL`], and no transaction is held past
//! [`MEMPOOL_TX_THRESHOLD_AGE_IN_SECS`] after its timestamp, after which the
//! previous release refuses it.
//!
//! Like the [`Mempool`], the pool reports changes as [`MempoolEvent`]s, which
//! the caller forwards to the wallet; see [`GlobalState`](super::GlobalState).
//!
//! [`Mempool`]: super::mempool::Mempool

use std::collections::HashMap;
use std::collections::HashSet;

use get_size2::GetSize;
use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tracing::debug;

use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::peer::transfer_transaction::TransactionProofQuality;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::mempool::mempool_event::AddReason;
use crate::state::mempool::mempool_event::MempoolEvent;
use crate::state::mempool::mempool_event::RemovalReason;
use crate::state::mempool::mempool_update_job::MempoolUpdateJob;
use crate::state::mempool::primitive_witness_update::PrimitiveWitnessUpdate;
use crate::state::mempool::MEMPOOL_TX_THRESHOLD_AGE_IN_SECS;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;

/// The largest number of transactions the pool holds.
pub(crate) const MAX_NUM_TRANSACTIONS: usize = 512;

/// How long a foreign transaction is held, at most. It is normally dropped
/// earlier, by the next block.
pub(crate) const FOREIGN_TRANSACTION_TTL: Timestamp = Timestamp::minutes(30);

#[derive(Debug, Clone)]
struct PoolEntry {
    transaction: Transaction,

    /// The primitive witness of a transaction of this node, from which it is
    /// proven again. `None` for foreign transactions.
    primitive_witness: Option<PrimitiveWitness>,

    /// When the transaction entered the pool.
    inserted_at: Timestamp,

    /// The size of the transaction in memory, in bytes.
    size: usize,
}

impl PoolEntry {
    fn is_own(&self) -> bool {
        self.primitive_witness.is_some()
    }
}

/// How close a transaction's proof is to being mined: a primitive witness, a
/// proof collection, or a single proof.
fn proof_tier(proof: &TransactionProof) -> u8 {
    match proof {
        TransactionProof::Witness(_) => 0,
        TransactionProof::ProofCollection(_) => 1,
        TransactionProof::SingleProof(_) => 2,
    }
}

/// The input index sets of a kernel, by which two transactions spending the
/// same input are recognized.
fn input_index_sets(kernel: &TransactionKernel) -> HashSet<Vec<u128>> {
    kernel
        .inputs
        .iter()
        .map(|removal_record| removal_record.absolute_indices.to_array().to_vec())
        .collect()
}

/// The transactions of the era before the next hard fork, see the
/// [module documentation](self).
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct LegacyRelayPool {
    /// The largest total size of the transactions held, in bytes.
    max_total_size: usize,

    /// The largest number of transactions held.
    max_num_transactions: usize,

    entries: HashMap<TransactionKernelId, PoolEntry>,

    /// The digest of the tip the pool was last updated to, by which
    /// reorganizations are discovered.
    tip_digest: Digest,

    /// The hash of the tip's mutator set, against which transactions are
    /// synced.
    tip_mutator_set_hash: Digest,
}

impl LegacyRelayPool {
    /// An empty pool for the given tip, holding transactions of at most this
    /// total size in bytes.
    pub fn new(max_total_size: usize, tip: &Block) -> Self {
        Self {
            max_total_size,
            max_num_transactions: MAX_NUM_TRANSACTIONS,
            entries: HashMap::new(),
            tip_digest: tip.hash(),
            tip_mutator_set_hash: tip
                .mutator_set_accumulator_after()
                .expect("Provided block must have mutator set after")
                .hash(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, txid: TransactionKernelId) -> bool {
        self.entries.contains_key(&txid)
    }

    /// Whether the pool holds the transaction with this id as one of this
    /// node's, with its primitive witness.
    pub(crate) fn is_own(&self, txid: TransactionKernelId) -> bool {
        self.entries.get(&txid).is_some_and(PoolEntry::is_own)
    }

    /// The transaction with this id, if the pool holds it.
    pub fn get(&self, txid: TransactionKernelId) -> Option<&Transaction> {
        self.entries.get(&txid).map(|entry| &entry.transaction)
    }

    /// The primitive witness of the transaction with this id, if it is one of
    /// this node's.
    #[cfg(test)]
    pub(crate) fn primitive_witness(&self, txid: TransactionKernelId) -> Option<&PrimitiveWitness> {
        self.entries
            .get(&txid)
            .and_then(|entry| entry.primitive_witness.as_ref())
    }

    /// The number of transactions of this node in the pool.
    pub fn num_own(&self) -> usize {
        self.entries.values().filter(|entry| entry.is_own()).count()
    }

    /// The total size of the transactions held, in bytes.
    pub fn total_size(&self) -> usize {
        self.entries.values().map(|entry| entry.size).sum()
    }

    /// The ids of the transactions held, in descending order of fee density.
    pub fn txids_by_fee_density(&self) -> Vec<TransactionKernelId> {
        self.entries
            .iter()
            .map(|(txid, entry)| (*txid, entry.transaction.fee_density()))
            .sorted_by(|(_, left), (_, right)| right.cmp(left))
            .map(|(txid, _)| txid)
            .collect()
    }

    /// The transactions held, in no particular order.
    pub fn transactions(&self) -> impl Iterator<Item = &Transaction> {
        self.entries.values().map(|entry| &entry.transaction)
    }

    fn is_synced(&self, kernel: &TransactionKernel) -> bool {
        kernel.mutator_set_hash == self.tip_mutator_set_hash
    }

    /// Whether the pool would take a transaction with this id, proof quality
    /// and mutator set hash: it does not hold it, or holds it with a proof of
    /// lower quality, or unsynced while this one is synced.
    pub(crate) fn accept_transaction(
        &self,
        txid: TransactionKernelId,
        proof_quality: TransactionProofQuality,
        mutator_set_hash: Digest,
    ) -> bool {
        let Some(entry) = self.entries.get(&txid) else {
            return true;
        };
        let Ok(held_quality) = entry.transaction.proof.proof_quality() else {
            // Any proof is better than a primitive witness.
            return true;
        };

        held_quality < proof_quality
            || held_quality == proof_quality
                && !self.is_synced(&entry.transaction.kernel)
                && mutator_set_hash == self.tip_mutator_set_hash
    }

    /// Insert a transaction. It is the caller's responsibility to verify it
    /// under the rule set of the era before the fork.
    ///
    /// A transaction backed by a primitive witness, or inserted with one, is
    /// this node's own. An own transaction replaces whatever it conflicts
    /// with; a foreign one never replaces an own one, and replaces foreign
    /// ones only with a proof closer to being mined or, at the same proof
    /// quality, a higher fee density. A transaction already held under the
    /// same id is replaced only by a proof of higher quality, or by a synced
    /// one at the same quality; its primitive witness is kept.
    ///
    /// Returns the events for the wallet: none if the transaction was not
    /// taken.
    pub(crate) fn insert(
        &mut self,
        transaction: Transaction,
        primitive_witness: Option<PrimitiveWitness>,
        add_reason: AddReason,
        now: Timestamp,
    ) -> Vec<MempoolEvent> {
        let txid = transaction.txid();
        let primitive_witness = match &transaction.proof {
            TransactionProof::Witness(witness) => Some(witness.clone()),
            _ => primitive_witness.or_else(|| {
                self.entries
                    .get(&txid)
                    .and_then(|entry| entry.primitive_witness.clone())
            }),
        };
        let is_own = primitive_witness.is_some();

        if let Some(held) = self.entries.get(&txid) {
            if held.transaction == transaction {
                return vec![];
            }
            let new_tier = proof_tier(&transaction.proof);
            let held_tier = proof_tier(&held.transaction.proof);
            let replaces = new_tier > held_tier
                || new_tier == held_tier
                    && !self.is_synced(&held.transaction.kernel)
                    && self.is_synced(&transaction.kernel);
            if !replaces {
                debug!("Not adding transaction {txid} to the legacy pool: it holds a better one");
                return vec![];
            }
        }

        let new_inputs = input_index_sets(&transaction.kernel);
        let conflicts = self
            .entries
            .iter()
            .filter(|(held_txid, entry)| {
                **held_txid != txid
                    && !input_index_sets(&entry.transaction.kernel).is_disjoint(&new_inputs)
            })
            .map(|(conflicting_txid, entry)| (*conflicting_txid, entry))
            .collect_vec();
        if !is_own {
            let new_tier = proof_tier(&transaction.proof);
            let new_fee_density = transaction.fee_density();
            let wins = conflicts.iter().all(|(_, entry)| {
                let held_tier = proof_tier(&entry.transaction.proof);
                !entry.is_own()
                    && (new_tier > held_tier
                        || new_tier == held_tier
                            && new_fee_density > entry.transaction.fee_density())
            });
            if !wins {
                debug!(
                    "Not adding transaction {txid} to the legacy pool: it conflicts with a \
                     transaction that stays"
                );
                return vec![];
            }
        }

        let conflicting_txids = conflicts
            .into_iter()
            .map(|(conflicting_txid, _)| conflicting_txid)
            .collect_vec();
        let mut events = vec![];
        if let Some(held) = self.entries.remove(&txid) {
            events.push(MempoolEvent::RemoveTx(
                held.transaction.kernel,
                RemovalReason::Updated,
            ));
        }
        for conflicting_txid in conflicting_txids {
            if let Some(event) = self.remove(conflicting_txid, RemovalReason::Replaced) {
                events.push(event);
            }
        }

        let size = transaction.get_size();
        events.push(MempoolEvent::AddTx(transaction.kernel.clone(), add_reason));
        self.entries.insert(
            txid,
            PoolEntry {
                transaction,
                primitive_witness,
                inserted_at: now,
                size,
            },
        );

        events.extend(self.shrink_to_bounds());

        MempoolEvent::normalize(events)
    }

    /// Record the primitive witness of a transaction of this node. If the pool
    /// does not hold the transaction, it is inserted backed by the witness, so
    /// that the witness is not lost if the transaction arrives later with a
    /// proof.
    pub(crate) fn set_primitive_witness(
        &mut self,
        txid: TransactionKernelId,
        primitive_witness: PrimitiveWitness,
        now: Timestamp,
    ) -> Vec<MempoolEvent> {
        if let Some(entry) = self.entries.get_mut(&txid) {
            entry.primitive_witness = Some(primitive_witness);
            return vec![];
        }

        self.insert(primitive_witness.into(), None, AddReason::Updated, now)
    }

    /// Evict foreign transactions, those of the lowest fee density first,
    /// until the pool is within its bounds. This node's own transactions are
    /// not evicted.
    fn shrink_to_bounds(&mut self) -> Vec<MempoolEvent> {
        let mut events = vec![];
        let mut total_size = self.total_size();
        while self.entries.len() > self.max_num_transactions || total_size > self.max_total_size {
            let Some(victim) = self
                .entries
                .iter()
                .filter(|(_, entry)| !entry.is_own())
                .min_by_key(|(_, entry)| entry.transaction.fee_density())
                .map(|(txid, _)| *txid)
            else {
                break;
            };
            let entry = self.entries.remove(&victim).expect("victim exists");
            total_size -= entry.size;
            events.push(MempoolEvent::RemoveTx(
                entry.transaction.kernel,
                RemovalReason::MempoolFull,
            ));
        }

        events
    }

    /// Remove the transaction with this id, if the pool holds it.
    pub(crate) fn remove(
        &mut self,
        txid: TransactionKernelId,
        reason: RemovalReason,
    ) -> Option<MempoolEvent> {
        self.entries
            .remove(&txid)
            .map(|entry| MempoolEvent::RemoveTx(entry.transaction.kernel, reason))
    }

    /// Remove every transaction for which `keep` fails.
    fn retain(
        &mut self,
        mut keep: impl FnMut(&PoolEntry) -> bool,
        reason: RemovalReason,
    ) -> Vec<MempoolEvent> {
        let victims = self
            .entries
            .iter()
            .filter(|(_, entry)| !keep(entry))
            .map(|(txid, _)| *txid)
            .collect_vec();

        victims
            .into_iter()
            .filter_map(|txid| self.remove(txid, reason))
            .collect()
    }

    /// Remove every transaction.
    pub(crate) fn clear(&mut self, reason: RemovalReason) -> Vec<MempoolEvent> {
        self.retain(|_| false, reason)
    }

    /// Remove every transaction, and return the primitive witnesses of this
    /// node's own ones, so that they can be proven for the era after the fork.
    pub(crate) fn clear_and_take_own_witnesses(
        &mut self,
        reason: RemovalReason,
    ) -> (Vec<MempoolEvent>, Vec<PrimitiveWitness>) {
        let witnesses = self
            .entries
            .values()
            .filter_map(|entry| entry.primitive_witness.clone())
            .collect_vec();

        (self.clear(reason), witnesses)
    }

    /// Remove the foreign transactions that entered the pool more than
    /// [`FOREIGN_TRANSACTION_TTL`] ago, and every transaction whose timestamp
    /// is more than [`MEMPOOL_TX_THRESHOLD_AGE_IN_SECS`] old, which the nodes
    /// of the previous release refuse.
    pub(crate) fn prune_stale_transactions(&mut self, now: Timestamp) -> Vec<MempoolEvent> {
        let foreign_cutoff = now - FOREIGN_TRANSACTION_TTL;
        let timestamp_cutoff = now - Timestamp::seconds(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS);

        self.retain(
            |entry| {
                timestamp_cutoff < entry.transaction.kernel.timestamp
                    && (entry.is_own() || foreign_cutoff < entry.inserted_at)
            },
            RemovalReason::Pruned,
        )
    }

    /// Update the pool to a new tip.
    ///
    /// The transactions that spend an input the block spends are removed, and
    /// so are the foreign ones: their mutator set data is stale now, and this
    /// node cannot update it. This node's own transactions stay, also across a
    /// reorganization, for which an update job is returned for each. One
    /// backed by its primitive witness or a proof collection is proven again
    /// as a proof collection, also if the job that was to prove it first did
    /// not complete. Of one backed by a single proof, only the primitive
    /// witness is updated: the nodes of the previous release update single
    /// proofs themselves, and proving one again takes minutes and a large
    /// machine. An update that fails, as when the mutator set it was made for
    /// is not on the new chain, removes the transaction.
    ///
    /// Fails if the block does not have a mutator set after.
    pub(crate) fn update_with_block(
        &mut self,
        block: &Block,
    ) -> anyhow::Result<(Vec<MempoolEvent>, Vec<MempoolUpdateJob>)> {
        let mut events = vec![];
        if block.header().prev_block_digest != self.tip_digest {
            events.extend(self.retain(PoolEntry::is_own, RemovalReason::Orphaned));
        }

        let block_indices: HashSet<u128> = block
            .kernel
            .body
            .transaction_kernel
            .inputs
            .iter()
            .flat_map(|removal_record| removal_record.absolute_indices.to_array())
            .collect();
        let unspent = |entry: &PoolEntry| {
            entry
                .transaction
                .kernel
                .inputs
                .iter()
                .all(|removal_record| {
                    removal_record
                        .absolute_indices
                        .to_array()
                        .iter()
                        .any(|index| !block_indices.contains(index))
                })
        };
        events.extend(self.retain(unspent, RemovalReason::Merged));
        events.extend(self.retain(PoolEntry::is_own, RemovalReason::Abandoned));
        events.extend(self.retain(
            |entry| !entry.transaction.kernel.inputs.is_empty(),
            RemovalReason::EmptyInputs,
        ));

        let update_jobs = self
            .entries
            .values()
            .filter_map(|entry| {
                let witness = entry.primitive_witness.clone()?;
                let update = PrimitiveWitnessUpdate::new(witness);
                Some(match entry.transaction.proof {
                    TransactionProof::Witness(_) | TransactionProof::ProofCollection(_) => {
                        MempoolUpdateJob::ProofCollection(update)
                    }
                    TransactionProof::SingleProof(_) => MempoolUpdateJob::PrimitiveWitness(update),
                })
            })
            .collect_vec();

        self.tip_digest = block.hash();
        self.tip_mutator_set_hash = block.mutator_set_accumulator_after()?.hash();

        Ok((MempoolEvent::normalize(events), update_jobs))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
