//! Bridge registry - tracks pool UTXOs and unlock operations for the Leviathan bridge.
//!
//! **Pool entries**: Each deposit creates a pool UTXO. On withdrawal, the tx proof
//! handles unlock. This module only does pool DB bookkeeping.
//!
//! **Delta**: Per-block undo log for reorg rollback. Stores pool DB changes
//! and state commitment snapshot.

use std::collections::HashMap;

use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::InvalidBridgeChange;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::bridge::aggregated_announcement::AggregatedAnnouncementData;
use crate::protocol::consensus::bridge::authority::StoredBridgeAuthoritySet;
use crate::protocol::consensus::bridge::deposit_announcement::BridgeDepositData;
use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
use crate::protocol::consensus::bridge::pool_consolidation::input_digest;
use crate::protocol::consensus::bridge::pool_consolidation::utxo_input_digest;
use crate::protocol::consensus::bridge::pool_consolidation::PoolConsolidationAuthorization;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::util_types::mutator_set::commit;

/// A bridge pool UTXO entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoolEntry {
    pub utxo: Utxo,
    pub amount: NativeCurrencyAmount,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    /// AOCL leaf index from when the UTXO was added to the mutator set.
    /// Used by `restore_membership_proof` during unlock.
    pub aocl_leaf_index: u64,
}

impl PoolEntry {
    /// The pool DB key: unique per AOCL leaf, unlike the commitment two UTXOs can share.
    pub fn key(&self) -> PoolKey {
        utxo_input_digest(
            &self.utxo,
            self.sender_randomness,
            self.receiver_preimage,
            self.aocl_leaf_index,
        )
    }

    pub fn commitment(&self) -> Digest {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_preimage.hash(),
        )
        .canonical_commitment
    }
}

/// The authority set as it stood BEFORE a block rotated it, kept so a reorg can
/// restore it. Absent field (`None`) means the block did not rotate authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthorityRollback {
    /// No authority key was stored before this block → delete the key on revert.
    WasAbsent,
    /// The stored value before this block (inner `None` = explicitly cleared).
    WasSet(Option<StoredBridgeAuthoritySet>),
}

/// Per-block bridge delta for reorg rollback.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeRegistryDelta {
    pub pool_added: Vec<(Digest, PoolEntry)>,
    pub pool_removed: Vec<(Digest, PoolEntry)>,
    pub state_commitment: Option<Digest>,
    /// Previous authority set if this block rotated it (for reorg rollback).
    pub authority_rollback: Option<AuthorityRollback>,
    /// This block installed the (set-once) bridge registration.
    pub registered: bool,
}

impl BridgeRegistryDelta {
    pub fn new(state_commitment: Option<Digest>) -> Self {
        Self {
            pool_added: Vec::new(),
            pool_removed: Vec::new(),
            state_commitment,
            authority_rollback: None,
            registered: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pool_added.is_empty()
            && self.pool_removed.is_empty()
            && self.authority_rollback.is_none()
            && !self.registered
    }
}

pub type PoolKey = Digest;
pub type PoolValue = PoolEntry;
pub type DeltaKey = Digest;
pub type DeltaValue = BridgeRegistryDelta;

/// Pool entries keyed by [`PoolEntry::key`].
pub(crate) type PoolView = HashMap<PoolKey, PoolEntry>;

#[derive(Debug, Clone, Default)]
pub(crate) struct UnlockEffects {
    pub(crate) removed: Vec<(PoolKey, PoolEntry)>,
    pub(crate) change: Option<PoolChange>,
}

#[derive(Debug, Clone)]
pub(crate) struct PoolChange {
    pub(crate) commitment: Digest,
    pub(crate) output_index: usize,
    pub(crate) amount: NativeCurrencyAmount,
    pub(crate) sender_randomness: Digest,
}

impl PoolChange {
    pub(crate) fn entry(&self, prev_aocl_len: u64) -> PoolEntry {
        PoolEntry {
            utxo: Utxo::new_native_currency(bridge_lock_script().hash(), self.amount),
            amount: self.amount,
            sender_randomness: self.sender_randomness,
            receiver_preimage: Digest::default(),
            aocl_leaf_index: prev_aocl_len + self.output_index as u64,
        }
    }
}

pub(crate) fn first_output_aocl_index(block: &Block) -> u64 {
    let outputs = block.body().transaction_kernel.outputs.len() as u64;
    block
        .body()
        .mutator_set_accumulator_without_guesser_fees()
        .aocl
        .num_leafs()
        - outputs
}

/// A deposit whose commitment or output doesn't match is skipped.
pub(crate) fn bridge_deposit_entries(
    block: &Block,
    prev_aocl_len: u64,
) -> Vec<(PoolKey, PoolEntry)> {
    let lock_script_hash = bridge_lock_script().hash();
    let outputs = &block.body().transaction_kernel.outputs;
    let mut entries = vec![];
    for announcement in &block.body().transaction_kernel.announcements {
        let Some(deposit) = BridgeDepositData::from_announcement(announcement) else {
            continue;
        };

        let utxo = Utxo::new_native_currency(lock_script_hash, deposit.amount);
        let sender_randomness = Digest::new(deposit.sender_randomness);
        let receiver_preimage = Digest::new(deposit.receiver_preimage);
        let computed = commit(
            Tip5::hash(&utxo),
            sender_randomness,
            receiver_preimage.hash(),
        );
        let announced = Digest::new(deposit.utxo_commitment);
        if computed.canonical_commitment != announced {
            tracing::warn!(
                "Bridge deposit commitment mismatch: announced={}, computed={}, amount={}, lock_script_hash={}",
                announced.to_hex(),
                computed.canonical_commitment.to_hex(),
                deposit.amount,
                lock_script_hash.to_hex(),
            );
            continue;
        }

        let Some(pos) = outputs
            .iter()
            .position(|o| o.canonical_commitment == announced)
        else {
            tracing::warn!(
                "Bridge deposit {} not found in block outputs",
                announced.to_hex()
            );
            continue;
        };
        tracing::info!(
            "Bridge deposit accepted: commitment={}, amount={}",
            announced.to_hex(),
            deposit.amount,
        );
        let entry = PoolEntry {
            utxo,
            amount: deposit.amount,
            sender_randomness,
            receiver_preimage,
            aocl_leaf_index: prev_aocl_len + pos as u64,
        };
        entries.push((entry.key(), entry));
    }
    entries
}

/// Errors mean apply could not track the change, so the block (or tx) is invalid.
pub(crate) fn bridge_unlock_effects(
    kernel: &TransactionKernel,
    pool: &PoolView,
) -> Result<UnlockEffects, InvalidBridgeChange> {
    let Some(ann) = AggregatedAnnouncementData::find_in_announcements(&kernel.announcements) else {
        return Ok(UnlockEffects::default());
    };

    let removed = kernel
        .inputs
        .iter()
        .filter_map(|input| {
            let key = input_digest(input);
            pool.get(&key).map(|entry| (key, entry.clone()))
        })
        .collect::<Vec<_>>();

    let authorization =
        PoolConsolidationAuthorization::find_in_announcements(&kernel.announcements);
    if let Some(auth) = &authorization {
        let mut spent = removed.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        spent.sort();
        if spent != auth.input_digests {
            return Err(InvalidBridgeChange::ConsolidationInputsMismatch);
        }
    }

    let Some(change_sr) = ann.change_sender_randomness else {
        return Ok(UnlockEffects {
            removed,
            change: None,
        });
    };
    let total_burn = ann
        .burns
        .iter()
        .try_fold(NativeCurrencyAmount::zero(), |total, burn| {
            total.checked_add(&burn.payout()?)
        })
        .ok_or(InvalidBridgeChange::AmountOverflow)?;
    let total_consumed = removed
        .iter()
        .try_fold(NativeCurrencyAmount::zero(), |total, (_, entry)| {
            total.checked_add(&entry.amount)
        })
        .ok_or(InvalidBridgeChange::AmountOverflow)?;
    let change_amount = total_consumed
        .checked_sub(&total_burn)
        .ok_or(InvalidBridgeChange::BurnsExceedPoolInputs)?;

    let change = if change_amount.is_zero() {
        None
    } else {
        let utxo = Utxo::new_native_currency(bridge_lock_script().hash(), change_amount);
        let commitment =
            commit(Tip5::hash(&utxo), change_sr, Digest::default().hash()).canonical_commitment;
        let output_index = kernel
            .outputs
            .iter()
            .position(|o| o.canonical_commitment == commitment)
            .ok_or(InvalidBridgeChange::ChangeMissing(commitment))?;
        Some(PoolChange {
            commitment,
            output_index,
            amount: change_amount,
            sender_randomness: change_sr,
        })
    };

    if let Some(auth) = authorization {
        let rebuilt = change.as_ref().map(|change| change.commitment);
        if rebuilt != Some(auth.change_commitment) {
            return Err(InvalidBridgeChange::ConsolidationChangeMismatch {
                rebuilt,
                signed: auth.change_commitment,
            });
        }
    }
    Ok(UnlockEffects { removed, change })
}

/// As apply does to the pool DB; the settlement only under `bav_active`.
pub(crate) fn advance_pool(
    pool: &mut PoolView,
    block: &Block,
    bav_active: bool,
) -> Result<(), InvalidBridgeChange> {
    if !bav_active {
        return Ok(());
    }
    let prev_aocl_len = first_output_aocl_index(block);
    pool.extend(bridge_deposit_entries(block, prev_aocl_len));
    let effects = bridge_unlock_effects(&block.body().transaction_kernel, pool)?;
    for (key, _) in &effects.removed {
        pool.remove(key);
    }
    if let Some(change) = effects.change {
        let entry = change.entry(prev_aocl_len);
        pool.insert(entry.key(), entry);
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use super::*;
    use crate::protocol::consensus::bridge::aggregated_announcement::BurnRecord;
    use crate::protocol::consensus::bridge::aggregated_announcement::StatePreimage;
    use crate::protocol::consensus::bridge::aggregated_announcement::STATE_PREIMAGE_LEN;
    use crate::protocol::consensus::bridge::faucet_registration::FaucetId;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    fn pool_of(entries: &[&PoolEntry]) -> PoolView {
        entries.iter().map(|e| (e.key(), (*e).clone())).collect()
    }

    fn change_sr() -> Digest {
        Digest::new([BFieldElement::new(4); Digest::LEN])
    }

    fn entry(coins: u32, aocl_leaf_index: u64) -> PoolEntry {
        let amount = NativeCurrencyAmount::coins(coins);
        PoolEntry {
            utxo: Utxo::new_native_currency(bridge_lock_script().hash(), amount),
            amount,
            sender_randomness: Digest::new([BFieldElement::new(aocl_leaf_index); Digest::LEN]),
            receiver_preimage: Digest::default(),
            aocl_leaf_index,
        }
    }

    fn spending(entry: &PoolEntry) -> RemovalRecord {
        RemovalRecord {
            absolute_indices: AbsoluteIndexSet::compute(
                Tip5::hash(&entry.utxo),
                entry.sender_randomness,
                entry.receiver_preimage,
                entry.aocl_leaf_index,
            ),
            target_chunks: Default::default(),
        }
    }

    fn change(coins: u32) -> AdditionRecord {
        let utxo = Utxo::new_native_currency(
            bridge_lock_script().hash(),
            NativeCurrencyAmount::coins(coins),
        );
        commit(Tip5::hash(&utxo), change_sr(), Digest::default().hash())
    }

    fn settlement_tx(
        burns: Vec<BurnRecord>,
        inputs: Vec<RemovalRecord>,
        outputs: Vec<AdditionRecord>,
    ) -> TransactionKernel {
        let settlement = AggregatedAnnouncementData {
            prev_state_commitment: Digest::default(),
            new_state_commitment: Digest::new([BFieldElement::new(1); Digest::LEN]),
            exit_root: Digest::default(),
            faucet_id: FaucetId {
                suffix: BFieldElement::new(1),
                prefix: BFieldElement::new(2),
            },
            prev_state_preimage: StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
            burns,
            change_sender_randomness: Some(change_sr()),
            authority_signatures: vec![],
        };
        TransactionKernelProxy {
            inputs,
            outputs,
            announcements: vec![settlement.to_announcement()],
            fee: NativeCurrencyAmount::zero(),
            coinbase: None,
            timestamp: Timestamp::now(),
            mutator_set_hash: Digest::default(),
            merge_bit: false,
        }
        .into_kernel()
    }

    #[test]
    fn settlement_spends_its_pool_inputs_into_the_change() {
        let (a, b) = (entry(1, 3), entry(2, 4));
        let pool = pool_of(&[&a, &b]);
        let effects = bridge_unlock_effects(
            &settlement_tx(vec![], vec![spending(&a)], vec![change(1)]),
            &pool,
        )
        .unwrap();
        assert_eq!(effects.removed.len(), 1);
        let change = effects.change.unwrap();
        assert_eq!(change.amount, NativeCurrencyAmount::coins(1));
        assert_eq!(change.entry(7).aocl_leaf_index, 7);
    }

    #[test]
    fn untrackable_change_is_an_error() {
        let a = entry(3, 3);
        let pool = pool_of(&[&a]);
        // The change BAAV forced also counts an input the pool doesn't track.
        assert!(matches!(
            bridge_unlock_effects(
                &settlement_tx(vec![], vec![spending(&a)], vec![change(5)]),
                &pool
            ),
            Err(InvalidBridgeChange::ChangeMissing(_))
        ));
        let burn = BurnRecord {
            receiver_identifier: BFieldElement::new(0),
            privacy_digest: Digest::default(),
            lock_script_hash: Digest::default(),
            amount: 1_000_000,
            serial: [BFieldElement::new(0); 4],
        };
        assert!(matches!(
            bridge_unlock_effects(&settlement_tx(vec![burn], vec![], vec![]), &pool),
            Err(InvalidBridgeChange::BurnsExceedPoolInputs)
        ));
    }

    fn consolidation_tx(
        authorization: &PoolConsolidationAuthorization,
        inputs: Vec<RemovalRecord>,
        outputs: Vec<AdditionRecord>,
    ) -> TransactionKernel {
        let no_op = AggregatedAnnouncementData {
            prev_state_commitment: Digest::default(),
            new_state_commitment: Digest::default(),
            exit_root: Digest::default(),
            faucet_id: FaucetId {
                suffix: BFieldElement::new(1),
                prefix: BFieldElement::new(2),
            },
            prev_state_preimage: StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
            burns: vec![],
            change_sender_randomness: Some(change_sr()),
            authority_signatures: vec![],
        };
        TransactionKernelProxy {
            inputs,
            outputs,
            announcements: vec![no_op.to_announcement(), authorization.to_announcement()],
            fee: NativeCurrencyAmount::zero(),
            coinbase: None,
            timestamp: Timestamp::now(),
            mutator_set_hash: Digest::default(),
            merge_bit: false,
        }
        .into_kernel()
    }

    #[test]
    fn consolidation_must_spend_exactly_the_signed_pool_entries() {
        let (a, b, c) = (entry(1, 3), entry(2, 4), entry(4, 5));
        let pool = pool_of(&[&a, &b, &c]);
        let signed = PoolConsolidationAuthorization::new(
            change(3).canonical_commitment,
            vec![a.key(), b.key()],
        );

        let extra_pool_input = consolidation_tx(
            &signed,
            vec![spending(&a), spending(&b), spending(&c)],
            vec![change(7)],
        );
        assert!(matches!(
            bridge_unlock_effects(&extra_pool_input, &pool),
            Err(InvalidBridgeChange::ConsolidationInputsMismatch)
        ));

        // The pool tracks the decoy, so its value is unchanged and only the attacker pays.
        let rogue = spending(&entry(5, 99));
        let decoy = change(3);
        let attack = consolidation_tx(
            &signed,
            vec![spending(&a), spending(&b), rogue],
            vec![change(8), decoy],
        );
        let effects = bridge_unlock_effects(&attack, &pool).unwrap();
        let removed = effects
            .removed
            .iter()
            .map(|(_, entry)| entry.amount)
            .sum::<NativeCurrencyAmount>();
        let tracked_change = effects.change.unwrap();
        assert_eq!(removed, NativeCurrencyAmount::coins(3));
        assert_eq!(tracked_change.amount, removed);
        assert_eq!(tracked_change.commitment, decoy.canonical_commitment);
        assert_eq!(tracked_change.output_index, 1);
    }

    #[test]
    fn colliding_deposit_and_change_are_both_tracked() {
        use crate::api::export::Network;
        use crate::protocol::consensus::bridge::deposit_announcement::BridgeDepositData;
        use crate::protocol::consensus::transaction::announcement::Announcement;
        use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
        use crate::tests::shared::blocks::invalid_block_with_transaction;
        use crate::tests::shared::mock_tx::make_mock_transaction_with_mutator_set_hash;

        let block_spending = |parent: &Block,
                              inputs: Vec<RemovalRecord>,
                              outputs: Vec<AdditionRecord>,
                              announcements: Vec<Announcement>| {
            let mut tx = make_mock_transaction_with_mutator_set_hash(
                inputs,
                outputs,
                parent.mutator_set_accumulator_after().unwrap().hash(),
            );
            tx.kernel = TransactionKernelModifier::default()
                .announcements(announcements)
                .modify(tx.kernel);
            invalid_block_with_transaction(parent, tx)
        };

        let (a, b) = (entry(1, 3), entry(2, 4));
        let mut pool = pool_of(&[&a, &b]);
        // A deposit copying the change's commitment, a block before the consolidation.
        let collider = BridgeDepositData {
            account_id: [BFieldElement::new(3), BFieldElement::new(4)],
            amount: NativeCurrencyAmount::coins(3),
            utxo_commitment: change(3).canonical_commitment.values(),
            sender_randomness: change_sr().values(),
            receiver_preimage: Digest::default().values(),
        }
        .to_announcement();
        let genesis = Block::genesis(Network::RegTest);
        let deposit_block = block_spending(&genesis, vec![], vec![change(3)], vec![collider]);
        let mut before_the_bridge = pool.clone();
        advance_pool(&mut before_the_bridge, &deposit_block, false).unwrap();
        assert_eq!(
            pool, before_the_bridge,
            "no deposits are pooled before the bridge"
        );
        advance_pool(&mut pool, &deposit_block, true).unwrap();

        let auth = PoolConsolidationAuthorization::new(
            change(3).canonical_commitment,
            vec![a.key(), b.key()],
        );
        let consolidation =
            consolidation_tx(&auth, vec![spending(&a), spending(&b)], vec![change(3)]);
        let consolidation_block = block_spending(
            &deposit_block,
            consolidation.inputs.clone(),
            consolidation.outputs.clone(),
            consolidation.announcements.clone(),
        );
        advance_pool(&mut pool, &consolidation_block, true).unwrap();

        assert_eq!(pool.len(), 2);
        assert!(pool
            .values()
            .all(|entry| entry.commitment() == change(3).canonical_commitment));
        assert!(pool
            .values()
            .all(|entry| entry.amount == NativeCurrencyAmount::coins(3)));
    }
}
