//! Flow: build the settlement announcement and have the authority sign it, [`build_settlement`],
//! `ProofCollection::produce_settlement`, then merge with a fee tx (see `settlement_fee`).

use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use num_traits::Zero;
use tasm_lib::prelude::Digest;

use crate::application::config::network::Network;
use crate::protocol::consensus::bridge::aggregated_announcement::AggregatedAnnouncementData;
use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::unlocked_utxo::UnlockedUtxo;
use crate::state::wallet::utxo_notification::UtxoNotificationMethod;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SettlementBuildError {
    #[error("{inputs} pool inputs but {proofs} membership proofs")]
    ProofCountMismatch { inputs: usize, proofs: usize },

    #[error("pool input {index} is not locked by the bridge lock script")]
    NotPoolLocked { index: usize },

    #[error("pool or burn total overflows")]
    AmountOverflow,

    #[error("burns exceed the pool inputs")]
    BurnsExceedPoolInputs,

    #[error("the announcement's change randomness must be set exactly when there is change")]
    ChangeRandomnessMismatch,
}

/// Fee 0: the fee comes from the tx it is merged with. `announcement` is final (change randomness
/// and signatures set); its outputs are one payout per burn record, in order, then the change.
pub fn build_settlement(
    pool_inputs: Vec<Utxo>,
    membership_proofs: Vec<MsMembershipProof>,
    msa: MutatorSetAccumulator,
    announcement: &AggregatedAnnouncementData,
    timestamp: Timestamp,
    network: Network,
) -> Result<PrimitiveWitness, SettlementBuildError> {
    if pool_inputs.len() != membership_proofs.len() {
        return Err(SettlementBuildError::ProofCountMismatch {
            inputs: pool_inputs.len(),
            proofs: membership_proofs.len(),
        });
    }
    let bridge_lock_hash = bridge_lock_script().hash();
    if let Some(index) = pool_inputs
        .iter()
        .position(|utxo| utxo.lock_script_hash() != bridge_lock_hash)
    {
        return Err(SettlementBuildError::NotPoolLocked { index });
    }

    let pool_total = pool_inputs
        .iter()
        .try_fold(NativeCurrencyAmount::zero(), |total, utxo| {
            total.checked_add(&utxo.get_native_currency_amount())
        })
        .ok_or(SettlementBuildError::AmountOverflow)?;
    let mut outputs = Vec::with_capacity(announcement.burns.len() + 1);
    let mut burn_total = NativeCurrencyAmount::zero();
    for burn in &announcement.burns {
        let payout = burn.payout().ok_or(SettlementBuildError::AmountOverflow)?;
        burn_total = burn_total
            .checked_add(&payout)
            .ok_or(SettlementBuildError::AmountOverflow)?;
        outputs.push(TxOutput::new(
            Utxo::new_native_currency(burn.lock_script_hash, payout),
            burn.sender_randomness(),
            burn.privacy_digest,
            UtxoNotificationMethod::None,
            false,
            false,
        ));
    }
    let change = pool_total
        .checked_sub(&burn_total)
        .ok_or(SettlementBuildError::BurnsExceedPoolInputs)?;
    match (change.is_zero(), announcement.change_sender_randomness) {
        (true, None) => (),
        (false, Some(change_sender_randomness)) => outputs.push(TxOutput::new(
            Utxo::new_native_currency(bridge_lock_hash, change),
            change_sender_randomness,
            Digest::default().hash(),
            UtxoNotificationMethod::None,
            false,
            false,
        )),
        _ => return Err(SettlementBuildError::ChangeRandomnessMismatch),
    }

    let inputs: Vec<UnlockedUtxo> = pool_inputs
        .into_iter()
        .zip(membership_proofs)
        .map(|(utxo, membership_proof)| {
            UnlockedUtxo::unlock(
                utxo,
                LockScriptAndWitness::new(bridge_lock_script().program),
                membership_proof,
            )
        })
        .collect();
    let details = TransactionDetails::new(
        inputs,
        outputs,
        NativeCurrencyAmount::zero(),
        None,
        timestamp,
        msa,
        network,
    )
    .with_announcements(vec![announcement.to_announcement()]);
    Ok(PrimitiveWitness::from_transaction_details(&details))
}
