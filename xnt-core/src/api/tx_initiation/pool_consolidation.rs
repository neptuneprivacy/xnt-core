//! Flow: [`pool_consolidation_authorization`], have the authority sign its digest,
//! [`build_pool_consolidation`], [`produce_pool_consolidation`], then merge with a fee tx.

use std::sync::Arc;

use num_traits::CheckedAdd;
use num_traits::Zero;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::application::config::network::Network;
use crate::application::json_rpc::core::model::message::RpcPoolEntry;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::bridge::aggregated_announcement::AggregatedAnnouncementData;
use crate::protocol::consensus::bridge::aggregated_announcement::StatePreimage;
use crate::protocol::consensus::bridge::aggregated_announcement::STATE_PREIMAGE_LEN;
use crate::protocol::consensus::bridge::authority::AUTHORITY_SIGNATURE_BYTES;
use crate::protocol::consensus::bridge::faucet_registration::FaucetId;
use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
use crate::protocol::consensus::bridge::pool_consolidation::PoolConsolidationAuthorization;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::transaction::validity::single_proof::produce_single_proof;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::bridge_pool::PoolEntry;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::unlocked_utxo::UnlockedUtxo;
use crate::state::wallet::utxo_notification::UtxoNotificationMethod;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// Fewer would churn the pool without shrinking it much; the signer enforces it.
pub const MIN_POOL_CONSOLIDATION_INPUTS: usize = 8;

/// Keeps its merge with a one-input fee tx within 2^21 (about 59k Ram rows per input).
pub const MAX_POOL_CONSOLIDATION_INPUTS: usize = 22;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PoolConsolidationError {
    #[error("{got} pool inputs, need at least {MIN_POOL_CONSOLIDATION_INPUTS}")]
    TooFewInputs { got: usize },

    #[error("{got} pool inputs, at most {MAX_POOL_CONSOLIDATION_INPUTS}")]
    TooManyInputs { got: usize },

    #[error("{entries} pool entries but {proofs} membership proofs")]
    ProofCountMismatch { entries: usize, proofs: usize },

    #[error(
        "pool entry at AOCL {aocl_leaf_index} rebuilds to another commitment or input digest than the node's"
    )]
    CommitmentMismatch { aocl_leaf_index: u64 },

    #[error("pool entry at AOCL {aocl_leaf_index} is not locked by the bridge lock script")]
    NotPoolLocked { aocl_leaf_index: u64 },

    #[error("pool total overflows")]
    AmountOverflow,

    #[error("the authorization does not list these pool inputs and change")]
    AuthorizationMismatch,
}

fn pool_utxos(
    entries: &[RpcPoolEntry],
) -> Result<(Vec<Utxo>, NativeCurrencyAmount), PoolConsolidationError> {
    if entries.len() < MIN_POOL_CONSOLIDATION_INPUTS {
        return Err(PoolConsolidationError::TooFewInputs { got: entries.len() });
    }
    if entries.len() > MAX_POOL_CONSOLIDATION_INPUTS {
        return Err(PoolConsolidationError::TooManyInputs { got: entries.len() });
    }
    let bridge_lock_hash = bridge_lock_script().hash();
    let mut total = NativeCurrencyAmount::zero();
    let mut utxos = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.lock_script_hash != bridge_lock_hash {
            return Err(PoolConsolidationError::NotPoolLocked {
                aocl_leaf_index: entry.aocl_leaf_index,
            });
        }
        let amount = NativeCurrencyAmount::from(entry.amount_nau);
        let utxo = Utxo::new_native_currency(entry.lock_script_hash, amount);
        let rebuilt = PoolEntry {
            utxo: utxo.clone(),
            amount,
            sender_randomness: entry.sender_randomness,
            receiver_preimage: entry.receiver_preimage,
            aocl_leaf_index: entry.aocl_leaf_index,
        };
        if rebuilt.commitment() != entry.commitment || rebuilt.key() != entry.input_digest {
            return Err(PoolConsolidationError::CommitmentMismatch {
                aocl_leaf_index: entry.aocl_leaf_index,
            });
        }
        total = total
            .checked_add(&amount)
            .ok_or(PoolConsolidationError::AmountOverflow)?;
        utxos.push(utxo);
    }
    Ok((utxos, total))
}

/// The pool change: receiver preimage default, as apply rebuilds it.
fn change_output(total: NativeCurrencyAmount, change_sender_randomness: Digest) -> TxOutput {
    TxOutput::new(
        Utxo::new_native_currency(bridge_lock_script().hash(), total),
        change_sender_randomness,
        Digest::default().hash(),
        UtxoNotificationMethod::None,
        false,
        false,
    )
}

/// What the authority signs, via [`PoolConsolidationAuthorization::digest`].
pub fn pool_consolidation_authorization(
    entries: &[RpcPoolEntry],
    change_sender_randomness: Digest,
) -> Result<PoolConsolidationAuthorization, PoolConsolidationError> {
    let (_, total) = pool_utxos(entries)?;
    let pool_digests = entries.iter().map(|entry| entry.input_digest);
    Ok(PoolConsolidationAuthorization::new(
        change_output(total, change_sender_randomness)
            .addition_record()
            .canonical_commitment,
        pool_digests.collect(),
    ))
}

/// Fee 0: the fee comes from the tx it is merged with.
#[expect(clippy::too_many_arguments)]
pub fn build_pool_consolidation(
    entries: &[RpcPoolEntry],
    membership_proofs: Vec<MsMembershipProof>,
    msa: MutatorSetAccumulator,
    faucet_id: FaucetId,
    state_commitment: Digest,
    change_sender_randomness: Digest,
    authorization: &PoolConsolidationAuthorization,
    authority_signatures: Vec<[u8; AUTHORITY_SIGNATURE_BYTES]>,
    timestamp: Timestamp,
    network: Network,
) -> Result<PrimitiveWitness, PoolConsolidationError> {
    let (utxos, total) = pool_utxos(entries)?;
    if entries.len() != membership_proofs.len() {
        return Err(PoolConsolidationError::ProofCountMismatch {
            entries: entries.len(),
            proofs: membership_proofs.len(),
        });
    }
    if *authorization != pool_consolidation_authorization(entries, change_sender_randomness)? {
        return Err(PoolConsolidationError::AuthorizationMismatch);
    }
    let change = change_output(total, change_sender_randomness);

    let inputs: Vec<UnlockedUtxo> = utxos
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
    let settlement = AggregatedAnnouncementData {
        prev_state_commitment: state_commitment,
        new_state_commitment: state_commitment,
        exit_root: Digest::default(),
        faucet_id,
        prev_state_preimage: StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
        burns: vec![],
        change_sender_randomness: Some(change_sender_randomness),
        authority_signatures,
    };
    let details = TransactionDetails::new(
        inputs,
        vec![change],
        NativeCurrencyAmount::zero(),
        None,
        timestamp,
        msa,
        network,
    )
    .with_announcements(vec![
        settlement.to_announcement(),
        authorization.to_announcement(),
    ]);
    Ok(PrimitiveWitness::from_transaction_details(&details))
}

pub async fn produce_pool_consolidation(
    primitive_witness: &PrimitiveWitness,
    triton_vm_job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
    consensus_rule_set: ConsensusRuleSet,
) -> anyhow::Result<Transaction> {
    anyhow::ensure!(
        consensus_rule_set.bav_active(),
        "the bridge is not active under consensus rule set {consensus_rule_set}"
    );
    let proof = produce_single_proof(
        primitive_witness,
        triton_vm_job_queue,
        proof_job_options,
        consensus_rule_set,
    )
    .await?;
    Ok(Transaction {
        kernel: primitive_witness.kernel.clone(),
        proof: TransactionProof::SingleProof(proof),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;

    use super::*;
    use crate::application::triton_vm_job_queue::vm_job_queue;
    use crate::protocol::consensus::bridge::pool_consolidation::input_digest;
    use crate::protocol::consensus::transaction::validity::bridge_aggregated_announcement_validator::tests::bridge_pw;
    use crate::protocol::consensus::transaction::validity::bridge_aggregated_announcement_validator::tests::pool_utxo;
    use crate::protocol::consensus::transaction::validity::bridge_aggregated_announcement_validator::BridgeAggregatedAnnouncementValidator;
    use crate::protocol::consensus::transaction::validity::bridge_aggregated_announcement_validator::BridgeAggregatedAnnouncementValidatorWitness;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::protocol::proof_abstractions::SecretWitness;
    use crate::tests::shared_tokio_runtime;

    const NETWORK: Network = Network::RegTest;

    #[apply(shared_tokio_runtime)]
    async fn no_pool_consolidation_before_the_bridge_era() {
        let pw = bridge_pw(
            &[pool_utxo(1)],
            &[pool_utxo(1)],
            &[],
            NativeCurrencyAmount::zero(),
            None,
        );
        let result = produce_pool_consolidation(
            &pw,
            vm_job_queue(),
            TritonVmProofJobOptions::default_with_network(NETWORK),
            ConsensusRuleSet::UpgradeVMv8,
        )
        .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("the bridge is not active"));
    }

    struct Pool {
        entries: Vec<RpcPoolEntry>,
        membership_proofs: Vec<MsMembershipProof>,
        msa: MutatorSetAccumulator,
    }

    fn pool(n: usize) -> Pool {
        let pw = bridge_pw(
            &vec![pool_utxo(1); n],
            &[pool_utxo(u32::try_from(n).unwrap())],
            &[],
            NativeCurrencyAmount::zero(),
            None,
        );
        let entries = pw
            .input_utxos
            .utxos
            .iter()
            .zip(&pw.input_membership_proofs)
            .map(|(utxo, mp)| {
                let entry = PoolEntry {
                    utxo: utxo.clone(),
                    amount: NativeCurrencyAmount::coins(1),
                    sender_randomness: mp.sender_randomness,
                    receiver_preimage: mp.receiver_preimage,
                    aocl_leaf_index: mp.aocl_leaf_index,
                };
                RpcPoolEntry {
                    commitment: entry.commitment(),
                    input_digest: entry.key(),
                    lock_script_hash: utxo.lock_script_hash(),
                    amount_nau: entry.amount.into(),
                    sender_randomness: entry.sender_randomness,
                    receiver_preimage: entry.receiver_preimage,
                    aocl_leaf_index: entry.aocl_leaf_index,
                }
            })
            .collect();
        Pool {
            entries,
            membership_proofs: pw.input_membership_proofs,
            msa: pw.mutator_set_accumulator,
        }
    }

    fn faucet() -> FaucetId {
        FaucetId {
            suffix: BFieldElement::new(1),
            prefix: BFieldElement::new(2),
        }
    }

    fn build(
        pool: &Pool,
        authorization: &PoolConsolidationAuthorization,
    ) -> Result<PrimitiveWitness, PoolConsolidationError> {
        build_pool_consolidation(
            &pool.entries,
            pool.membership_proofs.clone(),
            pool.msa.clone(),
            faucet(),
            Digest::default(),
            change_sr(),
            authorization,
            vec![],
            Timestamp::now(),
            NETWORK,
        )
    }

    fn change_sr() -> Digest {
        Digest::new([BFieldElement::new(4); Digest::LEN])
    }

    #[test]
    fn consolidation_takes_the_no_proof_path_and_lists_its_inputs() {
        let pool = pool(MIN_POOL_CONSOLIDATION_INPUTS);
        let authorization = pool_consolidation_authorization(&pool.entries, change_sr()).unwrap();
        let pw = build(&pool, &authorization).unwrap();
        let mut spent = pw
            .kernel
            .inputs
            .iter()
            .map(input_digest)
            .collect::<Vec<_>>();
        spent.sort();
        assert_eq!(spent, authorization.input_digests);

        let settlement =
            AggregatedAnnouncementData::find_in_announcements(&pw.kernel.announcements).unwrap();
        assert!(settlement.is_pool_consolidation());
        let witness =
            BridgeAggregatedAnnouncementValidatorWitness::from_announcement(settlement, None, pw);
        BridgeAggregatedAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .expect("BAAV accepts the consolidation without a converted proof");
    }

    #[test]
    fn refuses_wrong_counts_commitments_and_authorizations() {
        let few = pool(MIN_POOL_CONSOLIDATION_INPUTS - 1);
        assert!(matches!(
            pool_consolidation_authorization(&few.entries, change_sr()),
            Err(PoolConsolidationError::TooFewInputs { .. })
        ));

        let mut forged = pool(MIN_POOL_CONSOLIDATION_INPUTS);
        forged.entries[0].amount_nau = NativeCurrencyAmount::coins(2).into();
        assert!(matches!(
            pool_consolidation_authorization(&forged.entries, change_sr()),
            Err(PoolConsolidationError::CommitmentMismatch { .. })
        ));

        let pool = pool(MIN_POOL_CONSOLIDATION_INPUTS + 1);
        let other_change =
            pool_consolidation_authorization(&pool.entries, Digest::default()).unwrap();
        let other_inputs =
            pool_consolidation_authorization(&pool.entries[1..], change_sr()).unwrap();
        for other in [other_change, other_inputs] {
            assert!(matches!(
                build(&pool, &other),
                Err(PoolConsolidationError::AuthorizationMismatch)
            ));
        }
    }
}
