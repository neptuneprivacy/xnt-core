//! The rules deciding which link transactions this node admits to its
//! mempool.
//!
//! These are *policy*, not consensus. What the rules express is which link
//! transactions this node is willing to store and relay. Link transactions
//! must be synced to the tip, since their thruputs are checked against the
//! current mempool.
//!
//! The order in which the rules are applied is deliberate. Verifying a link
//! transaction's proof costs orders of magnitude more than every other check
//! combined. So validity is established last, once no cheaper reason to reject
//! the link transaction remains.
//!
//! This function does *not* check that a link transaction's thruputs are
//! outputs of mempool members; [`Mempool::insert_link`] refuses those that are
//! not, and callers may check it beforehand with
//! [`Mempool::contains_outputs`] to avoid verifying a proof in vain.
//!
//! [`Mempool::insert_link`]: super::Mempool::insert_link
//! [`Mempool::contains_outputs`]: super::Mempool::contains_outputs

use crate::protocol::consensus::bridge::has_proof_bound_tag;
use std::collections::HashSet;

use crate::application::config::network::Network;
use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::protocol::consensus::block::FUTUREDATING_LIMIT;
use crate::protocol::consensus::chaintx::link_tx::LinkTx;
use crate::protocol::consensus::chaintx::link_tx::LinkTxProof;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::consensus_rule_set::TransactionTooBig;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionConfirmabilityError;
use crate::protocol::consensus::transaction::validity::single_proof_v2::link_tx_claim;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::protocol::proof_abstractions::verifier::verify_transaction_proof;
use crate::state::mempool::MEMPOOL_TX_THRESHOLD_AGE_IN_SECS;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use tasm_lib::prelude::Digest;

/// Why a link transaction was refused admission to the mempool.
///
/// Rejection is not a claim that the link transaction is invalid: several of
/// these reasons describe link transactions that are perfectly valid but not
/// admissible on this node right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkTxAdmissionError {
    /// The rule set has no chain branches, so the link transaction could not
    /// be fixed into a block-eligible transaction.
    NotYetActive,

    /// Not built against the tip.
    NotSynced,

    /// Only the miner may produce transactions that mint a coinbase.
    HasCoinbase,

    /// Carries a bridge announcement that only a ProofCollection-backed transaction may carry.
    ProofBoundAnnouncement,

    /// Only proof upgraders may produce transactions with negative fees.
    NegativeFee,

    /// More items than a mempool transaction may have. Thruputs count as
    /// inputs.
    TooBig(TransactionTooBig),

    /// The same output is listed as a thruput more than once.
    DuplicateThruput,

    /// A thruput is also one of the link transaction's own outputs.
    ThruputIsOwnOutput,

    /// Older than the mempool is willing to hold.
    TooOld,

    /// Dated too far into the future.
    FutureDated,

    /// Already held, at no worse quality.
    AlreadyKnown,

    /// Its confirmed inputs cannot be confirmed against the tip's mutator set.
    NotConfirmable(TransactionConfirmabilityError),

    /// Cannot be applied to the tip's mutator set. Not expected to occur when
    /// the link transaction is confirmable; checked to be sure.
    CannotApplyToMutatorSet,

    /// The link transaction's proof does not attest to its kernel.
    Invalid,
}

/// Determine whether a link transaction may be admitted to the mempool.
///
/// `already_known` answers whether the mempool already holds this link
/// transaction at no worse quality; see
/// [`Mempool::accept_link_transaction`](super::Mempool::accept_link_transaction).
///
/// Checks run cheapest first, so that the proof is verified only once nothing
/// cheaper rejects the link transaction. Callers must therefore not verify the
/// proof themselves beforehand.
pub(crate) async fn link_tx_admissible(
    link_tx: &LinkTx,
    tip_mutator_set_accumulator: &MutatorSetAccumulator,
    already_known: bool,
    now: Timestamp,
    network: Network,
    consensus_rule_set: ConsensusRuleSet,
) -> Result<(), LinkTxAdmissionError> {
    link_tx_precheck(
        link_tx,
        tip_mutator_set_accumulator.hash(),
        now,
        consensus_rule_set,
    )?;

    if already_known {
        return Err(LinkTxAdmissionError::AlreadyKnown);
    }

    let kernel = &link_tx.kernel.kernel;

    // This covers the confirmed inputs; thruputs are not removal records.
    kernel
        .is_confirmable_relative_to(tip_mutator_set_accumulator)
        .map_err(LinkTxAdmissionError::NotConfirmable)?;

    let mutator_set_update = MutatorSetUpdate::new(kernel.inputs.clone(), kernel.outputs.clone());
    if mutator_set_update
        .apply_to_accumulator(&mut tip_mutator_set_accumulator.clone())
        .is_err()
    {
        return Err(LinkTxAdmissionError::CannotApplyToMutatorSet);
    }

    // Verifying the proof is by far the most expensive check, so it runs once
    // every cheaper reason to reject has been ruled out.
    let valid = match &link_tx.proof {
        LinkTxProof::Witness(link_primitive_witness) => {
            link_primitive_witness.validate().await.is_ok()
                && link_primitive_witness.kernel.mast_hash() == link_tx.kernel.mast_hash()
        }
        LinkTxProof::Proof(proof) => {
            let claim = link_tx_claim(link_tx.kernel.mast_hash(), consensus_rule_set);
            verify_transaction_proof(claim, proof.clone(), network).await
        }
    };
    if !valid {
        return Err(LinkTxAdmissionError::Invalid);
    }

    Ok(())
}

/// The checks of [`link_tx_admissible`] that read only the link transaction's
/// kernel. They bound the size of the link transaction, and so the work of
/// every check after them, which is why callers run them before anything that
/// looks at the mempool.
pub(crate) fn link_tx_precheck(
    link_tx: &LinkTx,
    tip_mutator_set_hash: Digest,
    now: Timestamp,
    consensus_rule_set: ConsensusRuleSet,
) -> Result<(), LinkTxAdmissionError> {
    if !consensus_rule_set.has_chain_branches() {
        return Err(LinkTxAdmissionError::NotYetActive);
    }

    let kernel = &link_tx.kernel.kernel;
    if kernel.mutator_set_hash != tip_mutator_set_hash {
        return Err(LinkTxAdmissionError::NotSynced);
    }

    if kernel.coinbase.is_some() {
        return Err(LinkTxAdmissionError::HasCoinbase);
    }

    // Bridge transactions are never chained, and `Forge` refuses these announcements.
    if consensus_rule_set.bav_active() && kernel.announcements.iter().any(has_proof_bound_tag) {
        return Err(LinkTxAdmissionError::ProofBoundAnnouncement);
    }

    // No negative fees anywhere in the chain pipeline.
    if kernel.fee.is_negative() {
        return Err(LinkTxAdmissionError::NegativeFee);
    }

    // Every thruput is an input of the link transaction, so it counts against
    // the input limit, as it does in the proofs that resolve it.
    let num_inputs = kernel
        .inputs
        .len()
        .saturating_add(link_tx.kernel.thruputs.len());
    consensus_rule_set
        .mempool_size_check(num_inputs, kernel.outputs.len(), kernel.announcements.len())
        .map_err(LinkTxAdmissionError::TooBig)?;

    check_thruputs(link_tx)?;

    let timestamp = kernel.timestamp;
    if timestamp < now - Timestamp::seconds(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS) {
        return Err(LinkTxAdmissionError::TooOld);
    }
    if timestamp >= now + FUTUREDATING_LIMIT {
        return Err(LinkTxAdmissionError::FutureDated);
    }

    Ok(())
}

/// Refuse thruput shapes that no wallet produces: a thruput listed twice, or a
/// thruput that is also one of the link transaction's own outputs.
pub(crate) fn check_thruputs(link_tx: &LinkTx) -> Result<(), LinkTxAdmissionError> {
    let mut thruputs = HashSet::with_capacity(link_tx.kernel.thruputs.len());
    for thruput in &link_tx.kernel.thruputs {
        if !thruputs.insert(thruput) {
            return Err(LinkTxAdmissionError::DuplicateThruput);
        }
    }

    if link_tx
        .kernel
        .kernel
        .outputs
        .iter()
        .any(|output| thruputs.contains(output))
    {
        return Err(LinkTxAdmissionError::ThruputIsOwnOutput);
    }

    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use tasm_lib::prelude::Digest;
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use super::*;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::chaintx::link_kernel::LinkKernel;
    use crate::protocol::consensus::transaction::announcement::Announcement;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::protocol::consensus::transaction::validity::neptune_proof::NeptuneProof;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use tasm_lib::triton_vm::proof::Claim;

    const NETWORK: Network = Network::RegTest;

    /// The genesis mutator set, and a link transaction synced to it that passes
    /// every check but, unless `valid_proof`, the proof.
    fn setup(valid_proof: bool) -> (MutatorSetAccumulator, LinkTx) {
        let tip_msa = Block::genesis(NETWORK)
            .mutator_set_accumulator_after()
            .unwrap();
        let kernel = TransactionKernelProxy {
            inputs: vec![],
            outputs: vec![],
            announcements: vec![],
            fee: NativeCurrencyAmount::coins(1),
            timestamp: Timestamp::now(),
            coinbase: None,
            mutator_set_hash: tip_msa.hash(),
            merge_bit: false,
        }
        .into_kernel();
        let claim = Claim::new(Digest::default());
        let proof = if valid_proof {
            NeptuneProof::valid_mock(claim)
        } else {
            NeptuneProof::invalid_mock(claim)
        };
        let link_tx = LinkTx {
            kernel: LinkKernel {
                kernel,
                thruputs: vec![],
            },
            proof: LinkTxProof::Proof(proof),
        };

        (tip_msa, link_tx)
    }

    async fn admit(
        link_tx: &LinkTx,
        tip_msa: &MutatorSetAccumulator,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<(), LinkTxAdmissionError> {
        link_tx_admissible(
            link_tx,
            tip_msa,
            false,
            Timestamp::now(),
            NETWORK,
            consensus_rule_set,
        )
        .await
    }

    #[apply(shared_tokio_runtime)]
    async fn link_tx_is_admitted_on_its_proof() {
        for (valid_proof, expected) in [(true, Ok(())), (false, Err(LinkTxAdmissionError::Invalid))]
        {
            let (tip_msa, link_tx) = setup(valid_proof);
            assert_eq!(
                expected,
                admit(&link_tx, &tip_msa, ConsensusRuleSet::UpgradeVMv8).await
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn link_tx_is_refused_without_chain_branches() {
        let (tip_msa, link_tx) = setup(true);
        assert_eq!(
            Err(LinkTxAdmissionError::NotYetActive),
            admit(&link_tx, &tip_msa, ConsensusRuleSet::UpgradeVMv7).await
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn link_tx_with_a_proof_bound_announcement_is_refused_in_the_bridge_era() {
        let (tip_msa, link_tx) = setup(true);
        for tag in crate::protocol::consensus::bridge::PROOF_BOUND_TAGS {
            let tagged = LinkTx {
                kernel: LinkKernel {
                    kernel: TransactionKernelModifier::default()
                        .announcements(vec![Announcement::new(vec![BFieldElement::new(tag)])])
                        .modify(link_tx.kernel.kernel.clone()),
                    thruputs: vec![],
                },
                proof: link_tx.proof.clone(),
            };
            assert_eq!(
                Err(LinkTxAdmissionError::ProofBoundAnnouncement),
                admit(&tagged, &tip_msa, ConsensusRuleSet::LeviathanSettlement).await
            );
            assert_ne!(
                Err(LinkTxAdmissionError::ProofBoundAnnouncement),
                admit(&tagged, &tip_msa, ConsensusRuleSet::UpgradeVMv8).await
            );
        }
    }

    /// Each of these link transactions carries an invalid proof, but is
    /// refused for a cheaper reason first.
    #[apply(shared_tokio_runtime)]
    async fn cheaper_checks_run_before_the_proof() {
        let (tip_msa, link_tx) = setup(false);
        let modified = |modifier: TransactionKernelModifier| LinkTx {
            kernel: LinkKernel {
                kernel: modifier.modify(link_tx.kernel.kernel.clone()),
                thruputs: vec![],
            },
            proof: link_tx.proof.clone(),
        };
        let now = Timestamp::now();
        let cases = [
            (
                TransactionKernelModifier::default().mutator_set_hash(Digest::default()),
                LinkTxAdmissionError::NotSynced,
            ),
            (
                TransactionKernelModifier::default().coinbase(Some(NativeCurrencyAmount::coins(1))),
                LinkTxAdmissionError::HasCoinbase,
            ),
            (
                TransactionKernelModifier::default().fee(-NativeCurrencyAmount::coins(1)),
                LinkTxAdmissionError::NegativeFee,
            ),
            (
                TransactionKernelModifier::default().timestamp(now - Timestamp::days(30)),
                LinkTxAdmissionError::TooOld,
            ),
            (
                TransactionKernelModifier::default().timestamp(now + Timestamp::hours(1)),
                LinkTxAdmissionError::FutureDated,
            ),
        ];
        for (modifier, expected) in cases {
            assert_eq!(
                Err(expected),
                admit(&modified(modifier), &tip_msa, ConsensusRuleSet::UpgradeVMv8).await
            );
        }

        let already_known = link_tx_admissible(
            &link_tx,
            &tip_msa,
            true,
            now,
            NETWORK,
            ConsensusRuleSet::UpgradeVMv8,
        )
        .await;
        assert_eq!(Err(LinkTxAdmissionError::AlreadyKnown), already_known);
    }

    #[apply(shared_tokio_runtime)]
    async fn thruputs_count_against_the_input_limit() {
        let consensus_rule_set = ConsensusRuleSet::UpgradeVMv8;
        let (tip_msa, mut link_tx) = setup(true);
        let limit = consensus_rule_set.max_num_inputs_in_mempool();
        let thruput = |i: usize| {
            AdditionRecord::new(Digest::new([BFieldElement::new(i as u64); Digest::LEN]))
        };
        link_tx.kernel.thruputs = (0..limit).map(thruput).collect();
        assert_eq!(Ok(()), admit(&link_tx, &tip_msa, consensus_rule_set).await);

        link_tx.kernel.thruputs.push(thruput(limit));
        assert_eq!(
            Err(LinkTxAdmissionError::TooBig(
                TransactionTooBig::TooManyInputs
            )),
            admit(&link_tx, &tip_msa, consensus_rule_set).await
        );
    }
}
