//! Pays a settlement's fee from relayer coins; the settlement itself must pay none (pool funds).

use std::sync::Arc;

use num_traits::Zero;

use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::bridge::aggregated_announcement::AggregatedAnnouncementData;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::state::bridge_gate::has_bridge_announcements;

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
pub enum MergeRole {
    Settlement,
    Fee,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SettlementFeeError {
    #[error("{0} transaction is not backed by a SingleProof")]
    NotSingleProof(MergeRole),

    #[error("{0} transaction has a coinbase")]
    Coinbase(MergeRole),

    #[error("settlement and fee transactions are synced to different mutator sets")]
    MutatorSetMismatch,

    #[error(
        "settlement transaction must carry exactly one settlement announcement and pay no fee"
    )]
    NotAZeroFeeSettlement,

    #[error("fee transaction must not carry bridge announcements")]
    BridgeAnnouncementInFeeTx,

    #[error("fee transaction must pay a positive fee")]
    NonPositiveFee,

    /// The merge would have none either, and the mempool drops zero-input txs on every new tip.
    #[error("fee transaction has no inputs")]
    FeeTxWithoutInputs,

    #[error("merge failed")]
    Merge(#[source] anyhow::Error),
}

/// Both transactions must be SingleProof-backed and synced to the same tip.
pub async fn merge_settlement_with_fee(
    settlement: Transaction,
    fee_tx: Transaction,
    triton_vm_job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
    consensus_rule_set: ConsensusRuleSet,
) -> Result<Transaction, SettlementFeeError> {
    check_mergeable(&settlement, &fee_tx)?;
    settlement
        .merge_with(
            fee_tx,
            rand::random(),
            triton_vm_job_queue,
            proof_job_options,
            consensus_rule_set,
        )
        .await
        .map_err(SettlementFeeError::Merge)
}

fn check_mergeable(
    settlement: &Transaction,
    fee_tx: &Transaction,
) -> Result<(), SettlementFeeError> {
    for (tx, role) in [
        (settlement, MergeRole::Settlement),
        (fee_tx, MergeRole::Fee),
    ] {
        if !matches!(tx.proof, TransactionProof::SingleProof(_)) {
            return Err(SettlementFeeError::NotSingleProof(role));
        }
        if tx.kernel.coinbase.is_some() {
            return Err(SettlementFeeError::Coinbase(role));
        }
    }
    if settlement.kernel.mutator_set_hash != fee_tx.kernel.mutator_set_hash {
        return Err(SettlementFeeError::MutatorSetMismatch);
    }

    let num_settlements = settlement
        .kernel
        .announcements
        .iter()
        .filter(|a| AggregatedAnnouncementData::is_settlement_tagged(a))
        .count();
    if num_settlements != 1 || !settlement.kernel.fee.is_zero() {
        return Err(SettlementFeeError::NotAZeroFeeSettlement);
    }

    if has_bridge_announcements(&fee_tx.kernel.announcements) {
        return Err(SettlementFeeError::BridgeAnnouncementInFeeTx);
    }
    if fee_tx.kernel.fee <= NativeCurrencyAmount::zero() {
        return Err(SettlementFeeError::NonPositiveFee);
    }
    if fee_tx.kernel.inputs.is_empty() {
        return Err(SettlementFeeError::FeeTxWithoutInputs);
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use tasm_lib::prelude::Digest;
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use super::*;
    use crate::api::export::Network;
    use crate::application::triton_vm_job_queue::vm_job_queue;
    use crate::protocol::consensus::block::block_height::BlockHeight;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::bridge::aggregated_announcement::StatePreimage;
    use crate::protocol::consensus::bridge::aggregated_announcement::STATE_PREIMAGE_LEN;
    use crate::protocol::consensus::bridge::faucet_registration::FaucetId;
    use crate::protocol::consensus::transaction::announcement::Announcement;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
    use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
    use crate::protocol::consensus::transaction::validity::single_proof::single_proof_claim;
    use crate::protocol::proof_abstractions::mast_hash::MastHash;
    use crate::tests::shared::mock_tx::make_mock_transaction_with_mutator_set_hash;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    const NETWORK: Network = Network::RegTest;

    fn rule_set() -> ConsensusRuleSet {
        ConsensusRuleSet::infer_from(NETWORK, BlockHeight::genesis().next())
    }

    fn settlement_announcement() -> Announcement {
        AggregatedAnnouncementData {
            prev_state_commitment: Digest::default(),
            new_state_commitment: Digest::new([BFieldElement::new(9); 5]),
            exit_root: Digest::default(),
            faucet_id: FaucetId {
                suffix: BFieldElement::new(1 << 8),
                prefix: BFieldElement::new(1),
            },
            prev_state_preimage: StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
            burns: vec![],
            change_sender_randomness: None,
            authority_signatures: vec![],
        }
        .to_announcement()
    }

    fn with(
        template: &Transaction,
        announcements: Vec<Announcement>,
        fee: NativeCurrencyAmount,
    ) -> Transaction {
        let kernel = TransactionKernelModifier::default()
            .inputs(vec![])
            .outputs(vec![])
            .announcements(announcements)
            .fee(fee)
            .modify(template.kernel.clone());
        let claim = single_proof_claim(kernel.mast_hash(), rule_set());
        Transaction {
            kernel,
            proof: TransactionProof::SingleProof(Proof::valid_mock(claim)),
        }
    }

    fn fee_tx() -> Transaction {
        let msa_hash = Block::genesis(NETWORK)
            .mutator_set_accumulator_after()
            .unwrap()
            .hash();
        let template = make_mock_transaction_with_mutator_set_hash(vec![], vec![], msa_hash);
        let mut fee_tx = with(&template, vec![], NativeCurrencyAmount::coins(1));
        let input = proptest_arbitrary_interop::arb::<RemovalRecord>()
            .new_tree(&mut TestRunner::deterministic())
            .unwrap()
            .current();
        fee_tx.kernel = TransactionKernelModifier::default()
            .inputs(vec![input])
            .modify(fee_tx.kernel);
        fee_tx
    }

    #[apply(shared_tokio_runtime)]
    async fn merged_tx_pays_the_fee_and_keeps_the_settlement() {
        let fee_tx = fee_tx();
        let settlement = with(
            &fee_tx,
            vec![settlement_announcement()],
            NativeCurrencyAmount::zero(),
        );

        let merged = merge_settlement_with_fee(
            settlement,
            fee_tx.clone(),
            vm_job_queue(),
            TritonVmProofJobOptions::default_with_network(NETWORK),
            rule_set(),
        )
        .await
        .unwrap();

        assert_eq!(merged.kernel.fee, fee_tx.kernel.fee);
        assert!(merged.kernel.merge_bit);
        assert!(matches!(merged.proof, TransactionProof::SingleProof(_)));
        assert_eq!(
            AggregatedAnnouncementData::find_in_announcements(&merged.kernel.announcements),
            AggregatedAnnouncementData::from_announcement(&settlement_announcement())
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn refuses_txs_that_do_not_fit_the_settlement_fee_shape() {
        let fee_tx = fee_tx();
        let zero = NativeCurrencyAmount::zero();
        let one = NativeCurrencyAmount::coins(1);
        let settlement = with(&fee_tx, vec![settlement_announcement()], zero);

        let paying_settlement = with(&fee_tx, vec![settlement_announcement()], one);
        let no_settlement = with(&fee_tx, vec![], zero);
        let two_settlements = with(
            &fee_tx,
            vec![settlement_announcement(), settlement_announcement()],
            zero,
        );
        for bad in [paying_settlement, no_settlement, two_settlements] {
            assert!(matches!(
                check_mergeable(&bad, &fee_tx),
                Err(SettlementFeeError::NotAZeroFeeSettlement)
            ));
        }

        let fee_tx_with_settlement = with(&fee_tx, vec![settlement_announcement()], one);
        assert!(matches!(
            check_mergeable(&settlement, &fee_tx_with_settlement),
            Err(SettlementFeeError::BridgeAnnouncementInFeeTx)
        ));
        assert!(matches!(
            check_mergeable(&settlement, &with(&fee_tx, vec![], zero)),
            Err(SettlementFeeError::NonPositiveFee)
        ));
        assert!(matches!(
            check_mergeable(&settlement, &with(&fee_tx, vec![], one)),
            Err(SettlementFeeError::FeeTxWithoutInputs)
        ));

        let mut other_tip = settlement.clone();
        other_tip.kernel = TransactionKernelModifier::default()
            .mutator_set_hash(Digest::new([BFieldElement::new(3); 5]))
            .modify(other_tip.kernel);
        assert!(matches!(
            check_mergeable(&other_tip, &fee_tx),
            Err(SettlementFeeError::MutatorSetMismatch)
        ));

        let mut coinbase = fee_tx.clone();
        coinbase.kernel = TransactionKernelModifier::default()
            .coinbase(Some(one))
            .modify(coinbase.kernel);
        assert!(matches!(
            check_mergeable(&settlement, &coinbase),
            Err(SettlementFeeError::Coinbase(MergeRole::Fee))
        ));

        let mut unproven = fee_tx.clone();
        unproven.proof = TransactionProof::ProofCollection(ProofCollection::invalid().into());
        assert!(matches!(
            check_mergeable(&settlement, &unproven),
            Err(SettlementFeeError::NotSingleProof(MergeRole::Fee))
        ));

        assert!(check_mergeable(&settlement, &fee_tx).is_ok());
    }
}
