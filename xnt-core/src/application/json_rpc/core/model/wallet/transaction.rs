use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::api::export::NeptuneProof;
use crate::api::export::Transaction;
use crate::api::export::TransactionProof;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcTransactionKernel;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::AnyProofCollection;
use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::LeviathanProofCollection;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::proof_abstractions::mast_hash::MastHash;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcNeptuneProof(RpcBFieldElements);

impl From<NeptuneProof> for RpcNeptuneProof {
    fn from(proof: NeptuneProof) -> Self {
        Self(proof.0.clone().into())
    }
}

impl From<RpcNeptuneProof> for NeptuneProof {
    fn from(proof: RpcNeptuneProof) -> NeptuneProof {
        proof.0 .0.into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcProofCollection {
    pub removal_records_integrity: RpcNeptuneProof,
    pub collect_lock_scripts: RpcNeptuneProof,
    pub lock_scripts_halt: Vec<RpcNeptuneProof>,
    pub kernel_to_outputs: RpcNeptuneProof,
    pub collect_type_scripts: RpcNeptuneProof,
    pub type_scripts_halt: Vec<RpcNeptuneProof>,
    pub lock_script_hashes: Vec<Digest>,
    pub type_script_hashes: Vec<Digest>,
    pub kernel_mast_hash: Digest,
    pub salted_inputs_hash: Digest,
    pub salted_outputs_hash: Digest,
    pub merge_bit_mast_path: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_deposit_announcement_validator: Option<RpcNeptuneProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_aggregated_proof: Option<RpcNeptuneProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_prev_state_commitment: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_new_state_commitment: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_exit_root: Option<Digest>,
}

/// A collection with bridge fields has the Leviathan layout, any other the upstream one; the
/// node puts it in the layout of the era it is submitted in, see
/// `Transaction::with_proof_collection_layout_of`. The announcements copy is the kernel's.
impl From<RpcProofCollection> for AnyProofCollection {
    fn from(pc: RpcProofCollection) -> Self {
        let base = ProofCollection {
            removal_records_integrity: pc.removal_records_integrity.into(),
            collect_lock_scripts: pc.collect_lock_scripts.into(),
            lock_scripts_halt: pc.lock_scripts_halt.into_iter().map(Into::into).collect(),
            kernel_to_outputs: pc.kernel_to_outputs.into(),
            collect_type_scripts: pc.collect_type_scripts.into(),
            type_scripts_halt: pc.type_scripts_halt.into_iter().map(Into::into).collect(),
            lock_script_hashes: pc.lock_script_hashes,
            type_script_hashes: pc.type_script_hashes,
            kernel_mast_hash: pc.kernel_mast_hash,
            salted_inputs_hash: pc.salted_inputs_hash,
            salted_outputs_hash: pc.salted_outputs_hash,
            merge_bit_mast_path: pc.merge_bit_mast_path,
        };
        let has_bridge_fields = pc.bridge_deposit_announcement_validator.is_some()
            || pc.bridge_aggregated_proof.is_some()
            || pc.bridge_prev_state_commitment.is_some()
            || pc.bridge_new_state_commitment.is_some()
            || pc.bridge_exit_root.is_some();
        if !has_bridge_fields {
            return Self::Upstream(base);
        }
        Self::Leviathan(LeviathanProofCollection {
            removal_records_integrity: base.removal_records_integrity,
            collect_lock_scripts: base.collect_lock_scripts,
            lock_scripts_halt: base.lock_scripts_halt,
            kernel_to_outputs: base.kernel_to_outputs,
            collect_type_scripts: base.collect_type_scripts,
            type_scripts_halt: base.type_scripts_halt,
            lock_script_hashes: base.lock_script_hashes,
            type_script_hashes: base.type_script_hashes,
            kernel_mast_hash: base.kernel_mast_hash,
            salted_inputs_hash: base.salted_inputs_hash,
            salted_outputs_hash: base.salted_outputs_hash,
            merge_bit_mast_path: base.merge_bit_mast_path,
            bridge_deposit_announcement_validator: pc
                .bridge_deposit_announcement_validator
                .map(Into::into),
            bridge_aggregated_proof: pc.bridge_aggregated_proof.map(Into::into),
            bridge_prev_state_commitment: pc.bridge_prev_state_commitment,
            bridge_new_state_commitment: pc.bridge_new_state_commitment,
            bridge_exit_root: pc.bridge_exit_root,
            announcements: vec![],
            announcements_mast_path: vec![],
        })
    }
}

impl From<AnyProofCollection> for RpcProofCollection {
    fn from(pc: AnyProofCollection) -> Self {
        let (base, bridge) = match pc {
            AnyProofCollection::Upstream(base) => (base, None),
            AnyProofCollection::Leviathan(pc) => {
                let base = pc.base();
                (base, Some(pc))
            }
        };
        Self {
            removal_records_integrity: base.removal_records_integrity.into(),
            collect_lock_scripts: base.collect_lock_scripts.into(),
            lock_scripts_halt: base.lock_scripts_halt.into_iter().map(Into::into).collect(),
            kernel_to_outputs: base.kernel_to_outputs.into(),
            collect_type_scripts: base.collect_type_scripts.into(),
            type_scripts_halt: base.type_scripts_halt.into_iter().map(Into::into).collect(),
            lock_script_hashes: base.lock_script_hashes,
            type_script_hashes: base.type_script_hashes,
            kernel_mast_hash: base.kernel_mast_hash,
            salted_inputs_hash: base.salted_inputs_hash,
            salted_outputs_hash: base.salted_outputs_hash,
            merge_bit_mast_path: base.merge_bit_mast_path,
            bridge_deposit_announcement_validator: bridge
                .as_ref()
                .and_then(|leviathan| leviathan.bridge_deposit_announcement_validator.clone())
                .map(Into::into),
            bridge_aggregated_proof: bridge
                .as_ref()
                .and_then(|leviathan| leviathan.bridge_aggregated_proof.clone())
                .map(Into::into),
            bridge_prev_state_commitment: bridge
                .as_ref()
                .and_then(|leviathan| leviathan.bridge_prev_state_commitment),
            bridge_new_state_commitment: bridge
                .as_ref()
                .and_then(|leviathan| leviathan.bridge_new_state_commitment),
            bridge_exit_root: bridge
                .as_ref()
                .and_then(|leviathan| leviathan.bridge_exit_root),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RpcTransactionProof {
    ProofCollection(Box<RpcProofCollection>),
    SingleProof(RpcNeptuneProof),
}

impl From<RpcTransactionProof> for TransactionProof {
    fn from(proof: RpcTransactionProof) -> TransactionProof {
        match proof {
            RpcTransactionProof::ProofCollection(pc) => {
                TransactionProof::ProofCollection((*pc).into())
            }
            RpcTransactionProof::SingleProof(sp) => TransactionProof::SingleProof(sp.into()),
        }
    }
}

impl From<TransactionProof> for RpcTransactionProof {
    fn from(proof: TransactionProof) -> RpcTransactionProof {
        match proof {
            TransactionProof::ProofCollection(pc) => {
                RpcTransactionProof::ProofCollection(Box::new(pc.into()))
            }
            TransactionProof::SingleProof(sp) => RpcTransactionProof::SingleProof(sp.into()),
            TransactionProof::Witness(_) => panic!("Witness proofs contain secret material and must never be serialized or sent over RPC"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransaction {
    pub kernel: RpcTransactionKernel,
    pub proof: RpcTransactionProof,
}

impl From<RpcTransaction> for Transaction {
    fn from(tx: RpcTransaction) -> Self {
        let kernel: TransactionKernel = tx.kernel.into();
        let mut proof: TransactionProof = tx.proof.into();
        // The RPC schema omits the proof collection's copy of the kernel's announcements.
        if let TransactionProof::ProofCollection(AnyProofCollection::Leviathan(pc)) = &mut proof {
            pc.announcements = kernel.announcements.clone();
            pc.announcements_mast_path = kernel.mast_path(TransactionKernelField::Announcements);
        }
        Transaction { kernel, proof }
    }
}

impl From<Transaction> for RpcTransaction {
    fn from(tx: Transaction) -> Self {
        RpcTransaction {
            // TODO: Two impls when possible, ref clones and other takes
            // ownership...
            kernel: RpcTransactionKernel::from(&tx.kernel),
            proof: tx.proof.into(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;

    use super::*;
    use crate::api::tx_initiation::bridge_deposit::tests::deposit_witness;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::tests::mock_proof_collection;
    use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::tests::plain_tx_witness;
    use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::VerifyOptions;
    use crate::tests::shared_tokio_runtime;

    fn through_json(transaction: Transaction) -> (Transaction, String) {
        let rpc: RpcTransaction = transaction.into();
        let json = serde_json::to_string(&rpc).unwrap();
        let back: RpcTransaction = serde_json::from_str(&json).unwrap();
        (back.into(), json)
    }

    #[apply(shared_tokio_runtime)]
    async fn deposit_proof_collection_survives_json_rpc() {
        let pw = deposit_witness(1);
        let pc = mock_proof_collection(&pw).await;
        assert!(pc.bridge_deposit_announcement_validator.is_some());
        let transaction = Transaction {
            kernel: pw.kernel.clone(),
            proof: TransactionProof::ProofCollection(pc.into()),
        };

        let (back, _) = through_json(transaction.clone());
        assert_eq!(back, transaction);
        let TransactionProof::ProofCollection(received) = back.proof else {
            panic!("a proof collection stays one");
        };
        assert!(
            received
                .verify_v2(
                    pw.kernel.mast_hash(),
                    Network::RegTest,
                    ProofCollection::claim_version_for(ConsensusRuleSet::LeviathanSettlement),
                    ConsensusRuleSet::LeviathanSettlement,
                    VerifyOptions::default()
                )
                .await
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn non_bridge_proof_collection_json_has_no_bridge_fields() {
        let pw = plain_tx_witness(false);
        let transaction = Transaction {
            kernel: pw.kernel.clone(),
            proof: TransactionProof::ProofCollection(mock_proof_collection(&pw).await.into()),
        };
        let (back, json) = through_json(transaction.clone());
        assert_eq!(
            back.with_proof_collection_layout_of(ConsensusRuleSet::LeviathanSettlement),
            transaction
        );
        assert!(!json.contains("bridge"), "old clients see the same shape");
    }
}
