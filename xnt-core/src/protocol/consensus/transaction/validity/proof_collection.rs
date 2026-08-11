use std::sync::Arc;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::*;
use tracing::debug;
use tracing::info;
use tracing::trace;

use super::collect_type_scripts::CollectTypeScriptsWitness;
use super::kernel_to_outputs::KernelToOutputsWitness;
use super::removal_records_integrity::RemovalRecordsIntegrity;
use crate::api::tx_initiation::error::CreateProofError;
use crate::application::config::network::Network;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScripts;
use crate::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScriptsWitness;
use crate::protocol::consensus::transaction::validity::collect_type_scripts::CollectTypeScripts;
use crate::protocol::consensus::transaction::validity::kernel_to_outputs::KernelToOutputs;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrityWitness;
use crate::protocol::consensus::transaction::BFieldCodec;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::verifier::verify_transaction_proof;
use crate::protocol::proof_abstractions::SecretWitness;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct ProofCollection {
    pub removal_records_integrity: Proof,
    pub collect_lock_scripts: Proof,
    pub lock_scripts_halt: Vec<Proof>,
    pub kernel_to_outputs: Proof,
    pub collect_type_scripts: Proof,
    pub type_scripts_halt: Vec<Proof>,
    pub lock_script_hashes: Vec<Digest>,
    pub type_script_hashes: Vec<Digest>,
    pub kernel_mast_hash: Digest,
    pub salted_inputs_hash: Digest,
    pub salted_outputs_hash: Digest,
    pub merge_bit_mast_path: Vec<Digest>,
}

impl ProofCollection {
    /// Get the total number of proofs in this collection
    pub(crate) fn num_proofs(&self) -> usize {
        1 + // removal_records_integrity
        1 + // collect_lock_scripts
        self.lock_scripts_halt.len() + // lock_scripts_halt
        1 + // kernel_to_outputs
        1 + // collect_type_scripts
        self.type_scripts_halt.len() // type_scripts_halt
    }

    fn extract_specific_witnesses(
        primitive_witness: &PrimitiveWitness,
    ) -> (
        RemovalRecordsIntegrityWitness,
        CollectLockScriptsWitness,
        KernelToOutputsWitness,
        CollectTypeScriptsWitness,
    ) {
        // collect witnesses
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(primitive_witness);
        let collect_lock_scripts_witness = CollectLockScriptsWitness::from(primitive_witness);
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(primitive_witness);
        let collect_type_scripts_witness = CollectTypeScriptsWitness::from(primitive_witness);

        (
            removal_records_integrity_witness,
            collect_lock_scripts_witness,
            kernel_to_outputs_witness,
            collect_type_scripts_witness,
        )
    }

    pub async fn produce(
        primitive_witness: &PrimitiveWitness,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> Result<Self, CreateProofError> {
        let (
            removal_records_integrity_witness,
            collect_lock_scripts_witness,
            kernel_to_outputs_witness,
            collect_type_scripts_witness,
        ) = Self::extract_specific_witnesses(primitive_witness);

        let txk_mast_hash = primitive_witness.kernel.mast_hash();
        let txk_mast_hash_as_input = PublicInput::new(txk_mast_hash.reversed().values().to_vec());
        let salted_inputs_hash = Tip5::hash(&primitive_witness.input_utxos);
        let salted_outputs_hash = Tip5::hash(&primitive_witness.output_utxos);
        debug!("proving, txk hash: {}", txk_mast_hash);
        debug!("proving, salted inputs hash: {}", salted_inputs_hash);
        debug!("proving, salted outputs hash: {}", salted_outputs_hash);

        // prove
        debug!("proving RemovalRecordsIntegrity");
        let removal_records_integrity = RemovalRecordsIntegrity
            .prove(
                removal_records_integrity_witness.claim(),
                removal_records_integrity_witness.nondeterminism(),
                triton_vm_job_queue.clone(),
                proof_job_options.clone(),
            )
            .await?;

        debug!("proving CollectLockScripts");
        let collect_lock_scripts = CollectLockScripts
            .prove(
                collect_lock_scripts_witness.claim(),
                collect_lock_scripts_witness.nondeterminism(),
                triton_vm_job_queue.clone(),
                proof_job_options.clone(),
            )
            .await?;

        debug!("proving KernelToOutputs");
        let kernel_to_outputs = KernelToOutputs
            .prove(
                kernel_to_outputs_witness.claim(),
                kernel_to_outputs_witness.nondeterminism(),
                triton_vm_job_queue.clone(),
                proof_job_options.clone(),
            )
            .await?;

        debug!("proving CollectTypeScripts");
        let collect_type_scripts = CollectTypeScripts
            .prove(
                collect_type_scripts_witness.claim(),
                collect_type_scripts_witness.nondeterminism(),
                triton_vm_job_queue.clone(),
                proof_job_options.clone(),
            )
            .await?;

        debug!("proving lock scripts");
        let mut lock_scripts_halt = vec![];
        for lock_script_and_witness in &primitive_witness.lock_scripts_and_witnesses {
            lock_scripts_halt.push(
                lock_script_and_witness
                    .prove(
                        txk_mast_hash_as_input.clone(),
                        triton_vm_job_queue.clone(),
                        proof_job_options.clone(),
                    )
                    .await?,
            );
        }

        debug!("proving type scripts");
        let mut type_scripts_halt = vec![];
        for (i, tsaw) in primitive_witness
            .type_scripts_and_witnesses
            .iter()
            .enumerate()
        {
            debug!("proving type script number {i}: {:x}", tsaw.program.hash());
            type_scripts_halt.push(
                tsaw.prove(
                    txk_mast_hash,
                    salted_inputs_hash,
                    salted_outputs_hash,
                    triton_vm_job_queue.clone(),
                    proof_job_options.clone(),
                )
                .await?,
            );
        }
        info!("done proving proof collection");

        // collect hashes
        let lock_script_hashes = primitive_witness
            .lock_scripts_and_witnesses
            .iter()
            .map(|lsaw| lsaw.program.hash())
            .collect_vec();
        let type_script_hashes = primitive_witness
            .type_scripts_and_witnesses
            .iter()
            .map(|tsaw| tsaw.program.hash())
            .collect_vec();

        let merge_bit_mast_path = primitive_witness
            .kernel
            .mast_path(TransactionKernelField::MergeBit);

        Ok(ProofCollection {
            removal_records_integrity,
            collect_lock_scripts,
            lock_scripts_halt,
            kernel_to_outputs,
            collect_type_scripts,
            type_scripts_halt,
            lock_script_hashes,
            type_script_hashes,
            kernel_mast_hash: txk_mast_hash,
            salted_inputs_hash,
            salted_outputs_hash,
            merge_bit_mast_path,
        })
    }

    /// V2 counterpart of [`produce`]. Identical to V1 except that the
    /// CollectTypeScripts proof is generated against `CollectTypeScriptsV2`
    /// (which remaps any legacy `TimeLock` hash to `TimeLockV2`) and the
    /// per-type-script witnesses are rebuilt via the V2 dispatch so coins
    /// still tagged with the legacy hash are proved by `TimeLockV2`. The
    /// resulting `type_script_hashes` field reflects the post-remap set,
    /// matching what `CollectTypeScriptsV2` emits.
    pub async fn produce_v2(
        primitive_witness: &PrimitiveWitness,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> Result<Self, CreateProofError> {
        use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
        use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2Witness;
        use crate::protocol::consensus::type_scripts::known_type_scripts::match_type_script_and_generate_witness_v2;
        use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
        use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;

        let (removal_records_integrity_witness, collect_lock_scripts_witness, kernel_to_outputs_witness, _) =
            Self::extract_specific_witnesses(primitive_witness);
        let collect_type_scripts_witness = CollectTypeScriptsV2Witness::from(primitive_witness);

        let txk_mast_hash = primitive_witness.kernel.mast_hash();
        let txk_mast_hash_as_input = PublicInput::new(txk_mast_hash.reversed().values().to_vec());
        let salted_inputs_hash = Tip5::hash(&primitive_witness.input_utxos);
        let salted_outputs_hash = Tip5::hash(&primitive_witness.output_utxos);

        debug!("proving RemovalRecordsIntegrity (V2)");
        let removal_records_integrity = RemovalRecordsIntegrity
            .prove(
                removal_records_integrity_witness.claim(),
                removal_records_integrity_witness.nondeterminism(),
                triton_vm_job_queue.clone(),
                proof_job_options.clone(),
            )
            .await?;

        debug!("proving CollectLockScripts (V2)");
        let collect_lock_scripts = CollectLockScripts
            .prove(
                collect_lock_scripts_witness.claim(),
                collect_lock_scripts_witness.nondeterminism(),
                triton_vm_job_queue.clone(),
                proof_job_options.clone(),
            )
            .await?;

        debug!("proving KernelToOutputs (V2)");
        let kernel_to_outputs = KernelToOutputs
            .prove(
                kernel_to_outputs_witness.claim(),
                kernel_to_outputs_witness.nondeterminism(),
                triton_vm_job_queue.clone(),
                proof_job_options.clone(),
            )
            .await?;

        debug!("proving CollectTypeScriptsV2");
        let collect_type_scripts = CollectTypeScriptsV2
            .prove(
                collect_type_scripts_witness.claim(),
                collect_type_scripts_witness.nondeterminism(),
                triton_vm_job_queue.clone(),
                proof_job_options.clone(),
            )
            .await?;

        debug!("proving lock scripts (V2)");
        let mut lock_scripts_halt = vec![];
        for lock_script_and_witness in &primitive_witness.lock_scripts_and_witnesses {
            lock_scripts_halt.push(
                lock_script_and_witness
                    .prove(
                        txk_mast_hash_as_input.clone(),
                        triton_vm_job_queue.clone(),
                        proof_job_options.clone(),
                    )
                    .await?,
            );
        }

        // Rebuild type-script witnesses using the V2 dispatch so OLD_HASH
        // coins are proved by TimeLockV2.
        debug!("proving type scripts (V2)");
        let mut type_scripts_halt = vec![];
        let old_timelock_hash = TimeLock.hash();
        let new_timelock_hash = TimeLockV2.hash();
        // Collect the post-remap, deduplicated set of type-script hashes
        // (same set CollectTypeScriptsV2 emits).
        let mut remapped_hashes: Vec<Digest> = vec![];
        for tsaw in &primitive_witness.type_scripts_and_witnesses {
            let h = tsaw.program.hash();
            let remapped = if h == old_timelock_hash {
                new_timelock_hash
            } else {
                h
            };
            if !remapped_hashes.contains(&remapped) {
                remapped_hashes.push(remapped);
            }
        }
        // Build a V2 witness for every distinct remapped hash and prove it.
        for type_script_hash in &remapped_hashes {
            let v2_tsaw = match_type_script_and_generate_witness_v2(
                *type_script_hash,
                primitive_witness.kernel.clone(),
                primitive_witness.input_utxos.clone(),
                primitive_witness.output_utxos.clone(),
            )
            .unwrap_or_else(|| {
                panic!("unknown type script hash post-remap: {type_script_hash}")
            });
            type_scripts_halt.push(
                v2_tsaw
                    .prove(
                        txk_mast_hash,
                        salted_inputs_hash,
                        salted_outputs_hash,
                        triton_vm_job_queue.clone(),
                        proof_job_options.clone(),
                    )
                    .await?,
            );
        }
        info!("done proving proof collection (V2)");

        let lock_script_hashes = primitive_witness
            .lock_scripts_and_witnesses
            .iter()
            .map(|lsaw| lsaw.program.hash())
            .collect_vec();
        let type_script_hashes = remapped_hashes;

        let merge_bit_mast_path = primitive_witness
            .kernel
            .mast_path(TransactionKernelField::MergeBit);

        Ok(ProofCollection {
            removal_records_integrity,
            collect_lock_scripts,
            lock_scripts_halt,
            kernel_to_outputs,
            collect_type_scripts,
            type_scripts_halt,
            lock_script_hashes,
            type_script_hashes,
            kernel_mast_hash: txk_mast_hash,
            salted_inputs_hash,
            salted_outputs_hash,
            merge_bit_mast_path,
        })
    }

    // produce ProofCollection with mock proofs
    pub(crate) fn produce_mock(primitive_witness: &PrimitiveWitness, valid_mock: bool) -> Self {
        let txk_mast_hash = primitive_witness.kernel.mast_hash();
        let salted_inputs_hash = Tip5::hash(&primitive_witness.input_utxos);
        let salted_outputs_hash = Tip5::hash(&primitive_witness.output_utxos);
        debug!("proving, txk hash: {}", txk_mast_hash);
        debug!("proving, salted inputs hash: {}", salted_inputs_hash);
        debug!("proving, salted outputs hash: {}", salted_outputs_hash);

        let claim = Claim::new(Digest::default());
        let mock_proof = if valid_mock {
            Proof::valid_mock(claim)
        } else {
            Proof::invalid_mock(claim)
        };

        let merge_bit_mast_path = primitive_witness
            .kernel
            .mast_path(TransactionKernelField::MergeBit);

        let lock_scripts_halt = primitive_witness
            .lock_scripts_and_witnesses
            .iter()
            .map(|_| mock_proof.clone())
            .collect_vec();

        let type_scripts_halt = primitive_witness
            .type_scripts_and_witnesses
            .iter()
            .map(|_| mock_proof.clone())
            .collect_vec();

        // collect hashes
        let lock_script_hashes = primitive_witness
            .lock_scripts_and_witnesses
            .iter()
            .map(|lsaw| lsaw.program.hash())
            .collect_vec();
        let type_script_hashes = primitive_witness
            .type_scripts_and_witnesses
            .iter()
            .map(|tsaw| tsaw.program.hash())
            .collect_vec();

        ProofCollection {
            removal_records_integrity: mock_proof.clone(),
            collect_lock_scripts: mock_proof.clone(),
            lock_scripts_halt,
            kernel_to_outputs: mock_proof.clone(),
            collect_type_scripts: mock_proof.clone(),
            type_scripts_halt,
            lock_script_hashes,
            type_script_hashes,
            kernel_mast_hash: txk_mast_hash,
            salted_inputs_hash,
            salted_outputs_hash,
            merge_bit_mast_path,
        }
    }

    /// Whether there is exactly one halting proof per collected script hash.
    ///
    /// The verification loops in [`verify`](Self::verify) and
    /// [`verify_v2`](Self::verify_v2) pair claims with proofs using `zip`, which
    /// silently truncates to the shorter operand; without this guard a prover
    /// could submit fewer (e.g. zero) `*_scripts_halt` proofs than
    /// `*_script_hashes` and have the surplus lock-/type-script checks skipped
    /// while verification still returns `true`. Reject the
    /// (attacker-controlled) length mismatch as invalid here rather than via
    /// `zip_eq`, which would panic on untrusted input.
    fn halt_proof_counts_match(&self) -> bool {
        self.lock_scripts_halt.len() == self.lock_script_hashes.len()
            && self.type_scripts_halt.len() == self.type_script_hashes.len()
    }

    pub(crate) async fn verify(&self, txk_mast_hash: Digest, network: Network) -> bool {
        debug!("verifying, txk hash: {}", txk_mast_hash);
        debug!("verifying, salted inputs hash: {}", self.salted_inputs_hash);
        debug!(
            "verifying, salted outputs hash: {}",
            self.salted_outputs_hash
        );
        // make sure we are talking about the same tx
        if self.kernel_mast_hash != txk_mast_hash {
            return false;
        }

        if !self.halt_proof_counts_match() {
            return false;
        }

        // compile claims
        let removal_records_integrity_claim =
            Claim::about_program(&RemovalRecordsIntegrity.program())
                .with_input(self.kernel_mast_hash.reversed().values())
                .with_output(self.salted_inputs_hash.values().to_vec());
        trace!(
            "removal records integrity claim: {:?}",
            removal_records_integrity_claim
        );
        let kernel_to_outputs_claim = Claim::about_program(&KernelToOutputs.program())
            .with_input(self.kernel_mast_hash.reversed().values())
            .with_output(self.salted_outputs_hash.values().to_vec());
        let collect_lock_scripts_claim = Claim::about_program(&CollectLockScripts.program())
            .with_input(self.salted_inputs_hash.reversed().values())
            .with_output(
                self.lock_script_hashes
                    .iter()
                    .flat_map(|d| d.values())
                    .collect(),
            );
        let collect_type_scripts_claim = Claim::about_program(&CollectTypeScripts.program())
            .with_input(
                [self.salted_inputs_hash, self.salted_outputs_hash]
                    .into_iter()
                    .flat_map(|d| d.reversed().values())
                    .collect_vec(),
            )
            .with_output(
                self.type_script_hashes
                    .iter()
                    .flat_map(|d| d.values())
                    .collect_vec(),
            );
        trace!("collect_type_scripts_claim:\n{collect_type_scripts_claim:?}\n\n");
        let lock_script_claims = self
            .lock_script_hashes
            .iter()
            .map(|&lsh| Claim::new(lsh).with_input(self.kernel_mast_hash.reversed().values()))
            .collect_vec();
        let type_script_claims = self
            .type_script_hashes
            .iter()
            .map(|tsh| {
                Claim::new(*tsh).with_input(
                    [
                        self.kernel_mast_hash,
                        self.salted_inputs_hash,
                        self.salted_outputs_hash,
                    ]
                    .into_iter()
                    .flat_map(|d| d.reversed().values())
                    .collect_vec(),
                )
            })
            .collect_vec();

        // verify
        debug!("verifying removal records integrity ...");
        let rri = verify_transaction_proof(
            removal_records_integrity_claim.clone(),
            self.removal_records_integrity.clone(),
            network,
        )
        .await;
        debug!("{rri}");
        debug!("verifying kernel to outputs ...");
        let k2o = verify_transaction_proof(
            kernel_to_outputs_claim.clone(),
            self.kernel_to_outputs.clone(),
            network,
        )
        .await;
        debug!("{k2o}");
        debug!("verifying collect lock scripts ...");
        let cls = verify_transaction_proof(
            collect_lock_scripts_claim.clone(),
            self.collect_lock_scripts.clone(),
            network,
        )
        .await;
        debug!("{cls}");
        debug!("verifying collect type scripts ...");
        let cts = verify_transaction_proof(
            collect_type_scripts_claim.clone(),
            self.collect_type_scripts.clone(),
            network,
        )
        .await;
        debug!("{cts}");
        debug!("verifying that all lock scripts halt ...");
        let mut lsh = true;
        for (cl, pr) in lock_script_claims.iter().zip(self.lock_scripts_halt.iter()) {
            lsh &= verify_transaction_proof(cl.clone(), pr.clone(), network).await;
        }
        debug!("{lsh}");
        debug!("verifying that all type scripts halt ...");
        let mut tsh = true;
        for (cl, pr) in type_script_claims.iter().zip(self.type_scripts_halt.iter()) {
            tsh &= verify_transaction_proof(cl.clone(), pr.clone(), network).await;
        }
        debug!("{tsh}");

        // and all bits together and return
        rri && k2o && cls && cts && lsh && tsh
    }

    /// V2 counterpart of [`verify`]. Identical except that the inline
    /// collect_type_scripts claim is built against `CollectTypeScriptsV2`,
    /// matching what a V2 ProofCollection (created via [`produce_v2`])
    /// carries. Called from the transaction-validation path post-fork.
    pub(crate) async fn verify_v2(&self, txk_mast_hash: Digest, network: Network) -> bool {
        use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
        debug!("verifying (V2), txk hash: {}", txk_mast_hash);
        if self.kernel_mast_hash != txk_mast_hash {
            return false;
        }

        if !self.halt_proof_counts_match() {
            return false;
        }

        let removal_records_integrity_claim = self.removal_records_integrity_claim();
        let kernel_to_outputs_claim = self.kernel_to_outputs_claim();
        let collect_lock_scripts_claim = self.collect_lock_scripts_claim();
        let collect_type_scripts_claim = self.collect_type_scripts_claim_v2();
        let _ = &CollectTypeScriptsV2; // ensure import is used

        let lock_script_claims = self.lock_script_claims();
        let type_script_claims = self.type_script_claims();

        let rri = verify_transaction_proof(
            removal_records_integrity_claim,
            self.removal_records_integrity.clone(),
            network,
        )
        .await;
        let k2o = verify_transaction_proof(kernel_to_outputs_claim, self.kernel_to_outputs.clone(), network).await;
        let cls = verify_transaction_proof(
            collect_lock_scripts_claim,
            self.collect_lock_scripts.clone(),
            network,
        )
        .await;
        let cts = verify_transaction_proof(
            collect_type_scripts_claim,
            self.collect_type_scripts.clone(),
            network,
        )
        .await;

        let mut lsh = true;
        for (cl, pr) in lock_script_claims.iter().zip(self.lock_scripts_halt.iter()) {
            lsh &= verify_transaction_proof(cl.clone(), pr.clone(), network).await;
        }
        let mut tsh = true;
        for (cl, pr) in type_script_claims.iter().zip(self.type_scripts_halt.iter()) {
            tsh &= verify_transaction_proof(cl.clone(), pr.clone(), network).await;
        }

        rri && k2o && cls && cts && lsh && tsh
    }

    pub fn removal_records_integrity_claim(&self) -> Claim {
        Claim::about_program(&RemovalRecordsIntegrity.program())
            .with_input(self.kernel_mast_hash.reversed().values())
            .with_output(self.salted_inputs_hash.values().to_vec())
    }

    pub fn kernel_to_outputs_claim(&self) -> Claim {
        Claim::about_program(&KernelToOutputs.program())
            .with_input(self.kernel_mast_hash.reversed().values())
            .with_output(self.salted_outputs_hash.values().to_vec())
    }

    pub fn collect_lock_scripts_claim(&self) -> Claim {
        let mut lock_script_hashes_as_output = vec![];
        let mut i: usize = 0;
        while i < self.lock_script_hashes.len() {
            let lock_script_hash: Digest = self.lock_script_hashes[i];
            let mut j: usize = 0;
            while j < Digest::LEN {
                lock_script_hashes_as_output.push(lock_script_hash.values()[j]);
                j += 1;
            }
            i += 1;
        }
        Claim::about_program(&CollectLockScripts.program())
            .with_input(self.salted_inputs_hash.reversed().values())
            .with_output(lock_script_hashes_as_output)
    }

    pub fn collect_type_scripts_claim(&self) -> Claim {
        let mut type_script_hashes_as_output = vec![];
        let mut i = 0;
        while i < self.type_script_hashes.len() {
            let type_script_hash: Digest = self.type_script_hashes[i];
            let mut j: usize = 0;
            while j < Digest::LEN {
                type_script_hashes_as_output.push(type_script_hash.values()[j]);
                j += 1;
            }
            i += 1;
        }
        Claim::about_program(&CollectTypeScripts.program())
            .with_input(
                [self.salted_inputs_hash, self.salted_outputs_hash]
                    .map(|digest| digest.reversed().values())
                    .concat(),
            )
            .with_output(type_script_hashes_as_output)
    }

    /// V2 counterpart of [`collect_type_scripts_claim`]. Builds the claim
    /// against `CollectTypeScriptsV2` so that a V2 SingleProof verifier
    /// matches the post-fork program hash. `type_script_hashes` on `self`
    /// is already the post-remap set when this ProofCollection was created
    /// via [`produce_v2`].
    pub fn collect_type_scripts_claim_v2(&self) -> Claim {
        use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
        let mut type_script_hashes_as_output = vec![];
        let mut i = 0;
        while i < self.type_script_hashes.len() {
            let type_script_hash: Digest = self.type_script_hashes[i];
            let mut j: usize = 0;
            while j < Digest::LEN {
                type_script_hashes_as_output.push(type_script_hash.values()[j]);
                j += 1;
            }
            i += 1;
        }
        Claim::about_program(&CollectTypeScriptsV2.program())
            .with_input(
                [self.salted_inputs_hash, self.salted_outputs_hash]
                    .map(|digest| digest.reversed().values())
                    .concat(),
            )
            .with_output(type_script_hashes_as_output)
    }

    pub fn lock_script_claims(&self) -> Vec<Claim> {
        let mut claims = vec![];
        let mut i = 0;
        while i < self.lock_script_hashes.len() {
            let claim = Claim::new(self.lock_script_hashes[i])
                .with_input(self.kernel_mast_hash.reversed().values());
            claims.push(claim);

            i += 1;
        }

        claims
    }

    pub fn type_script_claims(&self) -> Vec<Claim> {
        let type_script_input = [
            self.kernel_mast_hash.reversed().values(),
            self.salted_inputs_hash.reversed().values(),
            self.salted_outputs_hash.reversed().values(),
        ]
        .concat();
        let mut claims = vec![];
        let mut i = 0;
        while i < self.type_script_hashes.len() {
            let type_script_hash = self.type_script_hashes[i];
            let claim = Claim::new(type_script_hash).with_input(type_script_input.clone());
            claims.push(claim);
            i += 1;
        }
        claims
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use macro_rules_attr::apply;
    use proptest::prelude::Strategy;
    use proptest::prelude::TestCaseError;
    use proptest::prop_assert;
    use proptest::test_runner::TestRunner;
    use test_strategy::proptest;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::NeptuneProof;
    use crate::application::triton_vm_job_queue::vm_job_queue;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::tests::shared_tokio_runtime;

    impl ProofCollection {
        /// Return an invalid proof collection for testing purposes
        pub(crate) fn invalid() -> Self {
            Self {
                removal_records_integrity: NeptuneProof::invalid(),
                collect_lock_scripts: NeptuneProof::invalid(),
                lock_scripts_halt: vec![],
                kernel_to_outputs: NeptuneProof::invalid(),
                collect_type_scripts: NeptuneProof::invalid(),
                type_scripts_halt: vec![],
                lock_script_hashes: vec![],
                type_script_hashes: vec![],
                kernel_mast_hash: Digest::default(),
                salted_inputs_hash: Digest::default(),
                salted_outputs_hash: Digest::default(),
                merge_bit_mast_path: vec![],
            }
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_produce_valid_collection_from_arbitrary_with_fee_deterministic() {
        // Test proof-collection generation with both positive and negative
        // fees.
        for fee in [
            NativeCurrencyAmount::from_nau(1),
            NativeCurrencyAmount::from_nau(800_000_000),
            NativeCurrencyAmount::coins(2),
            NativeCurrencyAmount::coins(50),
            NativeCurrencyAmount::coins(100),
        ] {
            for fee_inner in [-fee, fee] {
                let mut test_runner = TestRunner::deterministic();
                let primitive_witness = PrimitiveWitness::arbitrary_with_fee(fee_inner)
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();
                prop(primitive_witness).await.unwrap();
            }
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_produce_valid_collection_small_deterministic() {
        for num_inputs in 0..=2 {
            for num_outputs in 0..=2 {
                for num_public_announcements in 0..=1 {
                    let mut test_runner = TestRunner::deterministic();
                    let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(
                        Some(num_inputs),
                        num_outputs,
                        num_public_announcements,
                    )
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();
                    prop(primitive_witness).await.unwrap();
                }
            }
        }
    }

    /// Regression test for the `.zip()` truncation bug (opus48_neptune_cash7.md):
    /// `verify` must reject a collection whose `*_scripts_halt` proof count
    /// differs from its `*_script_hashes` count. Before the length guard, `zip`
    /// silently truncated to the shorter side, so a collection with zero halting
    /// proofs but non-empty hashes was accepted — skipping every lock-script
    /// (spend authorization) and type-script (value conservation) check.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn verify_rejects_halt_proof_count_mismatch() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let txk = primitive_witness.kernel.mast_hash();

        // RegTest accepts valid mock proofs, so a well-formed mock collection
        // verifies. This isolates the length guard as the sole reason a mutated
        // collection is rejected.
        let network = Network::RegTest;
        let valid = ProofCollection::produce_mock(&primitive_witness, true);
        assert!(!valid.lock_script_hashes.is_empty());
        assert!(!valid.type_script_hashes.is_empty());
        assert!(
            valid.verify(txk, network).await,
            "sanity: a well-formed valid-mock collection must verify"
        );

        // Drop the lock-script halting proofs (the part needing the spender's key).
        let mut missing_lock_proofs = valid.clone();
        missing_lock_proofs.lock_scripts_halt.clear();
        assert!(
            !missing_lock_proofs.verify(txk, network).await,
            "non-empty lock_script_hashes with no lock_scripts_halt must be rejected"
        );

        // Drop the type-script halting proofs (value conservation).
        let mut missing_type_proofs = valid.clone();
        missing_type_proofs.type_scripts_halt.clear();
        assert!(
            !missing_type_proofs.verify(txk, network).await,
            "non-empty type_script_hashes with no type_scripts_halt must be rejected"
        );
    }

    /// The V2 verification path must reject the same mismatches as `verify`.
    ///
    /// `verify_v2` has no upstream counterpart — it is this chain's post-fork
    /// validation path — so the guard has to be asserted separately here. Were
    /// it applied only to `verify`, every transaction validated after the V2
    /// fork would still skip its lock- and type-script checks.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn verify_v2_rejects_halt_proof_count_mismatch() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let txk = primitive_witness.kernel.mast_hash();

        let network = Network::RegTest;
        let valid = ProofCollection::produce_mock(&primitive_witness, true);
        assert!(!valid.lock_script_hashes.is_empty());
        assert!(!valid.type_script_hashes.is_empty());
        assert!(
            valid.verify_v2(txk, network).await,
            "sanity: a well-formed valid-mock collection must verify under V2"
        );

        let mutations: [(&str, fn(ProofCollection) -> ProofCollection); 3] = [
            ("no lock-script proofs", |mut pc| {
                pc.lock_scripts_halt.clear();
                pc
            }),
            ("no type-script proofs", |mut pc| {
                pc.type_scripts_halt.clear();
                pc
            }),
            ("one lock-script proof too few", |mut pc| {
                pc.lock_scripts_halt.pop();
                pc
            }),
        ];

        for (description, mutate) in mutations {
            assert!(
                !mutate(valid.clone()).verify_v2(txk, network).await,
                "verify_v2 must reject a collection with {description}"
            );
        }
    }

    #[proptest(cases = 5)]
    fn can_produce_valid_collection(
        #[strategy(0usize..7)] _num_inputs_own: usize,
        #[strategy(0usize..7)] _num_outputs_own: usize,
        #[strategy(0usize..7)] _num_public_announcements_own: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs_own), #_num_outputs_own, #_num_public_announcements_own))]
        primitive_witness: PrimitiveWitness,
    ) {
        prop_assert!(ProofCollection::can_produce(&primitive_witness));
    }

    async fn prop(primitive_witness: PrimitiveWitness) -> std::result::Result<(), TestCaseError> {
        prop_assert!(ProofCollection::can_produce(&primitive_witness));
        let pc = ProofCollection::produce(
            &primitive_witness,
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap();
        prop_assert!(
            pc.verify(primitive_witness.kernel.mast_hash(), Network::Main)
                .await
        );

        Ok(())
    }

    impl ProofCollection {
        pub(crate) fn can_produce(primitive_witness: &PrimitiveWitness) -> bool {
            fn witness_halts_gracefully(
                program: impl ConsensusProgramSpecification,
                witness: impl SecretWitness,
            ) -> bool {
                program
                    .run_rust(&witness.standard_input(), witness.nondeterminism())
                    .map(|output| output == witness.output())
                    .unwrap_or(false)
            }

            let txk_mast_hash = primitive_witness.kernel.mast_hash();
            let txk_mast_hash_as_input =
                PublicInput::new(txk_mast_hash.reversed().values().to_vec());
            let salted_inputs_hash = Tip5::hash(&primitive_witness.input_utxos);
            let salted_outputs_hash = Tip5::hash(&primitive_witness.output_utxos);

            let all_lock_scripts_halt = primitive_witness
                .lock_scripts_and_witnesses
                .iter()
                .all(|lsaw| lsaw.halts_gracefully(txk_mast_hash_as_input.clone()));
            let all_type_scripts_halt =
                primitive_witness
                    .type_scripts_and_witnesses
                    .iter()
                    .all(|ts| {
                        ts.halts_gracefully(txk_mast_hash, salted_inputs_hash, salted_outputs_hash)
                    });

            let (
                removal_records_integrity_witness,
                collect_lock_scripts_witness,
                kernel_to_outputs_witness,
                collect_type_scripts_witness,
            ) = Self::extract_specific_witnesses(primitive_witness);

            witness_halts_gracefully(RemovalRecordsIntegrity, removal_records_integrity_witness)
                && witness_halts_gracefully(CollectLockScripts, collect_lock_scripts_witness)
                && witness_halts_gracefully(KernelToOutputs, kernel_to_outputs_witness)
                && witness_halts_gracefully(CollectTypeScripts, collect_type_scripts_witness)
                && all_lock_scripts_halt
                && all_type_scripts_halt
        }
    }
}
