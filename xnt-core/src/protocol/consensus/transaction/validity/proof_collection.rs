use std::sync::Arc;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::MerkleTreeInclusionProof;
use tracing::debug;
use tracing::info;
use tracing::trace;

use super::collect_type_scripts::CollectTypeScriptsWitness;
use super::kernel_to_outputs::KernelToOutputsWitness;
use super::removal_records_integrity::RemovalRecordsIntegrity;
use crate::api::tx_initiation::builder::proof_builder::ProofBuilder;
use crate::api::tx_initiation::error::CreateProofError;
use crate::application::config::network::Network;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::consensus_rule_set::TritonProofVersion;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScripts;
use crate::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScriptsWitness;
use crate::protocol::consensus::transaction::validity::collect_type_scripts::CollectTypeScripts;
use crate::protocol::consensus::transaction::validity::kernel_to_outputs::KernelToOutputs;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrityWitness;
use crate::protocol::consensus::transaction::BFieldCodec;
use crate::protocol::proof_abstractions::mast_hash::HasDiscriminant;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::verifier::verify_transaction_proof;
use crate::protocol::proof_abstractions::SecretWitness;
use crate::util_types::mutator_set::shared::deserialize_bounded_vec;

const MAX_NUM_SCRIPT_PROOFS: usize = 2 * MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct ProofCollection {
    pub removal_records_integrity: Proof,
    pub collect_lock_scripts: Proof,
    #[serde(deserialize_with = "deserialize_bounded_vec::<_, _, MAX_NUM_SCRIPT_PROOFS>")]
    pub lock_scripts_halt: Vec<Proof>,
    pub kernel_to_outputs: Proof,
    pub collect_type_scripts: Proof,
    #[serde(deserialize_with = "deserialize_bounded_vec::<_, _, MAX_NUM_SCRIPT_PROOFS>")]
    pub type_scripts_halt: Vec<Proof>,
    pub lock_script_hashes: Vec<Digest>,
    pub type_script_hashes: Vec<Digest>,
    pub kernel_mast_hash: Digest,
    pub salted_inputs_hash: Digest,
    pub salted_outputs_hash: Digest,
    pub merge_bit_mast_path: Vec<Digest>,
}

/// Where a proof collection's sub-proofs are proven.
#[derive(Debug)]
pub(crate) enum SubProver {
    Queue {
        queue: Arc<TritonVmJobQueue>,
        options: TritonVmProofJobOptions,
    },
    InProcess {
        network: Network,
    },
}

impl SubProver {
    /// `nondeterminism` is only called for a real proof: mock networks can't always produce it.
    pub(crate) async fn prove<'a>(
        &self,
        program: Program,
        claim: Claim,
        nondeterminism: impl FnOnce() -> NonDeterminism + Send + Sync + 'a,
    ) -> Result<Proof, CreateProofError> {
        match self {
            Self::Queue { queue, options } => {
                ProofBuilder::new()
                    .program(program)
                    .claim(claim)
                    .nondeterminism(nondeterminism)
                    .job_queue(queue.clone())
                    .proof_job_options(options.clone())
                    .build()
                    .await
            }
            Self::InProcess { network } => {
                if network.use_mock_proof() {
                    return Ok(Proof::mock(true));
                }
                let nondeterminism = nondeterminism();
                let proof = tokio::task::spawn_blocking(move || {
                    tasm_lib::triton_vm::prove(Stark::default(), &claim, program, nondeterminism)
                })
                .await
                .map_err(CreateProofError::InProcessTask)??;
                Ok(proof.into())
            }
        }
    }
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
        let claim_version = TritonProofVersion::V8.claim_version();
        let mut lock_scripts_halt = vec![];
        for lock_script_and_witness in &primitive_witness.lock_scripts_and_witnesses {
            lock_scripts_halt.push(
                lock_script_and_witness
                    .prove(
                        txk_mast_hash_as_input.clone(),
                        claim_version,
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
                    claim_version,
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
    ///
    /// Every claim carries the claim version
    /// [`Self::claim_version_for`] the given rule set, which selects the Triton
    /// VM generation that proves it: `UpgradeVMv8` claims are proven by the
    /// linked triton-vm, `UpgradeVMv7` claims by the legacy triton-vm v7. The
    /// programs are the same in both eras.
    pub async fn produce_v2(
        primitive_witness: &PrimitiveWitness,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Self, CreateProofError> {
        let prover = SubProver::Queue {
            queue: triton_vm_job_queue,
            options: proof_job_options,
        };
        Self::produce_with(primitive_witness, &prover, consensus_rule_set).await
    }

    /// [`Self::produce_v2`] proven in this process, without the job queue or prover binary.
    pub async fn produce_in_process(
        primitive_witness: &PrimitiveWitness,
        network: Network,
        block_height: BlockHeight,
    ) -> Result<Self, CreateProofError> {
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        if consensus_rule_set.is_legacy_era() {
            return Err(CreateProofError::NotProducible {
                proof: "an in-process proof collection",
                consensus_rule_set,
            });
        }
        Self::produce_with(
            primitive_witness,
            &SubProver::InProcess { network },
            consensus_rule_set,
        )
        .await
    }

    pub(crate) async fn produce_with(
        primitive_witness: &PrimitiveWitness,
        prover: &SubProver,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Self, CreateProofError> {
        use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
        use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2Witness;
        use crate::protocol::consensus::type_scripts::known_type_scripts::match_type_script_and_generate_witness_v2;

        // The nodes of the era before the fork take a v7 collection only of
        // the programs they know.
        if consensus_rule_set == ConsensusRuleSet::UpgradeVMv7 {
            super::legacy_v7::check_v7_proof_collection_programs()
                .map_err(CreateProofError::V7ProgramDigestMismatch)?;
        }

        let (removal_records_integrity_witness, collect_lock_scripts_witness, kernel_to_outputs_witness, _) =
            Self::extract_specific_witnesses(primitive_witness);
        let collect_type_scripts_witness = CollectTypeScriptsV2Witness::from(primitive_witness);

        let txk_mast_hash = primitive_witness.kernel.mast_hash();
        let txk_mast_hash_as_input = PublicInput::new(txk_mast_hash.reversed().values().to_vec());
        let salted_inputs_hash = Tip5::hash(&primitive_witness.input_utxos);
        let salted_outputs_hash = Tip5::hash(&primitive_witness.output_utxos);
        let claim_version = Self::claim_version_for(consensus_rule_set);

        debug!("proving RemovalRecordsIntegrity (V2)");
        let removal_records_integrity = prover
            .prove(
                RemovalRecordsIntegrity.program(),
                removal_records_integrity_witness
                    .claim()
                    .about_version(claim_version),
                || removal_records_integrity_witness.nondeterminism(),
            )
            .await?;

        debug!("proving CollectLockScripts (V2)");
        let collect_lock_scripts = prover
            .prove(
                CollectLockScripts.program(),
                collect_lock_scripts_witness
                    .claim()
                    .about_version(claim_version),
                || collect_lock_scripts_witness.nondeterminism(),
            )
            .await?;

        debug!("proving KernelToOutputs (V2)");
        let kernel_to_outputs = prover
            .prove(
                KernelToOutputs.program(),
                kernel_to_outputs_witness
                    .claim()
                    .about_version(claim_version),
                || kernel_to_outputs_witness.nondeterminism(),
            )
            .await?;

        debug!("proving CollectTypeScriptsV2");
        let collect_type_scripts = prover
            .prove(
                CollectTypeScriptsV2.program(),
                collect_type_scripts_witness
                    .claim()
                    .about_version(claim_version),
                || collect_type_scripts_witness.nondeterminism(),
            )
            .await?;

        debug!("proving lock scripts (V2)");
        let mut lock_scripts_halt = vec![];
        for lock_script_and_witness in &primitive_witness.lock_scripts_and_witnesses {
            lock_scripts_halt.push(
                prover
                    .prove(
                        lock_script_and_witness.program.clone(),
                        lock_script_and_witness
                            .claim(txk_mast_hash_as_input.clone(), claim_version),
                        || lock_script_and_witness.nondeterminism(),
                    )
                    .await?,
            );
        }

        // Rebuild type-script witnesses using the V2 dispatch so OLD_HASH
        // coins are proved by TimeLockV2.
        debug!("proving type scripts (V2)");
        let type_script_hashes = Self::remapped_type_script_hashes(primitive_witness);
        let mut type_scripts_halt = vec![];
        for type_script_hash in &type_script_hashes {
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
                prover
                    .prove(
                        v2_tsaw.program.clone(),
                        v2_tsaw.claim(
                            txk_mast_hash,
                            salted_inputs_hash,
                            salted_outputs_hash,
                            claim_version,
                        ),
                        || v2_tsaw.nondeterminism(),
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

    /// The post-remap, deduplicated type-script hashes, the set `CollectTypeScriptsV2` emits.
    fn remapped_type_script_hashes(primitive_witness: &PrimitiveWitness) -> Vec<Digest> {
        use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
        use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;

        let old_timelock_hash = TimeLock.hash();
        let new_timelock_hash = TimeLockV2.hash();
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
        remapped_hashes
    }

    /// The collection of a settlement, whose BAAV proof covers the sub-proofs: dummy proofs, no
    /// halting proofs, and the script hashes of [`Self::produce_v2`].
    pub(crate) fn with_dummy_sub_proofs(primitive_witness: &PrimitiveWitness) -> Self {
        let dummy_proof = Proof::valid_mock(Claim::new(Digest::default()));
        ProofCollection {
            removal_records_integrity: dummy_proof.clone(),
            collect_lock_scripts: dummy_proof.clone(),
            lock_scripts_halt: vec![],
            kernel_to_outputs: dummy_proof.clone(),
            collect_type_scripts: dummy_proof,
            type_scripts_halt: vec![],
            lock_script_hashes: primitive_witness
                .lock_scripts_and_witnesses
                .iter()
                .map(|lsaw| lsaw.program.hash())
                .collect_vec(),
            type_script_hashes: Self::remapped_type_script_hashes(primitive_witness),
            kernel_mast_hash: primitive_witness.kernel.mast_hash(),
            salted_inputs_hash: Tip5::hash(&primitive_witness.input_utxos),
            salted_outputs_hash: Tip5::hash(&primitive_witness.output_utxos),
            merge_bit_mast_path: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::MergeBit),
        }
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
    pub(crate) fn halt_proof_counts_match(&self) -> bool {
        self.lock_scripts_halt.len() == self.lock_script_hashes.len()
            && self.type_scripts_halt.len() == self.type_script_hashes.len()
    }

    /// Whether the collection proves that the kernel's merge bit is *unset*.
    ///
    /// A `ProofCollection` may only back an unmerged transaction: the merged
    /// variant is proven by `SingleProof`. The collection carries a MAST
    /// authentication path for the merge-bit field, and the leaf value checked
    /// here is hardcoded to `false`, so a collection whose kernel has the merge
    /// bit set cannot authenticate — regardless of the path it supplies.
    pub(crate) fn proves_unset_merge_bit(&self, txk_mast_hash: Digest) -> bool {
        MerkleTreeInclusionProof {
            tree_height: TransactionKernel::MAST_HEIGHT.try_into().unwrap(),
            indexed_leafs: vec![(
                TransactionKernelField::MergeBit.discriminant(),
                Tip5::hash(&false),
            )],
            authentication_structure: self.merge_bit_mast_path.clone(),
        }
        .verify(txk_mast_hash)
    }

    /// The claim version of a collection produced for the given rule set: that
    /// of `UpgradeVMv7` for the legacy era, whose collections the legacy
    /// triton-vm v7 proves, and that of `UpgradeVMv8` for every other rule set.
    ///
    /// The eras before `UpgradeVMv7` are checkpointed, and no verifier of this
    /// version checks their collections. Stamping their own claim version (1,
    /// 2 or 5) would make claims that verify nowhere, or, for 5, claims that
    /// the legacy verifier takes for v7 claims. So a collection for such a rule
    /// set, as only tests make, carries the claim version of the current era,
    /// as all collections did before v7 collections were produced.
    pub(crate) fn claim_version_for(consensus_rule_set: ConsensusRuleSet) -> u32 {
        match consensus_rule_set {
            ConsensusRuleSet::UpgradeVMv7 => TritonProofVersion::V7.claim_version(),
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5
            | ConsensusRuleSet::UpgradeVMv8
            | ConsensusRuleSet::LeviathanSettlement => TritonProofVersion::V8.claim_version(),
        }
    }

    /// Whether the collection meets the checks that precede the proof
    /// verifications of [`Self::verify_v2`]: it is about the kernel with this
    /// MAST hash, it has one halting proof per script hash, and it proves an
    /// unset merge bit.
    pub(crate) fn meets_verification_preconditions(&self, txk_mast_hash: Digest) -> bool {
        self.kernel_mast_hash == txk_mast_hash
            && self.halt_proof_counts_match()
            && self.proves_unset_merge_bit(txk_mast_hash)
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

        if !self.proves_unset_merge_bit(txk_mast_hash) {
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

        // Verify, returning on the first proof that fails.
        //
        // The two `collect_*_scripts` claims commit to the script-hash lists,
        // and those lists' lengths decide how many proofs the loop below
        // verifies. All four claims here are checked before that loop is
        // entered, which bounds the work an attacker can make the victim do
        // without constructing a valid transaction.
        for (name, claim, proof) in [
            (
                "removal records integrity",
                removal_records_integrity_claim,
                &self.removal_records_integrity,
            ),
            (
                "kernel to outputs",
                kernel_to_outputs_claim,
                &self.kernel_to_outputs,
            ),
            (
                "collect lock scripts",
                collect_lock_scripts_claim,
                &self.collect_lock_scripts,
            ),
            (
                "collect type scripts",
                collect_type_scripts_claim,
                &self.collect_type_scripts,
            ),
        ] {
            debug!("verifying {name} ...");
            if !verify_transaction_proof(claim, proof.clone(), network).await {
                debug!("{name} is invalid");
                return false;
            }
        }

        debug!("verifying that all lock scripts halt ...");
        for (claim, proof) in lock_script_claims.into_iter().zip(&self.lock_scripts_halt) {
            if !verify_transaction_proof(claim, proof.clone(), network).await {
                debug!("a lock script does not halt gracefully");
                return false;
            }
        }

        debug!("verifying that all type scripts halt ...");
        for (claim, proof) in type_script_claims.into_iter().zip(&self.type_scripts_halt) {
            if !verify_transaction_proof(claim, proof.clone(), network).await {
                debug!("a type script does not halt gracefully");
                return false;
            }
        }

        true
    }

    /// V2 counterpart of [`verify`]. Identical except that the inline
    /// collect_type_scripts claim is built against `CollectTypeScriptsV2`,
    /// matching what a V2 ProofCollection (created via [`produce_v2`])
    /// carries. Called from the transaction-validation path post-fork.
    ///
    /// Every claim is stamped with the given claim version, which also selects
    /// the verifier: the claim version of `UpgradeVMv7` is checked by the legacy
    /// triton-vm v7, that of `UpgradeVMv8` by the linked triton-vm.
    pub(crate) async fn verify_v2(
        &self,
        txk_mast_hash: Digest,
        network: Network,
        claim_version: u32,
    ) -> bool {
        debug!("verifying (V2), txk hash: {}", txk_mast_hash);
        if !self.meets_verification_preconditions(txk_mast_hash) {
            return false;
        }

        // Verify in the same order as `verify`, returning on the first proof
        // that fails: the script-hash lists, whose lengths decide how many
        // proofs the halting loops verify, are checked before those loops.
        for (claim, proof) in self.claims_and_proofs(claim_version) {
            if !verify_transaction_proof(claim, proof.clone(), network).await {
                return false;
            }
        }

        true
    }

    /// [`Self::verify_v2`] for the claim version of `UpgradeVMv7`, as the
    /// previous release checks a collection: without the checks that it has
    /// one halting proof per script hash and proves an unset merge bit, which
    /// this version adds. Neither is covered by the proofs, so a third party
    /// can make a collection that fails them from one that passes them, which
    /// the nodes of the previous release still take and relay.
    pub(crate) async fn verify_v2_as_previous_release(
        &self,
        txk_mast_hash: Digest,
        network: Network,
    ) -> bool {
        if self.kernel_mast_hash != txk_mast_hash {
            return false;
        }

        for (claim, proof) in self.claims_and_proofs(TritonProofVersion::V7.claim_version()) {
            if !verify_transaction_proof(claim, proof.clone(), network).await {
                return false;
            }
        }

        true
    }

    /// Every (claim, proof) pair of a V2 collection, each claim stamped with
    /// the given claim version, in the order in which both [`Self::verify_v2`]
    /// and the in-VM verifier of `SingleProofV2` visit them: removal records
    /// integrity, kernel to outputs, collect lock scripts, collect type scripts
    /// (V2), then every lock script, then every type script.
    ///
    /// Pairs claims with proofs like `zip`; see
    /// [`Self::halt_proof_counts_match`].
    pub(crate) fn claims_and_proofs(&self, claim_version: u32) -> Vec<(Claim, &Proof)> {
        let fixed = [
            (
                self.removal_records_integrity_claim(),
                &self.removal_records_integrity,
            ),
            (self.kernel_to_outputs_claim(), &self.kernel_to_outputs),
            (
                self.collect_lock_scripts_claim(),
                &self.collect_lock_scripts,
            ),
            (
                self.collect_type_scripts_claim_v2(),
                &self.collect_type_scripts,
            ),
        ];
        let lock_scripts = self
            .lock_script_claims()
            .into_iter()
            .zip(&self.lock_scripts_halt);
        let type_scripts = self
            .type_script_claims()
            .into_iter()
            .zip(&self.type_scripts_halt);

        fixed
            .into_iter()
            .chain(lock_scripts)
            .chain(type_scripts)
            .map(|(claim, proof)| (claim.about_version(claim_version), proof))
            .collect()
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
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::tests::shared_tokio_runtime;

    /// The claim versions of the rule sets that verify collections with
    /// [`ProofCollection::verify_v2`] and that this version proves under.
    const V2_CLAIM_VERSIONS: [u32; 2] = [5, tasm_lib::triton_vm::proof::CURRENT_VERSION];

    #[test]
    fn v2_claim_versions_are_those_of_the_v7_and_v8_eras() {
        assert_eq!(
            V2_CLAIM_VERSIONS,
            [
                ConsensusRuleSet::UpgradeVMv7
                    .triton_proof_version()
                    .claim_version(),
                ConsensusRuleSet::UpgradeVMv8
                    .triton_proof_version()
                    .claim_version(),
            ]
        );
    }

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

    /// Neither verification path may accept a collection whose kernel has the
    /// merge bit set: a `ProofCollection` only ever backs an unmerged
    /// transaction, the merged variant being proven by `SingleProof`.
    ///
    /// The collection below is *derived from the modified kernel*, so its
    /// merge-bit MAST path correctly authenticates `true` under the new kernel
    /// MAST hash. It must still be rejected, because the leaf value the guard
    /// checks is hardcoded to `false`.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn verify_rejects_a_set_merge_bit() {
        let mut test_runner = TestRunner::deterministic();
        let mut primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let network = Network::RegTest;
        let merge_bit_false = ProofCollection::produce_mock(&primitive_witness, true);
        let txk_unmerged = primitive_witness.kernel.mast_hash();
        assert!(
            merge_bit_false.verify(txk_unmerged, network).await,
            "sanity: an unmerged collection must verify"
        );
        for claim_version in V2_CLAIM_VERSIONS {
            assert!(
                merge_bit_false
                    .verify_v2(txk_unmerged, network, claim_version)
                    .await,
                "sanity: an unmerged collection must verify under V2"
            );
        }

        primitive_witness.kernel = TransactionKernelModifier::default()
            .merge_bit(true)
            .modify(primitive_witness.kernel.clone());
        let merge_bit_true = ProofCollection::produce_mock(&primitive_witness, true);
        let txk_merged = primitive_witness.kernel.mast_hash();

        assert!(
            !merge_bit_true.verify(txk_merged, network).await,
            "a collection whose kernel has the merge bit set must be rejected"
        );
        for claim_version in V2_CLAIM_VERSIONS {
            assert!(
                !merge_bit_true
                    .verify_v2(txk_merged, network, claim_version)
                    .await,
                "a collection whose kernel has the merge bit set must be rejected under V2"
            );
        }
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
        for claim_version in V2_CLAIM_VERSIONS {
            assert!(
                valid.verify_v2(txk, network, claim_version).await,
                "sanity: a well-formed valid-mock collection must verify under V2"
            );
        }

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
            for claim_version in V2_CLAIM_VERSIONS {
                assert!(
                    !mutate(valid.clone())
                        .verify_v2(txk, network, claim_version)
                        .await,
                    "verify_v2 must reject a collection with {description}"
                );
            }
        }
    }

    /// `claims_and_proofs` stamps every claim with the requested version,
    /// leaves the rest of each claim as the claim builders make it, and visits
    /// the proofs in the order of the in-VM verifier.
    #[test]
    fn claims_and_proofs_carry_the_requested_claim_version() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let pc = ProofCollection::produce_mock(&primitive_witness, true);
        let num_proofs = pc.num_proofs();

        let expected_claims = [
            pc.removal_records_integrity_claim(),
            pc.kernel_to_outputs_claim(),
            pc.collect_lock_scripts_claim(),
            pc.collect_type_scripts_claim_v2(),
        ]
        .into_iter()
        .chain(pc.lock_script_claims())
        .chain(pc.type_script_claims())
        .collect_vec();
        let expected_proofs = [
            &pc.removal_records_integrity,
            &pc.kernel_to_outputs,
            &pc.collect_lock_scripts,
            &pc.collect_type_scripts,
        ]
        .into_iter()
        .chain(&pc.lock_scripts_halt)
        .chain(&pc.type_scripts_halt)
        .collect_vec();

        for claim_version in V2_CLAIM_VERSIONS {
            let (claims, proofs): (Vec<_>, Vec<_>) =
                pc.claims_and_proofs(claim_version).into_iter().unzip();
            assert_eq!(num_proofs, claims.len());
            assert!(claims.iter().all(|claim| claim.version == claim_version));
            for (claim, expected) in claims.iter().zip(&expected_claims) {
                assert_eq!(expected.program_digest, claim.program_digest);
                assert_eq!(expected.input, claim.input);
                assert_eq!(expected.output, claim.output);
            }
            assert!(proofs
                .iter()
                .zip(&expected_proofs)
                .all(|(proof, expected)| std::ptr::eq(*proof, *expected)));
        }

        // The claim builders stamp the linked triton-vm's version, which is the
        // claim version of the current era.
        assert!(expected_claims
            .iter()
            .all(|claim| claim.version == TritonProofVersion::V8.claim_version()));
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
