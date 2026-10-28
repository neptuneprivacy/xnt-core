use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::OnceLock;

use crate::api::tx_initiation::builder::proof_builder::ProofBuilder;
use crate::api::tx_initiation::error::CreateProofError;
use crate::application::config::network::Network;
use crate::protocol::consensus::bridge::aggregated_announcement::AGGREGATED_ANNOUNCEMENT_TAG;
use crate::protocol::consensus::bridge::deposit_announcement::BRIDGE_DEPOSIT_TAG;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::validity::legacy_v7;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::triton_vm::prelude::*;
use itertools::Itertools;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::tasm_object::TasmStruct;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tracing::info;

use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::tasm::single_proof::merge_branch::MergeBranch;
use crate::protocol::consensus::transaction::validity::tasm::single_proof::update_branch::UpdateBranch;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::validity::tasm::claims::generate_aggregated_claim::GenerateAggregatedClaim;
use crate::protocol::consensus::transaction::validity::tasm::claims::generate_bridge_deposit_claim::GenerateBridgeDepositClaim;
use crate::protocol::consensus::transaction::validity::tasm::claims::generate_collect_lock_scripts_claim::GenerateCollectLockScriptsClaimFor;
use crate::protocol::consensus::transaction::validity::tasm::claims::generate_collect_type_scripts_claim_v2::GenerateCollectTypeScriptsClaimV2For;
use crate::protocol::consensus::transaction::validity::tasm::claims::generate_k2o_claim::GenerateK2oClaimFor;
use crate::protocol::consensus::transaction::validity::tasm::claims::generate_lock_script_claim_template::GenerateLockScriptClaimTemplateFor;
use crate::protocol::consensus::transaction::validity::tasm::claims::generate_type_script_claim_template::GenerateTypeScriptClaimTemplateFor;
use crate::protocol::consensus::transaction::validity::tasm::claims::generate_rri_claim::GenerateRriClaimFor;
use crate::protocol::consensus::transaction::Claim;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::proof_abstractions::SecretWitness;
use crate::BFieldElement;
use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::AnyProofCollection;
use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::LeviathanProofCollection;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;

use super::tasm::single_proof::fix_branch::FixBranch;
use super::tasm::single_proof::fix_branch::FixWitness;
use super::tasm::single_proof::merge_branch::MergeWitness;
use super::tasm::single_proof::update_branch::UpdateWitness;
use super::tasm::single_proof::weld_branch::WeldBranch;
use super::tasm::single_proof::weld_branch::WeldWitness;
use crate::protocol::consensus::chaintx::link_proof::link_proof_claim;
use crate::protocol::consensus::chaintx::link_proof::LeviathanLinkProof;
use crate::protocol::consensus::chaintx::link_proof::LinkProof;
use crate::protocol::consensus::chaintx::link_tx::LinkTx;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProof;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::proof_abstractions::verifier::verify;

pub(crate) const DISCRIMINANT_FOR_PROOF_COLLECTION: u64 = 0;
pub(crate) const DISCRIMINANT_FOR_UPDATE: u64 = 1;
pub(crate) const DISCRIMINANT_FOR_MERGE: u64 = 2;

/// Transaction chaining, from `UpgradeVMv8` onwards; see
/// [`ConsensusRuleSet::has_chain_branches`].
pub(crate) const DISCRIMINANT_FOR_FIX: u64 = 3;

/// Transaction chaining, from `UpgradeVMv8` onwards; see
/// [`ConsensusRuleSet::has_chain_branches`].
pub(crate) const DISCRIMINANT_FOR_WELD: u64 = 4;

const INVALID_WITNESS_DISCRIMINANT_ERROR: i128 = 1_000_050;
const NO_BRANCH_TAKEN_ERROR: i128 = 1_000_051;
const MANIPULATED_PROOF_COLLECTION_WITNESS_ERROR: i128 = 1_000_052;
const DEPOSIT_ANNOUNCEMENT_WITHOUT_BDAV_ERROR: i128 = 1_000_053;
const SETTLEMENT_ANNOUNCEMENT_WITHOUT_BAAV_ERROR: i128 = 1_000_054;

/// The claim version of the bridge proofs a `SingleProofV2` verifies: that of the program's own
/// proofs, which `NewClaim` stamps in the claim snippets.
const BRIDGE_CLAIM_VERSION: u32 = tasm_lib::triton_vm::proof::CURRENT_VERSION;

#[derive(Debug, Clone, BFieldCodec)]
pub enum SingleProofV2Witness {
    Collection(Box<AnyProofCollection>),
    Update(UpdateWitness),
    Merger(MergeWitness),
    /// `LinkTx -> Transaction`: send a chained transaction whose thruputs are
    /// all resolved to a block-borne, `SingleProof`-backed one.
    Fix(FixWitness),
    /// `Transaction * LinkTx -> Transaction`: fold a link transaction into a
    /// `SingleProof`-backed one, cutting every thruput through against that
    /// transaction's outputs. What `Fix(Chain(Cast(A), B))` computes in three
    /// proofs, in one.
    Weld(Box<WeldWitness>),
    // Wait for Hard Fork One:
    // IntegralMempool(IntegralMempoolMembershipWitness)
}

impl SingleProofV2Witness {
    pub fn from_collection(proof_collection: impl Into<AnyProofCollection>) -> Self {
        Self::Collection(Box::new(proof_collection.into()))
    }

    pub fn from_update(witness: UpdateWitness) -> Self {
        Self::Update(witness)
    }

    pub(crate) fn from_merge(merge_witness: MergeWitness) -> Self {
        Self::Merger(merge_witness)
    }

    pub fn from_fix(witness: FixWitness) -> Self {
        Self::Fix(witness)
    }

    pub fn from_weld(witness: WeldWitness) -> Self {
        Self::Weld(Box::new(witness))
    }

    /// Prove this witness under the given rule set's [`SingleProofV2`]
    /// program, yielding a [`SingleProofV2`]-backed [`Proof`].
    ///
    /// Under `UpgradeVMv7` only a [`ProofCollection`] can be raised, and the
    /// padded-height limit of the job is lowered to what the available memory
    /// holds; see `nondeterminism_for` and `SingleProofV2::job_options_for`.
    pub async fn produce(
        self,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Proof, CreateProofError> {
        // Through the versioned builder, like the verifier.
        let claim = single_proof_claim(self.kernel_mast_hash(), consensus_rule_set);
        let program = SingleProofV2::program_for(consensus_rule_set)?;
        let nondeterminism = self
            .nondeterminism_for(consensus_rule_set, proof_job_options.job_settings.network)
            .await?;
        let proof_job_options =
            SingleProofV2::job_options_for(consensus_rule_set, proof_job_options);
        ProofBuilder::new()
            .program(program)
            .claim(claim)
            .nondeterminism(|| nondeterminism)
            .job_queue(triton_vm_job_queue)
            .proof_job_options(proof_job_options)
            .build()
            .await
    }

    /// The nondeterminism for proving this witness under the given rule set's
    /// [`SingleProofV2`] program; see [`SingleProofV2::program_for`].
    ///
    /// The `UpgradeVMv7` program verifies triton-vm v7 proofs, so its
    /// nondeterminism comes from the tasm-lib v7 verifier, which verifies every
    /// sub-proof first; that runs in a blocking task. This version raises only
    /// proof collections to v7 single proofs; updating and merging v7 single
    /// proofs is left to nodes of that era. On networks with mock proofs the
    /// prover reads no nondeterminism, and the sub-proofs are mock proofs that
    /// the v7 verifier rejects, so none is derived.
    pub(crate) async fn nondeterminism_for(
        &self,
        consensus_rule_set: ConsensusRuleSet,
        network: Network,
    ) -> Result<NonDeterminism, CreateProofError> {
        match (consensus_rule_set, self) {
            (
                ConsensusRuleSet::UpgradeVMv8 | ConsensusRuleSet::LeviathanSettlement,
                Self::Collection(proof_collection),
            ) if !proof_collection.is_of(consensus_rule_set) => {
                Err(CreateProofError::NotProducible {
                    proof: "a single proof of a proof collection in another rule set's layout",
                    consensus_rule_set,
                })
            }
            // The prover reads none on mock networks, and mock sub-proofs have no stark_verify
            // nondeterminism to derive.
            (ConsensusRuleSet::UpgradeVMv8 | ConsensusRuleSet::LeviathanSettlement, _)
                if network.use_mock_proof() =>
            {
                Ok(NonDeterminism::default())
            }
            (ConsensusRuleSet::UpgradeVMv8 | ConsensusRuleSet::LeviathanSettlement, _) => {
                Ok(self.nondeterminism_with(single_proof_program_digest(consensus_rule_set)))
            }
            (ConsensusRuleSet::UpgradeVMv7, Self::Collection(_)) if network.use_mock_proof() => {
                Ok(NonDeterminism::default())
            }
            (ConsensusRuleSet::UpgradeVMv7, Self::Collection(proof_collection)) => {
                match &**proof_collection {
                    AnyProofCollection::Upstream(proof_collection) => {
                        Ok(legacy_v7::v7_single_proof_nondeterminism_blocking(
                            proof_collection.clone(),
                        )
                        .await?)
                    }
                    AnyProofCollection::Leviathan(_) => Err(CreateProofError::NotProducible {
                        proof: "a single proof of a LeviathanSettlement proof collection",
                        consensus_rule_set,
                    }),
                }
            }
            (ConsensusRuleSet::UpgradeVMv7, _) => Err(CreateProofError::NotProducible {
                proof: "a single proof other than from a proof collection",
                consensus_rule_set,
            }),
            _ => Err(CreateProofError::NotProducible {
                proof: "a single proof",
                consensus_rule_set,
            }),
        }
    }

    /// MAST hash of the transaction kernel this witness attests to -- the public
    /// input of the `SingleProof` claim.
    pub fn kernel_mast_hash(&self) -> Digest {
        match self {
            Self::Collection(pc) => pc.kernel_mast_hash(),
            Self::Update(witness) => witness.new_kernel_mast_hash,
            Self::Merger(witness) => witness.new_kernel.mast_hash(),
            Self::Fix(witness) => witness.kernel_mast_hash(),
            Self::Weld(witness) => witness.kernel_mast_hash(),
        }
    }
}

// This implementation of `TasmObject` is required for `decode_iter` and the
// method `decode_from_memory` that relies on it.
impl TasmObject for SingleProofV2Witness {
    fn label_friendly_name() -> String {
        "SingleProofV2Witness".to_string()
    }

    fn compute_size_and_assert_valid_size_indicator(
        _library: &mut Library,
    ) -> Vec<LabelledInstruction> {
        unimplemented!()
    }

    fn decode_iter<Itr: Iterator<Item = BFieldElement>>(
        iterator: &mut Itr,
    ) -> Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let discriminant = iterator
            .next()
            .ok_or(Box::new(BFieldCodecError::EmptySequence))?;
        let field_size = iterator
            .next()
            .ok_or(Box::new(BFieldCodecError::SequenceTooShort))?
            .value()
            .try_into()
            .map_err(|_| Box::new(BFieldCodecError::ElementOutOfRange))?;
        let field_data = iterator.take(field_size).collect_vec();

        match discriminant.value() {
            DISCRIMINANT_FOR_PROOF_COLLECTION => Ok(Box::new(Self::Collection(Box::new(
                *BFieldCodec::decode(&field_data)?,
            )))),
            DISCRIMINANT_FOR_UPDATE => {
                Ok(Box::new(Self::Update(*BFieldCodec::decode(&field_data)?)))
            }
            DISCRIMINANT_FOR_MERGE => {
                Ok(Box::new(Self::Merger(*BFieldCodec::decode(&field_data)?)))
            }
            DISCRIMINANT_FOR_FIX => Ok(Box::new(Self::Fix(*BFieldCodec::decode(&field_data)?))),
            DISCRIMINANT_FOR_WELD => Ok(Box::new(Self::Weld(Box::new(*BFieldCodec::decode(
                &field_data,
            )?)))),
            _ => Err(Box::new(BFieldCodecError::ElementOutOfRange)),
        }
    }
}

impl SecretWitness for SingleProofV2Witness {
    fn standard_input(&self) -> PublicInput {
        self.kernel_mast_hash().reversed().values().into()
    }

    fn output(&self) -> Vec<BFieldElement> {
        std::vec![]
    }

    fn program(&self) -> Program {
        SingleProofV2.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        self.nondeterminism_with(SingleProofV2.hash())
    }
}

/// The nondeterminism of the sub-proofs of a [`ProofCollection`], in the order the
/// `SingleProofV2` program verifies them.
fn add_sub_proof_nondeterminism(
    nondeterminism: &mut NonDeterminism,
    stark_verify_snippet: &StarkVerify,
    proof_collection: &ProofCollection,
) {
    // removal records integrity
    let rri_claim = proof_collection.removal_records_integrity_claim();
    let rri_proof = &proof_collection.removal_records_integrity;
    stark_verify_snippet.update_nondeterminism(nondeterminism, rri_proof, &rri_claim);

    // kernel to outputs
    let k2o_claim = proof_collection.kernel_to_outputs_claim();
    let k2o_proof = &proof_collection.kernel_to_outputs;
    stark_verify_snippet.update_nondeterminism(nondeterminism, k2o_proof, &k2o_claim);

    // collect lock scripts
    let cls_claim = proof_collection.collect_lock_scripts_claim();
    let cls_proof = &proof_collection.collect_lock_scripts;
    stark_verify_snippet.update_nondeterminism(nondeterminism, cls_proof, &cls_claim);

    // collect type scripts
    let cts_claim = proof_collection.collect_type_scripts_claim_v2();
    let cts_proof = &proof_collection.collect_type_scripts;
    stark_verify_snippet.update_nondeterminism(nondeterminism, cts_proof, &cts_claim);

    // lock scripts
    for (claim, proof) in proof_collection
        .lock_script_claims()
        .into_iter()
        .zip(&proof_collection.lock_scripts_halt)
    {
        stark_verify_snippet.update_nondeterminism(nondeterminism, proof, &claim);
    }

    // type scripts
    for (claim, proof) in proof_collection
        .type_script_claims()
        .into_iter()
        .zip(&proof_collection.type_scripts_halt)
    {
        stark_verify_snippet.update_nondeterminism(nondeterminism, proof, &claim);
    }
}

impl SingleProofV2Witness {
    /// The nondeterminism for the `SingleProofV2` program whose digest is
    /// `single_proof_program_hash`, which the recursive branches verify against.
    pub(crate) fn nondeterminism_with(&self, single_proof_program_hash: Digest) -> NonDeterminism {
        // populate nondeterministic memory with witness
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

        let mut nondeterminism = NonDeterminism::default().with_ram(memory);
        let stark_verify_snippet = StarkVerify::new_with_dynamic_layout(Stark::default());

        match self {
            SingleProofV2Witness::Collection(proof_collection) => match &**proof_collection {
                AnyProofCollection::Upstream(proof_collection) => {
                    nondeterminism
                        .digests
                        .extend_from_slice(&proof_collection.merge_bit_mast_path);
                    add_sub_proof_nondeterminism(
                        &mut nondeterminism,
                        &stark_verify_snippet,
                        proof_collection,
                    );
                }
                AnyProofCollection::Leviathan(proof_collection) => {
                    nondeterminism
                        .digests
                        .extend_from_slice(&proof_collection.merge_bit_mast_path);
                    nondeterminism
                        .digests
                        .extend_from_slice(&proof_collection.announcements_mast_path);

                    // A BAAV proof covers the sub-proofs, which are then not verified.
                    if proof_collection.bridge_aggregated_proof.is_none() {
                        add_sub_proof_nondeterminism(
                            &mut nondeterminism,
                            &stark_verify_snippet,
                            &proof_collection.base(),
                        );
                    }

                    if let Some(bdav_proof) =
                        &proof_collection.bridge_deposit_announcement_validator
                    {
                        let bdav_claim = proof_collection
                            .bridge_deposit_announcement_validator_claim(BRIDGE_CLAIM_VERSION);
                        stark_verify_snippet.update_nondeterminism(
                            &mut nondeterminism,
                            bdav_proof,
                            &bdav_claim,
                        );
                    }

                    // The BAAV claim's public input is divined: prev_state, new_state, exit_root;
                    // the kernel hash comes from the stack.
                    if let (Some(baav_proof), Some(prev_state), Some(new_state), Some(exit_root)) = (
                        &proof_collection.bridge_aggregated_proof,
                        proof_collection.bridge_prev_state_commitment,
                        proof_collection.bridge_new_state_commitment,
                        proof_collection.bridge_exit_root,
                    ) {
                        for digest in [prev_state, new_state, exit_root] {
                            nondeterminism
                                .individual_tokens
                                .extend(digest.values().iter().rev());
                        }
                        let baav_claim = proof_collection
                            .bridge_aggregated_proof_claim(Some(prev_state), BRIDGE_CLAIM_VERSION)
                            .expect("the settlement fields are set");
                        stark_verify_snippet.update_nondeterminism(
                            &mut nondeterminism,
                            baav_proof,
                            &baav_claim,
                        );
                    }
                }
            },
            SingleProofV2Witness::Update(witness) => {
                witness.populate_nd_streams(&mut nondeterminism, single_proof_program_hash);
            }
            SingleProofV2Witness::Merger(witness_of_merge) => {
                witness_of_merge
                    .populate_nd_streams(&mut nondeterminism, single_proof_program_hash);
            }
            SingleProofV2Witness::Fix(witness) => {
                witness.populate_nd_streams(&mut nondeterminism, single_proof_program_hash);
            }
            SingleProofV2Witness::Weld(witness) => {
                witness.populate_nd_streams(&mut nondeterminism, single_proof_program_hash);
            }
        }

        nondeterminism
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SingleProofV2;

impl SingleProofV2 {
    /// Not to be confused with SingleProofV2Witness::claim
    pub(crate) fn claim(tx_kernel_mast_hash: Digest) -> Claim {
        Claim::about_program(&SingleProofV2.program())
            .with_input(tx_kernel_mast_hash.reversed().values())
    }

    /// The `SingleProofV2` program of the given rule set, for the rule sets
    /// this version proves under: the linked programs for `UpgradeVMv8` and
    /// `LeviathanSettlement`, and the program reassembled with the tasm-lib v7
    /// verifier for `UpgradeVMv7` (see [`legacy_v7::single_proof_v2_v7_program`]).
    /// Each hashes to the program digest of [`single_proof_claim`] for its rule
    /// set.
    pub(crate) fn program_for(
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Program, CreateProofError> {
        match consensus_rule_set {
            ConsensusRuleSet::UpgradeVMv8 => Ok(SingleProofV2.program()),
            ConsensusRuleSet::LeviathanSettlement => Ok(LeviathanSingleProofV2.program()),
            ConsensusRuleSet::UpgradeVMv7 => {
                // Refuse to prove if the reassembled program drifted from the
                // pinned digest: no node of that era would accept the proof.
                let program = legacy_v7::single_proof_v2_v7_program();
                if program.hash() != single_proof_program_digest(consensus_rule_set) {
                    return Err(CreateProofError::NotProducible {
                        proof: "a single proof: the assembled program does not hash to the pinned \
                                digest",
                        consensus_rule_set,
                    });
                }

                Ok(program)
            }
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5 => Err(CreateProofError::NotProducible {
                proof: "a single proof",
                consensus_rule_set,
            }),
        }
    }

    /// The job options for proving the given rule set's program on this
    /// machine: for `UpgradeVMv7`, with the padded-height limit lowered to
    /// what the available memory holds; see
    /// [`legacy_v7::v7_single_proof_job_options`].
    pub(crate) fn job_options_for(
        consensus_rule_set: ConsensusRuleSet,
        proof_job_options: TritonVmProofJobOptions,
    ) -> TritonVmProofJobOptions {
        match consensus_rule_set {
            ConsensusRuleSet::UpgradeVMv7 => {
                legacy_v7::v7_single_proof_job_options(proof_job_options)
            }
            _ => proof_job_options,
        }
    }

    /// Generate a [SingleProofV2] for the transaction, given its primitive
    /// witness.
    ///
    /// This involves generating a [ProofCollection] as an intermediate step.
    ///
    /// Use [produce_single_proof] to automatically select the right single
    /// proof version.
    pub(crate) async fn produce(
        primitive_witness: &PrimitiveWitness,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Proof, CreateProofError> {
        // Fail before proving the collection if the rule set's program is not
        // available.
        SingleProofV2::program_for(consensus_rule_set)?;

        let proof_collection = AnyProofCollection::produce_v2(
            primitive_witness,
            triton_vm_job_queue.clone(),
            proof_job_options.clone(),
            consensus_rule_set,
        )
        .await?;
        let single_proof_witness = SingleProofV2Witness::from_collection(proof_collection);

        // The witness builds the claim through the versioned builder rather
        // than its default `claim()`, which stamps the LINKED triton-vm's
        // `CURRENT_VERSION`. Those two agree only while the era being produced
        // for is the current one; for any other era they disagree, and because
        // the claim's version is part of the Fiat-Shamir transcript the proof
        // then answers a different question than the verifier asks. Going
        // through the same builder the verifier uses makes them agree by
        // construction. Upstream: d4742c65.
        info!("Start: generate single proof from proof collection");
        let proof = single_proof_witness
            .produce(triton_vm_job_queue, proof_job_options, consensus_rule_set)
            .await?;
        info!("Done");

        Ok(proof)
    }
}

/// Generate a [SingleProofV2] for the transaction, given its primitive
/// witness.
///
/// This involves generating a [ProofCollection] as an intermediate step.
//
// This function calls SingleProofV2::produce but with the correct merge
// version.
pub(crate) async fn produce_single_proof(
    primitive_witness: &PrimitiveWitness,
    triton_vm_job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
    consensus_rule_set: ConsensusRuleSet,
) -> Result<Proof, CreateProofError> {
    match consensus_rule_set {
        ConsensusRuleSet::Reboot
        | ConsensusRuleSet::HardforkAlpha
        | ConsensusRuleSet::Xnt
        | ConsensusRuleSet::TimelockExtension
        | ConsensusRuleSet::UpgradeVM
        | ConsensusRuleSet::UpgradeVMv4
        | ConsensusRuleSet::UpgradeVMv5
        | ConsensusRuleSet::UpgradeVMv7
        | ConsensusRuleSet::UpgradeVMv8
        | ConsensusRuleSet::LeviathanSettlement => {
            // backed by CollectTypeScriptsV2's hash. For now it shares V1 so
            // the variant is wired and the rest of the cascade can be built.
            SingleProofV2::produce(
                primitive_witness,
                triton_vm_job_queue,
                proof_job_options,
                consensus_rule_set,
            )
            .await
        }
    }
}

/// Not to be confused with SingleProofV2Witness::claim
///
/// Consensus rule set refers to the rule set for which the claim must be valid.
//
// This function calls SingleProofV2::claim but with the correct merge version.
pub(crate) fn single_proof_claim(
    tx_kernel_mast_hash: Digest,
    consensus_rule_set: ConsensusRuleSet,
) -> Claim {
    // Pre-upgrade SingleProof / SingleProofV2 digests, COMPUTED by building each
    // historical source tree with its own tasm-lib (`~/xnt-core-v0|v1|v2`); the
    // in-tree snapshot literals were stale for these programs.
    const SINGLE_PROOF_REBOOT_DIGEST: &str = // SingleProof, v0 tree (Reboot/HardforkAlpha)
        "b975c61c2efd9321bddd99d43d5d25c336054bf70abd6db919cb57dcf27d1427e34365d7ddebc381";
    const SINGLE_PROOF_XNT_DIGEST: &str = // SingleProof, v1 tree (Xnt)
        "d69c074e55c4dde6794f65cfcd1d8f5a88904845fa3218d60adbfc134337e03661feede4fa3d4491";
    const SINGLE_PROOF_V2_TIMELOCK_DIGEST: &str = // SingleProofV2, v2 tree (TimelockExtension)
        "19d8f2cf2dfcf917772f27fbc9762419512a4e628775ef64d4cab55ea5e157faa7e1ea4507dc1b6b";
    const SINGLE_PROOF_V2_UPGRADE_VM_DIGEST: &str = // SingleProofV2, v3 tree (UpgradeVM)
        "6f6ea3083e506c048203a8505f8793aa70e4b1f610a352b14360f9e3fde21aa9373d607ddcf69888";
    const SINGLE_PROOF_V2_UPGRADE_VM_V4_DIGEST: &str = // SingleProofV2, v4 tree (UpgradeVMv4)
        "15312e1a996ae949b1c5aa9b3af6c3ca5f9566cae3e40aa7d0552b2ed780a279a7c3a3bb783aeee7";
    const SINGLE_PROOF_V2_UPGRADE_VM_V5_DIGEST: &str = // SingleProofV2, v5 tree (UpgradeVMv5)
        "e66985a98e4d5e455c5d11e57a16c3dca3cce2bd2a16d6f5e791f592801cc32eb99c57c32bf90e88";
    const SINGLE_PROOF_V2_UPGRADE_VM_V7_DIGEST: &str = // SingleProofV2, v7 tree (UpgradeVMv7)
        "5c75cc2d808464503cccf3bf2467ff13bd3fc736d06aa4f661415852549900e04eb667ddd9792d76";

    let input = tx_kernel_mast_hash.reversed().values().to_vec();
    let version = consensus_rule_set.triton_proof_version().claim_version();
    match consensus_rule_set {
        ConsensusRuleSet::Reboot | ConsensusRuleSet::HardforkAlpha => {
            Claim::new(Digest::try_from_hex(SINGLE_PROOF_REBOOT_DIGEST).unwrap())
                .about_version(version)
                .with_input(input)
        }
        ConsensusRuleSet::Xnt => Claim::new(Digest::try_from_hex(SINGLE_PROOF_XNT_DIGEST).unwrap())
            .about_version(version)
            .with_input(input),
        ConsensusRuleSet::TimelockExtension => {
            Claim::new(Digest::try_from_hex(SINGLE_PROOF_V2_TIMELOCK_DIGEST).unwrap())
                .about_version(version)
                .with_input(input)
        }
        // UpgradeVM (v3) bytecode — now a pre-v4 era, hardcoded.
        ConsensusRuleSet::UpgradeVM => {
            Claim::new(Digest::try_from_hex(SINGLE_PROOF_V2_UPGRADE_VM_DIGEST).unwrap())
                .about_version(version)
                .with_input(input)
        }
        // UpgradeVMv4 (v4) bytecode — now a pre-v5 era, hardcoded.
        ConsensusRuleSet::UpgradeVMv4 => {
            Claim::new(Digest::try_from_hex(SINGLE_PROOF_V2_UPGRADE_VM_V4_DIGEST).unwrap())
                .about_version(version)
                .with_input(input)
        }
        // UpgradeVMv5 (v5) bytecode — now a pre-v7 era, hardcoded.
        ConsensusRuleSet::UpgradeVMv5 => {
            Claim::new(Digest::try_from_hex(SINGLE_PROOF_V2_UPGRADE_VM_V5_DIGEST).unwrap())
                .about_version(version)
                .with_input(input)
        }
        // UpgradeVMv7 (v7) bytecode — now a pre-v8 era, hardcoded.
        ConsensusRuleSet::UpgradeVMv7 => {
            Claim::new(Digest::try_from_hex(SINGLE_PROOF_V2_UPGRADE_VM_V7_DIGEST).unwrap())
                .about_version(version)
                .with_input(input)
        }
        // Current (v8) bytecode — recompute from the linked program.
        ConsensusRuleSet::UpgradeVMv8 => SingleProofV2::claim(tx_kernel_mast_hash),
        ConsensusRuleSet::LeviathanSettlement => LeviathanSingleProofV2::claim(tx_kernel_mast_hash),
    }
}

/// The digest of this consensus rule set's `SingleProof` program: the `D` that
/// link proofs under it carry.
pub(crate) fn single_proof_program_digest(consensus_rule_set: ConsensusRuleSet) -> Digest {
    single_proof_claim(Digest::default(), consensus_rule_set).program_digest
}

/// The claim a proof-backed [`LinkTx`]'s proof must relate to, for this
/// consensus rule set: the [`link_proof_claim`] with `D` instantiated to the
/// rule set's `SingleProof` digest.
///
/// Only meaningful for a rule set with chain branches; see
/// [`ConsensusRuleSet::has_chain_branches`].
pub(crate) fn link_tx_claim(
    link_kernel_mast_hash: Digest,
    consensus_rule_set: ConsensusRuleSet,
) -> Claim {
    link_proof_claim(
        link_kernel_mast_hash,
        single_proof_program_digest(consensus_rule_set),
        consensus_rule_set,
    )
}

/// Fix a resolved [`LinkTx`] into a `SingleProof`-backed [`Transaction`].
///
/// The exit of the chain pipeline: the link transaction must be proof-backed
/// with no thruputs left, and the resulting transaction is block-eligible
/// like any other single-proof transaction.
///
/// Returns [`CreateProofError::LinkTxNotFixable`] if the link transaction
/// carries thruputs, is not proof-backed, or if the rule set's `SingleProof`
/// program has no `Fix` branch.
pub(crate) async fn fix_link_tx(
    link_tx: LinkTx,
    consensus_rule_set: ConsensusRuleSet,
    triton_vm_job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
) -> Result<Transaction, CreateProofError> {
    if !consensus_rule_set.has_chain_branches() {
        return Err(CreateProofError::LinkTxNotFixable(
            "the rule set's SingleProof program has no Fix branch",
        ));
    }
    if !link_tx.kernel.thruputs.is_empty() {
        return Err(CreateProofError::LinkTxNotFixable(
            "it has unresolved thruputs",
        ));
    }
    if !link_tx.proof.is_proof() {
        return Err(CreateProofError::LinkTxNotFixable(
            "it is not backed by a link proof",
        ));
    }

    let witness = FixWitness::fix(link_tx);
    let kernel = witness.kernel.clone();

    let network = proof_job_options.job_settings.network;
    let proof = if network.use_mock_proof() {
        Proof::valid_mock(Claim::new(Digest::default()))
    } else {
        // The link proof must answer the claim `Fix` builds for it, which
        // names this rule set's `SingleProof` program. Checked here, as an
        // error, rather than while assembling the nondeterminism.
        let claim = witness.link_proof_claim(single_proof_program_digest(consensus_rule_set));
        if !verify(claim, witness.link_proof.clone(), network).await {
            return Err(CreateProofError::LinkTxNotFixable(
                "its link proof does not answer the Fix claim",
            ));
        }

        SingleProofV2Witness::from_fix(witness)
            .produce(triton_vm_job_queue, proof_job_options, consensus_rule_set)
            .await?
    };

    Ok(Transaction {
        kernel,
        proof: TransactionProof::SingleProof(proof),
    })
}

pub(crate) fn produce_single_proof_mock(valid_mock: bool) -> Proof {
    let claim = Claim::new(Digest::default());
    if valid_mock {
        Proof::valid_mock(claim)
    } else {
        Proof::invalid_mock(claim)
    }
}

impl SingleProofV2 {
    /// Assemble the program, with or without the transaction-chaining
    /// branches, over the proof collection `P`, with or without the bridge
    /// checks.
    ///
    /// The `UpgradeVMv8` program, over upstream's [`ProofCollection`] without
    /// the bridge checks, is upstream's; the `LeviathanSettlement` one is
    /// [`LeviathanSingleProofV2`]. Assembling without the chaining branches
    /// reproduces the program as it was before they were added, which is what
    /// shows that adding them changed nothing else.
    fn assemble<P: TasmStruct + Clone + std::fmt::Debug + 'static>(
        &self,
        with_chain_branches: bool,
        with_bridge: bool,
    ) -> (Library, Vec<LabelledInstruction>) {
        self.assemble_into::<P>(Library::new(), with_chain_branches, with_bridge)
    }

    /// Like [`Self::assemble`], into a library that may already hold imports.
    ///
    /// Imports deduplicate by entrypoint label, so a snippet imported up front
    /// replaces every later import of the same label. The `UpgradeVMv7`
    /// program uses this to substitute the tasm-lib v7 STARK verifier and the
    /// claim builder for claim version 5; see
    /// [`legacy_v7::single_proof_v2_v7_code`].
    pub(crate) fn assemble_into<P: TasmStruct + Clone + std::fmt::Debug + 'static>(
        &self,
        mut library: Library,
        with_chain_branches: bool,
        with_bridge: bool,
    ) -> (Library, Vec<LabelledInstruction>) {
        // imports
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let assemble_rri_claim = library.import(Box::new(GenerateRriClaimFor::<P>(PhantomData)));
        let assemble_k2o_claim = library.import(Box::new(GenerateK2oClaimFor::<P>(PhantomData)));
        let assemble_cls_claim = library.import(Box::new(GenerateCollectLockScriptsClaimFor::<P>(
            PhantomData,
        )));
        let assemble_cts_claim = library.import(Box::new(
            GenerateCollectTypeScriptsClaimV2For::<P>(PhantomData),
        ));
        let assemble_lock_script_claim_template = library.import(Box::new(
            GenerateLockScriptClaimTemplateFor::<P>(PhantomData),
        ));
        let assemble_type_script_claim_template = library.import(Box::new(
            GenerateTypeScriptClaimTemplateFor::<P>(PhantomData),
        ));

        let proof_collection_field_kernel_mast_hash = field!(P::kernel_mast_hash);
        let proof_collection_field_removal_records_integrity = field!(P::removal_records_integrity);
        let proof_collection_field_collect_lock_scripts = field!(P::collect_lock_scripts);
        let proof_collection_field_kernel_to_outputs = field!(P::kernel_to_outputs);
        let proof_collection_field_collect_type_scripts = field!(P::collect_type_scripts);
        let proof_collection_field_lock_scripts_halt = field!(P::lock_scripts_halt);
        let proof_collection_field_type_scripts_halt = field!(P::type_scripts_halt);

        let update_branch = library.import(Box::new(UpdateBranch));
        let merge_branch = library.import(Box::new(MergeBranch));

        let audit_witness_of_proof_collection =
            library.import(Box::new(VerifyNdSiIntegrity::<P>::default()));

        let claim_field_with_size_output = triton_asm!(read_mem 1 addi 1 place 1 addi -1);
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));

        // The chaining branches are imported last: an import both emits code and
        // hands out static-memory addresses, and importing them after every
        // other snippet keeps the existing branches' allocations where they were.
        //
        // `Fix` and `Weld` share one slot for `D`, this program's own digest: both
        // instantiate the `LinkProof` family at it, neither runs in the same
        // execution as the other, and one slot is one `kmalloc` less.
        let chain_branches = with_chain_branches.then(|| {
            let single_proof_digest_alloc = library.kmalloc(u32::try_from(Digest::LEN).unwrap());
            let link_proof_digest = if with_bridge {
                LeviathanLinkProof.hash()
            } else {
                LinkProof.hash()
            };
            let fix = library.import(Box::new(FixBranch::new(
                single_proof_digest_alloc,
                link_proof_digest,
            )));
            let weld = library.import(Box::new(WeldBranch::new(
                single_proof_digest_alloc,
                link_proof_digest,
            )));
            (fix, weld)
        });

        // Imported after every snippet of the upstream program, which keeps its allocations.
        let bridge_imports = with_bridge.then(|| {
            (
                library.import(Box::new(GenerateBridgeDepositClaim)),
                library.import(Box::new(GenerateAggregatedClaim)),
                library.import(Box::new(HashVarlen)),
            )
        });

        // INVARIANT: _ count *announcement[i]_si num_remaining. Counts announcements whose message
        // is non-empty and starts with `tag`.
        let count_tagged_announcements = |label: &str, tag: u64| {
            triton_asm! {
                {label}:
                    dup 0 push 0 eq skiz return

                    dup 1 read_mem 1 pop 1
                    // _ count *ann_si n encoded_len

                    dup 2 addi 2 read_mem 1 pop 1
                    push 0 eq push 0 eq
                    dup 3 addi 3 read_mem 1 pop 1
                    push {tag} eq
                    mul
                    // _ count *ann_si n encoded_len is_tagged

                    pick 4 add place 3
                    // _ count' *ann_si n encoded_len

                    addi 1 dup 2 add swap 2 pop 1
                    addi -1
                    // _ count' *next_ann_si (n-1)

                    recurse
            }
        };
        let count_deposit_announcements_label = "neptune_transaction_count_deposit_announcements";
        let count_deposit_announcements_body =
            count_tagged_announcements(count_deposit_announcements_label, BRIDGE_DEPOSIT_TAG);
        let count_settlement_announcements_label =
            "neptune_transaction_count_settlement_announcements";
        let count_settlement_announcements_body = count_tagged_announcements(
            count_settlement_announcements_label,
            AGGREGATED_ANNOUNCEMENT_TAG,
        );
        let sub_proofs_verify_label = "neptune_transaction_verify_sub_proofs";
        let bdav_verify_label = "neptune_transaction_verify_bdav";
        let baav_verify_label = "neptune_transaction_verify_baav";

        // The `Fix` and `Weld` discriminants are only legal when their branches
        // are present.
        let (accept_chain_discriminants, dispatch_chain_branches) = match chain_branches {
            None => (triton_asm!(), triton_asm!()),
            Some((fix_branch, weld_branch)) => (
                triton_asm!(
                    dup 1 push {DISCRIMINANT_FOR_FIX} eq add
                    dup 1 push {DISCRIMINANT_FOR_WELD} eq add
                ),
                triton_asm!(
                    dup 0 push {DISCRIMINANT_FOR_FIX} eq
                    skiz call {fix_branch}

                    dup 0 push {DISCRIMINANT_FOR_WELD} eq
                    skiz call {weld_branch}
                ),
            ),
        };

        let verify_scripts_loop_label = "neptune_transaction_verify_lock_scripts_loop";
        let verify_scripts_loop_body = triton_asm! {
            // INVARIANT: _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size
            {verify_scripts_loop_label}:
                hint current_proof_size = stack[0]
                hint current_proof_ptr = stack[1]
                hint eof = stack[2]
                hint current_program_digest = stack[3]
                hint claim_program_digest = stack[4]
                hint claim_template = stack[5]

                dup 3 dup 3 eq skiz return
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size

                dup 3
                addi {Digest::LEN - 1}
                read_mem {Digest::LEN}
                pop 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size [current_program_digest]

                dup 9
                write_mem {Digest::LEN}
                pop 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size

                dup 5
                dup 2
                call {stark_verify}
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size

                add
                // _ *claim_template *claim_program_digest *current_program_digest *eof *next_proof_si

                read_mem 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof next_proof_size (*next_proof_si-1)
                addi 2
                // _ *claim_template *claim_program_digest *current_program_digest *eof next_proof_size *next_proof
                swap 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof *next_proof next_proof_size

                swap 3
                addi {Digest::LEN}
                swap 3
                // _ *claim_template *claim_program_digest *next_program_digest *eof *next_proof next_proof_size

                recurse
        };

        let verify_merge_bit_false = triton_asm! {
            // _ [txk_digest] garb garb

                dup 6
                dup 6
                dup 6
                dup 6
                dup 6
                // _ [txk_digest] garb garb [txk_digest]

                push {TransactionKernel::MAST_HEIGHT as u32}
                push {TransactionKernelField::MergeBit as u32}
                // _ [txk_digest] garb garb [txk_digest] height index

                push 0
                push 0
                push 0
                push 0
                push 0
                push 0
                push 0
                push 0
                push 1
                push {u32::from(false)}
                // _ [txk_digest] garb garb [txk_digest] height index [padded-false-encoded]

                sponge_init
                sponge_absorb
                sponge_squeeze

                pick 5 pop 1
                pick 5 pop 1
                pick 5 pop 1
                pick 5 pop 1
                pick 5 pop 1
                // _ [txk_digest] garb garb [txk_digest] height index [false-digest]

                call {merkle_verify}
                // _ [txk_digest] garb garb
        };

        let proof_collection_case_label =
            "neptune_transaction_single_proof_case_collection".to_string();
        let sub_proofs_core = triton_asm! {
                /* create and verify removal records integrity claim */
                call {assemble_rri_claim}
                hint rri_claim = stack[0]
                // [txk_digest] *spw disc *proof_collection *rri_claim

                dup 1 {&proof_collection_field_removal_records_integrity}
                // [txk_digest] *spw disc *proof_collection *rri_claim *rri_proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection


                /* create and verify kernel to outputs claim */
                call {assemble_k2o_claim}
                // [txk_digest] *spw disc *proof_collection *k2o_claim

                dup 1 {&proof_collection_field_kernel_to_outputs}
                // [txk_digest] *spw disc *proof_collection *k2o_claim *proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection


                /* assemble and verify collect lock scripts claim */
                dup 0
                // [txk_digest] *spw disc *proof_collection

                call {assemble_cls_claim}
                hint cls_claim = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim

                dup 1 dup 1 swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cls_claim *proof_collection

                {&proof_collection_field_collect_lock_scripts}
                // [txk_digest] *spw disc *proof_collection *cls_claim *cls_claim *cls_proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection *cls_claim


                /* assemble and verify collect type scripts claim */

                dup 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *proof_collection

                call {assemble_cts_claim}
                hint cts_claim = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim

                dup 0 dup 3
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *cts_claim *proof_collection

                {&proof_collection_field_collect_type_scripts}
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *cts_claim *cts_proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim


                /* for all lock scripts, assemble claim and verify */
                dup 2
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *proof_collection

                call {assemble_lock_script_claim_template}
                hint program_digest_ptr = stack[0]
                hint lock_script_claim_ptr = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr

                dup 3 {&claim_field_with_size_output}
                hint output_size = stack[0]
                hint lock_script_hashes = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes size

                dup 1 add addi 2
                hint eof = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes *eof

                swap 1 addi 2
                hint lock_script_hashes_i = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *eof *lock_script_hashes[0]

                swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes[0] *eof


                dup 6
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes[0] *eof *proof_collection

                {&proof_collection_field_lock_scripts_halt} addi 1
                hint lock_script_proofs_i_si = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes *eof *lock_script_proofs[0]_si

                read_mem 1
                hint proof_size = stack[1]
                addi 2
                swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes *eof *lock_script_proofs[0] proof_size

                call {verify_scripts_loop_label}

                pop 5 pop 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim


                /* for all type scripts, assemble claim and verify */
                dup 2
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *proof_collection

                call {assemble_type_script_claim_template}
                hint program_digest_ptr = stack[0]
                hint type_script_claim_ptr = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr

                dup 2 {&claim_field_with_size_output}
                hint output_size = stack[0]
                hint type_script_hashes = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes size

                dup 1 add addi 2
                hint eof = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof

                pick 1 addi 2
                hint type_script_hashes_i = stack[0]
                place 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes[0] *eof


                dup 6
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes[0] *eof *proof_collection

                {&proof_collection_field_type_scripts_halt}
                addi 1
                hint type_script_proofs_i_si = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof *type_script_proofs[0]_si

                read_mem 1
                hint proof_size = stack[1]
                addi 2
                place 1
                hint type_script_proofs_i = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof *type_script_proofs[0] proof_size

                call {verify_scripts_loop_label}

                pop 5 pop 4
        };
        let (proof_collection_case_body, bridge_before_loop, bridge_after_loop) =
            match bridge_imports {
                None => {
                    let case_body = triton_asm! {
                                // BEFORE: [txk_digest] *single_proof_witness discriminant
                                // AFTER: [txk_digest] *single_proof_witness discriminant
                                {proof_collection_case_label}:
                                    hint discriminant = stack[0]
                                    hint single_proof_witness = stack[1]
                                    hint txk_digest = stack[2..7]
                                    // _ [txk_digest] *single_proof_witness discriminant

                                    {&verify_merge_bit_false}
                                    // _ [txk_digest] *single_proof_witness discriminant

                                    dup 1 addi 2
                                    hint proof_collection_ptr = stack[0]
                                    // _ [txk_digest] *spw disc *proof_collection

                                    dup 0
                                    call {audit_witness_of_proof_collection}
                                    // _ [txk_digest] *spw disc *proof_collection proof_collection_size

                                    place 8
                                    // _ pc_size [txk_digest] *spw disc *proof_collection
                                    // _ [txk_digest] *spw disc *proof_collection <-- rename


                                    /* check kernel MAST hash */

                                    dup 0 {&proof_collection_field_kernel_mast_hash}
                                    // [txk_digest] *spw disc *proof_collection *kernel_mast_hash

                                    push {Digest::LEN - 1} add
                                    read_mem {Digest::LEN}
                                    pop 1
                                    hint kernel_mast_hash: Digest = stack[0..5]
                                    // [txk_digest] *spw disc *proof_collection [kernel_mast_hash]

                                    dup 12
                                    dup 12
                                    dup 12
                                    dup 12
                                    dup 12
                                    // [txk_digest] *spw disc *proof_collection [kernel_mast_hash] [txk_digest]

                                    assert_vector
                                    pop {Digest::LEN}
                                    // [txk_digest] *spw disc *proof_collection

                    {&sub_proofs_core}
                                    addi {-(DISCRIMINANT_FOR_PROOF_COLLECTION as isize) - 1}
                                    // [txk_digest] *spw -1

                                    dup 1 addi 2
                                    // _ [txk_digest] *spw -1 *proof_collection
                                    // _ pc_size_init [txk_digest] *spw -1 *proof_collection <-- rename

                                    call {audit_witness_of_proof_collection}
                                    // _ pc_size_init [txk_digest] *spw -1 pc_size_end

                                    pick 8
                                    eq
                                    assert error_id {MANIPULATED_PROOF_COLLECTION_WITNESS_ERROR}
                                    // _ [txk_digest] *spw -1

                                    return
                                        };
                    (case_body, vec![], vec![])
                }
                Some((assemble_bdav_claim, assemble_baav_claim, hash_varlen)) => {
                    let proof_collection_field_bridge_deposit_announcement_validator =
                        field!(P::bridge_deposit_announcement_validator);
                    let proof_collection_field_bridge_aggregated_proof =
                        field!(P::bridge_aggregated_proof);
                    let proof_collection_field_announcements = field!(P::announcements);
                    let proof_collection_field_with_size_announcements =
                        field_with_size!(P::announcements);
                    let case_body = triton_asm! {
                    // BEFORE: [txk_digest] *single_proof_witness discriminant
                    // AFTER: [txk_digest] *single_proof_witness discriminant
                    {proof_collection_case_label}:
                        hint discriminant = stack[0]
                        hint single_proof_witness = stack[1]
                        hint txk_digest = stack[2..7]
                        // _ [txk_digest] *single_proof_witness discriminant

                        {&verify_merge_bit_false}
                        // _ [txk_digest] *single_proof_witness discriminant

                        dup 1 addi 2
                        hint proof_collection_ptr = stack[0]
                        // _ [txk_digest] *spw disc *proof_collection

                        dup 0
                        call {audit_witness_of_proof_collection}
                        // _ [txk_digest] *spw disc *proof_collection proof_collection_size

                        place 8
                        // _ pc_size [txk_digest] *spw disc *proof_collection
                        // _ [txk_digest] *spw disc *proof_collection <-- rename


                        /* check kernel MAST hash */

                        dup 0 {&proof_collection_field_kernel_mast_hash}
                        // [txk_digest] *spw disc *proof_collection *kernel_mast_hash

                        push {Digest::LEN - 1} add
                        read_mem {Digest::LEN}
                        pop 1
                        hint kernel_mast_hash: Digest = stack[0..5]
                        // [txk_digest] *spw disc *proof_collection [kernel_mast_hash]

                        dup 12
                        dup 12
                        dup 12
                        dup 12
                        dup 12
                        // [txk_digest] *spw disc *proof_collection [kernel_mast_hash] [txk_digest]

                        assert_vector
                        pop {Digest::LEN}
                        // [txk_digest] *spw disc *proof_collection


                        /* authenticate the announcements copy against the kernel */
                        dup 7 dup 7 dup 7 dup 7 dup 7
                        push {TransactionKernel::MAST_HEIGHT as u32}
                        push {TransactionKernelField::Announcements as u32}
                        dup 7 {&proof_collection_field_with_size_announcements}
                        call {hash_varlen}
                        call {merkle_verify}
                        // [txk_digest] *spw disc *proof_collection

                        /* a deposit-tagged announcement requires the BDAV proof */
                        push 0
                        dup 1 {&proof_collection_field_announcements}
                        read_mem 1 addi 2 swap 1
                        // [txk_digest] *spw disc *proof_collection 0 *announcement[0]_si num_announcements
                        call {count_deposit_announcements_label}
                        pop 2
                        // [txk_digest] *spw disc *proof_collection num_deposits

                        push 0 eq push 0 eq
                        dup 1 {&proof_collection_field_bridge_deposit_announcement_validator}
                        read_mem 1 addi 1 pop 1
                        // [txk_digest] *spw disc *proof_collection has_deposit bdav_disc
                        push 0 eq mul
                        push 0 eq
                        assert error_id {DEPOSIT_ANNOUNCEMENT_WITHOUT_BDAV_ERROR}
                        // [txk_digest] *spw disc *proof_collection

                        /* a settlement-tagged announcement requires the BAAV proof */
                        push 0
                        dup 1 {&proof_collection_field_announcements}
                        read_mem 1 addi 2 swap 1
                        call {count_settlement_announcements_label}
                        pop 2
                        // [txk_digest] *spw disc *proof_collection num_settlements

                        push 0 eq push 0 eq
                        dup 1 {&proof_collection_field_bridge_aggregated_proof}
                        read_mem 1 addi 1 pop 1
                        // [txk_digest] *spw disc *proof_collection has_settlement baav_disc
                        push 0 eq mul
                        push 0 eq
                        assert error_id {SETTLEMENT_ANNOUNCEMENT_WITHOUT_BAAV_ERROR}
                        // [txk_digest] *spw disc *proof_collection

                        /* a BAAV proof covers the sub-proofs; without one, verify them */
                        dup 0 {&proof_collection_field_bridge_aggregated_proof}
                        read_mem 1 addi 1 pop 1
                        push 0 eq
                        // [txk_digest] *spw disc *proof_collection baav_absent
                        skiz call {sub_proofs_verify_label}
                        // [txk_digest] *spw disc *proof_collection

                        dup 0 {&proof_collection_field_bridge_deposit_announcement_validator}
                        read_mem 1 addi 1 pop 1
                        skiz call {bdav_verify_label}
                        // [txk_digest] *spw disc *proof_collection

                        dup 0 {&proof_collection_field_bridge_aggregated_proof}
                        read_mem 1 addi 1 pop 1
                        skiz call {baav_verify_label}
                        // [txk_digest] *spw disc *proof_collection

                        pop 1
                        addi {-(DISCRIMINANT_FOR_PROOF_COLLECTION as isize) - 1}
                        // [txk_digest] *spw -1

                        dup 1 addi 2
                        // _ [txk_digest] *spw -1 *proof_collection
                        // _ pc_size_init [txk_digest] *spw -1 *proof_collection <-- rename

                        call {audit_witness_of_proof_collection}
                        // _ pc_size_init [txk_digest] *spw -1 pc_size_end

                        pick 8
                        eq
                        assert error_id {MANIPULATED_PROOF_COLLECTION_WITNESS_ERROR}
                        // _ [txk_digest] *spw -1

                        return
                            };
                    let sub_proofs_verify_body = triton_asm! {
                                // BEFORE: _ [txk_digest] *spw disc *proof_collection
                                // AFTER:  _ [txk_digest] *spw disc *proof_collection
                                {sub_proofs_verify_label}:

                    {&sub_proofs_core}
                                    // [txk_digest] *spw disc

                                    dup 1 addi 2
                                    // [txk_digest] *spw disc *proof_collection

                                    return
                                        };
                    let bdav_verify_body = triton_asm! {
                        // BEFORE: _ [txk_digest] *spw disc *proof_collection
                        // AFTER:  _ [txk_digest] *spw disc *proof_collection
                        {bdav_verify_label}:
                            call {assemble_bdav_claim}
                            // _ [txk_digest] *spw disc *proof_collection *bdav_claim

                            // the field points at the Option; +1 skips its discriminant
                            dup 1 {&proof_collection_field_bridge_deposit_announcement_validator}
                            addi 1
                            // _ [txk_digest] *spw disc *proof_collection *bdav_claim *bdav_proof

                            call {stark_verify}
                            return
                    };

                    let baav_verify_body = triton_asm! {
                        // BEFORE: _ [txk_digest] *spw disc *proof_collection
                        // AFTER:  _ [txk_digest] *spw disc *proof_collection
                        {baav_verify_label}:
                            call {assemble_baav_claim}
                            // _ [txk_digest] *spw disc *proof_collection *baav_claim

                            dup 1 {&proof_collection_field_bridge_aggregated_proof}
                            addi 1
                            // _ [txk_digest] *spw disc *proof_collection *baav_claim *baav_proof

                            call {stark_verify}
                            return
                    };
                    (
                        case_body,
                        sub_proofs_verify_body,
                        [
                            count_deposit_announcements_body,
                            count_settlement_announcements_body,
                            bdav_verify_body,
                            baav_verify_body,
                        ]
                        .concat(),
                    )
                }
            };

        let verify_discriminant_has_legal_value = triton_asm!(

            // _ discr

            dup 0
            push {DISCRIMINANT_FOR_PROOF_COLLECTION}
            eq

            dup 1
            push {DISCRIMINANT_FOR_UPDATE}
            eq

            dup 2
            push {DISCRIMINANT_FOR_MERGE}
            eq
            // _ discr (discr == proof_coll) (discr == update) (discr == merge)

            add
            add
            // _ discr (discr == proof_coll || discr == update || discr == merge)

            {&accept_chain_discriminants}
            // _ discr (.. [|| discr == fix || discr == weld])

            assert error_id {INVALID_WITNESS_DISCRIMINANT_ERROR}
            // _ discr
        );

        let main = triton_asm! {
            // _

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [own_digest]

            read_io 5
            // _ [own_digest] [txk_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ [own_digest] [txk_digest] *single_proof_witness

            read_mem 1 addi 1 swap 1
            // _ [own_digest] [txk_digest] *single_proof_witness discriminant

            {&verify_discriminant_has_legal_value}
            // _ [own_digest] [txk_digest] *single_proof_witness discriminant

            /* match discriminant */
            dup 0 push {DISCRIMINANT_FOR_PROOF_COLLECTION} eq
            skiz call {proof_collection_case_label}

            dup 0 push {DISCRIMINANT_FOR_UPDATE} eq
            skiz call {update_branch}

            dup 0 push {DISCRIMINANT_FOR_MERGE} eq
            skiz call {merge_branch}

            {&dispatch_chain_branches}

            // _ [own_digest] [txk_digest] *single_proof_witness discriminant

            // a discriminant of -1 indicates that some branch was executed
            push -1
            eq
            assert error_id {NO_BRANCH_TAKEN_ERROR}

            pop 1 pop 5 pop 5
            // _

            halt
        };

        let code = triton_asm! {
            {&main}
            {&proof_collection_case_body}
            {&bridge_before_loop}
            {&verify_scripts_loop_body}
            {&bridge_after_loop}
            {&library.all_imports()}
        };

        (library, code)
    }
}

impl ConsensusProgram for SingleProofV2 {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        self.assemble::<ProofCollection>(ConsensusRuleSet::UpgradeVMv8.has_chain_branches(), false)
    }

    fn hash(&self) -> Digest {
        static PROGRAM_DIGEST: OnceLock<Digest> = OnceLock::new();

        let digest = PROGRAM_DIGEST.get_or_init(|| self.program().hash());

        *digest
    }

    fn program(&self) -> Program {
        // Overwrite trait-implementation since this leads to much faster code.
        // Throughout the lifetime of a client, the `SingleProofV2` program for a
        // given version never changes, so this is OK.
        static PROGRAM: OnceLock<Program> = OnceLock::new();

        let program = PROGRAM.get_or_init(|| {
            let (_, code) = self.library_and_code();
            Program::new(&code)
        });

        program.clone()
    }
}

/// The `SingleProofV2` program of `LeviathanSettlement`: over a [`LeviathanProofCollection`], with
/// the bridge checks.
#[derive(Debug, Copy, Clone)]
pub struct LeviathanSingleProofV2;

impl LeviathanSingleProofV2 {
    /// Like [`SingleProofV2::claim`].
    pub(crate) fn claim(tx_kernel_mast_hash: Digest) -> Claim {
        Claim::about_program(&LeviathanSingleProofV2.program())
            .with_input(tx_kernel_mast_hash.reversed().values())
    }
}

impl ConsensusProgram for LeviathanSingleProofV2 {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        SingleProofV2.assemble::<LeviathanProofCollection>(
            ConsensusRuleSet::LeviathanSettlement.has_chain_branches(),
            true,
        )
    }

    fn hash(&self) -> Digest {
        static PROGRAM_DIGEST: OnceLock<Digest> = OnceLock::new();
        *PROGRAM_DIGEST.get_or_init(|| self.program().hash())
    }

    fn program(&self) -> Program {
        static PROGRAM: OnceLock<Program> = OnceLock::new();
        PROGRAM
            .get_or_init(|| Program::new(&self.library_and_code().1))
            .clone()
    }
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {

    use assert2::let_assert;
    use macro_rules_attr::apply;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::config::network::Network;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::protocol::consensus::bridge::aggregated_announcement::AggregatedAnnouncementData;
    use crate::protocol::consensus::bridge::deposit_announcement::is_deposit_tagged;
    use crate::protocol::consensus::consensus_rule_set::TritonProofVersion;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::transaction::validity::single_proof_v2::SingleProofV2;
    use crate::protocol::consensus::transaction::validity::single_proof_v2::SingleProofV2Witness;
    use crate::protocol::consensus::transaction::validity::tasm::single_proof::merge_branch::tests::deterministic_merge_witness;
    use crate::protocol::consensus::transaction::validity::tasm::single_proof::update_branch::tests::deterministic_update_witness_only_additions_to_mutator_set;
    use crate::protocol::consensus::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::protocol::proof_abstractions::tasm::program::ConsensusError;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::tests::shared_tokio_runtime;

    impl ConsensusProgramSpecification for SingleProofV2 {
        fn source(&self) {
            let stark: Stark = Stark::default();
            let own_program_digest: Digest = tasm::own_program_digest();
            let txk_digest: Digest = tasm::tasmlib_io_read_stdin___digest();

            match tasm::decode_from_memory::<SingleProofV2Witness>(
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            ) {
                SingleProofV2Witness::Collection(pc) => {
                    let AnyProofCollection::Upstream(pc) = *pc else {
                        panic!("a LeviathanSettlement collection");
                    };
                    assert_eq!(txk_digest, pc.kernel_mast_hash);

                    let claimed_merge_bit = false;
                    tasm::tasmlib_hashing_merkle_verify(
                        txk_digest,
                        TransactionKernelField::MergeBit as u32,
                        Tip5::hash(&claimed_merge_bit),
                        TransactionKernel::MAST_HEIGHT as u32,
                    );

                    let removal_records_integrity_claim: Claim =
                        pc.removal_records_integrity_claim();
                    tasm::verify_stark(
                        stark,
                        &removal_records_integrity_claim,
                        &pc.removal_records_integrity,
                    );

                    let kernel_to_outputs_claim: Claim = pc.kernel_to_outputs_claim();
                    tasm::verify_stark(stark, &kernel_to_outputs_claim, &pc.kernel_to_outputs);

                    let collect_lock_scripts_claim: Claim = pc.collect_lock_scripts_claim();
                    tasm::verify_stark(
                        stark,
                        &collect_lock_scripts_claim,
                        &pc.collect_lock_scripts,
                    );

                    let collect_type_scripts_claim: Claim = pc.collect_type_scripts_claim_v2();
                    tasm::verify_stark(
                        stark,
                        &collect_type_scripts_claim,
                        &pc.collect_type_scripts,
                    );

                    let mut i = 0;
                    let lock_script_claims: Vec<Claim> = pc.lock_script_claims();
                    assert_eq!(lock_script_claims.len(), pc.lock_script_hashes.len());
                    while i < pc.lock_script_hashes.len() {
                        let claim: &Claim = &lock_script_claims[i];
                        let lock_script_halts_proof: &Proof = &pc.lock_scripts_halt[i];
                        tasm::verify_stark(stark, claim, lock_script_halts_proof);

                        i += 1;
                    }

                    i = 0;
                    let type_script_claims = pc.type_script_claims();
                    assert_eq!(type_script_claims.len(), pc.type_script_hashes.len());
                    while i < pc.type_script_hashes.len() {
                        let claim: &Claim = &type_script_claims[i];
                        let type_script_halts_proof: &Proof = &pc.type_scripts_halt[i];
                        tasm::verify_stark(stark, claim, type_script_halts_proof);
                        i += 1;
                    }
                }
                SingleProofV2Witness::Update(witness) => {
                    debug_assert_eq!(txk_digest, witness.new_kernel_mast_hash);
                    witness.branch_source(own_program_digest, txk_digest);
                }
                SingleProofV2Witness::Merger(witness) => {
                    witness.branch_source(own_program_digest, txk_digest)
                }
                SingleProofV2Witness::Fix(witness) => {
                    witness.branch_source(own_program_digest, txk_digest)
                }
                SingleProofV2Witness::Weld(witness) => {
                    witness.branch_source(own_program_digest, txk_digest)
                }
            }
        }
    }

    impl ConsensusProgramSpecification for LeviathanSingleProofV2 {
        fn source(&self) {
            let stark: Stark = Stark::default();
            let own_program_digest: Digest = tasm::own_program_digest();
            let txk_digest: Digest = tasm::tasmlib_io_read_stdin___digest();

            match tasm::decode_from_memory::<SingleProofV2Witness>(
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            ) {
                SingleProofV2Witness::Collection(pc) => {
                    let AnyProofCollection::Leviathan(pc) = *pc else {
                        panic!("an upstream collection");
                    };
                    let base = pc.base();
                    assert_eq!(txk_digest, pc.kernel_mast_hash);

                    let claimed_merge_bit = false;
                    tasm::tasmlib_hashing_merkle_verify(
                        txk_digest,
                        TransactionKernelField::MergeBit as u32,
                        Tip5::hash(&claimed_merge_bit),
                        TransactionKernel::MAST_HEIGHT as u32,
                    );

                    tasm::tasmlib_hashing_merkle_verify(
                        txk_digest,
                        TransactionKernelField::Announcements as u32,
                        Tip5::hash_varlen(&pc.announcements.encode()),
                        TransactionKernel::MAST_HEIGHT as u32,
                    );
                    assert!(
                        pc.bridge_deposit_announcement_validator.is_some()
                            || !pc.announcements.iter().any(is_deposit_tagged)
                    );
                    assert!(
                        pc.bridge_aggregated_proof.is_some()
                            || !pc
                                .announcements
                                .iter()
                                .any(AggregatedAnnouncementData::is_settlement_tagged)
                    );

                    if pc.bridge_aggregated_proof.is_none() {
                        let removal_records_integrity_claim: Claim =
                            base.removal_records_integrity_claim();
                        tasm::verify_stark(
                            stark,
                            &removal_records_integrity_claim,
                            &pc.removal_records_integrity,
                        );

                        let kernel_to_outputs_claim: Claim = base.kernel_to_outputs_claim();
                        tasm::verify_stark(stark, &kernel_to_outputs_claim, &pc.kernel_to_outputs);

                        let collect_lock_scripts_claim: Claim = base.collect_lock_scripts_claim();
                        tasm::verify_stark(
                            stark,
                            &collect_lock_scripts_claim,
                            &pc.collect_lock_scripts,
                        );

                        let collect_type_scripts_claim: Claim =
                            base.collect_type_scripts_claim_v2();
                        tasm::verify_stark(
                            stark,
                            &collect_type_scripts_claim,
                            &pc.collect_type_scripts,
                        );

                        let mut i = 0;
                        let lock_script_claims: Vec<Claim> = base.lock_script_claims();
                        assert_eq!(lock_script_claims.len(), pc.lock_script_hashes.len());
                        while i < pc.lock_script_hashes.len() {
                            let claim: &Claim = &lock_script_claims[i];
                            let lock_script_halts_proof: &Proof = &pc.lock_scripts_halt[i];
                            tasm::verify_stark(stark, claim, lock_script_halts_proof);

                            i += 1;
                        }

                        i = 0;
                        let type_script_claims = base.type_script_claims();
                        assert_eq!(type_script_claims.len(), pc.type_script_hashes.len());
                        while i < pc.type_script_hashes.len() {
                            let claim: &Claim = &type_script_claims[i];
                            let type_script_halts_proof: &Proof = &pc.type_scripts_halt[i];
                            tasm::verify_stark(stark, claim, type_script_halts_proof);
                            i += 1;
                        }
                    }

                    if let Some(bdav_proof) = &pc.bridge_deposit_announcement_validator {
                        let bdav_claim =
                            pc.bridge_deposit_announcement_validator_claim(BRIDGE_CLAIM_VERSION);
                        tasm::verify_stark(stark, &bdav_claim, bdav_proof);
                    }

                    if let (Some(baav_proof), Some(prev_state)) =
                        (&pc.bridge_aggregated_proof, pc.bridge_prev_state_commitment)
                    {
                        let baav_claim = pc
                            .bridge_aggregated_proof_claim(Some(prev_state), BRIDGE_CLAIM_VERSION)
                            .unwrap();
                        tasm::verify_stark(stark, &baav_claim, baav_proof);
                    }
                }
                SingleProofV2Witness::Update(witness) => {
                    debug_assert_eq!(txk_digest, witness.new_kernel_mast_hash);
                    witness.branch_source(own_program_digest, txk_digest);
                }
                SingleProofV2Witness::Merger(witness) => {
                    witness.branch_source(own_program_digest, txk_digest)
                }
                SingleProofV2Witness::Fix(witness) => {
                    witness.branch_source(own_program_digest, txk_digest)
                }
                SingleProofV2Witness::Weld(witness) => {
                    witness.branch_source(own_program_digest, txk_digest)
                }
            }
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn invalid_discriminant_crashes_execution() {
        let pub_input = PublicInput::new(bfe_vec![0, 0, 0, 0, 0]);
        for illegal_discriminant_value in bfe_array![-1, 5, 6, 1u64 << 40] {
            let init_ram: HashMap<_, _> = [(
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                illegal_discriminant_value,
            )]
            .into_iter()
            .collect();

            let nondeterminism = NonDeterminism::default().with_ram(init_ram);

            let consensus_err = SingleProofV2.run_tasm(&pub_input, nondeterminism.clone());

            let_assert!(Err(ConsensusError::TritonVMPanic(_, instruction_err)) = consensus_err);
            let_assert!(InstructionError::AssertionFailed(assertion_err) = instruction_err);
            let_assert!(Some(err_id) = assertion_err.id);
            assert_eq!(INVALID_WITNESS_DISCRIMINANT_ERROR, err_id);
        }
    }

    fn positive_prop(witness: SingleProofV2Witness) {
        let claim = witness.claim();
        let public_input = PublicInput::new(claim.input);
        let rust_result = SingleProofV2.run_rust(&public_input, witness.nondeterminism());
        let tasm_result = SingleProofV2.run_tasm(&public_input, witness.nondeterminism());
        assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }

    mod proof_collection_tests {
        use tasm_lib::hashing::merkle_verify::MerkleVerify;

        use super::*;

        #[apply(shared_tokio_runtime)]
        async fn disallow_set_merge_bit_in_pc_path() {
            let mut test_runner = TestRunner::deterministic();

            let good_primitive_witness =
                PrimitiveWitness::arbitrary_with_size_numbers_and_merge_bit(Some(6), 6, 7, false)
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();

            let good_proof_collection = ProofCollection::produce_v2(
                &good_primitive_witness,
                TritonVmJobQueue::get_instance(),
                TritonVmJobPriority::default().into(),
                ConsensusRuleSet::UpgradeVMv8,
            )
            .await
            .unwrap();
            let good_witness = SingleProofV2Witness::from_collection(good_proof_collection.clone());
            positive_prop(good_witness);

            // Setting the `merge_bit` must make program crash, as this bit may
            // only be set to true through the execution of the merge branch.
            let bad_primitive_witness =
                PrimitiveWitness::arbitrary_with_size_numbers_and_merge_bit(Some(6), 6, 7, true)
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();

            let bad_proof_collection = ProofCollection::produce_v2(
                &bad_primitive_witness,
                TritonVmJobQueue::get_instance(),
                TritonVmJobPriority::default().into(),
                ConsensusRuleSet::UpgradeVMv8,
            )
            .await
            .unwrap();

            let bad_witness = SingleProofV2Witness::from_collection(bad_proof_collection);

            // This witness fails with a Merkle auth path error since it never
            // reads the actual bit but rather just verifies that it is set to
            // false in this execution path.
            SingleProofV2
                .test_assertion_failure(
                    bad_witness.standard_input(),
                    bad_witness.nondeterminism(),
                    &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
                )
                .unwrap();
        }

        #[apply(shared_tokio_runtime)]
        async fn can_verify_via_valid_proof_collection() {
            let network = Network::Main;
            let mut test_runner = TestRunner::deterministic();

            let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            let txk_mast_hash = primitive_witness.kernel.mast_hash();

            let proof_collection = ProofCollection::produce_v2(
                &primitive_witness,
                TritonVmJobQueue::get_instance(),
                TritonVmJobPriority::default().into(),
                ConsensusRuleSet::UpgradeVMv8,
            )
            .await
            .unwrap();
            let claim_version = TritonProofVersion::V8.claim_version();
            assert!(
                proof_collection
                    .verify_v2(txk_mast_hash, network, claim_version)
                    .await
            );

            let witness = SingleProofV2Witness::from_collection(proof_collection.clone());
            let claim = witness.claim();
            let public_input = PublicInput::new(claim.input);
            let rust_result = SingleProofV2.run_rust(&public_input, witness.nondeterminism());
            let tasm_result = SingleProofV2.run_tasm(&public_input, witness.nondeterminism());
            assert_eq!(rust_result.unwrap(), tasm_result.unwrap());

            // Verify equivalence of claim functions
            assert_eq!(
                witness.claim(),
                SingleProofV2::claim(txk_mast_hash),
                "Claim functions must agree"
            );
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn can_verify_via_valid_proof_collection_if_timelocked_expired() {
            // V2-aware: under TimelockExtension a coin tagged with the legacy
            // TimeLock hash needs `release_date + 1 year < tx.timestamp` to be
            // spendable. The inherited `arbitrary_primitive_witness_with_expired_timelocks`
            // helper places release dates within the past 6 months of `now`,
            // which is enough for V1 but not for V2. Bump the kernel timestamp
            // 2 years ahead of `now` so the V2 +1y enforcement is satisfied.
            use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
            let network = Network::Main;
            let mut test_runner = TestRunner::deterministic();
            let deterministic_now = arb::<Timestamp>()
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            let mut primitive_witness =
                arbitrary_primitive_witness_with_expired_timelocks(2, 2, 2, deterministic_now)
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();
            primitive_witness.kernel = TransactionKernelModifier::default()
                .timestamp(deterministic_now + Timestamp::years(2))
                .modify(primitive_witness.kernel);
            let txk_mast_hash = primitive_witness.kernel.mast_hash();

            let proof_collection = ProofCollection::produce_v2(
                &primitive_witness,
                TritonVmJobQueue::get_instance(),
                TritonVmJobPriority::default().into(),
                ConsensusRuleSet::UpgradeVMv8,
            )
            .await
            .unwrap();
            let claim_version = TritonProofVersion::V8.claim_version();
            assert!(
                proof_collection
                    .verify_v2(txk_mast_hash, network, claim_version)
                    .await
            );

            let witness = SingleProofV2Witness::from_collection(proof_collection.clone());
            let claim = witness.claim();
            let public_input = PublicInput::new(claim.input);
            let rust_result = SingleProofV2.run_rust(&public_input, witness.nondeterminism());
            let tasm_result = SingleProofV2.run_tasm(&public_input, witness.nondeterminism());
            assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
        }
    }

    mod merge_tests {
        use crate::protocol::consensus::{
            consensus_rule_set::ConsensusRuleSet,
            transaction::validity::tasm::single_proof::merge_branch::tests::deterministic_merge_witness_with_coinbase,
            transaction::validity::tasm::single_proof::merge_branch::tests::OperandProgram,
        };

        use super::*;

        fn positive_prop(witness: MergeWitness) {
            let witness = SingleProofV2Witness::from_merge(witness);
            let claim = witness.claim();
            let input = PublicInput::new(claim.input.clone());
            let nondeterminism = witness.nondeterminism();

            let rust_result = SingleProofV2.run_rust(&input, nondeterminism.clone());

            let tasm_result = SingleProofV2.run_tasm(&input, nondeterminism);

            assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
        }

        #[apply(shared_tokio_runtime)]
        async fn can_verify_transaction_merger_without_coinbase() {
            let network = Network::Main;

            let merge_witness = deterministic_merge_witness(
                (2, 2, 2),
                (2, 2, 2),
                OperandProgram::Era(ConsensusRuleSet::UpgradeVMv8),
                network,
            )
            .await;
            positive_prop(merge_witness);
        }

        #[apply(shared_tokio_runtime)]
        async fn can_verify_transaction_merger_with_coinbase() {
            let network = Network::Main;

            let merge_witness = deterministic_merge_witness_with_coinbase(
                3,
                3,
                3,
                network,
                OperandProgram::Era(ConsensusRuleSet::UpgradeVMv8),
            )
            .await;
            positive_prop(merge_witness);
        }
    }

    mod update_tests {
        use proptest::prelude::*;
        use rand::random;
        use tasm_lib::hashing::merkle_verify::MerkleVerify;
        use tasm_lib::twenty_first::prelude::Mmr;

        use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
        use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
        use crate::protocol::consensus::transaction::validity::tasm::single_proof::update_branch::tests::deterministic_update_witness_additions_and_removals;
        use crate::util_types::mutator_set::removal_record::RemovalRecord;

        use super::*;

        fn positive_prop(witness: UpdateWitness) {
            let witness = SingleProofV2Witness::from_update(witness);
            let claim = witness.claim();
            let input = PublicInput::new(claim.input.clone());
            let nondeterminism = witness.nondeterminism();

            let rust_result = SingleProofV2.run_rust(&input, nondeterminism.clone());

            let tasm_result = SingleProofV2.run_tasm(&input, nondeterminism);

            assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
        }

        fn negative_prop(witness: UpdateWitness, allowed_error_codes: &[i128]) {
            let witness = SingleProofV2Witness::from_update(witness.clone());
            let claim = witness.claim();
            let input = PublicInput::new(claim.input.clone());
            let nondeterminism = witness.nondeterminism();
            let test_result =
                SingleProofV2.test_assertion_failure(input, nondeterminism, allowed_error_codes);
            test_result.unwrap();
        }

        #[apply(shared_tokio_runtime)]
        async fn only_additions_small() {
            let consensus_rule_set = ConsensusRuleSet::TimelockExtension;
            positive_prop(
                deterministic_update_witness_only_additions_to_mutator_set(
                    2,
                    2,
                    2,
                    consensus_rule_set,
                )
                .await,
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn only_additions_medium() {
            let consensus_rule_set = ConsensusRuleSet::TimelockExtension;
            positive_prop(
                deterministic_update_witness_only_additions_to_mutator_set(
                    4,
                    4,
                    4,
                    consensus_rule_set,
                )
                .await,
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn addition_and_removals_tiny() {
            let consensus_rule_set = ConsensusRuleSet::TimelockExtension;
            positive_prop(
                deterministic_update_witness_additions_and_removals(1, 1, 1, consensus_rule_set)
                    .await,
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn addition_and_removals_small() {
            let consensus_rule_set = ConsensusRuleSet::TimelockExtension;
            positive_prop(
                deterministic_update_witness_additions_and_removals(2, 2, 2, consensus_rule_set)
                    .await,
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn addition_and_removals_midi() {
            let consensus_rule_set = ConsensusRuleSet::TimelockExtension;
            positive_prop(
                deterministic_update_witness_additions_and_removals(3, 3, 3, consensus_rule_set)
                    .await,
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn addition_and_removals_medium() {
            let consensus_rule_set = ConsensusRuleSet::TimelockExtension;
            positive_prop(
                deterministic_update_witness_additions_and_removals(4, 4, 4, consensus_rule_set)
                    .await,
            );
        }

        fn new_timestamp_older_than_old_prop(good_witness: &UpdateWitness) {
            let mut bad_witness = good_witness.to_owned();

            bad_witness.new_kernel = TransactionKernelModifier::default()
                .timestamp(bad_witness.old_kernel.timestamp - Timestamp::hours(1))
                .modify(bad_witness.new_kernel);
            bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();

            negative_prop(
                bad_witness,
                &[UpdateBranch::NEW_TIMESTAMP_NOT_GEQ_THAN_OLD_ERROR],
            )
        }

        fn bad_new_aocl_prop(good_witness: &UpdateWitness) {
            let mut bad_witness = good_witness.to_owned();
            bad_witness.new_aocl.append(random());

            negative_prop(bad_witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID])
        }

        fn bad_old_aocl_prop(good_witness: &UpdateWitness) {
            let mut bad_witness = good_witness.to_owned();
            bad_witness.old_aocl.append(random());

            negative_prop(bad_witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID])
        }

        fn bad_absolute_index_set_value_prop(good_witness: &UpdateWitness) {
            let mut bad_witness = good_witness.clone();

            let mut new_inputs = bad_witness.new_kernel.inputs.clone();
            new_inputs[0]
                .absolute_indices
                .decrement_bloom_filter_index(10);

            bad_witness.new_kernel = TransactionKernelModifier::default()
                .inputs(new_inputs)
                .modify(bad_witness.new_kernel);
            bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();

            negative_prop(bad_witness, &[UpdateBranch::INPUT_SETS_NOT_EQUAL_ERROR])
        }

        fn bad_absolute_index_set_length_too_short_prop(good_witness: &UpdateWitness) {
            let mut bad_witness = good_witness.clone();

            let mut new_inputs = bad_witness.new_kernel.inputs.clone();
            new_inputs.remove(0);
            bad_witness.new_kernel = TransactionKernelModifier::default()
                .inputs(new_inputs)
                .modify(bad_witness.new_kernel);
            bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();

            negative_prop(bad_witness, &[UpdateBranch::INPUT_SETS_NOT_EQUAL_ERROR])
        }

        fn bad_absolute_index_set_length_too_long_prop(
            good_witness: &UpdateWitness,
            rr: RemovalRecord,
        ) {
            let mut bad_witness = good_witness.clone();

            let mut new_inputs = bad_witness.new_kernel.inputs.clone();
            new_inputs.push(rr);

            bad_witness.new_kernel = TransactionKernelModifier::default()
                .inputs(new_inputs)
                .modify(bad_witness.new_kernel);
            bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();

            negative_prop(bad_witness, &[UpdateBranch::INPUT_SETS_NOT_EQUAL_ERROR])
        }

        #[apply(shared_tokio_runtime)]
        async fn update_witness_negative_tests() {
            // It takes a long time to generate the witness, so we reuse it across
            // multiple tests

            let consensus_rule_set = ConsensusRuleSet::TimelockExtension;
            let good_witness = deterministic_update_witness_only_additions_to_mutator_set(
                2,
                2,
                2,
                consensus_rule_set,
            )
            .await;
            positive_prop(good_witness.clone());
            new_timestamp_older_than_old_prop(&good_witness);
            bad_new_aocl_prop(&good_witness);
            bad_old_aocl_prop(&good_witness);
            bad_absolute_index_set_value_prop(&good_witness);
            bad_absolute_index_set_length_too_short_prop(&good_witness);
            proptest::proptest! {
                ProptestConfig { cases: 3, .. ProptestConfig::default() },
                |(rr in arb::<RemovalRecord>())| {
                    bad_absolute_index_set_length_too_long_prop(&good_witness, rr);
                }
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn disallow_update_of_tx_with_zero_inputs() {
            let consensus_rule_set = ConsensusRuleSet::TimelockExtension;
            let only_new_additions_0_outputs =
                deterministic_update_witness_only_additions_to_mutator_set(
                    0,
                    0,
                    0,
                    consensus_rule_set,
                )
                .await;
            let only_new_additions_2_outputs =
                deterministic_update_witness_only_additions_to_mutator_set(
                    0,
                    2,
                    2,
                    consensus_rule_set,
                )
                .await;
            let new_additions_and_removals_2_outputs =
                deterministic_update_witness_additions_and_removals(0, 2, 2, consensus_rule_set)
                    .await;

            for bad_witness in [
                only_new_additions_0_outputs.clone(),
                only_new_additions_2_outputs.clone(),
                new_additions_and_removals_2_outputs.clone(),
            ] {
                let bad_witness = SingleProofV2Witness::from_update(bad_witness);
                let claim = bad_witness.claim();
                let input = PublicInput::new(claim.input.clone());
                let nondeterminism = bad_witness.nondeterminism();
                let test_result = SingleProofV2.test_assertion_failure(
                    input,
                    nondeterminism,
                    &[UpdateBranch::INPUT_SET_IS_EMPTY_ERROR],
                );
                test_result.unwrap();
            }
        }
    }

    /// The program without the chaining branches, which leave the other
    /// branches unchanged, down to their static-memory addresses: that is why
    /// `FixBranch` and `WeldBranch` are imported last.
    #[test]
    fn program_without_chain_branches_is_the_pre_chaining_program() {
        let (_, code) = SingleProofV2.assemble::<ProofCollection>(false, false);
        assert_eq!(
            "307f41ff80f6f7af27a6382ae91cf0d54f9464c0cda525652c1e5285c0ab0044374a488c3d7dc75e",
            Program::new(&code).hash().to_hex(),
        );
    }

    /// Without the chaining branches, their discriminants are as illegal as
    /// any other unknown value.
    #[apply(shared_tokio_runtime)]
    async fn chain_discriminants_are_illegal_without_chain_branches() {
        let (_, code) = SingleProofV2.assemble::<ProofCollection>(false, false);
        let program = Program::new(&code);
        let pub_input = PublicInput::new(bfe_vec![0, 0, 0, 0, 0]);
        for discriminant in [DISCRIMINANT_FOR_FIX, DISCRIMINANT_FOR_WELD] {
            let init_ram: HashMap<_, _> = [(
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                bfe!(discriminant),
            )]
            .into_iter()
            .collect();
            let nondeterminism = NonDeterminism::default().with_ram(init_ram);

            let_assert!(
                Err(vm_error) = VM::run(program.clone(), pub_input.clone(), nondeterminism)
            );
            let_assert!(InstructionError::AssertionFailed(assertion_err) = vm_error.source);
            assert_eq!(Some(INVALID_WITNESS_DISCRIMINANT_ERROR), assertion_err.id);
        }
    }

    mod bridge_announcements {
        use tasm_lib::hashing::merkle_verify::MerkleVerify;

        use super::*;
        use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::tests::mock_proof_collection;
        use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::tests::mock_settlement_proof_collection;
        use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::tests::plain_tx_witness;
        use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::tests::settlement_tx_witness;

        async fn proof_collection(with_deposit: bool, keep_bdav: bool) -> LeviathanProofCollection {
            let pw = plain_tx_witness(with_deposit);
            let mut pc = mock_proof_collection(&pw).await;
            if !keep_bdav {
                pc.bridge_deposit_announcement_validator = None;
            }
            pc
        }

        /// The witness's nondeterminism up to and including the bridge checks, which run before
        /// any sub-proof is verified, so mock sub-proofs need no stark_verify nondeterminism.
        fn nondeterminism_up_to_bridge_checks(pc: &LeviathanProofCollection) -> NonDeterminism {
            let witness = SingleProofV2Witness::from_collection(pc.clone());
            let mut memory = HashMap::default();
            encode_to_memory(
                &mut memory,
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                &witness,
            );
            let digests = [
                pc.merge_bit_mast_path.clone(),
                pc.announcements_mast_path.clone(),
            ]
            .concat();
            NonDeterminism::default()
                .with_ram(memory)
                .with_digests(digests)
        }

        fn assert_fails_with(pc: &LeviathanProofCollection, error_id: i128) {
            LeviathanSingleProofV2
                .test_assertion_failure(
                    pc.kernel_mast_hash.reversed().values().into(),
                    nondeterminism_up_to_bridge_checks(pc),
                    &[error_id],
                )
                .unwrap();
        }

        /// `LeviathanSettlement` proves deposits and settlements with the live program, the one
        /// carrying the bridge checks. On RegTest the proofs are mocks, so this checks the routing,
        /// the claim's program and that the witnesses build, not the bridge checks themselves.
        #[apply(shared_tokio_runtime)]
        async fn produce_single_proof_routes_leviathan_settlement_to_the_live_program() {
            use crate::api::tx_initiation::bridge_deposit::tests::deposit_witness;
            use crate::application::triton_vm_job_queue::vm_job_queue;
            use crate::protocol::consensus::transaction::validity::single_proof::produce_single_proof;

            let rule_set = ConsensusRuleSet::LeviathanSettlement;
            let deposit = deposit_witness(1);
            let proof = produce_single_proof(
                &deposit,
                vm_job_queue(),
                TritonVmProofJobOptions::default_with_network(Network::RegTest),
                rule_set,
            )
            .await
            .unwrap();
            let claim = single_proof_claim(deposit.kernel.mast_hash(), rule_set);
            assert_eq!(LeviathanSingleProofV2.hash(), claim.program_digest);
            assert!(verify(claim, proof, Network::RegTest).await);

            let settlement = mock_settlement_proof_collection(&settlement_tx_witness()).await;
            let settlement_proof = SingleProofV2Witness::from_collection(settlement.clone())
                .produce(
                    vm_job_queue(),
                    TritonVmProofJobOptions::default_with_network(Network::RegTest),
                    rule_set,
                )
                .await
                .unwrap();
            let settlement_claim = single_proof_claim(settlement.kernel_mast_hash, rule_set);
            assert!(verify(settlement_claim, settlement_proof, Network::RegTest).await);
        }

        #[apply(shared_tokio_runtime)]
        async fn deposit_announcement_without_bdav_fails_v2() {
            let pc = proof_collection(true, false).await;
            assert_fails_with(&pc, DEPOSIT_ANNOUNCEMENT_WITHOUT_BDAV_ERROR);
        }

        /// The deposit count walks every announcement, so a deposit behind others is still found.
        #[apply(shared_tokio_runtime)]
        async fn deposit_behind_other_announcements_without_bdav_fails_v2() {
            use crate::protocol::consensus::transaction::announcement::Announcement;
            use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;

            let untagged =
                |len: u64| Announcement::new((1..=len).map(BFieldElement::new).collect());
            let mut pw = plain_tx_witness(true);
            let announcements = [
                vec![untagged(3), untagged(0)],
                pw.kernel.announcements.clone(),
            ]
            .concat();
            pw.kernel = TransactionKernelModifier::default()
                .announcements(announcements)
                .modify(pw.kernel);
            let mut pc = mock_proof_collection(&pw).await;
            pc.bridge_deposit_announcement_validator = None;
            assert_fails_with(&pc, DEPOSIT_ANNOUNCEMENT_WITHOUT_BDAV_ERROR);
        }

        #[apply(shared_tokio_runtime)]
        async fn settlement_announcement_without_baav_fails_v2() {
            let mut pc = mock_settlement_proof_collection(&settlement_tx_witness()).await;
            assert!(pc.bridge_aggregated_proof.is_some());
            pc.bridge_aggregated_proof = None;
            assert_fails_with(&pc, SETTLEMENT_ANNOUNCEMENT_WITHOUT_BAAV_ERROR);
        }

        #[apply(shared_tokio_runtime)]
        async fn forged_announcements_copy_fails_v2() {
            let mut pc = proof_collection(true, false).await;
            pc.announcements.clear();
            assert_fails_with(&pc, MerkleVerify::ROOT_MISMATCH_ERROR_ID);
        }

        /// With no deposit, or with the BDAV proof, the checks pass; the run only stops later, at
        /// the first sub-proof, for lack of its stark_verify nondeterminism.
        #[apply(shared_tokio_runtime)]
        async fn deposit_check_passes_without_deposit_or_with_bdav_v2() {
            for with_deposit in [false, true] {
                let pc = proof_collection(with_deposit, true).await;
                let result = LeviathanSingleProofV2.run_tasm(
                    &pc.kernel_mast_hash.reversed().values().into(),
                    nondeterminism_up_to_bridge_checks(&pc),
                );
                let_assert!(Err(ConsensusError::TritonVMPanic(vm_state, _)) = result);
                assert!(
                    vm_state.contains("tasmlib_verifier_stark_verify"),
                    "must fail inside the first sub-proof's stark_verify, i.e. past the checks"
                );
            }
        }
    }

    test_program_snapshot!(
        SingleProofV2,
        // SP_V2_HASH frozen after phase 6 of the +1 year timelock hard fork.
        // The only TASM-level difference from V1 SingleProof is the import of
        // GenerateCollectTypeScriptsClaimV2 (which hardcodes CTS_V2_HASH),
        // so SingleProofV2 verifies a CollectTypeScriptsV2 proof instead of
        // a V1 proof. Used by BlockAppendix consensus_claims under
        // ConsensusRuleSet::TimelockExtension.
        // Program hash updated for UpgradeVMv8 (triton-vm v8: sound Hash/Program
        // Table AIR, randomized quotient table). The UpgradeVMv7 (v7) digest
        // (5c75cc2d…) lives on as a hardcoded constant in single_proof_claim,
        // as does the v5 one (e66985a8…).
        // Program hash updated again for the `Fix` and `Weld` branches
        // (transaction chaining), which activate together with the v8 virtual
        // machine. Without them the program still hashes to 307f41ff…; see
        // `program_without_chain_branches_is_the_pre_chaining_program`.
        "3ab71f45d12c1b1709197789ffe6194b25492fd0e7dd1aed054a68cf369ae14b17d9b80e99a5e8cf"
    );

    /// A real single proof of each era with a chaining-capable program verifies under its own era
    /// only.
    #[apply(shared_tokio_runtime)]
    #[ignore = "real proofs: tens of GB and minutes"]
    async fn real_single_proofs_verify_under_their_own_era_only() {
        use crate::application::triton_vm_job_queue::TritonVmJobQueue;
        use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::tests::plain_tx_witness;
        use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::VerifyOptions;
        use crate::protocol::consensus::transaction::TransactionProof;

        let network = Network::Testnet(0);
        let pw = plain_tx_witness(false);
        let txk_mast_hash = pw.kernel.mast_hash();
        let eras = [
            ConsensusRuleSet::UpgradeVMv8,
            ConsensusRuleSet::LeviathanSettlement,
        ];
        let mut proofs = vec![];
        for rule_set in eras {
            let proof = SingleProofV2::produce(
                &pw,
                TritonVmJobQueue::get_instance(),
                TritonVmProofJobOptions::default_with_network(network),
                rule_set,
            )
            .await
            .unwrap();
            proofs.push((rule_set, TransactionProof::SingleProof(proof)));
        }

        // Rejections first: the test verifier caches every claim it accepts.
        for valid in [false, true] {
            for (rule_set, proof) in &proofs {
                for era in eras.into_iter().filter(|era| (era == rule_set) == valid) {
                    assert_eq!(
                        valid,
                        proof
                            .verify(txk_mast_hash, network, era, VerifyOptions::default())
                            .await,
                        "proven under {rule_set}, verified under {era}"
                    );
                }
            }
        }
    }

    mod leviathan_snapshot {
        use super::*;

        test_program_snapshot!(
            LeviathanSingleProofV2,
            // With the bridge proofs, naming the `LeviathanLinkProof` in `Fix` and `Weld`.
            "c1c6d54464bf6091495c82fc81c9a0f5e842b3db5b7cddaa1a58755c408ef88f99e716c0d1a217be"
        );
    }
}
