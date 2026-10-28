use std::sync::Arc;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::MerkleTreeInclusionProof;
use tracing::debug;

use super::bridge_aggregated_announcement_validator::expected_verifier_program_digest;
use super::bridge_aggregated_announcement_validator::verifier_input;
use super::bridge_aggregated_announcement_validator::BridgeAggregatedAnnouncementValidator;
use super::bridge_aggregated_announcement_validator::BridgeAggregatedAnnouncementValidatorWitness;
use super::bridge_aggregated_announcement_validator::SettlementProverInput;
use super::bridge_deposit_announcement_validator::BridgeDepositAnnouncementValidator;
use super::bridge_deposit_announcement_validator::BridgeDepositAnnouncementValidatorWitness;
use super::proof_collection::ProofCollection;
use super::proof_collection::SubProver;
use crate::api::tx_initiation::error::CreateProofError;
use crate::api::tx_initiation::error::ProofRequirement;
use crate::application::config::network::Network;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;
use crate::protocol::consensus::bridge::aggregated_announcement::AggregatedAnnouncementData;
use crate::protocol::consensus::bridge::deposit_announcement::is_deposit_tagged;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::BFieldCodec;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::prove_consensus_program;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::verifier::verify_transaction_proof;
use crate::protocol::proof_abstractions::SecretWitness;
use crate::util_types::mutator_set::shared::deserialize_bounded_vec;

const MAX_NUM_SCRIPT_PROOFS: usize = 2 * MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;

/// Options for [`LeviathanProofCollection`] verification: chain state the bridge proofs need.
#[derive(Clone, Copy, Debug, Default)]
pub struct VerifyOptions {
    /// Current Leviathan state commitment from the chain state (block index).
    /// Required when verifying a `bridge_aggregated_proof`.
    /// Must come from the node's own chain state, NOT from the transaction.
    pub prev_state_commitment: Option<Digest>,
}

pub use layout::ProofCollection as LeviathanProofCollection;

mod layout {
    use super::*;

    /// The proof collection of `LeviathanSettlement`: the fields of
    /// [`ProofCollection`](super::ProofCollection), in its order, then the bridge proofs and a
    /// copy of the kernel's announcements. The `LeviathanSettlement` `SingleProofV2` program
    /// reads this layout.
    // Named `ProofCollection`: TASM labels carry the type name, and their order fixes the program digest.
    #[derive(
        Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject,
    )]
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
        /// Deposit announcement validator proof, present when a deposit is announced under
        /// `LeviathanSettlement`.
        pub bridge_deposit_announcement_validator: Option<Proof>,
        /// Unified bridge aggregated proof: stark_verifies the converted proof (verifier program
        /// execution) AND verifies burns against the exit_root from the verified output.
        pub bridge_aggregated_proof: Option<Proof>,
        /// BAAV public input components (from the announcement).
        /// Used by SingleProof TASM (via divine) to reconstruct the BAAV claim.
        /// NOT trusted for security: the BAAV proof constrains these via stark_verify,
        /// and verify checks prev_state against chain state.
        pub bridge_prev_state_commitment: Option<Digest>,
        pub bridge_new_state_commitment: Option<Digest>,
        pub bridge_exit_root: Option<Digest>,
        /// Copy of the kernel's announcements, authenticated against `kernel_mast_hash` by
        /// `announcements_mast_path`; a deposit-tagged one requires the BDAV proof.
        #[serde(
            deserialize_with = "deserialize_bounded_vec::<_, _, MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS>"
        )]
        pub announcements: Vec<Announcement>,
        pub announcements_mast_path: Vec<Digest>,
    }
}

/// The bridge part of a [`LeviathanProofCollection`].
#[derive(Debug, Clone, Default)]
struct BridgeProofs {
    deposit: Option<Proof>,
    aggregated: Option<Proof>,
    prev_state_commitment: Option<Digest>,
    new_state_commitment: Option<Digest>,
    exit_root: Option<Digest>,
}

impl LeviathanProofCollection {
    fn assemble(base: ProofCollection, bridge: BridgeProofs, kernel: &TransactionKernel) -> Self {
        Self {
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
            bridge_deposit_announcement_validator: bridge.deposit,
            bridge_aggregated_proof: bridge.aggregated,
            bridge_prev_state_commitment: bridge.prev_state_commitment,
            bridge_new_state_commitment: bridge.new_state_commitment,
            bridge_exit_root: bridge.exit_root,
            announcements: kernel.announcements.clone(),
            announcements_mast_path: kernel.mast_path(TransactionKernelField::Announcements),
        }
    }

    /// The [`ProofCollection`] fields, whose claims and proofs this collection shares.
    pub(crate) fn base(&self) -> ProofCollection {
        ProofCollection {
            removal_records_integrity: self.removal_records_integrity.clone(),
            collect_lock_scripts: self.collect_lock_scripts.clone(),
            lock_scripts_halt: self.lock_scripts_halt.clone(),
            kernel_to_outputs: self.kernel_to_outputs.clone(),
            collect_type_scripts: self.collect_type_scripts.clone(),
            type_scripts_halt: self.type_scripts_halt.clone(),
            lock_script_hashes: self.lock_script_hashes.clone(),
            type_script_hashes: self.type_script_hashes.clone(),
            kernel_mast_hash: self.kernel_mast_hash,
            salted_inputs_hash: self.salted_inputs_hash,
            salted_outputs_hash: self.salted_outputs_hash,
            merge_bit_mast_path: self.merge_bit_mast_path.clone(),
        }
    }

    /// [`ProofCollection::produce_v2`] plus the bridge proofs: BDAV when a deposit is announced,
    /// BAAV when a settlement is. A settlement needs its verifier program and RAM, see
    /// [`Self::produce_settlement`].
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
        Self::produce_inner(primitive_witness, &prover, None, consensus_rule_set).await
    }

    /// [`Self::produce_v2`] proven in this process, without the job queue or prover binary.
    pub async fn produce_in_process(
        primitive_witness: &PrimitiveWitness,
        network: Network,
        block_height: BlockHeight,
    ) -> Result<Self, CreateProofError> {
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        Self::produce_inner(
            primitive_witness,
            &SubProver::InProcess { network },
            None,
            consensus_rule_set,
        )
        .await
    }

    /// Produce for a settlement tx; `settlement` supplies the verifier program and its RAM, which
    /// the announcement does not carry.
    pub async fn produce_settlement(
        primitive_witness: &PrimitiveWitness,
        settlement: &SettlementProverInput,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Self, CreateProofError> {
        let prover = SubProver::Queue {
            queue: triton_vm_job_queue,
            options: proof_job_options,
        };
        Self::produce_inner(
            primitive_witness,
            &prover,
            Some(settlement),
            consensus_rule_set,
        )
        .await
    }

    async fn produce_inner(
        primitive_witness: &PrimitiveWitness,
        prover: &SubProver,
        settlement: Option<&SettlementProverInput>,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Self, CreateProofError> {
        let claim_version = ProofCollection::claim_version_for(consensus_rule_set);
        let aggregated_announcement = consensus_rule_set
            .bav_active()
            .then(|| {
                AggregatedAnnouncementData::find_in_announcements(
                    &primitive_witness.kernel.announcements,
                )
            })
            .flatten();

        // A settlement's BAAV proof covers RRI, K2O and the lock and type scripts, so those are
        // not proven.
        let base = if aggregated_announcement.is_some() {
            ProofCollection::with_dummy_sub_proofs(primitive_witness)
        } else {
            ProofCollection::produce_with(primitive_witness, prover, consensus_rule_set).await?
        };

        let has_deposits = consensus_rule_set.bav_active()
            && super::bridge_deposit_announcement_validator::count_deposit_announcements(
                &primitive_witness.kernel.announcements,
            ) > 0;
        let mut bridge = BridgeProofs::default();
        if has_deposits {
            debug!("proving BridgeDepositAnnouncementValidator");
            let bdav_witness = BridgeDepositAnnouncementValidatorWitness::from(primitive_witness);
            bridge.deposit = Some(
                prover
                    .prove(
                        BridgeDepositAnnouncementValidator.program(),
                        bdav_witness.claim().about_version(claim_version),
                        || bdav_witness.nondeterminism(),
                    )
                    .await?,
            );
        }

        if let Some(ann_data) = aggregated_announcement {
            // A pool consolidation has no converted proof: BAAV takes its no-proof path.
            let converted_proof = match (settlement, prover) {
                (Some(settlement), SubProver::Queue { queue, options }) => {
                    debug!("proving the verifier program (converted proof)");
                    // BAAV pins the verifier program; fail before proving with any other one (mock
                    // networks never run it).
                    if !options.job_settings.network.use_mock_proof()
                        && settlement.verifier_program.hash() != expected_verifier_program_digest()
                    {
                        return Err(CreateProofError::MissingRequirement(
                            ProofRequirement::Program,
                        ));
                    }
                    let verifier_program = settlement.verifier_program.clone();
                    let verifier_nd =
                        NonDeterminism::default().with_ram(settlement.verifier_ram.clone());
                    let verifier_output = [
                        ann_data.new_state_commitment.values(),
                        ann_data.prev_state_commitment.values(),
                        ann_data.exit_root.values(),
                    ]
                    .concat();
                    let verifier_claim = Claim::about_program(&verifier_program)
                        .with_input(verifier_input(
                            ann_data.prev_state_commitment,
                            ann_data.faucet_id,
                        ))
                        .with_output(verifier_output)
                        .about_version(claim_version);
                    Some(
                        prove_consensus_program(
                            verifier_program,
                            verifier_claim,
                            verifier_nd,
                            queue.clone(),
                            options.clone(),
                        )
                        .await?,
                    )
                }
                _ if ann_data.is_pool_consolidation() => None,
                _ => {
                    return Err(CreateProofError::MissingRequirement(
                        ProofRequirement::Program,
                    ))
                }
            };

            debug!("proving BridgeAggregatedAnnouncementValidator");
            bridge.prev_state_commitment = Some(ann_data.prev_state_commitment);
            bridge.new_state_commitment = Some(ann_data.new_state_commitment);
            bridge.exit_root = Some(ann_data.exit_root);
            let baav_witness = BridgeAggregatedAnnouncementValidatorWitness::from_announcement(
                ann_data,
                converted_proof.map(Into::into),
                primitive_witness.clone(),
            );
            bridge.aggregated = Some(
                prover
                    .prove(
                        BridgeAggregatedAnnouncementValidator.program(),
                        baav_witness.claim().about_version(claim_version),
                        || baav_witness.nondeterminism(),
                    )
                    .await?,
            );
        }

        Ok(Self::assemble(base, bridge, &primitive_witness.kernel))
    }

    /// [`ProofCollection::produce_mock`] with a mock BDAV proof.
    pub(crate) fn produce_mock(primitive_witness: &PrimitiveWitness, valid_mock: bool) -> Self {
        let base = ProofCollection::produce_mock(primitive_witness, valid_mock);
        let bridge = BridgeProofs {
            deposit: Some(base.removal_records_integrity.clone()),
            ..BridgeProofs::default()
        };
        Self::assemble(base, bridge, &primitive_witness.kernel)
    }

    fn announcements_match_kernel(&self) -> bool {
        MerkleTreeInclusionProof {
            tree_height: TransactionKernel::MAST_HEIGHT as u32,
            indexed_leafs: vec![(
                TransactionKernelField::Announcements as usize,
                Tip5::hash_varlen(&self.announcements.encode()),
            )],
            authentication_structure: self.announcements_mast_path.clone(),
        }
        .verify(self.kernel_mast_hash)
    }

    /// [`ProofCollection::verify_v2`] plus the bridge rules: under `LeviathanSettlement` a deposit
    /// needs its BDAV proof and a settlement its BAAV proof, which then covers the sub-proofs.
    /// Outside it, bridge proofs are ignored and every sub-proof is checked.
    pub(crate) async fn verify_v2(
        &self,
        txk_mast_hash: Digest,
        network: Network,
        claim_version: u32,
        consensus_rule_set: ConsensusRuleSet,
        opts: VerifyOptions,
    ) -> bool {
        if self.kernel_mast_hash != txk_mast_hash || !self.announcements_match_kernel() {
            return false;
        }

        let bav_active = consensus_rule_set.bav_active();
        if bav_active
            && self.bridge_deposit_announcement_validator.is_none()
            && self.announcements.iter().any(is_deposit_tagged)
        {
            debug!("deposit announcement without a BDAV proof");
            return false;
        }
        if bav_active
            && self.bridge_aggregated_proof.is_none()
            && self
                .announcements
                .iter()
                .any(AggregatedAnnouncementData::is_settlement_tagged)
        {
            debug!("settlement announcement without a BAAV proof");
            return false;
        }

        let has_baav = bav_active && self.bridge_aggregated_proof.is_some();
        let base = self.base();
        let base_holds = if has_baav {
            base.proves_unset_merge_bit(txk_mast_hash)
        } else {
            base.verify_v2(txk_mast_hash, network, claim_version).await
        };
        if !base_holds {
            return false;
        }

        if bav_active {
            if let Some(bdav_proof) = &self.bridge_deposit_announcement_validator {
                let claim = self.bridge_deposit_announcement_validator_claim(claim_version);
                if !verify_transaction_proof(claim, bdav_proof.clone(), network).await {
                    debug!("BDAV proof is invalid");
                    return false;
                }
            }
        }

        if has_baav {
            // No previous state means the bridge is unregistered: nothing can settle.
            let Some(claim) =
                self.bridge_aggregated_proof_claim(opts.prev_state_commitment, claim_version)
            else {
                debug!("bridge aggregated proof present but missing verification data");
                return false;
            };
            let Some(baav_proof) = &self.bridge_aggregated_proof else {
                return false;
            };
            if !verify_transaction_proof(claim, baav_proof.clone(), network).await {
                debug!("BAAV proof is invalid");
                return false;
            }
        }

        true
    }

    pub fn bridge_deposit_announcement_validator_claim(&self, claim_version: u32) -> Claim {
        Claim::about_program(&BridgeDepositAnnouncementValidator.program())
            .with_input(
                [self.kernel_mast_hash, self.salted_outputs_hash]
                    .map(|d| d.reversed().values())
                    .concat(),
            )
            .about_version(claim_version)
    }

    /// The BAAV claim against the chain's `prev_state_commitment`, `None` without one or without
    /// the collection's settlement fields.
    pub fn bridge_aggregated_proof_claim(
        &self,
        prev_state_commitment: Option<Digest>,
        claim_version: u32,
    ) -> Option<Claim> {
        let (Some(new_state), Some(exit_root), Some(prev_state)) = (
            self.bridge_new_state_commitment,
            self.bridge_exit_root,
            prev_state_commitment,
        ) else {
            return None;
        };
        let input = [
            prev_state.values(),
            new_state.values(),
            exit_root.values(),
            self.kernel_mast_hash.values(),
        ]
        .concat();
        Some(
            Claim::about_program(&BridgeAggregatedAnnouncementValidator.program())
                .with_input(input)
                .about_version(claim_version),
        )
    }
}

/// The proof collection of either era, encoded as the inner collection alone: the upstream
/// layout before `LeviathanSettlement`, the Leviathan layout from it, so that each era's wire
/// frames and `SingleProofV2` witness are byte-identical to that era's own.
#[derive(Clone, Debug, PartialEq, Eq, GetSize)]
#[allow(clippy::large_enum_variant)]
pub enum AnyProofCollection {
    Leviathan(LeviathanProofCollection),
    Upstream(ProofCollection),
}

/// Transparent in human-readable formats, whose objects tell the layouts apart by their fields;
/// tagged in binary ones, which cannot.
impl Serialize for AnyProofCollection {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        const NAME: &str = "AnyProofCollection";
        match (self, serializer.is_human_readable()) {
            (Self::Leviathan(collection), true) => collection.serialize(serializer),
            (Self::Upstream(collection), true) => collection.serialize(serializer),
            (Self::Leviathan(collection), false) => {
                serializer.serialize_newtype_variant(NAME, 0, "Leviathan", collection)
            }
            (Self::Upstream(collection), false) => {
                serializer.serialize_newtype_variant(NAME, 1, "Upstream", collection)
            }
        }
    }
}

impl<'de> Deserialize<'de> for AnyProofCollection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[allow(clippy::large_enum_variant)]
        #[serde(untagged)]
        enum Untagged {
            Leviathan(LeviathanProofCollection),
            Upstream(ProofCollection),
        }

        #[derive(Deserialize)]
        #[allow(clippy::large_enum_variant)]
        enum Tagged {
            Leviathan(LeviathanProofCollection),
            Upstream(ProofCollection),
        }

        if deserializer.is_human_readable() {
            Ok(match Untagged::deserialize(deserializer)? {
                Untagged::Leviathan(collection) => Self::Leviathan(collection),
                Untagged::Upstream(collection) => Self::Upstream(collection),
            })
        } else {
            Ok(match Tagged::deserialize(deserializer)? {
                Tagged::Leviathan(collection) => Self::Leviathan(collection),
                Tagged::Upstream(collection) => Self::Upstream(collection),
            })
        }
    }
}

impl BFieldCodec for AnyProofCollection {
    type Error = <ProofCollection as BFieldCodec>::Error;

    /// The Leviathan layout is the upstream one plus more fields, so a sequence decodes as at
    /// most one of them.
    fn decode(sequence: &[BFieldElement]) -> Result<Box<Self>, Self::Error> {
        if let Ok(collection) = LeviathanProofCollection::decode(sequence) {
            return Ok(Box::new(Self::Leviathan(*collection)));
        }
        ProofCollection::decode(sequence).map(|collection| Box::new(Self::Upstream(*collection)))
    }

    fn encode(&self) -> Vec<BFieldElement> {
        match self {
            Self::Leviathan(collection) => collection.encode(),
            Self::Upstream(collection) => collection.encode(),
        }
    }

    fn static_length() -> Option<usize> {
        None
    }
}

impl From<ProofCollection> for AnyProofCollection {
    fn from(collection: ProofCollection) -> Self {
        Self::Upstream(collection)
    }
}

impl From<LeviathanProofCollection> for AnyProofCollection {
    fn from(collection: LeviathanProofCollection) -> Self {
        Self::Leviathan(collection)
    }
}

impl AnyProofCollection {
    /// The collection of the given rule set: a [`LeviathanProofCollection`] under
    /// `LeviathanSettlement`, a [`ProofCollection`] before.
    pub async fn produce_v2(
        primitive_witness: &PrimitiveWitness,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Self, CreateProofError> {
        Ok(if consensus_rule_set.bav_active() {
            LeviathanProofCollection::produce_v2(
                primitive_witness,
                triton_vm_job_queue,
                proof_job_options,
                consensus_rule_set,
            )
            .await?
            .into()
        } else {
            ProofCollection::produce_v2(
                primitive_witness,
                triton_vm_job_queue,
                proof_job_options,
                consensus_rule_set,
            )
            .await?
            .into()
        })
    }

    /// [`Self::produce_v2`] proven in this process, for the rule set of `block_height`.
    pub async fn produce_in_process(
        primitive_witness: &PrimitiveWitness,
        network: Network,
        block_height: BlockHeight,
    ) -> Result<Self, CreateProofError> {
        Ok(
            if ConsensusRuleSet::infer_from(network, block_height).bav_active() {
                LeviathanProofCollection::produce_in_process(
                    primitive_witness,
                    network,
                    block_height,
                )
                .await?
                .into()
            } else {
                ProofCollection::produce_in_process(primitive_witness, network, block_height)
                    .await?
                    .into()
            },
        )
    }

    /// A mock collection of the given rule set's layout.
    pub(crate) fn produce_mock(
        primitive_witness: &PrimitiveWitness,
        valid_mock: bool,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Self {
        if consensus_rule_set.bav_active() {
            LeviathanProofCollection::produce_mock(primitive_witness, valid_mock).into()
        } else {
            ProofCollection::produce_mock(primitive_witness, valid_mock).into()
        }
    }

    /// This collection in the layout of the given rule set's collections: the upstream layout
    /// gains no bridge proofs and the kernel's announcements, the Leviathan one loses them if it
    /// has no bridge proofs. `None` if it has bridge proofs, which no upstream collection carries.
    pub(crate) fn into_layout_of(
        self,
        consensus_rule_set: ConsensusRuleSet,
        kernel: &TransactionKernel,
    ) -> Option<Self> {
        match (self, consensus_rule_set.bav_active()) {
            (Self::Upstream(collection), true) => Some(
                LeviathanProofCollection::assemble(collection, BridgeProofs::default(), kernel)
                    .into(),
            ),
            (Self::Leviathan(collection), false) => {
                let has_bridge_proofs = collection.bridge_deposit_announcement_validator.is_some()
                    || collection.bridge_aggregated_proof.is_some();
                (!has_bridge_proofs).then(|| collection.base().into())
            }
            (collection, _) => Some(collection),
        }
    }

    /// Whether this is the layout of the given rule set's collections.
    pub(crate) fn is_of(&self, consensus_rule_set: ConsensusRuleSet) -> bool {
        matches!(self, Self::Leviathan(_)) == consensus_rule_set.bav_active()
    }

    pub fn kernel_mast_hash(&self) -> Digest {
        match self {
            Self::Leviathan(collection) => collection.kernel_mast_hash,
            Self::Upstream(collection) => collection.kernel_mast_hash,
        }
    }

    /// The [`ProofCollection`] fields.
    pub(crate) fn base(&self) -> ProofCollection {
        match self {
            Self::Leviathan(collection) => collection.base(),
            Self::Upstream(collection) => collection.clone(),
        }
    }

    pub(crate) fn num_proofs(&self) -> usize {
        self.base().num_proofs()
    }

    /// Verify under the given rule set, whose layout it must have.
    pub(crate) async fn verify_v2(
        &self,
        txk_mast_hash: Digest,
        network: Network,
        claim_version: u32,
        consensus_rule_set: ConsensusRuleSet,
        opts: VerifyOptions,
    ) -> bool {
        if !self.is_of(consensus_rule_set) {
            return false;
        }
        match self {
            Self::Leviathan(collection) => {
                collection
                    .verify_v2(
                        txk_mast_hash,
                        network,
                        claim_version,
                        consensus_rule_set,
                        opts,
                    )
                    .await
            }
            Self::Upstream(collection) => {
                collection
                    .verify_v2(txk_mast_hash, network, claim_version)
                    .await
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use macro_rules_attr::apply;
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;

    use super::*;
    use crate::api::export::NativeCurrencyAmount;
    use crate::application::triton_vm_job_queue::vm_job_queue;
    use crate::tests::shared_tokio_runtime;

    impl LeviathanProofCollection {
        /// An invalid collection for testing purposes, as [`ProofCollection::invalid`].
        pub(crate) fn invalid() -> Self {
            let base = ProofCollection::invalid();
            Self {
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
                bridge_deposit_announcement_validator: None,
                bridge_aggregated_proof: None,
                bridge_prev_state_commitment: None,
                bridge_new_state_commitment: None,
                bridge_exit_root: None,
                announcements: vec![],
                announcements_mast_path: vec![],
            }
        }
    }

    /// Binary formats tag the layout; JSON carries the inner collection as it is.
    #[test]
    fn serde_round_trips_both_layouts_in_binary_and_json() {
        let upstream = ProofCollection::invalid();
        let leviathan = LeviathanProofCollection {
            bridge_exit_root: Some(Digest::default()),
            ..LeviathanProofCollection::invalid()
        };
        for collection in [
            AnyProofCollection::from(upstream.clone()),
            AnyProofCollection::from(leviathan.clone()),
        ] {
            let binary = bincode::serialize(&collection).unwrap();
            assert_eq!(
                collection,
                bincode::deserialize::<AnyProofCollection>(&binary).unwrap()
            );
            let json = serde_json::to_string(&collection).unwrap();
            assert_eq!(
                collection,
                serde_json::from_str::<AnyProofCollection>(&json).unwrap()
            );
        }

        assert_eq!(
            serde_json::to_string(&upstream).unwrap(),
            serde_json::to_string(&AnyProofCollection::from(upstream)).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&leviathan).unwrap(),
            serde_json::to_string(&AnyProofCollection::from(leviathan)).unwrap()
        );
    }

    /// An upstream collection takes the Leviathan layout with the same sub-proofs, and back; one
    /// with bridge proofs has no upstream layout.
    #[test]
    fn collections_convert_between_layouts() {
        let pw = plain_tx_witness(false);
        let upstream = AnyProofCollection::from(ProofCollection::produce_mock(&pw, true));
        let leviathan = upstream
            .clone()
            .into_layout_of(ConsensusRuleSet::LeviathanSettlement, &pw.kernel)
            .unwrap();
        assert!(leviathan.is_of(ConsensusRuleSet::LeviathanSettlement));
        assert_eq!(upstream.base(), leviathan.base());
        assert_eq!(
            upstream,
            leviathan
                .into_layout_of(ConsensusRuleSet::UpgradeVMv8, &pw.kernel)
                .unwrap()
        );

        let bridged = AnyProofCollection::from(LeviathanProofCollection {
            bridge_aggregated_proof: Some(Proof::invalid_with_size(4)),
            ..LeviathanProofCollection::invalid()
        });
        assert!(bridged
            .into_layout_of(ConsensusRuleSet::UpgradeVMv8, &pw.kernel)
            .is_none());
    }

    fn bridge_claim_version() -> u32 {
        ProofCollection::claim_version_for(ConsensusRuleSet::LeviathanSettlement)
    }

    /// A plain 1-in/1-out transaction with no bridge pool output, carrying a deposit-tagged
    /// announcement if `with_deposit` (as `custom_announcements` allows any user to do).
    pub(crate) fn plain_tx_witness(with_deposit: bool) -> PrimitiveWitness {
        use crate::protocol::consensus::bridge::deposit_announcement::BridgeDepositData;
        use crate::protocol::consensus::transaction::lock_script::LockScript;
        use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
        use crate::protocol::consensus::transaction::utxo::Utxo;

        let lock = LockScript::anyone_can_spend();
        let utxo = Utxo::new_native_currency(lock.hash(), NativeCurrencyAmount::coins(10));
        let deposit = BridgeDepositData {
            account_id: [
                bfe!(0x7db0_664f_500c_4c00_u64),
                bfe!(0x6942_9324_3acf_dec1_u64),
            ],
            amount: NativeCurrencyAmount::coins(5),
            utxo_commitment: [bfe!(123); 5],
            sender_randomness: [bfe!(7); 5],
            receiver_preimage: [bfe!(9); 5],
        };
        let announcements = if with_deposit {
            vec![deposit.to_announcement()]
        } else {
            vec![]
        };
        PrimitiveWitness::arbitrary_primitive_witness_with(
            std::slice::from_ref(&utxo),
            &[LockScriptAndWitness::new(lock.program)],
            std::slice::from_ref(&utxo),
            &announcements,
            NativeCurrencyAmount::coins(0),
            None,
        )
        .new_tree(&mut TestRunner::deterministic())
        .unwrap()
        .current()
    }

    /// RegTest proof collection: mock sub-proofs, BDAV present iff a deposit is announced.
    pub(crate) async fn mock_proof_collection(pw: &PrimitiveWitness) -> LeviathanProofCollection {
        LeviathanProofCollection::produce_v2(
            pw,
            vm_job_queue(),
            TritonVmProofJobOptions::default_with_network(Network::RegTest),
            ConsensusRuleSet::LeviathanSettlement,
        )
        .await
        .unwrap()
    }

    /// `plain_tx_witness(false)` whose kernel carries the zero settlement announcement instead.
    pub(crate) fn settlement_tx_witness() -> PrimitiveWitness {
        use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
        use crate::protocol::consensus::transaction::validity::bridge_aggregated_announcement_validator::tests::zero_settlement;

        let mut pw = plain_tx_witness(false);
        pw.kernel = TransactionKernelModifier::default()
            .announcements(vec![zero_settlement()])
            .modify(pw.kernel);
        pw
    }

    /// `mock_proof_collection` for a settlement tx (RegTest mock proofs never run the program).
    pub(crate) async fn mock_settlement_proof_collection(
        pw: &PrimitiveWitness,
    ) -> LeviathanProofCollection {
        let settlement = SettlementProverInput {
            verifier_program: Program::new(&triton_asm!(halt)),
            verifier_ram: std::collections::HashMap::new(),
        };
        LeviathanProofCollection::produce_settlement(
            pw,
            &settlement,
            vm_job_queue(),
            TritonVmProofJobOptions::default_with_network(Network::RegTest),
            ConsensusRuleSet::LeviathanSettlement,
        )
        .await
        .unwrap()
    }

    /// Verify as on a registered chain whose commitment is the zero settlement's `prev`.
    async fn verifies(pc: &LeviathanProofCollection, pw: &PrimitiveWitness) -> bool {
        let opts = VerifyOptions {
            prev_state_commitment: Some(Digest::default()),
        };
        pc.verify_v2(
            pw.kernel.mast_hash(),
            Network::RegTest,
            bridge_claim_version(),
            ConsensusRuleSet::LeviathanSettlement,
            opts,
        )
        .await
    }

    #[apply(shared_tokio_runtime)]
    async fn deposit_announcement_requires_bdav() {
        let pw = plain_tx_witness(true);
        let honest = mock_proof_collection(&pw).await;
        assert!(honest.bridge_deposit_announcement_validator.is_some());
        assert!(verifies(&honest, &pw).await);

        let mut without_bdav = honest;
        without_bdav.bridge_deposit_announcement_validator = None;
        assert!(!verifies(&without_bdav, &pw).await);
    }

    #[apply(shared_tokio_runtime)]
    async fn settlement_announcement_requires_baav() {
        let pw = settlement_tx_witness();
        assert!(matches!(
            LeviathanProofCollection::produce_v2(
                &pw,
                vm_job_queue(),
                TritonVmProofJobOptions::default_with_network(Network::RegTest),
                ConsensusRuleSet::LeviathanSettlement,
            )
            .await,
            Err(CreateProofError::MissingRequirement(
                ProofRequirement::Program
            ))
        ));
        let honest = mock_settlement_proof_collection(&pw).await;
        assert!(honest.bridge_aggregated_proof.is_some());
        assert!(verifies(&honest, &pw).await);
        let unregistered = honest
            .verify_v2(
                pw.kernel.mast_hash(),
                Network::RegTest,
                bridge_claim_version(),
                ConsensusRuleSet::LeviathanSettlement,
                VerifyOptions::default(),
            )
            .await;
        assert!(!unregistered, "no settlement before registration");

        let mut without_baav = honest;
        without_baav.bridge_aggregated_proof = None;
        assert!(!verifies(&without_baav, &pw).await);
    }

    /// The BAAV claim a settlement is proven for is the one verification builds from the chain's
    /// state commitment.
    #[apply(shared_tokio_runtime)]
    async fn baav_claim_prove_and_verify_sides_agree() {
        let pw = settlement_tx_witness();
        let announcement =
            AggregatedAnnouncementData::find_in_announcements(&pw.kernel.announcements).unwrap();
        let prev_state = announcement.prev_state_commitment;
        let prove_side = BridgeAggregatedAnnouncementValidatorWitness::from_announcement(
            announcement,
            None,
            pw.clone(),
        )
        .claim()
        .about_version(bridge_claim_version());
        let pc = mock_settlement_proof_collection(&pw).await;
        assert_eq!(
            Some(prove_side),
            pc.bridge_aggregated_proof_claim(Some(prev_state), bridge_claim_version())
        );
    }

    /// A settlement collection's dummy sub-proofs are skipped only under `LeviathanSettlement`,
    /// where its BAAV proof covers them; elsewhere they are verified, and fail.
    #[apply(shared_tokio_runtime)]
    async fn settlement_sub_proofs_are_skipped_only_where_baav_is_active() {
        let pw = settlement_tx_witness();
        let pc = mock_settlement_proof_collection(&pw).await;
        let opts = VerifyOptions {
            prev_state_commitment: Some(Digest::default()),
        };
        assert!(verifies(&pc, &pw).await);
        assert!(
            !pc.verify_v2(
                pw.kernel.mast_hash(),
                Network::RegTest,
                bridge_claim_version(),
                ConsensusRuleSet::UpgradeVMv8,
                opts,
            )
            .await
        );

        // The UpgradeVMv8 rejection above is the halt-proof counts; past them, every sub-proof
        // is the dummy, made for a claim none of them requires.
        assert!(!pc.base().halt_proof_counts_match());
        let dummy_claim = Claim::new(Digest::default());
        let base = pc.base();
        for (claim, proof) in base.claims_and_proofs(bridge_claim_version()) {
            assert_eq!(&Proof::valid_mock(dummy_claim.clone()), proof);
            assert_ne!(dummy_claim, claim);
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn no_deposit_announcement_needs_no_bdav() {
        let pw = plain_tx_witness(false);
        let pc = mock_proof_collection(&pw).await;
        assert!(pc.bridge_deposit_announcement_validator.is_none());
        assert!(verifies(&pc, &pw).await);
    }

    #[apply(shared_tokio_runtime)]
    async fn announcements_copy_must_match_kernel() {
        let pw = plain_tx_witness(true);
        let mut forged = mock_proof_collection(&pw).await;
        forged.bridge_deposit_announcement_validator = None;
        forged.announcements.clear();
        assert!(!verifies(&forged, &pw).await);
    }

    #[apply(shared_tokio_runtime)]
    async fn in_process_equals_the_queue_on_mock_networks() {
        use crate::api::tx_initiation::bridge_deposit::tests::deposit_witness;

        for pw in [
            plain_tx_witness(false),
            plain_tx_witness(true),
            deposit_witness(1),
        ] {
            let in_process = LeviathanProofCollection::produce_in_process(
                &pw,
                Network::RegTest,
                BlockHeight::genesis(),
            )
            .await
            .unwrap();
            assert_eq!(in_process, mock_proof_collection(&pw).await);
        }
    }

    #[apply(shared_tokio_runtime)]
    #[ignore = "real proofs: tens of GB and minutes"]
    async fn in_process_proves_a_real_deposit() {
        use crate::api::tx_initiation::bridge_deposit::tests::deposit_witness;

        let network = Network::Testnet(0);
        let pw = deposit_witness(1);
        let pc = LeviathanProofCollection::produce_in_process(&pw, network, BlockHeight::genesis())
            .await
            .unwrap();
        assert!(pc.bridge_deposit_announcement_validator.is_some());
        assert!(
            pc.verify_v2(
                pw.kernel.mast_hash(),
                network,
                bridge_claim_version(),
                ConsensusRuleSet::LeviathanSettlement,
                VerifyOptions::default(),
            )
            .await
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn in_process_sub_proof_verifies_on_a_real_network() {
        use crate::protocol::consensus::transaction::lock_script::LockScript;
        use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;

        let network = Network::Testnet(0);
        let lock = LockScriptAndWitness::new(LockScript::anyone_can_spend().program);
        let claim = lock.claim(
            PublicInput::new(vec![bfe!(1); Digest::LEN]),
            bridge_claim_version(),
        );
        let proof = SubProver::InProcess { network }
            .prove(lock.program.clone(), claim.clone(), || {
                lock.nondeterminism()
            })
            .await
            .unwrap();
        assert!(verify_transaction_proof(claim, proof, network).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "real proofs: minutes"]
    async fn in_process_deposit_with_dctidh_change_finishes() {
        use crate::api::tx_initiation::bridge_deposit::tests::deposit_witness_with_dctidh_change;

        let network = Network::Testnet(0);
        let pw = deposit_witness_with_dctidh_change(1);
        let pc = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            LeviathanProofCollection::produce_in_process(&pw, network, BlockHeight::genesis()),
        )
        .await
        .expect("in-process proving must not hang")
        .unwrap();
        assert!(
            pc.verify_v2(
                pw.kernel.mast_hash(),
                network,
                bridge_claim_version(),
                ConsensusRuleSet::LeviathanSettlement,
                VerifyOptions::default(),
            )
            .await
        );
    }
}
