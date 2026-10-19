//! Transaction proofs of the `UpgradeVMv7` era, which main net runs before the
//! `UpgradeVMv8` fork: v7 `ProofCollection`s and v7 `SingleProof`s, proven by
//! the linked triton-vm v7 for claims of version 5.
//!
//! The sub-programs of a `ProofCollection` (RemovalRecordsIntegrity,
//! KernelToOutputs, CollectLockScripts, CollectTypeScriptsV2, and the lock and
//! type scripts) have the same bytecode in both eras, so a v7 collection is
//! [`ProofCollection::produce_v2`] for `UpgradeVMv7`: only the claim version
//! and the prover differ.
//!
//! The v7 `SingleProofV2` program differs from the linked one in its STARK
//! verifier (that of tasm-lib v7, see `LegacyStarkVerify`), in the claim
//! version that its claim builder writes, and in the absence of the chaining
//! branches. This version raises v7 collections to v7 single proofs; it does
//! not update or merge v7 single proofs.
//!
//! A v7 single proof is far more expensive than a v7 collection, so this node
//! attempts one only where [`check_v7_single_proof_capability`] allows it (see
//! `api::tx_initiation::legacy_era::prove_legacy_era_transaction` and the
//! transaction proof builder), and keeps the v7 collection otherwise. Whatever
//! the caller, the job options of a v7 single proof cap its padded height at
//! what the available memory holds (see `v7_single_proof_job_options`).

use std::collections::HashMap;
use std::sync::OnceLock;

use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::proof_collection::ProofCollection;
use super::single_proof_v2::single_proof_claim;
use super::single_proof_v2::SingleProofV2;
use super::single_proof_v2::SingleProofV2Witness;
use super::tasm::claims::new_claim::VersionedNewClaim;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::proof_abstractions::tasm::legacy_v7;
use crate::protocol::proof_abstractions::tasm::legacy_v7::max_log2_padded_height_for_memory;
use crate::protocol::proof_abstractions::tasm::legacy_v7::v7_claim_version;
use crate::protocol::proof_abstractions::tasm::legacy_v7::LegacyProverPipeline;
use crate::protocol::proof_abstractions::tasm::legacy_v7::LegacyProvingError;
use crate::protocol::proof_abstractions::tasm::legacy_v7::LegacyStarkVerify;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::tasm::prover_job::ProverJobSettings;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;

/// The largest padded height, log2, of a v7 single proof that this node
/// attempts.
///
/// The padded height of the v7 `SingleProofV2` program grows with the number
/// of proofs it verifies: 2^21 for the six proofs of a transaction with one
/// input and no time lock, 2^22 for typical transactions (two or more inputs,
/// or a time lock). Larger transactions stay with their v7 collection.
pub const V7_SINGLE_PROOF_MAX_LOG2_PADDED_HEIGHT: u8 = 22;

/// The digests of the programs proven inside a v7 proof collection, as the
/// nodes of the era before the fork compute them: those of v0.2.5, which main
/// net runs until the fork. A v7 collection of programs that hash otherwise is
/// invalid there. The lock scripts are not listed: they are the ones of the
/// inputs, which their own digests commit to.
pub const V7_PROOF_COLLECTION_PROGRAM_DIGESTS: [(&str, &str); 7] = [
    (
        "RemovalRecordsIntegrity",
        "22096d01b54bf8ca4d8203515cbf0207803b707086cad8d3889a638fb2edb5012c9c452a4d065644",
    ),
    (
        "KernelToOutputs",
        "74e12c483cfd1c57a76bfaafa2ea2b92177103367b9cdc0ab2bd3491c051599fbbaef1b77cc00c75",
    ),
    (
        "CollectLockScripts",
        "7b608d9bbe5b5dc9f3f25af57ebb5a26302e404d0485d8b87abe74d9b339921493922b685efad062",
    ),
    (
        "CollectTypeScriptsV2",
        "1d33643dc5086e915e44d720af4a1efa195254aee6497166f5055a7bcb0d8313ce70f77fe0632c4e",
    ),
    (
        "NativeCurrency",
        "11fdd6eba11eda86ac300e63efa28bf8636b1bdcc1c5588f0539e4efb03c665bc779aa347c92e2f4",
    ),
    (
        "TimeLock",
        "4b4d251947a07f9f2c016c1c271c04ce41013ff50031bd42854919be6e0e4849ebf931e856b542ad",
    ),
    (
        "TimeLockV2",
        "8b6d23e675c97cb8e1d36a5e926f19449d37673636c64c0769b7778aded85ff29056832e366b580b",
    ),
];

/// The digests of this build's programs listed in
/// [`V7_PROOF_COLLECTION_PROGRAM_DIGESTS`], in its order.
fn v7_proof_collection_program_digests() -> [(&'static str, Digest); 7] {
    use crate::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScripts;
    use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
    use crate::protocol::consensus::transaction::validity::kernel_to_outputs::KernelToOutputs;
    use crate::protocol::consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
    use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
    use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
    use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;
    use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

    [
        ("RemovalRecordsIntegrity", RemovalRecordsIntegrity.hash()),
        ("KernelToOutputs", KernelToOutputs.hash()),
        ("CollectLockScripts", CollectLockScripts.hash()),
        ("CollectTypeScriptsV2", CollectTypeScriptsV2.hash()),
        ("NativeCurrency", NativeCurrency.hash()),
        ("TimeLock", TimeLock.hash()),
        ("TimeLockV2", TimeLockV2.hash()),
    ]
}

/// Whether this build's programs of a v7 proof collection have the digests of
/// [`V7_PROOF_COLLECTION_PROGRAM_DIGESTS`]; the name of the first that does
/// not, if any. Computed once.
pub(crate) fn check_v7_proof_collection_programs() -> Result<(), &'static str> {
    static CHECK: OnceLock<Result<(), &'static str>> = OnceLock::new();
    *CHECK.get_or_init(|| {
        for ((name, digest), (_, pinned)) in v7_proof_collection_program_digests()
            .into_iter()
            .zip(V7_PROOF_COLLECTION_PROGRAM_DIGESTS)
        {
            if digest.to_hex() != pinned {
                tracing::error!(
                    "Program {name} hashes to {}, not to its v7 digest {pinned}",
                    digest.to_hex()
                );
                return Err(name);
            }
        }
        Ok(())
    })
}

/// The assembly of the v7 `SingleProofV2` program: the linked program without
/// the chaining branches, with the STARK verifier of tasm-lib v7 and a claim
/// builder that writes claim version 5.
///
/// Both substitutes are imported before anything else. Imports deduplicate by
/// entrypoint label, so every later import of `StarkVerify` or `NewClaim`,
/// including those inside the update and merge branches, resolves to them, and
/// the verifier is the first import that allocates static memory, as in the v7
/// build.
pub fn single_proof_v2_v7_code() -> Vec<LabelledInstruction> {
    let mut library = Library::new();
    library.import(Box::new(LegacyStarkVerify::new_with_dynamic_layout()));
    library.import(Box::new(VersionedNewClaim {
        version: v7_claim_version(),
    }));
    let (_, code) = SingleProofV2.assemble_into(library, false);

    code
}

/// The v7 `SingleProofV2` program; see [`single_proof_v2_v7_code`].
pub fn single_proof_v2_v7_program() -> Program {
    static PROGRAM: OnceLock<Program> = OnceLock::new();

    PROGRAM
        .get_or_init(|| Program::new(&single_proof_v2_v7_code()))
        .clone()
}

/// The nondeterminism for proving the v7 `SingleProofV2` program on a v7
/// [`ProofCollection`]: the witness in memory, the merge-bit authentication
/// path, and, for every sub-proof, what the tasm-lib v7 STARK verifier reads.
///
/// The collection must meet the preconditions of its verification (see
/// [`ProofCollection::meets_verification_preconditions`]), and every sub-proof
/// is verified under triton-vm v7 first, with the checks of the transaction
/// proof verifier: what the in-VM verifier reads is derived from the proof,
/// which works for valid proofs only.
///
/// Verifies every sub-proof, which takes a while: call it from a blocking
/// task, where a panic counts as a failure; see
/// [`v7_single_proof_nondeterminism_blocking`].
pub(crate) fn v7_single_proof_nondeterminism(
    proof_collection: &ProofCollection,
) -> Result<NonDeterminism, LegacyProvingError> {
    if !proof_collection.meets_verification_preconditions(proof_collection.kernel_mast_hash) {
        return Err(LegacyProvingError::MalformedCollection);
    }

    let witness = SingleProofV2Witness::from_collection(proof_collection.clone());
    let mut memory = HashMap::default();
    encode_to_memory(
        &mut memory,
        FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
        &witness,
    );
    let mut nondeterminism = NonDeterminism::default().with_ram(memory);
    nondeterminism
        .digests
        .extend_from_slice(&proof_collection.merge_bit_mast_path);

    let stark_verify = LegacyStarkVerify::new_with_dynamic_layout();
    for (claim, proof) in proof_collection.claims_and_proofs(v7_claim_version()) {
        if !legacy_v7::verify(&claim, proof) {
            return Err(LegacyProvingError::InvalidProof(claim.program_digest));
        }
        stark_verify.update_nondeterminism(&mut nondeterminism, proof, &claim);
    }

    Ok(nondeterminism)
}

/// [`v7_single_proof_nondeterminism`] in a blocking task. A panic while
/// deriving the nondeterminism counts as a proof that does not verify.
pub(crate) async fn v7_single_proof_nondeterminism_blocking(
    proof_collection: ProofCollection,
) -> Result<NonDeterminism, LegacyProvingError> {
    let kernel_mast_hash = proof_collection.kernel_mast_hash;
    tokio::task::spawn_blocking(move || v7_single_proof_nondeterminism(&proof_collection))
        .await
        .unwrap_or(Err(LegacyProvingError::InvalidProof(kernel_mast_hash)))
}

/// The padded-height limit, log2, for proving a v7 single proof on a machine
/// with the given available memory: the configured limit, at most
/// [`V7_SINGLE_PROOF_MAX_LOG2_PADDED_HEIGHT`], and at most what the memory
/// holds according to
/// [`proving_memory_estimate`](crate::protocol::proof_abstractions::tasm::legacy_v7::proving_memory_estimate).
///
/// `None` if the memory does not hold a proof of any padded height.
pub fn v7_single_proof_max_log2_padded_height(
    configured_max_log2_padded_height: Option<u8>,
    available_memory: u64,
) -> Option<u8> {
    let memory_limit = max_log2_padded_height_for_memory(available_memory)?;
    let limit = configured_max_log2_padded_height
        .unwrap_or(V7_SINGLE_PROOF_MAX_LOG2_PADDED_HEIGHT)
        .min(V7_SINGLE_PROOF_MAX_LOG2_PADDED_HEIGHT)
        .min(memory_limit);

    Some(limit)
}

/// The job options for proving a v7 single proof on this machine now: the
/// padded-height limit lowered to [`v7_single_proof_max_log2_padded_height`]
/// for the memory available at this moment.
///
/// The prover executes the program before proving and gives up if the padded
/// height exceeds the limit, so a v7 single proof that this machine cannot hold
/// fails early, with
/// [`ProofComplexityLimitExceeded`](crate::protocol::proof_abstractions::tasm::prover_job::ProverJobError::ProofComplexityLimitExceeded),
/// instead of running out of memory.
///
/// The memory estimate assumes that the prover does not cache the
/// low-degree-extended trace, which triton-vm v7 otherwise does whenever the
/// allocation succeeds. So unless the operator decides it, through the
/// environment of the node or the per-height Triton VM environment variables,
/// the job sets `TVM_LDE_TRACE=no_cache` for every padded height it allows.
pub(crate) fn v7_single_proof_job_options(
    mut proof_job_options: TritonVmProofJobOptions,
) -> TritonVmProofJobOptions {
    let job_settings = &mut proof_job_options.job_settings;
    let available_memory = legacy_v7::available_memory();
    let limit = v7_single_proof_max_log2_padded_height(
        job_settings.max_log2_padded_height_for_proofs,
        available_memory,
    );
    // A limit of 2^0 refuses every proof.
    job_settings.max_log2_padded_height_for_proofs = Some(limit.unwrap_or(0));

    if std::env::var_os(LDE_TRACE_ENV_VAR).is_none() {
        for log2_padded_height in 0..=V7_SINGLE_PROOF_MAX_LOG2_PADDED_HEIGHT {
            let env_vars = job_settings
                .triton_vm_env_vars
                .entry(log2_padded_height)
                .or_default();
            if !env_vars.iter().any(|(key, _)| key == LDE_TRACE_ENV_VAR) {
                env_vars.push((LDE_TRACE_ENV_VAR.to_string(), "no_cache".to_string()));
            }
        }
    }

    proof_job_options
}

/// The environment variable by which Triton VM decides whether to cache the
/// low-degree-extended trace while proving.
const LDE_TRACE_ENV_VAR: &str = "TVM_LDE_TRACE";

/// Why this node does not attempt a v7 single proof.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum V7SingleProofUnavailable {
    #[error("proving capability {0} does not include single proofs")]
    Capability(TxProvingCapability),

    #[error(
        "the v7 single proof needs padded height 2^{log2_padded_height}, \
         above the limit 2^{limit} of this machine"
    )]
    PaddedHeight { log2_padded_height: u8, limit: u8 },

    #[error("the available memory does not hold any v7 single proof")]
    Memory,

    #[error("the v7 single proof program cannot be run on the collection: {0}")]
    Execution(LegacyProvingError),
}

/// Whether this node attempts to raise the v7 collection to a v7 single proof,
/// decided before anything is proven. Returns the padded height, log2, of the
/// v7 single proof if so.
///
/// The configured proving capability must include single proofs, and the
/// padded height must be within [`v7_single_proof_max_log2_padded_height`] for
/// the configured limit and the given available memory (see
/// [`available_memory`](crate::protocol::proof_abstractions::tasm::legacy_v7::available_memory)).
/// The padded height is found by executing the v7 program on the collection,
/// which takes seconds and a few GB. A transaction for which this fails stays
/// with its v7 collection.
pub fn check_v7_single_proof_capability(
    proof_collection: &ProofCollection,
    job_settings: &ProverJobSettings,
    available_memory: u64,
) -> Result<u8, V7SingleProofUnavailable> {
    let capability = job_settings.tx_proving_capability;
    if !capability.can_prove(TransactionProofType::SingleProof) {
        return Err(V7SingleProofUnavailable::Capability(capability));
    }

    let limit = v7_single_proof_max_log2_padded_height(
        job_settings.max_log2_padded_height_for_proofs,
        available_memory,
    )
    .ok_or(V7SingleProofUnavailable::Memory)?;

    let claim = single_proof_claim(
        proof_collection.kernel_mast_hash,
        ConsensusRuleSet::UpgradeVMv7,
    );
    let nondeterminism = v7_single_proof_nondeterminism(proof_collection)
        .map_err(V7SingleProofUnavailable::Execution)?;
    let log2_padded_height =
        LegacyProverPipeline::trace(&single_proof_v2_v7_program(), &claim, &nondeterminism)
            .map_err(V7SingleProofUnavailable::Execution)?
            .log2_padded_height();

    if log2_padded_height > limit {
        return Err(V7SingleProofUnavailable::PaddedHeight {
            log2_padded_height,
            limit,
        });
    }

    Ok(log2_padded_height)
}

/// [`check_v7_single_proof_capability`] in a blocking task, since it verifies
/// every sub-proof and runs the v7 program. A panic counts as an execution
/// failure.
pub async fn check_v7_single_proof_capability_blocking(
    proof_collection: ProofCollection,
    job_settings: ProverJobSettings,
    available_memory: u64,
) -> Result<u8, V7SingleProofUnavailable> {
    tokio::task::spawn_blocking(move || {
        check_v7_single_proof_capability(&proof_collection, &job_settings, available_memory)
    })
    .await
    .unwrap_or_else(|error| {
        Err(V7SingleProofUnavailable::Execution(
            LegacyProvingError::Execution(error.to_string()),
        ))
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
