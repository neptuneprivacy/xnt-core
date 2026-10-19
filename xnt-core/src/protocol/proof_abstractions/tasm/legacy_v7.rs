//! Proving for the `UpgradeVMv7` era (triton-vm v7, claim version 5) from a
//! binary whose linked triton-vm is v9 (claim version 8).
//!
//! Both generations share the instruction set and the program encoding, but
//! they are distinct crates over distinct `twenty-first` versions (1.1 and
//! 3.0), so every value crosses the boundary by value: field elements by their
//! canonical `u64`, programs by their `BFieldCodec` encoding. A proof is a list
//! of field elements in both generations and is never re-encoded.
//!
//! Contents:
//!  - value conversions between the two generations;
//!  - [`LegacyProverPipeline`], which traces and proves under triton-vm v7;
//!  - `execute` and [`verify`], running and verifying under triton-vm v7;
//!  - a memory estimate for proving under triton-vm v7;
//!  - `LegacyStarkVerify`, the STARK verifier snippet of tasm-lib v7 wrapped
//!    as a snippet of the linked tasm-lib, so that the v7 `SingleProofV2`
//!    program assembles to its pinned digest.
//!
//! Follows upstream neptune-core `89c8594e` (`legacy_stark_verify.rs`), plus
//! the field conversions that upstream does not need because its two tasm-libs
//! share one `twenty-first`. Remove together with the `triton-vm-v7` and
//! `tasm-lib-v7` dependencies once the `UpgradeVMv8` fork is final.

use std::collections::HashMap;

use itertools::Itertools;
use tasm_lib::data_type::DataType;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::config::CacheDecision;
use tasm_lib::triton_vm::isa::instruction::LabelledInstruction;
use tasm_lib::triton_vm::isa::parser::to_labelled_instructions;
use tasm_lib::triton_vm::isa::parser::tokenize;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::NonDeterminism;
use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof as VmProof;
use tasm_lib_v7::traits::basic_snippet::BasicSnippet as V7BasicSnippet;
use triton_vm_v7 as tvm7;
use tvm7::prelude::BFieldCodec as V7BFieldCodec;

use crate::protocol::consensus::consensus_rule_set::TritonProofVersion;

/// Peak memory per row of padded height when proving under triton-vm v7 with
/// the low-degree-extended trace not cached. Measured on the v7 `SingleProofV2`
/// program, whose proof at padded height 2^21 peaks at 96 GiB.
const PROVING_MEMORY_PER_ROW: u64 = 48 << 10;

/// The claim version of every `UpgradeVMv7` proof.
pub fn v7_claim_version() -> u32 {
    TritonProofVersion::V7.claim_version()
}

/// Whether the claim is answered by a triton-vm v7 proof: its version is the
/// claim version of `UpgradeVMv7`.
pub fn is_v7_claim(claim: &Claim) -> bool {
    claim.version == v7_claim_version()
}

pub(crate) fn bfe_to_v7(element: BFieldElement) -> tvm7::prelude::BFieldElement {
    tvm7::prelude::BFieldElement::new(element.value())
}

pub(crate) fn bfe_from_v7(element: tvm7::prelude::BFieldElement) -> BFieldElement {
    BFieldElement::new(element.value())
}

pub(crate) fn bfes_to_v7(elements: &[BFieldElement]) -> Vec<tvm7::prelude::BFieldElement> {
    elements.iter().copied().map(bfe_to_v7).collect()
}

pub(crate) fn bfes_from_v7(elements: &[tvm7::prelude::BFieldElement]) -> Vec<BFieldElement> {
    elements.iter().copied().map(bfe_from_v7).collect()
}

pub(crate) fn digest_to_v7(digest: Digest) -> tvm7::prelude::Digest {
    tvm7::prelude::Digest::new(digest.values().map(bfe_to_v7))
}

pub(crate) fn digest_from_v7(digest: tvm7::prelude::Digest) -> Digest {
    Digest::new(digest.values().map(bfe_from_v7))
}

/// The claim, carried over by value, version included.
pub(crate) fn claim_to_v7(claim: &Claim) -> tvm7::proof::Claim {
    tvm7::proof::Claim::new(digest_to_v7(claim.program_digest))
        .about_version(claim.version)
        .with_input(bfes_to_v7(&claim.input))
        .with_output(bfes_to_v7(&claim.output))
}

pub(crate) fn proof_to_v7(proof: &VmProof) -> tvm7::proof::Proof {
    tvm7::proof::Proof(bfes_to_v7(&proof.0))
}

pub(crate) fn proof_from_v7(proof: &tvm7::proof::Proof) -> VmProof {
    VmProof(bfes_from_v7(&proof.0))
}

/// The program, carried over through its encoding.
///
/// Fails if triton-vm v7 cannot decode the program or hashes it differently,
/// either of which would mean that the two generations no longer share the
/// program encoding.
pub(crate) fn program_to_v7(
    program: &Program,
) -> Result<tvm7::prelude::Program, LegacyProvingError> {
    let encoding = bfes_to_v7(&program.encode());
    let program_v7 = *tvm7::prelude::Program::decode(&encoding).map_err(|error| {
        LegacyProvingError::ProgramEncoding(format!("triton-vm v7 cannot decode it: {error}"))
    })?;
    if program.hash() != digest_from_v7(program_v7.hash()) {
        return Err(LegacyProvingError::ProgramEncoding(
            "it hashes differently under triton-vm v7".to_string(),
        ));
    }

    Ok(program_v7)
}

pub(crate) fn nondeterminism_to_v7(
    nondeterminism: &NonDeterminism,
) -> tvm7::prelude::NonDeterminism {
    let ram = nondeterminism
        .ram
        .iter()
        .map(|(&address, &value)| (bfe_to_v7(address), bfe_to_v7(value)))
        .collect::<HashMap<_, _>>();
    let digests = nondeterminism
        .digests
        .iter()
        .copied()
        .map(digest_to_v7)
        .collect_vec();

    tvm7::prelude::NonDeterminism::new(bfes_to_v7(&nondeterminism.individual_tokens))
        .with_digests(digests)
        .with_ram(ram)
}

pub(crate) fn nondeterminism_from_v7(
    nondeterminism: &tvm7::prelude::NonDeterminism,
) -> NonDeterminism {
    let ram = nondeterminism
        .ram
        .iter()
        .map(|(&address, &value)| (bfe_from_v7(address), bfe_from_v7(value)))
        .collect::<HashMap<_, _>>();
    let digests = nondeterminism
        .digests
        .iter()
        .copied()
        .map(digest_from_v7)
        .collect_vec();

    NonDeterminism::new(bfes_from_v7(&nondeterminism.individual_tokens))
        .with_digests(digests)
        .with_ram(ram)
}

/// Why a program could not be run or proven under triton-vm v7.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LegacyProvingError {
    /// The claim does not carry the v7 claim version. A v7 proof answers only
    /// a claim of that version, since the version enters the Fiat-Shamir
    /// transcript.
    #[error("claim version {0} is not the claim version of triton-vm v7 proofs")]
    ClaimVersion(u32),

    #[error("triton-vm v7 execution failed: {0}")]
    Execution(String),

    #[error("triton-vm v7 proving failed: {0}")]
    Proving(String),

    /// A proof to be verified inside the VM does not verify under triton-vm
    /// v7. The nondeterminism for its in-VM verification cannot be derived.
    #[error("a proof for program {0:x} does not verify under triton-vm v7")]
    InvalidProof(Digest),

    /// The proof collection does not meet the checks that precede the
    /// verification of its proofs: one halting proof per script hash, and an
    /// unset merge bit.
    #[error("the proof collection does not meet the preconditions of its verification")]
    MalformedCollection,

    /// The program does not cross over to triton-vm v7 unchanged.
    #[error("the program cannot be run under triton-vm v7: {0}")]
    ProgramEncoding(String),
}

/// Trace and prove under triton-vm v7, keeping the v7 types internal.
///
/// Two steps, like the prover binary: trace first, so that the padded height
/// can be inspected before committing to the expensive proving step.
#[derive(Debug)]
pub struct LegacyProverPipeline {
    aet: tvm7::aet::AlgebraicExecutionTrace,
    claim: tvm7::proof::Claim,
}

impl LegacyProverPipeline {
    /// Run the program under triton-vm v7, recording its algebraic execution
    /// trace. Fails if the claim is not a v7 claim, if the program does not
    /// halt gracefully, or if its output differs from the claimed output.
    pub fn trace(
        program: &Program,
        claim: &Claim,
        nondeterminism: &NonDeterminism,
    ) -> Result<Self, LegacyProvingError> {
        if !is_v7_claim(claim) {
            return Err(LegacyProvingError::ClaimVersion(claim.version));
        }

        let program = program_to_v7(program)?;
        let claim = claim_to_v7(claim);
        let nondeterminism = nondeterminism_to_v7(nondeterminism);
        let public_input = tvm7::prelude::PublicInput::new(claim.input.clone());
        let (aet, output) = tvm7::vm::VM::trace_execution(program, public_input, nondeterminism)
            .map_err(|error| LegacyProvingError::Execution(error.to_string()))?;
        if output != claim.output {
            return Err(LegacyProvingError::Execution(
                "program output does not match the claimed output".to_string(),
            ));
        }

        Ok(Self { aet, claim })
    }

    pub fn log2_padded_height(&self) -> u8 {
        self.aet.padded_height().ilog2() as u8
    }

    pub fn prove(self) -> Result<VmProof, LegacyProvingError> {
        let proof = tvm7::prelude::Stark::default()
            .prove(&self.claim, &self.aet)
            .map_err(|error| LegacyProvingError::Proving(error.to_string()))?;

        Ok(proof_from_v7(&proof))
    }
}

/// Run the program under triton-vm v7 without recording a trace. Compares the
/// two generations in tests.
///
/// Returns the program's output and its cycle count, which is the height of
/// the processor table.
#[cfg(test)]
pub(crate) fn execute(
    program: &Program,
    public_input: &[BFieldElement],
    nondeterminism: &NonDeterminism,
) -> Result<(Vec<BFieldElement>, u32), LegacyProvingError> {
    let public_input = tvm7::prelude::PublicInput::new(bfes_to_v7(public_input));
    let mut vm_state = tvm7::vm::VMState::new(
        program_to_v7(program)?,
        public_input,
        nondeterminism_to_v7(nondeterminism),
    );
    vm_state
        .run()
        .map_err(|error| LegacyProvingError::Execution(error.to_string()))?;

    Ok((bfes_from_v7(&vm_state.public_output), vm_state.cycle_count))
}

/// Verify a (claim, proof) pair with triton-vm v7, rejecting superfluous
/// proof items; see [`verify_with`].
pub fn verify(claim: &Claim, proof: &VmProof) -> bool {
    verify_with(claim, proof, true)
}

/// Verify a (claim, proof) pair with triton-vm v7, after the checks that the
/// transaction-proof verifier (`verifier::verify_transaction_proof`) applies
/// to every v7 proof: a supported padded height and, if
/// `reject_superfluous_items`, exactly the expected number of proof items.
///
/// Runs synchronously and may take a while; call it from a blocking task. A
/// panic in the verifier must count as a rejection, which `spawn_blocking`
/// provides by ending in an error.
pub(crate) fn verify_with(claim: &Claim, proof: &VmProof, reject_superfluous_items: bool) -> bool {
    let claim = claim_to_v7(claim);
    let proof = proof_to_v7(proof);
    if !has_supported_padded_height(&proof) {
        tracing::warn!("rejecting legacy v7 proof of unsupported padded height");
        return false;
    }
    if reject_superfluous_items && !has_expected_num_proof_items(&proof) {
        tracing::warn!("rejecting legacy v7 proof that holds an unexpected number of proof items");
        return false;
    }

    tvm7::verify(tvm7::prelude::Stark::default(), &claim, &proof)
}

/// Whether the v7 proof holds exactly as many proof items as a proof of its
/// padded height has. Like `verifier::has_expected_num_proof_items`, for
/// triton-vm v7, which sends one item fewer outside of FRI: its quotient
/// segments are a single item.
fn has_expected_num_proof_items(proof: &tvm7::proof::Proof) -> bool {
    const NUM_ITEMS_OUTSIDE_FRI: usize = 15;
    const NUM_ROUND_INDEPENDENT_FRI_ITEMS: usize = 4;
    const NUM_FRI_ITEMS_PER_ROUND: usize = 2;

    let Ok(padded_height) = proof.padded_height() else {
        return false;
    };
    let Ok(fri) = tvm7::prelude::Stark::default().fri(padded_height) else {
        return false;
    };
    let Ok(proof_stream) = tvm7::proof_stream::ProofStream::try_from(proof) else {
        return false;
    };
    let expected = NUM_ITEMS_OUTSIDE_FRI
        + NUM_ROUND_INDEPENDENT_FRI_ITEMS
        + NUM_FRI_ITEMS_PER_ROUND * fri.num_rounds();
    proof_stream.items.len() == expected
}

/// Whether the padded height that the v7 proof states is one that triton-vm
/// v7 can verify. Like `verifier::has_supported_padded_height`.
fn has_supported_padded_height(proof: &tvm7::proof::Proof) -> bool {
    let Ok(proof_stream) = tvm7::proof_stream::ProofStream::try_from(proof) else {
        return false;
    };
    let Some(Ok(log2_padded_height)) = proof_stream
        .items
        .into_iter()
        .next()
        .map(|item| item.try_into_log2_padded_height())
    else {
        return false;
    };
    let Some(padded_height) = 1_usize.checked_shl(log2_padded_height) else {
        return false;
    };

    tvm7::prelude::Stark::default()
        .fri(padded_height)
        .is_ok_and(|fri| u32::try_from(fri.domain.len()).is_ok())
}

/// Overwrite triton-vm v7's decision whether to cache the low-degree-extended
/// trace when proving, as `triton_vm::config::overwrite_lde_trace_caching_to`
/// does for the linked triton-vm. Applies to the calling thread.
pub fn overwrite_lde_trace_caching_to(decision: CacheDecision) {
    let decision = match decision {
        CacheDecision::Cache => tvm7::config::CacheDecision::Cache,
        CacheDecision::NoCache => tvm7::config::CacheDecision::NoCache,
    };
    tvm7::config::overwrite_lde_trace_caching_to(decision);
}

/// Estimated peak memory, in bytes, of proving a program of the given padded
/// height under triton-vm v7 with the low-degree-extended trace not cached.
///
/// Memory grows linearly with the padded height; caching the trace needs more.
pub fn proving_memory_estimate(log2_padded_height: u8) -> u64 {
    1_u64
        .checked_shl(u32::from(log2_padded_height))
        .map_or(u64::MAX, |num_rows| {
            num_rows.saturating_mul(PROVING_MEMORY_PER_ROW)
        })
}

/// The largest padded height, log2, whose triton-vm v7 proof fits into the
/// given number of bytes according to [`proving_memory_estimate`], or `None` if
/// no padded height does.
pub fn max_log2_padded_height_for_memory(memory: u64) -> Option<u8> {
    (0..u8::try_from(u64::BITS).unwrap())
        .rev()
        .find(|&log2_padded_height| proving_memory_estimate(log2_padded_height) <= memory)
}

/// The share of the available memory that [`available_memory`] holds back, in
/// percent, for the node itself and for estimation error.
const AVAILABLE_MEMORY_MARGIN_PERCENT: u64 = 10;

/// The memory currently available for starting new processes, in bytes: the
/// smaller of what the host and, where the process runs in a control group
/// with a memory limit, the control group have free, less a margin of
/// [`AVAILABLE_MEMORY_MARGIN_PERCENT`].
pub fn available_memory() -> u64 {
    let mut system = sysinfo::System::new();
    system.refresh_memory();

    let host_available = system.available_memory();
    let available = system.cgroup_limits().map_or(host_available, |limits| {
        host_available.min(limits.free_memory)
    });

    available - available / 100 * AVAILABLE_MEMORY_MARGIN_PERCENT
}

/// The STARK verifier of tasm-lib v7, wrapped as a snippet of the linked
/// tasm-lib, so that v7-era programs keep their exact instruction streams.
///
/// The two tasm-libs differ in substance only in the STARK verifier; the
/// instruction set and the `Library` semantics are the same. This wrapper
/// reproduces what `library.import(StarkVerify)` produced in the v7 build:
///
///  - The body of the v7 snippet and its whole dependency tree are generated
///    against a throwaway v7 library and parsed again as instructions of the
///    linked instruction set (a text round trip). Labels are preserved, so the
///    alphabetical function order of the assembled program is unchanged, and
///    dependencies shared with the surrounding program deduplicate under their
///    original names.
///  - Static memory is mirrored: the throwaway library starts with zero
///    allocated words, which matches the surrounding program as long as this
///    snippet is the first import that allocates static memory. Afterwards the
///    counter of the surrounding library is advanced by the total of the v7
///    verifier.
///
/// Imports deduplicate by entrypoint label, so importing this snippet first
/// makes every later import of the linked `StarkVerify` (same label) resolve to
/// it.
#[derive(Debug, Clone)]
pub(crate) struct LegacyStarkVerify {
    inner: tasm_lib_v7::verifier::stark_verify::StarkVerify,
}

impl LegacyStarkVerify {
    pub(crate) fn new_with_dynamic_layout() -> Self {
        let inner = tasm_lib_v7::verifier::stark_verify::StarkVerify::new_with_dynamic_layout(
            tvm7::prelude::Stark::default(),
        );

        Self { inner }
    }

    /// Extend the nondeterminism by what the in-VM verification of a v7 proof
    /// reads, through the helper of the v7 snippet. That helper replays the
    /// proof through the AIR of triton-vm v7, whose tables differ from those of
    /// the linked triton-vm, so the linked helper cannot be used for v7 proofs.
    pub(crate) fn update_nondeterminism(
        &self,
        nondeterminism: &mut NonDeterminism,
        proof: &VmProof,
        claim: &Claim,
    ) {
        let mut nondeterminism_v7 = nondeterminism_to_v7(nondeterminism);
        self.inner.update_nondeterminism(
            &mut nondeterminism_v7,
            &proof_to_v7(proof),
            &claim_to_v7(claim),
        );
        *nondeterminism = nondeterminism_from_v7(&nondeterminism_v7);
    }
}

/// Parse v7 instructions again as instructions of the linked instruction set.
fn convert_v7_assembly(
    assembly: &[tvm7::isa::instruction::LabelledInstruction],
) -> Vec<LabelledInstruction> {
    let source = assembly
        .iter()
        .map(|instruction| instruction.to_string())
        .join("\n");
    let (_, tokens) = tokenize(&source).expect("v7 assembly must parse under the linked ISA");

    to_labelled_instructions(&tokens)
}

impl BasicSnippet for LegacyStarkVerify {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "claim".to_string()),
            (DataType::VoidPointer, "*proof".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        self.inner.entrypoint()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let mut library_v7 = tasm_lib_v7::library::Library::new();
        let body = self.inner.code(&mut library_v7);

        for dependency in library_v7.all_external_dependencies() {
            let converted = convert_v7_assembly(&dependency);
            let label = converted
                .iter()
                .find_map(|instruction| match instruction {
                    LabelledInstruction::Label(label) => Some(label.clone()),
                    _ => None,
                })
                .expect("every dependency of the v7 verifier must be labelled");
            library.explicit_import(&label, &converted);
        }

        // The v7 library does not expose its allocation counter. Static memory
        // grows downwards from its first address, so the address of a probing
        // one-word allocation reveals how many words the verifier allocated.
        let probe = library_v7.kmalloc(1);
        let num_allocated_words =
            (tasm_lib_v7::library::STATIC_MEMORY_FIRST_ADDRESS - probe.write_address()).value();
        let num_allocated_words =
            u32::try_from(num_allocated_words).expect("v7 verifier's static memory fits u32");
        if num_allocated_words > 0 {
            library.kmalloc(num_allocated_words);
        }

        convert_v7_assembly(&body)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use tasm_lib::triton_vm::isa::triton_asm;
    use tasm_lib::triton_vm::isa::triton_program;

    use super::*;
    use crate::api::tx_initiation::error::CreateProofError;
    use crate::application::config::network::Network;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::proof_abstractions::tasm::program::prove_consensus_program;
    use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::protocol::proof_abstractions::tasm::prover_job::ProverJobError;
    use crate::protocol::proof_abstractions::tasm::prover_job::VmProcessError;
    use crate::tests::shared_tokio_runtime;

    fn halt_claim_v7() -> (Program, Claim) {
        let program = triton_program!(halt);
        let claim =
            Claim::about_program(&program).about_version(TritonProofVersion::V7.claim_version());

        (program, claim)
    }

    #[test]
    fn v7_claims_carry_claim_version_5() {
        let (program, claim) = halt_claim_v7();
        assert_eq!(5, claim.version);
        assert!(is_v7_claim(&claim));
        assert!(!is_v7_claim(&Claim::about_program(&program)));
    }

    #[test]
    fn values_cross_the_generations_unchanged() {
        let digest = Digest::new([1, 2, 3, 4, u64::MAX - 1].map(BFieldElement::new));
        assert_eq!(digest, digest_from_v7(digest_to_v7(digest)));

        let nondeterminism = NonDeterminism::new(vec![BFieldElement::new(7)])
            .with_digests(vec![digest])
            .with_ram(HashMap::from([(
                BFieldElement::new(3),
                BFieldElement::new(9),
            )]));
        assert_eq!(
            nondeterminism,
            nondeterminism_from_v7(&nondeterminism_to_v7(&nondeterminism))
        );

        let program = triton_program!(push 1 push 2 add pop 1 halt);
        assert_eq!(
            program.hash(),
            digest_from_v7(program_to_v7(&program).unwrap().hash())
        );
    }

    #[test]
    fn pipeline_rejects_claims_of_other_versions() {
        let (program, claim) = halt_claim_v7();
        let claim = claim.about_version(TritonProofVersion::V8.claim_version());
        let result = LegacyProverPipeline::trace(&program, &claim, &NonDeterminism::default());
        assert_eq!(
            Some(LegacyProvingError::ClaimVersion(claim.version)),
            result.err()
        );
    }

    #[test]
    fn pipeline_proves_a_claim_that_the_v7_verifier_accepts() {
        let (program, claim) = halt_claim_v7();
        let pipeline =
            LegacyProverPipeline::trace(&program, &claim, &NonDeterminism::default()).unwrap();
        let proof = pipeline.prove().unwrap();
        assert!(verify(&claim, &proof));

        let other_version = claim
            .clone()
            .about_version(TritonProofVersion::V8.claim_version());
        assert!(!verify(&other_version, &proof));
    }

    #[test]
    fn execution_matches_the_linked_vm() {
        use tasm_lib::triton_vm::vm::VMState;

        let program = triton_program!(read_io 1 push 2 mul write_io 1 halt);
        let input = [BFieldElement::new(21)];
        let (output, cycle_count) = execute(&program, &input, &NonDeterminism::default()).unwrap();
        assert_eq!(vec![BFieldElement::new(42)], output);

        let mut vm_state = VMState::new(program, input.to_vec().into(), NonDeterminism::default());
        vm_state.run().unwrap();
        assert_eq!(vm_state.public_output, output);
        assert_eq!(vm_state.cycle_count, cycle_count);

        let failing = triton_program!(push 0 assert halt);
        assert!(execute(&failing, &[], &NonDeterminism::default()).is_err());
    }

    #[test]
    fn memory_estimate_is_monotone_and_inverts() {
        assert_eq!(96 << 30, proving_memory_estimate(21));
        assert_eq!(192 << 30, proving_memory_estimate(22));
        assert_eq!(u64::MAX, proving_memory_estimate(64));
        for log2_padded_height in 10..=30 {
            let memory = proving_memory_estimate(log2_padded_height);
            assert_eq!(
                Some(log2_padded_height),
                max_log2_padded_height_for_memory(memory)
            );
            assert_eq!(
                Some(log2_padded_height - 1),
                max_log2_padded_height_for_memory(memory - 1)
            );
        }
        assert_eq!(None, max_log2_padded_height_for_memory(0));
    }

    /// A v7 claim goes through the job queue like any other: executed by
    /// triton-vm v7 to check its complexity, proven by triton-vm v7, and
    /// checked by the legacy verifier before it is returned.
    #[apply(shared_tokio_runtime)]
    async fn v7_claims_are_proven_through_the_job_queue() {
        let program = triton_program!(read_io 1 push 2 mul write_io 1 halt);
        let claim = Claim::about_program(&program)
            .about_version(v7_claim_version())
            .with_input(vec![BFieldElement::new(21)])
            .with_output(vec![BFieldElement::new(42)]);
        let proof = prove_consensus_program(
            program,
            claim.clone(),
            NonDeterminism::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(Network::Main),
        )
        .await
        .unwrap();

        assert!(verify(&claim, &proof));
    }

    #[apply(shared_tokio_runtime)]
    async fn v7_claims_are_checked_before_proving() {
        let program = triton_program!({&triton_asm![nop; 300]} halt);
        let claim = Claim::about_program(&program).about_version(v7_claim_version());

        let mut options = TritonVmProofJobOptions::default_with_network(Network::Main);
        options.job_settings.max_log2_padded_height_for_proofs = Some(8);
        let too_complex = prove_consensus_program(
            program.clone(),
            claim.clone(),
            NonDeterminism::default(),
            TritonVmJobQueue::get_instance(),
            options,
        )
        .await;
        assert!(
            matches!(
                too_complex,
                Err(CreateProofError::ProverJobError(
                    ProverJobError::ProofComplexityLimitExceeded { .. }
                ))
            ),
            "{too_complex:?}"
        );

        let wrong_output = claim.with_output(vec![BFieldElement::new(1)]);
        let result = prove_consensus_program(
            program,
            wrong_output,
            NonDeterminism::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(Network::Main),
        )
        .await;
        assert!(
            matches!(
                result,
                Err(CreateProofError::ProverJobError(
                    ProverJobError::TritonVmProverFailed(VmProcessError::LegacyTritonVmFailed(
                        LegacyProvingError::Execution(_)
                    ))
                ))
            ),
            "{result:?}"
        );
    }
}
