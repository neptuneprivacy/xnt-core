use tasm_lib::data_type::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::protocol::consensus::transaction::validity::bridge_aggregated_announcement_validator::BridgeAggregatedAnnouncementValidator;
use crate::protocol::consensus::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

/// Generates the unified BAV `Claim` in TASM.
///
/// Public input = prev_state(5) + new_state(5) + exit_root(5) + txk_mast_hash(5) = 20 BFEs.
/// First 15 BFEs (prev_state, new_state, exit_root) read from divine tokens.
/// Last 5 BFEs (txk_mast_hash) read from the stack where SingleProof already
/// verified them, preventing prover substitution.
/// Claim output: empty.
#[derive(Debug, Copy, Clone)]
pub(crate) struct GenerateAggregatedClaim;

impl BasicSnippet for GenerateAggregatedClaim {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
            (DataType::Bfe, "garb0".to_string()),
            (DataType::Bfe, "garb1".to_string()),
            (DataType::VoidPointer, "proof_collection_pointer".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
            (DataType::Bfe, "garb0".to_string()),
            (DataType::Bfe, "garb1".to_string()),
            (DataType::VoidPointer, "proof_collection_pointer".to_owned()),
            (DataType::VoidPointer, "claim".to_owned()),
        ]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_generate_aggregated_claim".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        const INPUT_LENGTH: usize = 20; // prev_state(5) + new_state(5) + exit_root(5) + txk_mast_hash(5)
        const OUTPUT_LENGTH: usize = 0;

        let entrypoint = self.entrypoint();

        let push_digest = |d: Digest| -> Vec<LabelledInstruction> {
            let [d0, d1, d2, d3, d4] = d.0;
            triton_asm! {
                push {d4}
                push {d3}
                push {d2}
                push {d1}
                push {d0}
            }
        };
        let push_program_hash = push_digest(BridgeAggregatedAnnouncementValidator.program().hash());

        let new_claim = library.import(Box::new(NewClaim));

        triton_asm!(
            // BEFORE: _ [txk_digest] garb0 garb1 *proof_collection
            // AFTER:  _ [txk_digest] garb0 garb1 *proof_collection *claim
            {entrypoint}:

                push {INPUT_LENGTH}
                push {OUTPUT_LENGTH}
                call {new_claim}
                // _ [txk_digest] garb0 garb1 *pc *claim *output *input *pd

                /* 1. Write program digest (compile-time constant) */
                {&push_program_hash}
                dup {Digest::LEN}
                write_mem {Digest::LEN}
                pop 2
                // _ [txk_digest] garb0 garb1 *pc *claim *output *input

                /* 2. Write input[0..5]: prev_state from divine */
                divine 5
                dup 5  // *input
                write_mem 5
                // _ ... *pc *claim *output *input (*input+5)

                /* 3. Write input[5..10]: new_state from divine */
                divine 5
                pick 5  // (*input+5)
                write_mem 5
                // _ ... *pc *claim *output *input (*input+10)

                /* 4. Write input[10..15]: exit_root from divine */
                divine 5
                pick 5  // (*input+10)
                write_mem 5
                // _ ... *pc *claim *output *input (*input+15)

                /* 5. Write input[15..20]: txk_mast_hash from STACK (not divine).
                 * txk_digest sits at st7..st11 at this point. Each dup 11
                 * picks the next element as earlier dups shift them deeper.
                 * This binds the BAAV claim to the kernel digest already
                 * verified by SingleProof, preventing prover substitution. */
                dup 11 dup 11 dup 11 dup 11 dup 11
                // _ ... txk_d0 txk_d1 txk_d2 txk_d3 txk_d4
                pick 5  // (*input+15)
                write_mem 5
                // _ ... *pc *claim *output *input (*input+20)

                /* Clean up */
                pop 2
                // _ [txk_digest] garb0 garb1 *pc *claim *output

                pop 1
                // _ [txk_digest] garb0 garb1 *pc *claim

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::procedure::Procedure;
    use tasm_lib::traits::procedure::ProcedureInitialState;
    use tasm_lib::traits::procedure::ShadowedProcedure;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;

    use super::*;
    use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::LeviathanProofCollection;

    /// The snippet builds the claim `LeviathanProofCollection::bridge_aggregated_proof_claim` builds, from
    /// the divined states and exit root, laid out as `SingleProofV2Witness::nondeterminism`
    /// lays them out, and the kernel digest on the stack.
    #[test]
    fn generate_aggregated_claim_matches_rust_claim() {
        ShadowedProcedure::new(GenerateAggregatedClaim).test();
    }

    fn divined_digest(tokens: &[BFieldElement]) -> Digest {
        let mut values: [BFieldElement; Digest::LEN] = tokens.try_into().unwrap();
        values.reverse();
        Digest::new(values)
    }

    impl Procedure for GenerateAggregatedClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            nondeterminism: &NonDeterminism,
            _public_input: &[BFieldElement],
            _sponge: &mut Option<Tip5>,
        ) -> Result<Vec<BFieldElement>, RustShadowError> {
            let pc_pointer = stack.pop().unwrap();
            let garb1 = stack.pop().unwrap();
            let garb0 = stack.pop().unwrap();
            let txk_digest = Digest::new([
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
            ]);

            let tokens = &nondeterminism.individual_tokens;
            let prev_state = divined_digest(&tokens[0..5]);
            let mut pc = LeviathanProofCollection::invalid();
            pc.kernel_mast_hash = txk_digest;
            pc.bridge_new_state_commitment = Some(divined_digest(&tokens[5..10]));
            pc.bridge_exit_root = Some(divined_digest(&tokens[10..15]));
            let claim = pc
                .bridge_aggregated_proof_claim(
                    Some(prev_state),
                    tasm_lib::triton_vm::proof::CURRENT_VERSION,
                )
                .unwrap();

            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            encode_to_memory(memory, claim_pointer, &claim);

            for value in txk_digest.values().into_iter().rev() {
                stack.push(value);
            }
            stack.push(garb0);
            stack.push(garb1);
            stack.push(pc_pointer);
            stack.push(claim_pointer);

            Ok(vec![])
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> ProcedureInitialState {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let txk_digest: Digest = rng.random();
            let mut tokens = vec![];
            for _ in 0..3 {
                let digest: Digest = rng.random();
                tokens.extend(digest.values().iter().rev());
            }

            let stack = [
                self.init_stack_for_isolated_run(),
                txk_digest.values().into_iter().rev().collect(),
                vec![rng.random(), rng.random(), bfe!(rng.next_u32() >> 1)],
            ]
            .concat();
            ProcedureInitialState {
                stack,
                nondeterminism: NonDeterminism::new(tokens),
                ..Default::default()
            }
        }
    }
}
