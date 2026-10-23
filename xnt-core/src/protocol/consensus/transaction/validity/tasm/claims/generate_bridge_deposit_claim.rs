use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::protocol::consensus::transaction::validity::bridge_deposit_announcement_validator::BridgeDepositAnnouncementValidator;
use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::LeviathanProofCollection;
use crate::protocol::consensus::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

/// Generates a `BridgeDepositAnnouncementValidator` `Claim` from a `LeviathanProofCollection` object.
///
/// BAV claim has input = [txk_mast_hash_reversed, salted_outputs_hash_reversed] (10 BFEs)
/// and no output.
#[derive(Debug, Copy, Clone)]
pub(crate) struct GenerateBridgeDepositClaim;

impl BasicSnippet for GenerateBridgeDepositClaim {
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
        "tasm_neptune_transaction_proof_collection_store_bav_claim".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        const INPUT_LENGTH: usize = 2 * Digest::LEN; // txk_mast_hash + salted_outputs_hash
        const OUTPUT_LENGTH: usize = 0;

        let entrypoint = self.entrypoint();

        let push_digest = |d: Digest| {
            let [d0, d1, d2, d3, d4] = d.values();
            triton_asm! {
                push {d4}
                push {d3}
                push {d2}
                push {d1}
                push {d0}
            }
        };
        let push_bav_program_hash =
            push_digest(BridgeDepositAnnouncementValidator.program().hash());

        let new_claim = library.import(Box::new(NewClaim));
        let proof_collection_field_salted_outputs_hash =
            field!(LeviathanProofCollection::salted_outputs_hash);

        triton_asm!(
            // BEFORE: _ [txk_digest] garb0 garb1 *proof_collection
            // AFTER:  _ [txk_digest] garb0 garb1 *proof_collection *claim
            {entrypoint}:

                push {INPUT_LENGTH}
                push {OUTPUT_LENGTH}
                call {new_claim}
                // _ [txk_digest] garb0 garb1 *proof_collection *claim *output *input *program_digest

                /* put the program digest on stack, then write to memory */
                {&push_bav_program_hash}
                dup {Digest::LEN}
                write_mem {Digest::LEN}
                pop 2
                // _ [txk_digest] garb0 garb1 *proof_collection *claim *output *input

                /* write input part 1: txk_digest (reversed, from stack) */
                dup 6
                dup 8
                dup 10
                dup 12
                dup 14
                dup 5
                write_mem {Digest::LEN}
                // _ [txk_digest] garb0 garb1 *proof_collection *claim *output *input (*input+5)

                /* write input part 2: salted_outputs_hash (reversed, from proof_collection) */
                dup 4
                {&proof_collection_field_salted_outputs_hash}
                // _ ... *proof_collection *claim *output *input (*input+5) *soh

                addi {Digest::LEN - 1}
                read_mem {Digest::LEN}
                pop 1
                // _ ... *input (*input+5) soh[0] soh[1] soh[2] soh[3] soh[4]

                swap 4
                swap 1
                swap 3
                swap 1
                // _ ... *input (*input+5) soh[4] soh[3] soh[2] soh[1] soh[0]

                dup 5
                write_mem {Digest::LEN}
                // _ ... *proof_collection *claim *output *input (*input+5) (*input+10)

                pop 3
                // _ [txk_digest] garb0 garb1 *proof_collection *claim *output

                pop 1
                // _ [txk_digest] garb0 garb1 *proof_collection *claim

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;

    use super::*;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::LeviathanProofCollection;

    #[test]
    fn unit_test() {
        ShadowedFunction::new(GenerateBridgeDepositClaim).test();
    }

    impl Function for GenerateBridgeDepositClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) -> Result<(), RustShadowError> {
            let proof_collection_pointer = stack.pop().unwrap();
            let garb1 = stack.pop().unwrap();
            let garb0 = stack.pop().unwrap();
            let txk_digest = Digest::new([
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
            ]);

            let proof_collection: LeviathanProofCollection =
                *LeviathanProofCollection::decode_from_memory(memory, proof_collection_pointer)
                    .unwrap();
            assert_eq!(
                txk_digest, proof_collection.kernel_mast_hash,
                "Inconsistent initial state detected"
            );

            let claim = proof_collection
                .bridge_deposit_announcement_validator_claim(triton_vm::proof::CURRENT_VERSION);
            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            encode_to_memory(memory, claim_pointer, &claim);

            stack.push(txk_digest.values()[4]);
            stack.push(txk_digest.values()[3]);
            stack.push(txk_digest.values()[2]);
            stack.push(txk_digest.values()[1]);
            stack.push(txk_digest.values()[0]);
            stack.push(garb0);
            stack.push(garb1);
            stack.push(proof_collection_pointer);
            stack.push(claim_pointer);

            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut test_runner = TestRunner::deterministic();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            let proof_collection = LeviathanProofCollection::produce_mock(&primitive_witness, true);

            let pw_pointer = rng.next_u32() >> 1;
            let pw_pointer = bfe!(pw_pointer);

            let mut memory = HashMap::default();
            encode_to_memory(&mut memory, pw_pointer, &proof_collection);

            let transaction_kernel_digest = proof_collection.kernel_mast_hash;

            let txk_digest_on_stack = transaction_kernel_digest
                .values()
                .into_iter()
                .rev()
                .collect_vec();
            FunctionInitialState {
                stack: [
                    self.init_stack_for_isolated_run(),
                    txk_digest_on_stack,
                    vec![rng.random(), rng.random(), pw_pointer],
                ]
                .concat(),
                memory,
            }
        }
    }
}
