use std::sync::OnceLock;

use itertools::Itertools;
use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::hash_from_stack::HashFromStack;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::isa::triton_instr;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tracing::debug;

use super::block_proof_witness::BlockProofWitness;
use crate::application::config::network::Network;
use crate::protocol::consensus::block::block_body::BlockBody;
use crate::protocol::consensus::block::block_body::BlockBodyField;
use crate::protocol::consensus::block::BlockAppendix;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::verifier::verify;

/// Verifies that all claims listed in the appendix are true.
///
/// The witness for this program is [`BlockProofWitness`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockProgram;

impl BlockProgram {
    const ILLEGAL_FEE: i128 = 1_000_210;
    const PROOF_SIZE_INDICATOR_TOO_BIG: i128 = 1_000_211;

    pub(crate) fn claim(
        block_body: &BlockBody,
        appendix: &BlockAppendix,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        Claim::new(Self::program_digest_for(consensus_rule_set))
            .about_version(consensus_rule_set.triton_proof_version().claim_version())
            .with_input(block_body.mast_hash().reversed().values().to_vec())
            .with_output(appendix.claims_as_output())
    }

    /// Era-correct BlockProgram program digest. Pre-upgrade digests are COMPUTED
    /// from the historical source trees (`~/xnt-core-v0|v1|v2`) and hardcoded,
    /// because the v3 tasm-lib builds a different BlockProgram; UpgradeVM
    /// recomputes from the linked program.
    pub(crate) fn program_digest_for(consensus_rule_set: ConsensusRuleSet) -> Digest {
        const BLOCK_PROGRAM_REBOOT_DIGEST: &str = // v0 tree (Reboot/HardforkAlpha)
            "2a3126ef86970a4a8df02711c2fbb4e5c9e025e257e0d169aab38114737a4cb9c84f9985b679c55a";
        const BLOCK_PROGRAM_XNT_DIGEST: &str = // v1/v2 tree (Xnt, TimelockExtension)
            "72d46afed8a1bf162814a432cf1ebe0f16a1cdb84bd339badc6fbd499172c3474c285dd0d5ba4e0c";
        const BLOCK_PROGRAM_UPGRADE_VM_DIGEST: &str = // v3 tree (UpgradeVM)
            "a7de94e8df6bba118dd6561d0e2ed391915e52b090330d6213cfb7160883e57b303a2481f11b85ab";
        const BLOCK_PROGRAM_UPGRADE_VM_V4_DIGEST: &str = // v4 tree (UpgradeVMv4), now pre-v5
            "1a4df646ce2b7d671d8b370870d91e2f0e0421b6cccb29e047109b823657ef31e86258586a699ad9";

        match consensus_rule_set {
            ConsensusRuleSet::Reboot | ConsensusRuleSet::HardforkAlpha => {
                Digest::try_from_hex(BLOCK_PROGRAM_REBOOT_DIGEST).unwrap()
            }
            ConsensusRuleSet::Xnt | ConsensusRuleSet::TimelockExtension => {
                Digest::try_from_hex(BLOCK_PROGRAM_XNT_DIGEST).unwrap()
            }
            ConsensusRuleSet::UpgradeVM => {
                Digest::try_from_hex(BLOCK_PROGRAM_UPGRADE_VM_DIGEST).unwrap()
            }
            ConsensusRuleSet::UpgradeVMv4 => {
                Digest::try_from_hex(BLOCK_PROGRAM_UPGRADE_VM_V4_DIGEST).unwrap()
            }
            // Current (v5) bytecode — recompute from the linked program.
            ConsensusRuleSet::UpgradeVMv5 => Self.hash(),
        }
    }

    pub(crate) async fn verify(
        block_body: &BlockBody,
        appendix: &BlockAppendix,
        proof: &Proof,
        network: Network,
        consensus_rule_set: ConsensusRuleSet,
    ) -> bool {
        let claim = Self::claim(block_body, appendix, consensus_rule_set);
        let proof_clone = proof.clone();

        debug!("** Calling triton_vm::verify to verify block proof ...");
        let verdict = verify(claim, proof_clone, network).await;
        debug!("** Call to triton_vm::verify to verify block proof completed; verdict: {verdict}.");

        verdict
    }
}

impl ConsensusProgram for BlockProgram {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        // restrict proof size to avoid jumping backwards or to arbitrary
        // place in memory.
        const MAX_PROOF_SIZE: u64 = 4_000_000;

        let mut library = Library::new();

        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let block_body_field = field!(BlockProofWitness::block_body);
        let body_field_kernel = field!(BlockBody::transaction_kernel);
        let kernel_field_fee = field!(TransactionKernel::fee);
        let block_witness_field_claims = field!(BlockProofWitness::claims);
        let block_witness_field_proofs = field!(BlockProofWitness::proofs);

        let merkle_verify = library.import(Box::new(MerkleVerify));
        let coin_size = NativeCurrencyAmount::static_length().unwrap();
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let hash_from_stack_digest = library.import(Box::new(HashFromStack::new(DataType::Digest)));
        let hash_from_stack_amount = library.import(Box::new(HashFromStack::new(DataType::I128)));
        let verify_fee_legality = triton_asm!(
            // _ *w [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            push {TransactionKernel::MAST_HEIGHT}
            // _ *w [txkmh] [txkmh] txkm_height

            push {TransactionKernelField::Fee as u32}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index

            dup 12 {&block_body_field} {&body_field_kernel} {&kernel_field_fee}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee

            addi {coin_size - 1} read_mem {coin_size} pop 1
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee]

            /* Using u128-lt here, guarantees fee is both positive and less
               than max allowed amount.
            */
            dup 3
            dup 3
            dup 3
            dup 3
            {&push_max_amount}
            call {u128_lt}
            push 0 eq
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee] (max >= fee)

            assert error_id {Self::ILLEGAL_FEE}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee]

            call {hash_from_stack_amount}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee_hash]

            call {merkle_verify}
            // _ *w [txkmh]
        );

        let hash_of_one = Tip5::hash(&1);
        let push_hash_of_one = hash_of_one
            .values()
            .into_iter()
            .rev()
            .map(|b| triton_instr!(push b))
            .collect_vec();
        let verify_set_merge_bit = triton_asm!(
            // _ [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            push {TransactionKernel::MAST_HEIGHT}
            // _ [txkmh] [txkmh] txkm_height

            push {TransactionKernelField::MergeBit as u32}
            // _ [txkmh] [txkmh] txkm_height leaf_index

            {&push_hash_of_one}
            // _ [txkmh] [txkmh] txkm_height fee_leaf_index [merge_bit_hash (true)]

            call {merkle_verify}
            // _ [txkmh]
        );

        let authenticate_txkmh = triton_asm!(
            // _ [bbd] *w [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            call {hash_from_stack_digest}
            // _ [bbd] *w [txkmh] [txkmh_hash]

            dup 15
            dup 15
            dup 15
            dup 15
            dup 15
            // _ [bbd] *w [txkmh] [txkmh_hash] [bbd]

            push {BlockBody::MAST_HEIGHT}
            push {BlockBodyField::TransactionKernel as u32}
            // _ [bbd] *w [txkmh] [txkmh_hash] [bbd] block_body_mast_height txk_leaf_index

            pick 11
            pick 11
            pick 11
            pick 11
            pick 11
            // _ [bbd] *w [txkmh] [bbd] block_body_mast_height txk_leaf_index [txkmh_hash]

            call {merkle_verify}
            // _ [bbd] *w [txkmh]
        );

        let hash_varlen = library.import(Box::new(HashVarlen));

        let verify_all_claims_loop = "verify_all_claims_loop".to_string();

        let verify_all_claims_function = triton_asm! {
            // INVARIANT: _ *claim[i]_si *proof[i]_si N i
            {verify_all_claims_loop}:

                // terminate if done
                dup 1 dup 1 eq skiz return

                pick 3
                // _ *proof[i]_si N i *claim[i]_si


                /* print claim hash */
                // _ *proof[i]_si N i *claim[i]_si

                read_mem 1
                addi 2
                // _ *proof[i]_si N i claim[i]_si *claim[i]

                dup 0
                dup 2
                call {hash_varlen}
                // _ *proof[i]_si N i claim[i]_si *claim[i] [hash(claim)]

                write_io {Digest::LEN}
                // _ *proof[i]_si N i claim[i]_si *claim[i]


                /* verify claim */
                dup 0
                dup 5
                addi 1
                // _ *proof[i]_si N i claim[i]_si *claim[i] *claim[i] *proof[i]

                call {stark_verify}
                // _ *proof[i]_si N i claim[i]_si *claim[i]


                /* Update pointers and counter */
                add
                // _ *proof[i]_si N i *claim[i+1]_si

                swap 3
                read_mem 1
                // _ *claim[i+1]_si N i proof[i]_si (*proof[i] - 2)

                push {MAX_PROOF_SIZE}
                dup 2
                lt
                assert error_id {Self::PROOF_SIZE_INDICATOR_TOO_BIG}

                addi 2
                add
                // _ *claim[i+1]_si N i *proof[i+1]_si

                place 2
                // _ *claim[i+1]_si *proof[i+1]_si N i

                addi 1
                // _ *claim[i+1]_si *proof[i+1]_si N (i + 1)

                recurse
        };

        let code = triton_asm! {
            // _

            read_io 5
            // _ [block_body_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint block_witness_ptr = stack[0]
            // _ [bbd] *w

            divine {Digest::LEN}
            // _ [bbd] *w [txkmh]

            {&authenticate_txkmh}
            // _ [bbd] *w [txkmh]

            {&verify_fee_legality}
            // _ [bbd] *w [txkmh]

            {&verify_set_merge_bit}
            // _ [bbd] *w [txkmh]

            pop {Digest::LEN}
            // _ [bbd] *w

            /* verify appendix claims */
            dup 0 {&block_witness_field_claims}
            hint claims = stack[0]
            swap 1 {&block_witness_field_proofs}
            hint proofs = stack[1]
            // _ [bbd] *claims *proofs

            dup 1 read_mem 1 pop 1
            // _ [bbd] *claims *proofs N

            pick 2 addi 1
            pick 2 addi 1
            pick 2
            // _ [bbd] *claim[0] *proof[0] N

            push 0
            // _ [bbd] *claim[0] *proof[0] N 0

            call {verify_all_claims_loop}
            // _ [bbd] *claim[0] *proof[0] N N

            pop 4
            pop 5
            // _

            halt

            {&verify_all_claims_function}
            {&library.all_imports()}
        };

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::triton_vm;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::prelude::Program;
    use tasm_lib::triton_vm::vm::NonDeterminism;
    use tasm_lib::triton_vm::vm::PublicInput;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::application::loops::mine_loop::create_block_transaction_from;
    use crate::application::loops::mine_loop::TxMergeOrigin;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::block::block_validation_error::BlockValidationError;
    use crate::protocol::consensus::block::validity::block_primitive_witness::tests::deterministic_block_primitive_witness;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::TritonVmProofJobOptions;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::Transaction;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::protocol::proof_abstractions::tasm::builtins::verify_stark;
    use crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::protocol::proof_abstractions::SecretWitness;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::transaction::tx_proving_capability::TxProvingCapability;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;
    use crate::GlobalStateLock;

    impl ConsensusProgramSpecification for BlockProgram {
        fn source(&self) {
            let block_body_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let start_address: BFieldElement =
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
            let block_witness: BlockProofWitness = tasm::decode_from_memory(start_address);
            let claims: Vec<Claim> = block_witness.claims;
            let proofs: Vec<Proof> = block_witness.proofs;

            let block_body = &block_witness.block_body;

            let txk_mast_hash: Digest = tasm::tasmlib_io_read_secin___digest();
            let txk_mast_hash_as_leaf = Tip5::hash(&txk_mast_hash);
            tasm::tasmlib_hashing_merkle_verify(
                block_body_digest,
                BlockBodyField::TransactionKernel as u32,
                txk_mast_hash_as_leaf,
                BlockBody::MAST_HEIGHT as u32,
            );

            // Verify fee is legal
            let fee = &block_body.transaction_kernel.fee;
            let fee_hash = Tip5::hash(fee);
            tasm::tasmlib_hashing_merkle_verify(
                txk_mast_hash,
                TransactionKernelField::Fee as u32,
                fee_hash,
                TransactionKernel::MAST_HEIGHT as u32,
            );

            assert!(!fee.is_negative());
            assert!(*fee <= NativeCurrencyAmount::max());

            // Verify that merge bit is set
            let merge_bit_hash = Tip5::hash(&1);
            tasm::tasmlib_hashing_merkle_verify(
                txk_mast_hash,
                TransactionKernelField::MergeBit as u32,
                merge_bit_hash,
                TransactionKernel::MAST_HEIGHT as u32,
            );

            let mut i = 0;
            while i < claims.len() {
                tasm::tasmlib_io_write_to_stdout___digest(Tip5::hash(&claims[i]));
                verify_stark(Stark::default(), &claims[i], &proofs[i]);

                i += 1;
            }
        }
    }

    #[traced_test]
    #[test]
    fn block_program_halts_gracefully() {
        let block_primitive_witness = deterministic_block_primitive_witness();
        let block_body_mast_hash_as_input = PublicInput::new(
            block_primitive_witness
                .body()
                .mast_hash()
                .reversed()
                .values()
                .to_vec(),
        );

        let block_proof_witness = BlockProofWitness::produce(block_primitive_witness);

        let block_program_nondeterminism = block_proof_witness.nondeterminism();
        let rust_output = BlockProgram
            .run_rust(
                &block_body_mast_hash_as_input,
                block_program_nondeterminism.clone(),
            )
            .unwrap();
        let tasm_output = match BlockProgram
            .run_tasm(&block_body_mast_hash_as_input, block_program_nondeterminism)
        {
            Ok(std_out) => std_out,
            Err(err) => panic!("{err:?}"),
        };

        assert_eq!(rust_output, tasm_output);

        let expected_output = block_proof_witness
            .claims()
            .iter()
            .flat_map(|appendix_claim| Tip5::hash(appendix_claim).values().to_vec())
            .collect_vec();
        assert_eq!(
            expected_output, tasm_output,
            "tasm output must equal rust output"
        );
    }

    // TODO: Add test that verifies that double spends *within* one block is
    //       disallowed.

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn disallow_double_spends_across_blocks() {
        async fn mine_tx(state: &GlobalStateLock, tx: Transaction, timestamp: Timestamp) -> Block {
            let predecessor = state.lock_guard().await.chain.light_state().to_owned();
            let (block_tx, _) = create_block_transaction_from(
                &predecessor,
                state.clone(),
                timestamp,
                TritonVmProofJobOptions::default(),
                TxMergeOrigin::ExplicitList(vec![tx]),
            )
            .await
            .unwrap();

            Block::compose(
                &predecessor,
                block_tx,
                timestamp,
                TritonVmJobQueue::get_instance(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap()
        }

        let network = Network::Main;
        let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);
        let alice_wallet = WalletEntropy::devnet_wallet();
        let mut alice =
            mock_genesis_global_state(3, WalletEntropy::devnet_wallet(), cli_args::Args::default())
                .await;

        let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let fee = NativeCurrencyAmount::coins(1);
        let tx_output = TxOutput::offchain_native_currency(
            NativeCurrencyAmount::coins(1),
            rng.random(),
            alice_key.to_address().into(),
            false,
        );

        let genesis_block = Block::genesis(network);
        let now = genesis_block.header().timestamp + Timestamp::months(12);
        let config = TxCreationConfig::default()
            .recover_change_off_chain(alice_key.into())
            .with_prover_capability(TxProvingCapability::SingleProof);

        let consensus_rule_set =
            ConsensusRuleSet::infer_from(network, genesis_block.header().height.next());
        let tx: Transaction = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(vec![tx_output].into(), fee, now, config, consensus_rule_set)
            .await
            .unwrap()
            .transaction
            .into();
        let block1 = mine_tx(&alice, tx.clone(), now).await;
        alice.set_new_tip(block1.clone()).await.unwrap();

        // Update transaction, stick it into block 2, and verify that block 2
        // is invalid.
        let later = now + Timestamp::months(1);
        let tx = Transaction::new_with_updated_mutator_set_records_given_proof(
            tx.kernel,
            &genesis_block.mutator_set_accumulator_after().unwrap(),
            &block1.mutator_set_update().unwrap(),
            tx.proof.into_single_proof(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            Some(later),
            consensus_rule_set,
        )
        .await
        .unwrap();

        let block2 = mine_tx(&alice, tx, later).await;
        assert_eq!(
            BlockValidationError::RemovalRecordsValidity,
            block2.validate(&block1, later, network).await.unwrap_err(),
            "Block doing a double-spend must be invalid."
        );
    }

    #[test]
    fn can_verify_block_program_with_two_claims() {
        let block_primitive_witness = deterministic_block_primitive_witness();
        let block_body_mast_hash_as_input = PublicInput::new(
            block_primitive_witness
                .body()
                .mast_hash()
                .reversed()
                .values()
                .to_vec(),
        );

        let halt_program = Program::new(&triton_asm!(halt));
        let halt_claim = Claim::new(halt_program.hash());
        let halt_nondeterminism = NonDeterminism::default();
        let halt_proof = triton_vm::prove(
            Stark::default(),
            &halt_claim,
            halt_program,
            halt_nondeterminism,
        )
        .unwrap();

        let block_proof_witness = BlockProofWitness::produce(block_primitive_witness)
            .with_claim_test(halt_claim, halt_proof.into());

        let block_program_nondeterminism = block_proof_witness.nondeterminism();
        let rust_output = BlockProgram
            .run_rust(
                &block_body_mast_hash_as_input,
                block_program_nondeterminism.clone(),
            )
            .unwrap();
        let tasm_output = match BlockProgram
            .run_tasm(&block_body_mast_hash_as_input, block_program_nondeterminism)
        {
            Ok(std_out) => std_out,
            Err(err) => panic!("{err:?}"),
        };

        assert_eq!(rust_output, tasm_output);

        let expected_output = block_proof_witness
            .claims()
            .iter()
            .flat_map(|appendix_claim| Tip5::hash(appendix_claim).values().to_vec())
            .collect_vec();
        assert_eq!(
            expected_output, tasm_output,
            "tasm output must equal rust output"
        );
    }

    /// Real-data proof of the UpgradeVM premise: feed REAL mainnet block
    /// proofs (produced by triton-vm v2.0.0, i.e. proof version 1) into the v3
    /// verifier with the hardcoded per-era BlockProgram digests. Passing ⟹ the
    /// v3 verifier accepts v2-era proofs, so Xnt/TimelockExtension history is
    /// trustlessly re-verifiable under a single tasm-lib. Fixtures were pulled
    /// from a mainnet node via JSON-RPC `archival_getBlock` (test_data/
    /// hf_upgrade_vm_blocks); the test skips gracefully if they're absent.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn pre_v5_block_proofs_are_checkpointed_under_v5() {
        use crate::application::json_rpc::core::model::block::appendix::RpcBlockAppendix;
        use crate::application::json_rpc::core::model::block::body::RpcBlockBody;
        use crate::application::json_rpc::core::model::block::RpcBlockProof;
        use crate::protocol::consensus::block::block_body::BlockBody;
        use crate::protocol::consensus::block::BlockProof;

        async fn verify_fixture(file: &str, crs: ConsensusRuleSet) -> Option<bool> {
            let path = format!(
                "{}/test_data/hf_upgrade_vm_blocks/{file}",
                env!("CARGO_MANIFEST_DIR")
            );
            if !std::path::Path::new(&path).exists() {
                eprintln!("fixture {path} absent — skipping");
                return None;
            }
            let json = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            let block = &v["result"]["block"];
            // BlockProgram::verify needs only body + appendix + proof; the header
            // (RpcBlockPow) is skipped — it doesn't round-trip and isn't used here.
            let body: BlockBody = serde_json::from_value::<RpcBlockBody>(block["kernel"]["body"].clone())
                .unwrap()
                .into();
            let appendix: BlockAppendix =
                serde_json::from_value::<RpcBlockAppendix>(block["kernel"]["appendix"].clone())
                    .unwrap()
                    .into();
            let rpc_proof: RpcBlockProof = serde_json::from_value(block["proof"].clone()).unwrap();
            let BlockProof::SingleProof(proof) = BlockProof::from(rpc_proof) else {
                panic!("expected SingleProof in {file}");
            };
            Some(BlockProgram::verify(&body, &appendix, &proof, Network::Main, crs).await)
        }

        // Under the v5 verifier every PRE-v5 era is checkpointed (trusted) rather
        // than re-verified: the binary links triton-vm v5, whose changed ISA
        // cannot check the superseded proofs (including v4's). Lock in the boundary.
        for crs in [
            ConsensusRuleSet::Reboot,
            ConsensusRuleSet::HardforkAlpha,
            ConsensusRuleSet::Xnt,
            ConsensusRuleSet::TimelockExtension,
            ConsensusRuleSet::UpgradeVM,
            ConsensusRuleSet::UpgradeVMv4,
        ] {
            assert!(
                crs.proofs_are_trusted(),
                "{crs} is a superseded proof format and must be checkpointed under v5"
            );
        }
        assert!(
            !ConsensusRuleSet::UpgradeVMv5.proofs_are_trusted(),
            "UpgradeVMv5 (current proof format) must be re-verified, not trusted"
        );

        // Demonstrate WHY the checkpoint is necessary, not gratuitous: a REAL
        // pre-v4 mainnet block proof does NOT verify under the v4 verifier
        // (version-0/1 proof vs version-2 verifier). If a fixture is present, the
        // direct `BlockProgram::verify` must return false.
        for (file, crs) in [
            // The immediate predecessor era — a real UpgradeVM (v3) mainnet block.
            // Its proof is version 1; the v4 verifier (version 2) cannot check it,
            // which is exactly why UpgradeVM is now checkpointed.
            ("block_upgrade_vm_56000.json", ConsensusRuleSet::UpgradeVM),
            (
                "block_timelock_54000.json",
                ConsensusRuleSet::TimelockExtension,
            ),
            ("block_xnt_30000.json", ConsensusRuleSet::Xnt),
            ("block_reboot_5000.json", ConsensusRuleSet::Reboot),
        ] {
            if let Some(ok) = verify_fixture(file, crs).await {
                assert!(
                    !ok,
                    "{file}: a pre-v4 proof must NOT verify under the v4 verifier — \
                     which is exactly why {crs} is checkpointed"
                );
            }
        }
    }

    /// Tripwire for the hardcoded pre-upgrade BlockProgram digests. Pins each
    /// pre-v4 rule set to its computed era digest (from `~/xnt-core-v0|v1|v2|v3`)
    /// so a future edit can't silently change a consensus value. UpgradeVMv4
    /// recomputes from the linked v4 program.
    #[test]
    fn pre_upgrade_block_program_digests_are_pinned() {
        use ConsensusRuleSet::*;
        let cases = [
            (
                Reboot,
                "2a3126ef86970a4a8df02711c2fbb4e5c9e025e257e0d169aab38114737a4cb9c84f9985b679c55a",
            ),
            (
                HardforkAlpha,
                "2a3126ef86970a4a8df02711c2fbb4e5c9e025e257e0d169aab38114737a4cb9c84f9985b679c55a",
            ),
            (
                Xnt,
                "72d46afed8a1bf162814a432cf1ebe0f16a1cdb84bd339badc6fbd499172c3474c285dd0d5ba4e0c",
            ),
            (
                TimelockExtension,
                "72d46afed8a1bf162814a432cf1ebe0f16a1cdb84bd339badc6fbd499172c3474c285dd0d5ba4e0c",
            ),
            // UpgradeVM (v3) is now a pre-v5 era with a hardcoded digest.
            (
                UpgradeVM,
                "a7de94e8df6bba118dd6561d0e2ed391915e52b090330d6213cfb7160883e57b303a2481f11b85ab",
            ),
            // UpgradeVMv4 (v4) is now a pre-v5 era with a hardcoded digest.
            (
                UpgradeVMv4,
                "1a4df646ce2b7d671d8b370870d91e2f0e0421b6cccb29e047109b823657ef31e86258586a699ad9",
            ),
        ];
        for (crs, hex) in cases {
            assert_eq!(
                BlockProgram::program_digest_for(crs),
                Digest::try_from_hex(hex).unwrap(),
                "{crs} BlockProgram digest drifted"
            );
        }
        // UpgradeVMv5 (current) recomputes from the linked (v5) program.
        assert_eq!(
            BlockProgram::program_digest_for(UpgradeVMv5),
            BlockProgram.hash()
        );
    }

    test_program_snapshot!(
        BlockProgram,
        // snapshot taken from master on 2025-04-11 e2a712efc34f78c6a28801544418e7051127d284
        // Program hash updated for UpgradeVMv5 (triton-vm v5); the UpgradeVMv4 (v4)
        // digest (1a4df646…) lives on as a hardcoded prior-era digest in
        // program_digest_for().
        "e14d426bd76aad647703efb21c880f678b9a2eabe8dcfba7d6fc97b4b6b0f402c38d0c1be5f4942f"
    );
}
