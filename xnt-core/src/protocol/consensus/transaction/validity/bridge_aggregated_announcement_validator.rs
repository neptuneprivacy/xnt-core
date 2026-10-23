//! Bridge aggregated announcement validator — unified exit root + TX validity for bridge unlocks.
//!
//! What it proves:
//! - Phase 0: bind the tx's settlement announcement (authenticated Announcements leaf) to the claim
//! - Phase 1: stark_verify the converted proof (Leviathan verifier execution) for the announced faucet
//! - Phase 2: fold the announced exit records into the exit chain from the previous epoch's
//!   exit_acc, assert the result == exit_root
//! - Phase 3: RRI - input UTXOs exist in mutator set, all locked by bridge_lock_script;
//!   kernel fee == 0 and coinbase == None (inputs are pool-only, so any fee would be pool funds)
//! - Phase 4: K2O — output commitments match txk mast hash
//! - Phase 5: output[i] matches burn[i] (rd + lsh + amount + sr), outputs = exits + announced change
//! - Phase 6: sum(inputs) == sum(outputs), no public output
//!
//! Public input:  prev_state(5) + new_state(5) + exit_root(5) + txk_mast_hash(5) = 20
//! Public output: (none)

use std::collections::HashMap;
use std::sync::OnceLock;

use num_traits::Zero;
use tasm_lib::data_type::DataType;
use tasm_lib::data_type::Literal;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::bag_peaks::BagPeaks;
use tasm_lib::mmr::verify_from_secret_in_leaf_index_on_stack::MmrVerifyFromSecretInLeafIndexOnStack;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::TasmObject;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::verifier::stark_verify::StarkVerify;

use crate::protocol::consensus::bridge::aggregated_announcement::AggregatedAnnouncementData;
use crate::protocol::consensus::bridge::aggregated_announcement::AGGREGATED_ANNOUNCEMENT_TAG;
use crate::protocol::consensus::bridge::aggregated_announcement::BURN_RECORD_LEN;
use crate::protocol::consensus::bridge::aggregated_announcement::MAX_BURNS_PER_SETTLEMENT;
use crate::protocol::consensus::bridge::aggregated_announcement::SIGNATURE_FELTS;
use crate::protocol::consensus::bridge::aggregated_announcement::STATE_PREIMAGE_LEN;
use crate::protocol::consensus::bridge::faucet_registration::FaucetId;
use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::protocol::consensus::transaction::validity::tasm::compute_absolute_indices::ComputeAbsoluteIndices;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

// =========================================================================
// Each non-deterministically initialized region and the program-written work region get their
// own window, larger than any block, so none can run into another.
// =========================================================================
const RAM_WINDOW: u64 = 1 << 28;
const PROOF_ADDR: u64 = RAM_WINDOW;
const ANN_BASE: u64 = 2 * RAM_WINDOW;
const WORK_BASE: u64 = 3 * RAM_WINDOW;
const _: () =
    assert!((ConsensusRuleSet::LeviathanSettlement.max_block_size() as u64) <= RAM_WINDOW);
const _: () = assert!(WORK_BASE + RAM_WINDOW <= 1 << 32);
const ANN_PS_ADDR: u64 = WORK_BASE + 50;
const ANN_NS_ADDR: u64 = WORK_BASE + 60;
const ER_ADDR: u64 = WORK_BASE + 100;
/// The announced faucet id: suffix, prefix.
const FAUCET_ADDR: u64 = WORK_BASE + 110;
/// Exit chain fold buffer: acc(5) at FOLD_BUF, then the 16-felt record, hashed together per exit.
const FOLD_BUF: u64 = WORK_BASE + 300;
/// The previous epoch's 19-felt StatePreimage, copied from the announcement.
const PREIMG_BUF: u64 = WORK_BASE + 330;
/// Scratch for a freshly hashed digest, so it can be read back in the same orientation as a
/// memory-resident digest before comparison.
const SCRATCH_DIG: u64 = WORK_BASE + 360;
// ANN_BASE holds `[size, Vec<Announcement>::encode()]`, authenticated against the txk leaf.
/// From the bound settlement announcement: E, *first record, *prev_state_preimage.
const SETTLE_E: u64 = WORK_BASE + 370;
const SETTLE_BURNS: u64 = WORK_BASE + 371;
const SETTLE_PREIMG: u64 = WORK_BASE + 372;
/// The bound announcement's change flag, and where its change sender randomness is.
const SETTLE_FLAG: u64 = WORK_BASE + 373;
const SETTLE_CHANGE: u64 = WORK_BASE + 374;
const BURN_CTR: u64 = WORK_BASE + 413;
/// Number of exits in this settlement (E).
const TOTAL_BURNS: u64 = WORK_BASE + 420;
const TXKMH_ADDR: u64 = WORK_BASE + 500;
const BURN_DATA: u64 = WORK_BASE + 10000;
const SAVED_WITNESS: u64 = WORK_BASE + 200000;
const _: () =
    assert!(BURN_DATA + ((MAX_BURNS_PER_SETTLEMENT * BURN_ENTRY_LEN) as u64) < SAVED_WITNESS);
const SAVED_SOU: u64 = WORK_BASE + 200001;
const SAVED_UTXO_FIXED: u64 = WORK_BASE + 200002;
/// Change output sender_randomness (5 BFE), copied from the bound announcement.
const CHANGE_SR_ADDR: u64 = WORK_BASE + 200010;

/// Offset of serial in a burn record, and of sr in a BURN_DATA entry.
const SERIAL_OFFSET: u64 = 12;

/// Burn entry in BURN_DATA RAM for Phase 5: ri(1) + pd(5) + lsh(5) + amount(1) + sr(5) = 17.
pub const BURN_ENTRY_LEN: usize = 17;

/// 1 Leviathan unit = 4 * 10^24 nau.
pub(crate) const LEVIATHAN_UNIT_TO_NAU: u128 = 4_000_000_000_000_000_000_000_000;

/// Expected Leviathan verifier program hash - consensus constant.
const EXPECTED_VP_HASH: [u64; 5] = [
    4982559726726871479,
    7680494493063872949,
    6260185866852539530,
    5590275759074763308,
    2267990108065574738,
];

/// The fixed Leviathan verifier program's digest, pinned by BAAV.
pub fn expected_verifier_program_digest() -> Digest {
    Digest::new(EXPECTED_VP_HASH.map(BFieldElement::new))
}

/// The fixed verifier's claim input: `prev_state(5) || faucet_suffix || faucet_prefix`.
pub fn verifier_input(prev_state: Digest, faucet_id: FaucetId) -> Vec<BFieldElement> {
    [
        prev_state.values().as_slice(),
        &[faucet_id.suffix, faucet_id.prefix],
    ]
    .concat()
}

/// What only a settlement's prover holds: the fixed Leviathan verifier program (whose digest must be
/// [`expected_verifier_program_digest`]) and its input RAM, the converted Leviathan proof (both from
/// miden-triton).
#[derive(Debug, Clone)]
pub struct SettlementProverInput {
    pub verifier_program: Program,
    pub verifier_ram: HashMap<BFieldElement, BFieldElement>,
}

// =========================================================================
// Program
// =========================================================================

#[derive(Debug, Clone, Copy)]
pub struct BridgeAggregatedAnnouncementValidator;

fn bridge_lock_hash_cached() -> Digest {
    static HASH: OnceLock<Digest> = OnceLock::new();
    *HASH.get_or_init(|| bridge_lock_script().hash())
}

/// Memory-resident witness data (TasmObject loaded into ND memory).
#[derive(Clone, Debug, PartialEq, Eq, BFieldCodec, TasmObject)]
pub struct BridgeUnlockWitnessMemory {
    pub output_utxos: SaltedUtxos,
    pub sender_randomnesses: Vec<Digest>,
    pub receiver_digests: Vec<Digest>,
    pub input_utxos: SaltedUtxos,
    pub removal_records: Vec<RemovalRecord>,
    pub aocl: MmrAccumulator,
    pub swbfi: MmrAccumulator,
}

impl ConsensusProgram for BridgeAggregatedAnnouncementValidator {
    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();
        *HASH.get_or_init(|| self.program().hash())
    }

    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        const MAX_JUMP: usize = 2_000_000;
        const MUL_BURN_LO: u64 = WORK_BASE + 430;
        const MUL_BURN_HI: u64 = WORK_BASE + 431;
        const MUL_P1_HI: u64 = WORK_BASE + 432;
        const MUL_P3_HI: u64 = WORK_BASE + 433;
        const MUL_CARRY: u64 = WORK_BASE + 434;
        const MUL_RESULT: u64 = WORK_BASE + 440;

        let mut library = Library::new();

        // === Phase 1-2 imports ===
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let new_claim = library.import(Box::new(NewClaim));

        // === Phase 3-6 imports ===
        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let bag_peaks = library.import(Box::new(BagPeaks));
        let ms_commit = library.import(Box::new(tasm_lib::neptune::mutator_set::commit::Commit));
        let mmr_verify = library.import(Box::new(MmrVerifyFromSecretInLeafIndexOnStack));
        let compute_absolute_indices = library.import(Box::new(ComputeAbsoluteIndices));
        let hash_absolute_indices = library.import(Box::new(HashStaticSize {
            size: AbsoluteIndexSet::static_length().expect("static size"),
        }));
        let audit_witness = library.import(Box::new(VerifyNdSiIntegrity::<
            BridgeUnlockWitnessMemory,
        >::default()));

        // === Field accessors ===
        let field_input_utxos = field!(BridgeUnlockWitnessMemory::input_utxos);
        let field_removal_records = field!(BridgeUnlockWitnessMemory::removal_records);
        let field_with_size_removal_records =
            field_with_size!(BridgeUnlockWitnessMemory::removal_records);
        let field_aocl = field!(BridgeUnlockWitnessMemory::aocl);
        let field_swbfi = field!(BridgeUnlockWitnessMemory::swbfi);
        let field_peaks = field!(MmrAccumulator::peaks);
        let field_mmr_num_leafs = field!(MmrAccumulator::leaf_count);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_utxos_with_size = field_with_size!(SaltedUtxos::utxos);
        let field_with_size_input_utxos = field_with_size!(BridgeUnlockWitnessMemory::input_utxos);
        let field_indices = field!(RemovalRecord::absolute_indices);

        let field_output_utxos = field!(BridgeUnlockWitnessMemory::output_utxos);
        let field_sender_randomnesses = field!(BridgeUnlockWitnessMemory::sender_randomnesses);
        let field_receiver_digests = field!(BridgeUnlockWitnessMemory::receiver_digests);
        let _field_with_size_output_utxos =
            field_with_size!(BridgeUnlockWitnessMemory::output_utxos);
        let new_list = library.import(Box::new(tasm_lib::list::new::New));
        let get_digest = library.import(Box::new(tasm_lib::list::get::Get::new(DataType::Digest)));

        let coin_size: usize = crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount::static_length().unwrap();
        let compare_coin_amount = DataType::compare_elem_of_stack_size(coin_size);
        let u128_overflowing_add = library.import(Box::new(
            tasm_lib::arithmetic::u128::overflowing_add::OverflowingAdd,
        ));

        let u64_stack_size: u32 = DataType::U64.stack_size().try_into().unwrap();
        let compare_digests = DataType::Digest.compare();

        let aocl_leaf_index_alloc = library.kmalloc(u64_stack_size);
        let digest_size: u32 = DataType::Digest.stack_size().try_into().unwrap();
        let receiver_preimage_alloc = library.kmalloc(digest_size);
        let sender_randomness_alloc = library.kmalloc(digest_size);
        let utxo_hash_alloc = library.kmalloc(digest_size);
        let nc_hash_alloc = library.kmalloc(Digest::LEN as u32);
        let bridge_lock_hash_alloc = library.kmalloc(Digest::LEN as u32);
        let sum_input_alloc = library.kmalloc(4);
        let sum_output_alloc = library.kmalloc(4);

        let k2o_loop_label = "bup_k2o_loop";
        let native_currency_hash = NativeCurrency.hash();
        let blh = bridge_lock_hash_cached();
        let change_rd = Digest::default().hash();

        // Every UTXO BAAV reads at fixed offsets: [size][header][amount(4)][type hash(5)][lock(5)].
        let canonical_utxo =
            Utxo::new_native_currency(Digest::default(), NativeCurrencyAmount::zero()).encode();
        let header_len = canonical_utxo.len() - 4 - 2 * Digest::LEN;
        assert_eq!(
            header_len, 5,
            "BAAV's fixed UTXO offsets assume a 5-felt header"
        );
        let amount_offset = 1 + header_len as u64;
        let assert_canonical_header: Vec<LabelledInstruction> = canonical_utxo[..header_len]
            .iter()
            .enumerate()
            .flat_map(|(k, felt)| {
                triton_asm! {
                    dup 0 addi {1 + k as u64} read_mem 1 pop 1
                    push {felt.value()} eq assert error_id {9_000_021i128}
                }
            })
            .collect();
        let assert_amount_limbs_u32: Vec<LabelledInstruction> = (0..4)
            .flat_map(|k| {
                triton_asm! {
                    dup 0 addi {amount_offset + k} read_mem 1 pop 1
                    split pop 1 push 0 eq assert error_id {9_000_022i128}
                }
            })
            .collect();
        let push_change_rd = triton_asm! {
            push {change_rd.values()[4]}
            push {change_rd.values()[3]}
            push {change_rd.values()[2]}
            push {change_rd.values()[1]}
            push {change_rd.values()[0]}
        };

        let c0: u64 = (LEVIATHAN_UNIT_TO_NAU & 0xFFFF_FFFF) as u64;
        let c1: u64 = ((LEVIATHAN_UNIT_TO_NAU >> 32) & 0xFFFF_FFFF) as u64;
        let c2: u64 = ((LEVIATHAN_UNIT_TO_NAU >> 64) & 0xFFFF_FFFF) as u64;

        // ================================================================
        // Phase 3: Authenticate MSA against txk_mast_hash (from RAM)
        // ================================================================
        let authenticate_msa = triton_asm!(
            push {TXKMH_ADDR + 4} read_mem 5 pop 1
            push {TransactionKernel::MAST_HEIGHT}
            dup 6
            push 0 push 0 push 0 push 0 push 1
            push 0 push 0 push 0 push 0 push 0
            divine {Digest::LEN}
            hash
            dup 10 {&field_swbfi}
            call {bag_peaks}
            dup 15 {&field_aocl}
            call {bag_peaks}
            hash
            hash
            sponge_init sponge_absorb
            sponge_squeeze
            swap 5 pop 1 swap 5 pop 1 swap 5 pop 1 swap 5 pop 1 swap 5 pop 1
            push {TransactionKernelField::MutatorSetHash as u32}
            swap 6 pop 1
            call {merkle_verify}
        );

        let authenticate_removal_records = triton_asm!(
            push {TXKMH_ADDR + 4} read_mem 5 pop 1
            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Inputs as u32}
            dup 7 {&field_with_size_removal_records}
            call {hash_varlen}
            call {merkle_verify}
        );

        // Leaves are `hash_varlen(field.encode())`, as in `MastHash::merkle_tree`.
        let zero_fee_leaf = Tip5::hash_varlen(&NativeCurrencyAmount::zero().encode());
        let no_coinbase_leaf = Tip5::hash_varlen(&None::<NativeCurrencyAmount>.encode());
        let authenticate_zero_fee_no_coinbase = triton_asm!(
            push {TXKMH_ADDR + 4} read_mem 5 pop 1
            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Fee as u32}
            {&Literal::Digest(zero_fee_leaf).push_to_stack_code()}
            call {merkle_verify}

            push {TXKMH_ADDR + 4} read_mem 5 pop 1
            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Coinbase as u32}
            {&Literal::Digest(no_coinbase_leaf).push_to_stack_code()}
            call {merkle_verify}
        );

        // ================================================================
        // Phase 4: RRI loop
        // ================================================================
        let for_all_utxos = "bup_for_all_utxos";

        let for_all_utxos_loop = triton_asm! {
            {for_all_utxos}:
                dup 3 dup 3 eq
                skiz return

                dup 1 call bup_assert_canonical_utxo pop 1

                dup 1
                read_mem 1 addi 2 swap 1
                call {hash_varlen}
                push {utxo_hash_alloc.write_address()}
                write_mem {Digest::LEN} pop 1

                // native currency only
                dup 1 addi 2 read_mem 1 pop 1
                push 1 eq assert error_id {9_000_010i128}

                dup 1 addi 14 read_mem 5 pop 1
                push {nc_hash_alloc.read_address()} read_mem 5 pop 1
                assert_vector error_id {9_000_011i128}
                pop 5

                // lock_script_hash == bridge_lock_hash
                dup 1 addi 19 read_mem 5 pop 1
                push {bridge_lock_hash_alloc.read_address()} read_mem 5 pop 1
                assert_vector error_id {9_001_001i128}
                pop 5

                // accumulate input amount
                push {sum_input_alloc.read_address()} read_mem 4 pop 1
                dup 5 addi 9 read_mem 4 pop 1
                call {u128_overflowing_add}
                push 0 eq assert error_id {9_000_024i128}
                push {sum_input_alloc.write_address()} write_mem 4 pop 1

                divine {u64_stack_size}
                push {aocl_leaf_index_alloc.write_address()}
                write_mem {u64_stack_size} pop 1

                divine {Digest::LEN}
                push {receiver_preimage_alloc.write_address()}
                write_mem {Digest::LEN} pop 1

                divine {Digest::LEN}
                push {sender_randomness_alloc.write_address()}
                write_mem {Digest::LEN} pop 1

                dup 0 {&field_peaks}
                push 0 push 0 push 0 push 0 push 0
                push {receiver_preimage_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                hash
                push {sender_randomness_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                push {utxo_hash_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                call {ms_commit}

                dup 6 {&field_mmr_num_leafs}
                addi 1 read_mem {u64_stack_size} pop 1
                push {aocl_leaf_index_alloc.read_address()}
                read_mem {u64_stack_size} pop 1
                call {mmr_verify}

                push {aocl_leaf_index_alloc.read_address()}
                read_mem {u64_stack_size} pop 1
                push {receiver_preimage_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                push {sender_randomness_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                push {utxo_hash_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                call {compute_absolute_indices}
                call {hash_absolute_indices}
                pop 1

                dup 9 addi 1
                {&field_indices}
                call {hash_absolute_indices}
                pop 1
                {&compare_digests}
                assert

                swap 1
                read_mem 1
                push {MAX_JUMP} dup 2 lt assert
                addi 2 add
                swap 1
                swap 2 addi 1 swap 2
                swap 4
                read_mem 1
                push {MAX_JUMP} dup 2 lt assert
                addi 2 add
                swap 4
                recurse
        };

        // ================================================================
        // Multiplication: burn_amount * LEVIATHAN_UNIT_TO_NAU → u128
        // Decompose: result = burn * const_lo + (burn * const_hi) << 64
        // Uses MulTwoU64sToU128 (4 stack elements in, 4 out) — no deep stack.
        // ================================================================

        let mul_burn_to_nau = triton_asm! {
            bup_mul_burn_to_nau:
                // _ burn_amount (u64)
                split
                // _ burn_hi burn_lo
                push {MUL_BURN_LO} write_mem 1 pop 1
                push {MUL_BURN_HI} write_mem 1 pop 1

                // Limb 0: burn_lo * c0
                push {MUL_BURN_LO} read_mem 1 pop 1
                push {c0} mul split
                push {MUL_RESULT} write_mem 1 pop 1
                push {MUL_CARRY} write_mem 1 pop 1

                // Limb 1
                push {MUL_BURN_LO} read_mem 1 pop 1
                push {c1} mul split
                swap 1 push {MUL_P1_HI} write_mem 1 pop 1

                push {MUL_BURN_HI} read_mem 1 pop 1
                push {c0} mul split
                swap 1 push {MUL_P3_HI} write_mem 1 pop 1

                add
                push {MUL_CARRY} read_mem 1 pop 1
                add
                split
                push {MUL_RESULT + 1} write_mem 1 pop 1
                push {MUL_CARRY} write_mem 1 pop 1

                // Limb 2
                push {MUL_CARRY} read_mem 1 pop 1
                push {MUL_P1_HI} read_mem 1 pop 1
                add
                push {MUL_P3_HI} read_mem 1 pop 1
                add

                push {MUL_BURN_LO} read_mem 1 pop 1
                push {c2} mul split
                swap 2 swap 1
                push {MUL_P1_HI} write_mem 1 pop 1
                add

                push {MUL_BURN_HI} read_mem 1 pop 1
                push {c1} mul split
                swap 2 swap 1
                push {MUL_P3_HI} write_mem 1 pop 1
                add
                split
                push {MUL_RESULT + 2} write_mem 1 pop 1

                // Limb 3
                push {MUL_P1_HI} read_mem 1 pop 1
                add
                push {MUL_P3_HI} read_mem 1 pop 1
                add

                push {MUL_BURN_HI} read_mem 1 pop 1
                push {c2} mul split
                swap 1
                push 0 eq assert error_id {9_002_001i128}
                add
                // result_3 is on the stack; store it directly
                push {MUL_RESULT + 3} write_mem 1 pop 1

                return
        };

        // ================================================================
        // Phase 1-2: Read inputs + stark_verify + exit tree
        // ================================================================
        let phase1_2 = triton_asm! {
            call bup_main
            halt

            bup_main:
                read_io 5
                swap 4 swap 1 swap 3 swap 1
                push {ANN_PS_ADDR} write_mem 5 pop 1

                read_io 5
                swap 4 swap 1 swap 3 swap 1
                push {ANN_NS_ADDR} write_mem 5 pop 1

                read_io 5
                swap 4 swap 1 swap 3 swap 1
                push {ER_ADDR} write_mem 5 pop 1

                read_io 5
                swap 4 swap 1 swap 3 swap 1
                push {TXKMH_ADDR} write_mem 5 pop 1

                push 0 push {TOTAL_BURNS} write_mem 1 pop 1

                call bup_bind_announcement

                // proof flag: 0 = no-proof empty settlement (bup_zero_halt), 1 = proof path
                divine 1
                dup 0 push 0 eq
                skiz call bup_zero_halt
                push 1 eq assert error_id {9_005_004i128}

                // E exits (0 allowed: then exit_root must equal acc_prev), at most the cap
                push {SETTLE_E} read_mem 1 pop 1
                dup 0 push {MAX_BURNS_PER_SETTLEMENT} lt push 0 eq
                assert error_id {9_005_001i128}
                push {TOTAL_BURNS} write_mem 1 pop 1

                push 7 push 15
                call {new_claim}

                divine 5
                dup 4 push {EXPECTED_VP_HASH[4]} eq assert error_id {9_005_005i128}
                dup 3 push {EXPECTED_VP_HASH[3]} eq assert error_id {9_005_005i128}
                dup 2 push {EXPECTED_VP_HASH[2]} eq assert error_id {9_005_005i128}
                dup 1 push {EXPECTED_VP_HASH[1]} eq assert error_id {9_005_005i128}
                dup 0 push {EXPECTED_VP_HASH[0]} eq assert error_id {9_005_005i128}
                dup {Digest::LEN}
                write_mem {Digest::LEN}
                pop 2

                push {ANN_PS_ADDR + 4} read_mem 5 pop 1
                dup 5 write_mem 5
                push {FAUCET_ADDR + 1} read_mem 2 pop 1
                pick 2 write_mem 2 pop 2

                push {ANN_NS_ADDR + 4} read_mem 5 pop 1
                dup 5 write_mem 5

                push {ANN_PS_ADDR + 4} read_mem 5 pop 1
                pick 5 write_mem 5

                push {ER_ADDR + 4} read_mem 5 pop 1
                pick 5 write_mem 5
                pop 2

                divine 1
                call {stark_verify}

                call bup_exit_chain
                call bup_phase3_6
                return

            bup_zero_halt:
                pop 1
                // The signed announcement must list no burns: this path pays none.
                push {SETTLE_E} read_mem 1 pop 1
                push 0 eq assert error_id {9_005_016i128}
                push {ER_ADDR + 4} read_mem 5 pop 1
                push 0 eq assert
                push 0 eq assert
                push 0 eq assert
                push 0 eq assert
                push 0 eq assert
                // A no-proof settlement must not move the state
                // commitment, so new_state must equal prev_state.
                push {ANN_PS_ADDR} read_mem 1 pop 1
                push {ANN_NS_ADDR} read_mem 1 pop 1
                eq assert
                push {ANN_PS_ADDR + 1} read_mem 1 pop 1
                push {ANN_NS_ADDR + 1} read_mem 1 pop 1
                eq assert
                push {ANN_PS_ADDR + 2} read_mem 1 pop 1
                push {ANN_NS_ADDR + 2} read_mem 1 pop 1
                eq assert
                push {ANN_PS_ADDR + 3} read_mem 1 pop 1
                push {ANN_NS_ADDR + 3} read_mem 1 pop 1
                eq assert
                push {ANN_PS_ADDR + 4} read_mem 1 pop 1
                push {ANN_NS_ADDR + 4} read_mem 1 pop 1
                eq assert
                call bup_phase3_6
                halt
        };

        // _ v -> _ v, failing unless v < 2^32
        let assert_u32 =
            triton_asm! { dup 0 split pop 1 push 0 eq assert error_id {9_005_018i128} };

        // Copy `n` felts from `*src..*src+n` (`*src` on top of the stack, consumed) to the
        // constant `dst..dst+n`.
        let copy_from_ptr = |n: u64, dst: u64| -> Vec<LabelledInstruction> {
            let body: Vec<LabelledInstruction> = (0..n)
                .flat_map(|k| {
                    triton_asm! {
                        dup 0
                        addi {k as i64}
                        read_mem 1
                        pop 1
                        push {dst + k}
                        write_mem 1
                        pop 1
                    }
                })
                .collect();
            triton_asm! { {&body} pop 1 }
        };

        // Copy `n` felts from `src..src+n` (constant) to `*entry..*entry+n`, where `*entry` is on
        // top of the stack and is preserved.
        let copy_to_entry = |n: u64, src: u64| -> Vec<LabelledInstruction> {
            (0..n)
                .flat_map(|k| {
                    triton_asm! {
                        push {src + k}
                        read_mem 1
                        pop 1
                        dup 1
                        addi {k as i64}
                        write_mem 1
                        pop 1
                    }
                })
                .collect()
        };

        //   acc_0   = 0 if prev_state is the zero digest, else preimage[13..18]
        //             after asserting hash_varlen(preimage) == prev_state
        //   acc_i+1 = hash_varlen(acc_i(5) || record_i(16));  assert acc_E == exit_root
        // Each record also fills its BURN_DATA entry for Phase 5, with sr = hash_varlen(serial).
        let exit_chain = triton_asm! {
            // The first settlement-tagged announcement's signed header must equal the claim; its
            // burns, preimage and change are then read from it, so BAAV pays what was signed.
            bup_bind_announcement:
                push {TXKMH_ADDR + 4} read_mem 5 pop 1
                push {TransactionKernel::MAST_HEIGHT}
                push {TransactionKernelField::Announcements as u32}
                push {ANN_BASE} read_mem 1 pop 1
                push {ANN_BASE + 1}
                swap 1
                call {hash_varlen}
                call {merkle_verify}

                push {ANN_BASE + 2}
                push {ANN_BASE + 1} read_mem 1 pop 1
                call bup_find_settlement
                pop 1
                // _ *cursor (msg_len at +2, msg[0] at +3)
                dup 0 addi 2 read_mem 1 pop 1
                swap 1 addi 3
                // _ L *msg

                dup 0 addi 5 read_mem 5 pop 1
                push {ANN_PS_ADDR + 4} read_mem 5 pop 1
                {&compare_digests}
                assert error_id {9_005_011i128}
                dup 0 addi 10 read_mem 5 pop 1
                push {ANN_NS_ADDR + 4} read_mem 5 pop 1
                {&compare_digests}
                assert error_id {9_005_012i128}
                dup 0 addi 15 read_mem 5 pop 1
                push {ER_ADDR + 4} read_mem 5 pop 1
                {&compare_digests}
                assert error_id {9_005_013i128}

                dup 0 addi 17 read_mem 2 pop 1
                push {FAUCET_ADDR} write_mem 2 pop 1

                dup 0 addi 18
                push {SETTLE_PREIMG} write_mem 1 pop 1

                // num_burns follows the preimage. Every length must be a u32 (as the Rust parser's
                // usize offsets), so the field arithmetic below cannot wrap.
                dup 0 addi 37
                // _ L *msg p_burns
                dup 0 read_mem 1 pop 1 {&assert_u32}
                push {SETTLE_E} write_mem 1 pop 1
                dup 0 addi 1
                push {SETTLE_BURNS} write_mem 1 pop 1
                push {SETTLE_E} read_mem 1 pop 1
                push {BURN_RECORD_LEN} mul add addi 1
                // _ L *msg p_flag; flag in {0, 1}
                dup 0 read_mem 1 pop 1
                dup 0 dup 0 addi -1 mul push 0 eq
                assert error_id {9_005_014i128}
                dup 0 push {SETTLE_FLAG} write_mem 1 pop 1
                dup 1 addi 1 push {SETTLE_CHANGE} write_mem 1 pop 1
                push {Digest::LEN} mul add addi 1
                // _ L *msg p_sigs
                dup 0 read_mem 1 pop 1 {&assert_u32}
                push {SIGNATURE_FELTS} mul add addi 1
                // _ L *msg end; end == *msg + L
                swap 1 pick 2 add
                eq assert error_id {9_005_015i128}
                return

            // _ *cursor n  ->  _ *cursor n  at the first element with msg_len > 0 and
            // msg[0] == AGGREGATED_ANNOUNCEMENT_TAG; fails if there is none.
            bup_find_settlement:
                dup 0 push 0 eq push 0 eq
                assert error_id {9_005_010i128}
                dup 1 addi 2 read_mem 1 pop 1 push 0 eq push 0 eq
                dup 2 addi 3 read_mem 1 pop 1 push {AGGREGATED_ANNOUNCEMENT_TAG} eq
                mul
                skiz return
                swap 1
                dup 0 read_mem 1 pop 1 addi 1 add
                swap 1 addi -1
                recurse

            // _ *utxo_si -> _ *utxo_si. The UTXO is exactly `Utxo::new_native_currency`'s encoding
            // (what apply rebuilds and what the offsets read here assume) with a non-negative amount;
            // its type script and lock are checked by the callers.
            bup_assert_canonical_utxo:
                dup 0 read_mem 1 pop 1
                push {canonical_utxo.len()} eq assert error_id {9_000_020i128}
                {&assert_canonical_header}
                {&assert_amount_limbs_u32}
                dup 0 addi {amount_offset + 3} read_mem 1 pop 1
                push {1u64 << 31} swap 1 lt assert error_id {9_000_023i128}
                return

            bup_load_change_sr:
                push {SETTLE_CHANGE} read_mem 1 pop 1
                {&copy_from_ptr(Digest::LEN as u64, CHANGE_SR_ADDR)}
                return

            bup_exit_chain:
                call bup_set_acc_prev
                push 0 push {BURN_CTR} write_mem 1 pop 1
                call bup_exit_loop

                // assert acc == exit_root (both read +4, same orientation)
                push {FOLD_BUF + 4} read_mem 5 pop 1
                push {ER_ADDR + 4} read_mem 5 pop 1
                {&compare_digests}
                assert error_id {9_005_002i128}
                return

            // acc_prev -> FOLD_BUF[0..5]
            bup_set_acc_prev:
                // prev_is_zero = AND over (ANN_PS[k] == 0)
                push 1
                push {ANN_PS_ADDR} read_mem 1 pop 1 push 0 eq mul
                push {ANN_PS_ADDR + 1} read_mem 1 pop 1 push 0 eq mul
                push {ANN_PS_ADDR + 2} read_mem 1 pop 1 push 0 eq mul
                push {ANN_PS_ADDR + 3} read_mem 1 pop 1 push 0 eq mul
                push {ANN_PS_ADDR + 4} read_mem 1 pop 1 push 0 eq mul
                // _ prev_is_zero
                dup 0 skiz call bup_acc_from_zero
                push 0 eq skiz call bup_acc_from_preimage
                return

            bup_acc_from_zero:
                push 0 push 0 push 0 push 0 push 0
                push {FOLD_BUF} write_mem 5 pop 1
                return

            bup_acc_from_preimage:
                push {SETTLE_PREIMG} read_mem 1 pop 1
                {&copy_from_ptr(STATE_PREIMAGE_LEN as u64, PREIMG_BUF)}
                push {PREIMG_BUF} push {STATE_PREIMAGE_LEN}
                call {hash_varlen}
                push {SCRATCH_DIG} write_mem 5 pop 1
                push {SCRATCH_DIG + 4} read_mem 5 pop 1
                push {ANN_PS_ADDR + 4} read_mem 5 pop 1
                {&compare_digests}
                assert error_id {9_005_003i128}
                // acc = preimage[13..18] -> FOLD_BUF[0..5]
                push {PREIMG_BUF + 13} read_mem 1 pop 1 push {FOLD_BUF} write_mem 1 pop 1
                push {PREIMG_BUF + 14} read_mem 1 pop 1 push {FOLD_BUF + 1} write_mem 1 pop 1
                push {PREIMG_BUF + 15} read_mem 1 pop 1 push {FOLD_BUF + 2} write_mem 1 pop 1
                push {PREIMG_BUF + 16} read_mem 1 pop 1 push {FOLD_BUF + 3} write_mem 1 pop 1
                push {PREIMG_BUF + 17} read_mem 1 pop 1 push {FOLD_BUF + 4} write_mem 1 pop 1
                return

            bup_exit_loop:
                push {BURN_CTR} read_mem 1 pop 1
                push {TOTAL_BURNS} read_mem 1 pop 1
                eq skiz return

                // record i (from the bound message) -> FOLD_BUF[5..21]
                push {SETTLE_BURNS} read_mem 1 pop 1
                push {BURN_CTR} read_mem 1 pop 1
                push {BURN_RECORD_LEN} mul add
                {&copy_from_ptr(BURN_RECORD_LEN as u64, FOLD_BUF + 5)}

                // acc' = hash_varlen(FOLD_BUF[0..21]); store to FOLD_BUF[0..5]
                push {FOLD_BUF} push {5 + BURN_RECORD_LEN}
                call {hash_varlen}
                push {FOLD_BUF} write_mem 5 pop 1

                push {BURN_CTR} read_mem 1 pop 1
                push {BURN_ENTRY_LEN}
                mul
                push {BURN_DATA}
                add
                // _ *entry
                {&copy_to_entry(SERIAL_OFFSET, FOLD_BUF + 5)}
                // sr = hash_varlen(serial = record[12..16]) -> entry[12..17]
                push {FOLD_BUF + 5 + SERIAL_OFFSET} push 4
                call {hash_varlen}
                // _ *entry [sr;5]
                dup 5 addi {SERIAL_OFFSET} write_mem 5 pop 1
                pop 1

                push {BURN_CTR} read_mem 1 pop 1 addi 1
                push {BURN_CTR} write_mem 1 pop 1
                recurse
        };

        // ================================================================
        // Phase 3-6 main
        // ================================================================
        let phase3_6 = triton_asm! {
            bup_phase3_6:
                push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
                dup 0 call {audit_witness} pop 1

                // change_sender_randomness comes from the bound announcement (none if flag == 0)
                push {SETTLE_FLAG} read_mem 1 pop 1
                skiz call bup_load_change_sr

                push 0 push 0 push 0 push 0
                push {sum_input_alloc.write_address()} write_mem 4 pop 1
                push 0 push 0 push 0 push 0
                push {sum_output_alloc.write_address()} write_mem 4 pop 1

                push {native_currency_hash.values()[4]}
                push {native_currency_hash.values()[3]}
                push {native_currency_hash.values()[2]}
                push {native_currency_hash.values()[1]}
                push {native_currency_hash.values()[0]}
                push {nc_hash_alloc.write_address()} write_mem 5 pop 1

                push {blh.values()[4]}
                push {blh.values()[3]}
                push {blh.values()[2]}
                push {blh.values()[1]}
                push {blh.values()[0]}
                push {bridge_lock_hash_alloc.write_address()} write_mem 5 pop 1

                {&authenticate_msa}
                {&authenticate_removal_records}
                {&authenticate_zero_fee_no_coinbase}

                dup 0 {&field_aocl}
                dup 1 {&field_input_utxos} {&field_utxos}
                read_mem 1 addi 2
                push 0 swap 1

                dup 4 {&field_removal_records}
                read_mem 1 addi 2
                swap 1 dup 4 eq assert
                swap 4

                call {for_all_utxos}

                pick 1 place 4
                pop 4

                dup 1
                place 2
                swap 1
                {&field_with_size_input_utxos}
                dup 1 {&field_utxos_with_size}
                add
                pick 3 eq assert
                pop 2

                // K2O — save *witness to RAM, build 6-element loop invariant
                // matching batch_proof exactly. No extra elements on stack.
                // Stack here: _ *witness

                // Save *witness to RAM (needed later for field access)
                dup 0
                push {SAVED_WITNESS} write_mem 1 pop 1

                // Save *salted_output_utxos
                dup 0 {&field_output_utxos}
                push {SAVED_SOU} write_mem 1 pop 1

                // Save *utxos[0]_len (fixed start pointer)
                dup 0 {&field_output_utxos} {&field_utxos} addi 1
                dup 0
                push {SAVED_UTXO_FIXED} write_mem 1 pop 1
                // _ *witness *utxos[0]_len

                // Remove *witness from stack
                swap 1 pop 1
                // _ *utxos[0]_len

                // Build K2O invariant: _ *utxos[i]_len *sr *rd[0]_lw *cc[0] N 0

                // sender_randomnesses pointer
                push {SAVED_WITNESS} read_mem 1 pop 1
                {&field_sender_randomnesses}
                // _ *utxos[0]_len *sr

                // receiver_digests: read N, compute walking pointer
                push {SAVED_WITNESS} read_mem 1 pop 1
                {&field_receiver_digests}
                read_mem 1
                addi {1 + Digest::LEN}
                swap 1
                dup 0
                // _ *utxos[0]_len *sr *rd[0]_lw N N

                // Verify N == num output utxos
                push {SAVED_SOU} read_mem 1 pop 1
                {&field_utxos}
                read_mem 1
                pop 1
                dup 1 eq assert
                // _ *utxos[0]_len *sr *rd[0]_lw N

                // every exit is paid and there is at most the announced change output
                dup 0
                push {TOTAL_BURNS} read_mem 1 pop 1
                push {SETTLE_FLAG} read_mem 1 pop 1
                add eq assert error_id {9_005_017i128}

                // Create commitment list, write N as first element
                call {new_list}
                write_mem 1
                // _ *utxos[0]_len *sr *rd[0]_lw *cc[0]

                // Reorder: swap *cc below N, push i=0
                swap 1
                push 0
                // _ *utxos[0]_len *sr *rd[0]_lw *cc[0] N 0
                // = *utxos(5) *sr(4) *rd(3) *cc(2) N(1) i(0) ✓

                call {k2o_loop_label}
                // _ *utxos[N]_len *sr *rd[N] *cc[N] N N

                pop 1
                // _ *utxos[N]_len *sr *rd[N] *cc[N] N

                push {-(Digest::LEN as isize)} mul addi -1 add
                // _ *utxos[N]_len *sr *rd[N] *cc_start

                dup 0 read_mem 1 pop 1
                push {Digest::LEN} mul addi 1

                call {hash_varlen}
                // _ *utxos[N]_len *sr *rd[N] [cc_hash]

                push {TXKMH_ADDR + 4} read_mem 5 pop 1
                push {TransactionKernel::MAST_HEIGHT}
                push {TransactionKernelField::Outputs as u32}
                dup 11 dup 11 dup 11 dup 11 dup 11
                call {merkle_verify}

                pop 5 pop 2
                // _ *utxos[N]_len

                // Verify salted_output_utxos traversal size
                push {SAVED_UTXO_FIXED} read_mem 1 pop 1
                // _ *utxos[N]_len *utxos[0]_len
                push -1 mul add
                // _ (utxos[N] - utxos[0])
                addi {3 + 1 + 1}
                // _ expected_salted_size

                push {SAVED_SOU} read_mem 1 pop 1
                addi -1 read_mem 1
                // _ expected indicated (*sou - 1)
                place 2 dup 1 eq assert
                // _ (*sou - 1) size
                swap 1 addi 2 swap 1
                // (no write_io — BAAV has no public output)
                pop 2

                // conservation
                push {sum_input_alloc.read_address()} read_mem 4 pop 1
                push {sum_output_alloc.read_address()} read_mem 4 pop 1
                {&compare_coin_amount}
                assert error_id {9_000_100i128}

                return
        };

        // K2O loop with burn matching
        let k2o_loop = triton_asm! {
            {k2o_loop_label}:
                dup 1 dup 1 eq skiz return

                dup 5 call bup_assert_canonical_utxo pop 1

                dup 5 addi 2 read_mem 1 pop 1
                push 1 eq assert error_id {9_000_001i128}

                dup 5 addi 14 read_mem 5 pop 1
                push {nc_hash_alloc.read_address()} read_mem 5 pop 1
                assert_vector error_id {9_000_002i128}
                pop 5

                push {sum_output_alloc.read_address()} read_mem 4 pop 1
                dup 9 addi 9 read_mem 4 pop 1
                call {u128_overflowing_add}
                push 0 eq assert error_id {9_000_025i128}
                push {sum_output_alloc.write_address()} write_mem 4 pop 1

                dup 0
                push {TOTAL_BURNS} read_mem 1 pop 1
                swap 1
                lt
                skiz call bup_match_burn

                dup 0
                push {TOTAL_BURNS} read_mem 1 pop 1
                swap 1
                lt push 0 eq
                skiz call bup_assert_change

                dup 3
                read_mem {Digest::LEN}
                addi {2 * Digest::LEN}
                swap 9 pop 1

                dup 9 dup 6 call {get_digest}

                dup 15
                read_mem 1 addi 2 swap 1
                call {hash_varlen}

                call {ms_commit}

                dup 7 write_mem 5
                swap 3 pop 1

                dup 5
                read_mem 1
                push {MAX_JUMP} dup 2 lt assert
                addi 2 add
                swap 6 pop 1

                addi 1
                recurse

            bup_match_burn:
                // Stack: _ ... *utxos[i]_len(st5) *sr(st4) *rd[i]_lw(st3) *cc(st2) N(st1) i(st0)
                dup 0
                push 17 mul
                push {BURN_DATA} add
                // _ ... N i burn_addr

                // === Check receiver_identifier (1 BFE at offset 0) — must be non-zero ===
                dup 0 read_mem 1 pop 1
                push 0 eq push 0 eq assert error_id {9_003_000i128}
                // _ ... N i burn_addr

                // === Check privacy_digest (5 BFE at offset 1) against output receiver_digest ===
                dup 0 addi 5 read_mem 5 pop 1
                // _ ... N i burn_addr [burn_pd(5)]

                dup 9
                read_mem {Digest::LEN} pop 1
                // _ ... burn_addr [burn_pd(5)] [output_rd(5)]
                assert_vector error_id {9_003_001i128}
                pop 5
                // _ ... N i burn_addr

                // === Check lock_script_hash (5 BFE at offset 6) ===
                dup 0 addi 10 read_mem 5 pop 1
                dup 11 addi 19 read_mem 5 pop 1
                assert_vector error_id {9_003_002i128}
                pop 5
                // _ ... N i burn_addr

                // === Check amount (1 BFE at offset 11) ===
                dup 0 addi 11 read_mem 1 pop 1
                call bup_mul_burn_to_nau

                dup 6 addi 9 read_mem 4 pop 1

                push {MUL_RESULT + 3} read_mem 4 pop 1

                pick 4 eq assert error_id {9_003_003i128}
                pick 3 eq assert error_id {9_003_004i128}
                pick 2 eq assert error_id {9_003_005i128}
                eq assert error_id {9_003_006i128}

                // === Check sender_randomness (5 BFE at offset 12) ===
                // Read burn sr from BURN_DATA[i * 17 + 12]
                dup 0 addi 16 read_mem 5 pop 1
                // _ ... burn_addr [burn_sr(5)]

                // Read output sr: *sr is at st4+6=st10 (6 pushed: burn_addr + 5 sr values)
                dup 10 dup 7 call {get_digest}
                // _ ... burn_addr [burn_sr(5)] [output_sr(5)]
                assert_vector error_id {9_003_007i128}
                pop 5
                // _ ... burn_addr

                pop 1
                return

            bup_assert_change:
                // Check lock_script_hash == bridge_lock_hash
                dup 5 addi 19 read_mem 5 pop 1
                push {bridge_lock_hash_alloc.read_address()} read_mem 5 pop 1
                assert_vector error_id {9_004_001i128}
                pop 5

                // Check sender_randomness == change_sender_randomness
                // *sr is at st4, i is at st0. Use get_digest to read sr[i].
                dup 4 dup 1 call {get_digest}
                // _ ... [output_sr(5)]
                push {CHANGE_SR_ADDR + 4} read_mem 5 pop 1
                // _ ... [output_sr(5)] [change_sr(5)]
                assert_vector error_id {9_004_002i128}
                pop 5

                // receiver_digest == the pool change's, which apply rebuilds
                dup 3 read_mem {Digest::LEN} pop 1
                {&push_change_rd}
                assert_vector error_id {9_004_003i128}
                pop 5

                return
        };

        let code = triton_asm! {
            {&phase1_2}
            {&exit_chain}
            {&phase3_6}
            {&for_all_utxos_loop}
            {&k2o_loop}
            {&mul_burn_to_nau}
            {&library.all_imports()}
        };

        (library, code)
    }
}

// =========================================================================
// Witness
// =========================================================================

#[derive(Debug)]
pub struct BridgeAggregatedAnnouncementValidatorWitness {
    pub prev_state_commitment: Digest,
    pub announcement_data: AggregatedAnnouncementData,
    pub converted_proof: Option<Proof>,
    pub primitive_witness: PrimitiveWitness,
}

impl BridgeAggregatedAnnouncementValidatorWitness {
    pub fn from_announcement(
        ann_data: AggregatedAnnouncementData,
        converted_proof: Option<Proof>,
        primitive_witness: PrimitiveWitness,
    ) -> Self {
        Self {
            prev_state_commitment: ann_data.prev_state_commitment,
            announcement_data: ann_data,
            converted_proof,
            primitive_witness,
        }
    }

    fn build_witness_memory(pw: &PrimitiveWitness) -> BridgeUnlockWitnessMemory {
        BridgeUnlockWitnessMemory {
            output_utxos: pw.output_utxos.clone(),
            sender_randomnesses: pw.output_sender_randomnesses.clone(),
            receiver_digests: pw.output_receiver_digests.clone(),
            input_utxos: pw.input_utxos.clone(),
            removal_records: pw.kernel.inputs.clone(),
            aocl: pw.mutator_set_accumulator.aocl.clone(),
            swbfi: pw.mutator_set_accumulator.swbf_inactive.clone(),
        }
    }
}

impl SecretWitness for BridgeAggregatedAnnouncementValidatorWitness {
    fn standard_input(&self) -> PublicInput {
        let mut input = Vec::with_capacity(20);
        input.extend(self.prev_state_commitment.values());
        input.extend(self.announcement_data.new_state_commitment.values());
        input.extend(self.announcement_data.exit_root.values());
        let txk_mast_hash = self.primitive_witness.kernel.mast_hash();
        input.extend(txk_mast_hash.values());
        PublicInput::new(input)
    }

    fn program(&self) -> Program {
        BridgeAggregatedAnnouncementValidator.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let ann = &self.announcement_data;
        let pw = &self.primitive_witness;

        let mut tokens: Vec<BFieldElement> = Vec::new();
        let mut ram: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        let mut digests: Vec<Digest> = Vec::new();

        // The kernel's announcements, authenticated first (bup_bind_announcement).
        let announcements = pw.kernel.announcements.encode();
        ram.insert(
            BFieldElement::new(ANN_BASE),
            BFieldElement::new(announcements.len() as u64),
        );
        for (i, bfe) in announcements.iter().enumerate() {
            ram.insert(BFieldElement::new(ANN_BASE + 1 + i as u64), *bfe);
        }
        digests.extend(pw.kernel.mast_path(TransactionKernelField::Announcements));

        // Proof flag: without a converted proof only the no-proof empty settlement is possible.
        tokens.push(BFieldElement::new(u64::from(
            self.converted_proof.is_some(),
        )));
        if let Some(converted_proof) = self.converted_proof.as_ref() {
            let prog_hash = expected_verifier_program_digest();
            for bfe in prog_hash.values().iter().rev() {
                tokens.push(*bfe);
            }

            let verifier_output = [
                ann.new_state_commitment.values(),
                self.prev_state_commitment.values(),
                ann.exit_root.values(),
            ]
            .concat();
            // The version the BAAV program's claim snippet stamps, and `ProofCollection` proves.
            let converted_claim = Claim::new(prog_hash)
                .about_version(tasm_lib::triton_vm::proof::CURRENT_VERSION)
                .with_input(verifier_input(self.prev_state_commitment, ann.faucet_id))
                .with_output(verifier_output);

            let proof_addr = BFieldElement::new(PROOF_ADDR);
            let proof_encoding = converted_proof.encode();
            for (i, bfe) in proof_encoding.iter().enumerate() {
                ram.insert(proof_addr + BFieldElement::new(i as u64), *bfe);
            }
            tokens.push(proof_addr);

            let stark_verify_snippet = StarkVerify::new_with_dynamic_layout(Stark::default());
            let mut nd_phase1 = NonDeterminism::new(vec![]).with_ram(HashMap::new());
            stark_verify_snippet.update_nondeterminism(
                &mut nd_phase1,
                converted_proof,
                &converted_claim,
            );
            digests.extend(nd_phase1.digests);
        }

        // Phase 3-6 nondeterminism

        let witness_mem = Self::build_witness_memory(pw);
        encode_to_memory(
            &mut ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &witness_mem,
        );

        let swbfa_hash = Tip5::hash(&pw.mutator_set_accumulator.swbf_active);
        tokens.extend(swbfa_hash.values().iter().rev());

        for mp in &pw.input_membership_proofs {
            let mut leaf_idx = mp.aocl_leaf_index.encode();
            leaf_idx.reverse();
            tokens.extend(leaf_idx);
            tokens.extend(mp.receiver_preimage.values().iter().rev());
            tokens.extend(mp.sender_randomness.values().iter().rev());
        }

        digests.extend(pw.kernel.mast_path(TransactionKernelField::MutatorSetHash));
        digests.extend(pw.kernel.mast_path(TransactionKernelField::Inputs));
        digests.extend(pw.kernel.mast_path(TransactionKernelField::Fee));
        digests.extend(pw.kernel.mast_path(TransactionKernelField::Coinbase));
        for mp in &pw.input_membership_proofs {
            digests.extend(mp.auth_path_aocl.authentication_path.iter());
        }
        digests.extend(pw.kernel.mast_path(TransactionKernelField::Outputs));

        NonDeterminism::new(tokens)
            .with_ram(ram)
            .with_digests(digests)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use super::*;
    use crate::protocol::consensus::bridge::aggregated_announcement::BurnRecord;
    use crate::protocol::consensus::bridge::aggregated_announcement::StatePreimage;
    use crate::protocol::consensus::transaction::announcement::Announcement;
    use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use tasm_lib::triton_vm::isa::instruction::AnInstruction;
    use tasm_lib::triton_vm::vm::VMState;

    impl ConsensusProgramSpecification for BridgeAggregatedAnnouncementValidator {
        fn source(&self) {
            todo!()
        }
    }

    pub(crate) fn pool_utxo(coins: u32) -> Utxo {
        Utxo::new_native_currency(
            bridge_lock_script().hash(),
            NativeCurrencyAmount::coins(coins),
        )
    }

    pub(crate) fn bridge_pw(
        inputs: &[Utxo],
        outputs: &[Utxo],
        announcements: &[Announcement],
        fee: NativeCurrencyAmount,
        coinbase: Option<NativeCurrencyAmount>,
    ) -> PrimitiveWitness {
        let lsaws = inputs
            .iter()
            .map(|_| LockScriptAndWitness::new(bridge_lock_script().program))
            .collect::<Vec<_>>();
        PrimitiveWitness::arbitrary_primitive_witness_with(
            inputs,
            &lsaws,
            outputs,
            announcements,
            fee,
            coinbase,
        )
        .new_tree(&mut TestRunner::deterministic())
        .unwrap()
        .current()
    }

    pub(crate) fn test_faucet() -> FaucetId {
        FaucetId {
            suffix: BFieldElement::new(0x1234_5600),
            prefix: BFieldElement::new(0xABCD_0021),
        }
    }

    /// Genesis -> genesis, no exits: what BAAV's no-proof path pays (nothing).
    pub(crate) fn zero_claim() -> AggregatedAnnouncementData {
        AggregatedAnnouncementData {
            prev_state_commitment: Digest::default(),
            new_state_commitment: Digest::default(),
            exit_root: Digest::default(),
            faucet_id: test_faucet(),
            prev_state_preimage: StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
            burns: vec![],
            change_sender_randomness: None,
            authority_signatures: vec![],
        }
    }

    /// The settlement announcement a zero-claim tx with no change output carries.
    pub(crate) fn zero_settlement() -> Announcement {
        zero_claim().to_announcement()
    }

    /// `pw` with `claim` (change sender randomness set to `pw`'s last output, if any) as its kernel's
    /// only announcement.
    pub(crate) fn with_settlement(
        mut pw: PrimitiveWitness,
        mut claim: AggregatedAnnouncementData,
    ) -> PrimitiveWitness {
        if let Some(rd) = pw.output_receiver_digests.last_mut() {
            *rd = Digest::default().hash();
        }
        claim.change_sender_randomness = pw.output_sender_randomnesses.last().copied();
        pw.kernel = TransactionKernelModifier::default()
            .outputs(addition_records(&pw))
            .announcements(vec![claim.to_announcement()])
            .modify(pw.kernel);
        pw
    }

    fn addition_records(pw: &PrimitiveWitness) -> Vec<AdditionRecord> {
        let commit = crate::util_types::mutator_set::commit;
        pw.output_utxos
            .utxos
            .iter()
            .zip(&pw.output_sender_randomnesses)
            .zip(&pw.output_receiver_digests)
            .map(|((utxo, sr), rd)| commit(Tip5::hash(utxo), *sr, *rd))
            .collect()
    }

    /// A bridge tx whose kernel carries the zero settlement, announcing its change output.
    pub(crate) fn settled_pw(
        inputs: &[Utxo],
        outputs: &[Utxo],
        fee: NativeCurrencyAmount,
        coinbase: Option<NativeCurrencyAmount>,
    ) -> PrimitiveWitness {
        with_settlement(bridge_pw(inputs, outputs, &[], fee, coinbase), zero_claim())
    }

    /// No-proof (no burns) witness: every output must be pool change.
    pub(crate) fn zero_pair_witness(
        pw: &PrimitiveWitness,
    ) -> BridgeAggregatedAnnouncementValidatorWitness {
        let claim = AggregatedAnnouncementData {
            change_sender_randomness: pw.output_sender_randomnesses.last().copied(),
            ..zero_claim()
        };
        BridgeAggregatedAnnouncementValidatorWitness::from_announcement(claim, None, pw.clone())
    }

    fn assert_accepts(pw: &PrimitiveWitness) {
        let w = zero_pair_witness(pw);
        BridgeAggregatedAnnouncementValidator
            .run_tasm(&w.standard_input(), w.nondeterminism())
            .unwrap();
    }

    fn assert_rejects(pw: &PrimitiveWitness, error_ids: &[i128]) {
        let w = zero_pair_witness(pw);
        BridgeAggregatedAnnouncementValidator
            .test_assertion_failure(w.standard_input(), w.nondeterminism(), error_ids)
            .unwrap();
    }

    #[test]
    fn accepts_honest_zero_fee_bridge_tx() {
        assert_accepts(&settled_pw(
            &[pool_utxo(10), pool_utxo(10)],
            &[pool_utxo(20)],
            NativeCurrencyAmount::zero(),
            None,
        ));
    }

    /// The same tx with zero fee and no coinbase is accepted, so the rejection is due to them alone.
    fn assert_rejected_by_fee_or_coinbase(
        inputs: &[Utxo],
        outputs: &[Utxo],
        fee: NativeCurrencyAmount,
        coinbase: Option<NativeCurrencyAmount>,
    ) {
        assert_accepts(&settled_pw(
            inputs,
            outputs,
            NativeCurrencyAmount::zero(),
            None,
        ));
        assert_rejects(
            &settled_pw(inputs, outputs, fee, coinbase),
            &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
        );
    }

    #[test]
    fn rejects_unbacked_fee_without_inputs() {
        assert_rejected_by_fee_or_coinbase(&[], &[], NativeCurrencyAmount::coins(1_000_000), None);
    }

    #[test]
    fn rejects_unbacked_fee_with_pool_inputs() {
        assert_rejected_by_fee_or_coinbase(
            &[pool_utxo(10)],
            &[pool_utxo(10)],
            NativeCurrencyAmount::coins(1_000_000),
            None,
        );
    }

    /// `in == out + fee` balances, but the fee is pool money.
    #[test]
    fn rejects_pool_paid_fee() {
        assert_rejects(
            &settled_pw(
                &[pool_utxo(10), pool_utxo(10)],
                &[pool_utxo(15)],
                NativeCurrencyAmount::coins(5),
                None,
            ),
            &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
        );
    }

    #[test]
    fn rejects_coinbase() {
        assert_rejected_by_fee_or_coinbase(
            &[pool_utxo(10)],
            &[pool_utxo(10)],
            NativeCurrencyAmount::zero(),
            Some(NativeCurrencyAmount::coins(1)),
        );
    }

    #[test]
    fn rejects_wrong_txk_and_bad_conservation() {
        let pw = settled_pw(
            &[pool_utxo(10)],
            &[pool_utxo(10)],
            NativeCurrencyAmount::zero(),
            None,
        );
        let w = zero_pair_witness(&pw);
        let mut wrong_txk = w.standard_input();
        wrong_txk.individual_tokens[19] += BFieldElement::new(1);
        BridgeAggregatedAnnouncementValidator
            .test_assertion_failure(
                wrong_txk,
                w.nondeterminism(),
                &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
            )
            .unwrap();

        assert_rejects(
            &settled_pw(
                &[pool_utxo(10)],
                &[pool_utxo(11)],
                NativeCurrencyAmount::zero(),
                None,
            ),
            &[9_000_100],
        );
    }

    fn settlement_with(edit: impl FnOnce(&mut AggregatedAnnouncementData)) -> Announcement {
        let mut claim = zero_claim();
        edit(&mut claim);
        claim.to_announcement()
    }

    fn one_pool_pw(announcements: &[Announcement]) -> PrimitiveWitness {
        bridge_pw(
            &[pool_utxo(10)],
            &[pool_utxo(10)],
            announcements,
            NativeCurrencyAmount::zero(),
            None,
        )
    }

    #[test]
    fn rejects_without_settlement_announcement() {
        assert_rejects(&one_pool_pw(&[]), &[9_005_010]);
    }

    /// The signed settlement moves the state (new != prev) while the claim BAAV pays does not.
    #[test]
    fn rejects_settlement_disagreeing_with_claim() {
        let other = Digest::new([BFieldElement::new(7); 5]);
        let new_differs = settlement_with(|c| c.new_state_commitment = other);
        assert_rejects(&one_pool_pw(&[new_differs]), &[9_005_012]);
        let prev_differs = settlement_with(|c| c.prev_state_commitment = other);
        assert_rejects(&one_pool_pw(&[prev_differs]), &[9_005_011]);
        let root_differs = settlement_with(|c| c.exit_root = other);
        assert_rejects(&one_pool_pw(&[root_differs]), &[9_005_013]);
    }

    /// The no-proof path pays nothing, so the signed settlement may list no burns.
    #[test]
    fn rejects_no_proof_path_with_signed_burns() {
        let signed = settlement_with(|c| {
            c.burns = vec![BurnRecord {
                receiver_identifier: BFieldElement::new(1),
                privacy_digest: Digest::new([BFieldElement::new(2); 5]),
                lock_script_hash: Digest::new([BFieldElement::new(3); 5]),
                amount: 1_000_000,
                serial: [BFieldElement::new(4); 4],
            }]
        });
        assert_rejects(&one_pool_pw(&[signed]), &[9_005_016]);
    }

    #[test]
    fn rejects_settlement_with_bad_layout() {
        let mut trailing = zero_settlement();
        trailing.message.push(BFieldElement::new(0));
        assert_rejects(&one_pool_pw(&[trailing]), &[9_005_015]);

        let mut bad_flag = zero_settlement();
        let flag_at = bad_flag.message.len() - 2;
        bad_flag.message[flag_at] = BFieldElement::new(2);
        assert_rejects(&one_pool_pw(&[bad_flag]), &[9_005_014]);
    }

    /// BAAV binds the first settlement-tagged announcement; other announcements are skipped.
    #[test]
    fn binds_first_settlement_after_other_announcements() {
        let mut pw = with_settlement(one_pool_pw(&[]), zero_claim());
        let settlement = pw.kernel.announcements[0].clone();
        let other = Announcement::new(vec![BFieldElement::new(5); 3]);
        let empty = Announcement::new(vec![]);
        pw.kernel = TransactionKernelModifier::default()
            .announcements(vec![other, empty, settlement])
            .modify(pw.kernel);
        assert_accepts(&pw);
    }

    /// Outputs are exactly the announced exits plus the announced change output.
    #[test]
    fn rejects_outputs_not_matching_announced_change() {
        // A change output the settlement does not announce.
        assert_rejects(&one_pool_pw(&[zero_settlement()]), &[9_005_017]);
        // An announced change output that is missing.
        let pw = bridge_pw(&[], &[], &[], NativeCurrencyAmount::zero(), None);
        let claim = AggregatedAnnouncementData {
            change_sender_randomness: Some(Digest::new([BFieldElement::new(3); 5])),
            ..zero_claim()
        };
        let pw = PrimitiveWitness {
            kernel: TransactionKernelModifier::default()
                .announcements(vec![claim.to_announcement()])
                .modify(pw.kernel),
            ..pw
        };
        assert_rejects(&pw, &[9_005_017]);
    }

    #[test]
    fn rejects_change_with_unannounced_sender_randomness() {
        let mut pw = with_settlement(one_pool_pw(&[]), zero_claim());
        let claim = AggregatedAnnouncementData {
            change_sender_randomness: Some(Digest::new([BFieldElement::new(3); 5])),
            ..zero_claim()
        };
        pw.kernel = TransactionKernelModifier::default()
            .announcements(vec![claim.to_announcement()])
            .modify(pw.kernel);
        assert_rejects(&pw, &[9_004_002]);
    }

    /// The change output must have the pool change's receiver digest, which apply rebuilds.
    #[test]
    fn rejects_change_with_other_receiver_digest() {
        let mut pw = with_settlement(one_pool_pw(&[]), zero_claim());
        let last = pw.output_receiver_digests.len() - 1;
        pw.output_receiver_digests[last] = Digest::new([BFieldElement::new(8); 5]);
        pw.kernel = TransactionKernelModifier::default()
            .outputs(addition_records(&pw))
            .modify(pw.kernel);
        assert_rejects(&pw, &[9_004_003]);
    }

    #[test]
    fn rejects_non_u32_length() {
        let mut ann = zero_settlement();
        ann.message[37] = BFieldElement::new(1 << 32);
        assert_rejects(&one_pool_pw(&[ann]), &[9_005_018]);
    }

    /// Where the proof-path stub leaves the pointer to the claim BAAV would `stark_verify`.
    const CLAIM_PTR_ADDR: u64 = WORK_BASE + 120;

    /// BAAV with `stark_verify` stubbed to store the claim pointer: the proof path without a proof.
    fn baav_without_converted_proof_check() -> Program {
        use tasm_lib::traits::basic_snippet::BasicSnippet;

        let entry = StarkVerify::new_with_dynamic_layout(Stark::default()).entrypoint();
        let (_, code) = BridgeAggregatedAnnouncementValidator.library_and_code();
        let mut replaced = 0;
        let code: Vec<LabelledInstruction> = code
            .into_iter()
            .flat_map(|instruction| match &instruction {
                LabelledInstruction::Instruction(AnInstruction::Call(label)) if *label == entry => {
                    replaced += 1;
                    triton_asm!(pop 1 push {CLAIM_PTR_ADDR} write_mem 1 pop 1)
                }
                _ => vec![instruction],
            })
            .collect();
        assert_eq!(replaced, 1, "BAAV calls stark_verify exactly once");
        Program::new(&code)
    }

    /// The proof-path nondeterminism: the zero-path stream with the flag set and the verifier
    /// program hash and a proof pointer inserted (no stark_verify nondeterminism needed).
    fn run_proof_path(
        pw: &PrimitiveWitness,
        claim: &AggregatedAnnouncementData,
    ) -> Result<HashMap<BFieldElement, BFieldElement>, String> {
        run_proof_path_with_verifier(pw, claim, EXPECTED_VP_HASH)
    }

    fn run_proof_path_with_verifier(
        pw: &PrimitiveWitness,
        claim: &AggregatedAnnouncementData,
        verifier_program_hash: [u64; 5],
    ) -> Result<HashMap<BFieldElement, BFieldElement>, String> {
        let w = BridgeAggregatedAnnouncementValidatorWitness::from_announcement(
            claim.clone(),
            None,
            pw.clone(),
        );
        let mut nd = w.nondeterminism();
        assert_eq!(nd.individual_tokens[0], BFieldElement::new(0));
        let mut tokens = vec![BFieldElement::new(1)];
        tokens.extend(
            verifier_program_hash
                .iter()
                .rev()
                .map(|&v| BFieldElement::new(v)),
        );
        tokens.push(BFieldElement::new(0));
        tokens.extend(nd.individual_tokens.drain(1..));
        nd.individual_tokens = tokens;
        let mut vm = VMState::new(baav_without_converted_proof_check(), w.standard_input(), nd);
        vm.run().map_err(|e| e.to_string())?;
        Ok(vm.ram)
    }

    fn exit(seed: u64, lock_script_hash: Digest) -> BurnRecord {
        BurnRecord {
            receiver_identifier: BFieldElement::new(seed),
            privacy_digest: Digest::new([BFieldElement::new(seed + 1); 5]),
            lock_script_hash,
            amount: 1_000_000,
            serial: [BFieldElement::new(seed + 2); 4],
        }
    }

    /// One pool input of `pool` coins paying each record (1 coin each) plus the change, with the
    /// settlement announcement in the kernel.
    fn settlement(
        records: &[BurnRecord],
        paid: &[BurnRecord],
        pool: u32,
        prev_state_preimage: StatePreimage,
        prev: Digest,
        exit_root: Digest,
    ) -> (PrimitiveWitness, AggregatedAnnouncementData) {
        let payouts: Vec<Utxo> = paid
            .iter()
            .map(|r| {
                Utxo::new_native_currency(
                    r.lock_script_hash,
                    NativeCurrencyAmount::from_nau(
                        i128::from(r.amount) * LEVIATHAN_UNIT_TO_NAU as i128,
                    ),
                )
            })
            .collect();
        let mut outputs = payouts;
        let change =
            NativeCurrencyAmount::coins(pool) + -NativeCurrencyAmount::coins(paid.len() as u32);
        outputs.push(Utxo::new_native_currency(
            bridge_lock_script().hash(),
            change,
        ));
        let mut pw = bridge_pw(
            &[pool_utxo(pool)],
            &outputs,
            &[],
            NativeCurrencyAmount::zero(),
            None,
        );
        for (i, r) in paid.iter().enumerate() {
            pw.output_sender_randomnesses[i] = r.sender_randomness();
            pw.output_receiver_digests[i] = r.privacy_digest;
        }
        *pw.output_receiver_digests.last_mut().unwrap() = Digest::default().hash();
        let claim = AggregatedAnnouncementData {
            prev_state_commitment: prev,
            new_state_commitment: Digest::new([BFieldElement::new(77); 5]),
            exit_root,
            faucet_id: test_faucet(),
            prev_state_preimage,
            burns: records.to_vec(),
            change_sender_randomness: pw.output_sender_randomnesses.last().copied(),
            authority_signatures: vec![],
        };
        pw.kernel = TransactionKernelModifier::default()
            .outputs(addition_records(&pw))
            .announcements(vec![claim.to_announcement()])
            .modify(pw.kernel);
        (pw, claim)
    }

    fn proof_path_accepts(settled: (PrimitiveWitness, AggregatedAnnouncementData)) {
        run_proof_path(&settled.0, &settled.1).unwrap();
    }

    /// The claim BAAV hands `stark_verify` is the fixed verifier's, for the announced faucet.
    #[test]
    fn inner_claim_binds_announced_faucet_id() {
        let records = [exit(1, lock(50))];
        let (pw, mut claim) = settlement(
            &records,
            &records,
            10,
            StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
            Digest::default(),
            chain(Digest::default(), &records),
        );
        let other_faucet = FaucetId {
            suffix: BFieldElement::new(5),
            prefix: BFieldElement::new(6),
        };
        for faucet_id in [test_faucet(), other_faucet] {
            claim.faucet_id = faucet_id;
            let pw = PrimitiveWitness {
                kernel: TransactionKernelModifier::default()
                    .announcements(vec![claim.to_announcement()])
                    .modify(pw.kernel.clone()),
                ..pw.clone()
            };
            let ram = run_proof_path(&pw, &claim).unwrap();
            let expected = Claim::new(expected_verifier_program_digest())
                .with_input(verifier_input(claim.prev_state_commitment, faucet_id))
                .with_output(
                    [
                        claim.new_state_commitment.values(),
                        claim.prev_state_commitment.values(),
                        claim.exit_root.values(),
                    ]
                    .concat(),
                )
                .encode();
            let claim_ptr = ram[&BFieldElement::new(CLAIM_PTR_ADDR)];
            let in_ram: Vec<BFieldElement> = (0..expected.len() as u64)
                .map(|i| ram[&(claim_ptr + BFieldElement::new(i))])
                .collect();
            assert_eq!(in_ram, expected);
        }
    }

    /// A verifier program other than the pinned one fails BAAV, whichever limb differs.
    #[test]
    fn foreign_verifier_program_is_refused() {
        let records = [exit(1, lock(50))];
        let (pw, claim) = settlement(
            &records,
            &records,
            10,
            StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
            Digest::default(),
            chain(Digest::default(), &records),
        );
        run_proof_path(&pw, &claim).unwrap();
        for limb in 0..EXPECTED_VP_HASH.len() {
            let mut foreign = EXPECTED_VP_HASH;
            foreign[limb] = foreign[limb].wrapping_add(1);
            let error = run_proof_path_with_verifier(&pw, &claim, foreign).unwrap_err();
            assert!(error.contains("9005005"), "limb {limb}: {error}");
        }
    }

    fn proof_path_error(settled: (PrimitiveWitness, AggregatedAnnouncementData)) -> String {
        run_proof_path(&settled.0, &settled.1).unwrap_err()
    }

    fn chain(acc: Digest, records: &[BurnRecord]) -> Digest {
        records.iter().fold(acc, |acc, r| r.fold_into(acc))
    }

    fn non_genesis_preimage() -> StatePreimage {
        StatePreimage(std::array::from_fn(|i| BFieldElement::new(100 + i as u64)))
    }

    fn lock(seed: u64) -> Digest {
        Digest::new([BFieldElement::new(seed); 5])
    }

    #[test]
    fn pays_signed_exits_from_previous_epoch_chain() {
        let preimage = non_genesis_preimage();
        let records = [exit(1, lock(50)), exit(11, lock(51))];
        let root = chain(preimage.exit_acc(), &records);
        proof_path_accepts(settlement(
            &records,
            &records,
            10,
            preimage,
            preimage.commitment(),
            root,
        ));
    }

    #[test]
    fn pays_signed_exits_from_genesis() {
        let zero = StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]);
        let records = [exit(1, lock(50))];
        let root = chain(Digest::default(), &records);
        proof_path_accepts(settlement(
            &records,
            &records,
            10,
            zero,
            Digest::default(),
            root,
        ));
    }

    /// The public builder makes the witness BAAV pays: one payout per record, then the change.
    #[test]
    fn built_settlement_passes_the_proof_path() {
        use crate::api::tx_initiation::settlement::build_settlement;
        use crate::api::tx_initiation::settlement::SettlementBuildError;
        use crate::application::config::network::Network;

        let pool = bridge_pw(
            &[pool_utxo(10)],
            &[],
            &[],
            NativeCurrencyAmount::zero(),
            None,
        );
        let build = |claim: &AggregatedAnnouncementData| {
            build_settlement(
                pool.input_utxos.utxos.clone(),
                pool.input_membership_proofs.clone(),
                pool.mutator_set_accumulator.clone(),
                claim,
                pool.kernel.timestamp,
                Network::RegTest,
            )
        };
        let records = [exit(1, lock(50)), exit(11, lock(51))];
        let mut claim = AggregatedAnnouncementData {
            exit_root: chain(Digest::default(), &records),
            burns: records.to_vec(),
            change_sender_randomness: Some(Digest::new([BFieldElement::new(7); 5])),
            ..zero_claim()
        };
        run_proof_path(&build(&claim).unwrap(), &claim).unwrap();

        claim.change_sender_randomness = None;
        assert_eq!(
            Err(SettlementBuildError::ChangeRandomnessMismatch),
            build(&claim)
        );
        claim.burns = vec![BurnRecord {
            amount: 11_000_000,
            ..exit(1, lock(50))
        }];
        assert_eq!(
            Err(SettlementBuildError::BurnsExceedPoolInputs),
            build(&claim)
        );
    }

    /// An epoch without exits still settles: exit_root must then equal the previous exit_acc.
    #[test]
    fn settles_epoch_without_exits() {
        let preimage = non_genesis_preimage();
        proof_path_accepts(settlement(
            &[],
            &[],
            10,
            preimage,
            preimage.commitment(),
            preimage.exit_acc(),
        ));
        assert!(proof_path_error(settlement(
            &[],
            &[],
            10,
            preimage,
            preimage.commitment(),
            lock(9)
        ))
        .contains("9005002"));
    }

    #[test]
    fn rejects_wrong_exit_root_and_unbound_preimage() {
        let preimage = non_genesis_preimage();
        let records = [exit(1, lock(50))];
        assert!(proof_path_error(settlement(
            &records,
            &records,
            10,
            preimage,
            preimage.commitment(),
            lock(9)
        ))
        .contains("9005002"));

        let root = chain(preimage.exit_acc(), &records);
        let mut forged = preimage;
        forged.0[13] += BFieldElement::new(1);
        assert!(proof_path_error(settlement(
            &records,
            &records,
            10,
            forged,
            preimage.commitment(),
            root
        ))
        .contains("9005003"));
    }

    #[test]
    fn rejects_unpaid_or_misdirected_exit() {
        let preimage = non_genesis_preimage();
        let records = [exit(1, lock(50)), exit(11, lock(51))];
        let root = chain(preimage.exit_acc(), &records);
        // Only the first exit is paid.
        assert!(proof_path_error(settlement(
            &records,
            &records[..1],
            10,
            preimage,
            preimage.commitment(),
            root
        ))
        .contains("9005017"));
        // The second exit is paid to another lock script.
        let misdirected = [records[0], exit(11, lock(99))];
        assert!(proof_path_error(settlement(
            &records,
            &misdirected,
            10,
            preimage,
            preimage.commitment(),
            root
        ))
        .contains("9003002"));
    }

    /// A bridge-locked native-currency UTXO whose coin state carries one extra felt.
    fn non_canonical_pool_utxo(coins: u32) -> Utxo {
        use crate::protocol::consensus::transaction::utxo::Coin;

        let mut state = NativeCurrencyAmount::coins(coins).encode();
        state.push(BFieldElement::new(0));
        let coin = Coin {
            type_script_hash: NativeCurrency.hash(),
            state,
        };
        Utxo::new(bridge_lock_script().hash(), vec![coin])
    }

    #[test]
    fn rejects_non_canonical_change_utxo() {
        let pw = settled_pw(
            &[pool_utxo(10)],
            &[non_canonical_pool_utxo(10)],
            NativeCurrencyAmount::zero(),
            None,
        );
        assert_rejects(&pw, &[9_000_020]);
    }

    /// Each amount is canonical (below 2^127), but three of them wrap a u128 sum.
    const BELOW_2_127_NAU: i128 = i128::MAX;

    #[test]
    fn rejects_pool_inputs_whose_sum_overflows() {
        let huge = Utxo::new_native_currency(
            bridge_lock_script().hash(),
            NativeCurrencyAmount::from_nau(BELOW_2_127_NAU),
        );
        let pw = settled_pw(
            &[huge.clone(), huge.clone(), huge],
            &[pool_utxo(10)],
            NativeCurrencyAmount::zero(),
            None,
        );
        assert_rejects(&pw, &[9_000_024]);
    }

    #[test]
    fn rejects_payouts_whose_sum_overflows() {
        let amount = u64::try_from(BELOW_2_127_NAU / LEVIATHAN_UNIT_TO_NAU as i128).unwrap();
        let records = [1, 11, 21].map(|seed| BurnRecord {
            amount,
            ..exit(seed, lock(50 + seed))
        });
        let preimage = non_genesis_preimage();
        let root = chain(preimage.exit_acc(), &records);
        let error = proof_path_error(settlement(
            &records,
            &records,
            10,
            preimage,
            preimage.commitment(),
            root,
        ));
        assert!(error.contains("9000025"), "{error}");
    }

    #[test]
    fn rejects_non_canonical_pool_input() {
        let pw = settled_pw(
            &[non_canonical_pool_utxo(10)],
            &[pool_utxo(10)],
            NativeCurrencyAmount::zero(),
            None,
        );
        assert_rejects(&pw, &[9_000_020]);
    }

    /// A negative change balances conservation but is not what apply rebuilds.
    #[test]
    fn rejects_negative_change() {
        let preimage = non_genesis_preimage();
        let records = [exit(1, lock(50)), exit(11, lock(51))];
        let root = chain(preimage.exit_acc(), &records);
        assert!(proof_path_error(settlement(
            &records,
            &records,
            1,
            preimage,
            preimage.commitment(),
            root
        ))
        .contains("9000023"));
    }

    crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot!(
        BridgeAggregatedAnnouncementValidator,
        "84607e7ef52c6fecfcbc247ed56cdabae450dcfd0b789c2e1ae586272f4c99ae557a6fbe0ed4592d"
    );
}
