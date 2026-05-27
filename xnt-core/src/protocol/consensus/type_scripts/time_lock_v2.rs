use std::collections::HashMap;
use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::TypeScript;
use super::TypeScriptWitness;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::utxo::Coin;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::TypeScriptAndWitness;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::protocol::proof_abstractions::SecretWitness;

#[derive(Debug, Copy, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct TimeLockV2;

impl TimeLockV2 {
    /// Create a `TimeLockV2` type-script-and-state-pair that releases the coins at the
    /// given release date, which corresponds to the number of milliseconds that passed
    /// since the unix epoch started (00:00 am UTC on Jan 1 1970).
    pub fn until(date: Timestamp) -> Coin {
        Coin {
            type_script_hash: TimeLockV2.hash(),
            state: vec![date.0],
        }
    }

    /// Get the release date from a `Utxo`, if any. If there aren't any, return
    /// the null release date.
    pub fn extract_release_date(utxo: &Utxo) -> Timestamp {
        utxo.coins()
            .iter()
            .find_map(Coin::release_date)
            .unwrap_or_else(Timestamp::zero)
    }

    pub const EXTENSION_MS: u64 = 31_556_736_000;

    pub fn target_utxo_digests() -> [Digest; 4] {
        [
            "af76d8dffd28c586ddb437ef84e2f14720434c85d274ba7dd9b3e85a1de3c9eed9f9f60f24589103",
            "e687c8e27d3026a17a50e8d7079b7bee009f488916cca9b2bb3cb4736d8c23a071d05cbb1c674aff",
            "b857b3d0ff334697b185858619245d9b27eb55bf526cc02b3edbce354a8c74802f74cc5c12ad6960",
            "0cf998a7db1cbb0b070b78a9488f3d9abe4512c4b07240418f47706453a716c30b74bd69becdb093",
        ]
        .map(|hex| Digest::try_from_hex(hex).expect("target UTXO digest hex must be valid"))
    }
}

impl TimeLockV2 {
    /// Build the program for a given target set. Production uses
    /// [`Self::target_utxo_digests`]; tests parameterize this to exercise the
    /// digest match against a constructible UTXO.
    pub(crate) fn library_and_code_for_targets(
        target_utxo_digests: &[Digest],
    ) -> (Library, Vec<LabelledInstruction>) {
        let (library, audit_preloaded_data, audit_subroutine) = {
            let mut library = Library::new();
            let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
                TimeLockV2WitnessMemory,
            >::default()));
            let audit_subroutine = library.all_imports();
            (library, audit_preloaded_data, audit_subroutine)
        };

        // Given the input-UTXO element pointer on top of the stack, set
        // mem[-18] = 1 iff Tip5::hash(&Utxo) matches one of the targets.
        // Stack-neutral: the element pointer is left on top.
        let target_flag_subroutine = {
            let mut sub = triton_asm! {
                _v2_compute_target_flag:
                // _ *utxo_element  (points at the element's size word)
                dup 0
                call tasm_langs_hash_varlen
                // _ *utxo_element [utxo_digest; 5]
            };
            for (idx, target) in target_utxo_digests.iter().enumerate() {
                // copy the digest (depth 0 first, depth 1 once the accumulator exists)
                if idx == 0 {
                    sub.extend(triton_asm! { dup 4 dup 4 dup 4 dup 4 dup 4 });
                } else {
                    sub.extend(triton_asm! { dup 5 dup 5 dup 5 dup 5 dup 5 });
                }
                // values reversed: matches tasm_langs_hash_varlen's stack order
                // under eq_digest (verified by the v2_target_utxo_* VM tests)
                for elem in target.values().iter().rev() {
                    sub.push(triton_instr!(push elem.value()));
                }
                sub.extend(triton_asm! { call tasmlib_hashing_eq_digest });
                // targets are distinct, so summing the booleans == OR-ing them
                if idx != 0 {
                    sub.extend(triton_asm! { add });
                }
            }
            sub.extend(triton_asm! {
                // _ *utxo_element [utxo_digest; 5] is_target
                push -18
                write_mem 1
                pop 1
                pop 5
                return
            });
            sub
        };

        // Generated by tasm-lang compiler
        // `tasm-lang typescript-timelock.rs type-script-time-lock.tasm`
        // 2024-09-09
        let code = triton_asm! {
        call main
        halt
        {&audit_subroutine}
        {&target_flag_subroutine}

        main:
        call tasmlib_verifier_own_program_digest
        dup 4
        dup 4
        dup 4
        dup 4
        dup 4
        push -6
        write_mem 5
        pop 1
        hint self_digest = stack[0..5]
        call tasmlib_io_read_stdin___digest
        dup 4
        dup 4
        dup 4
        dup 4
        dup 4
        push -11
        write_mem 5
        pop 1
        hint tx_kernel_digest = stack[0..5]
        call tasmlib_io_read_stdin___digest
        dup 4
        dup 4
        dup 4
        dup 4
        dup 4
        push -16
        write_mem 5
        pop 1
        hint input_utxos_digest = stack[0..5]
        call tasmlib_io_read_stdin___digest
        hint _output_utxos_digest = stack[0..5]
        push 5
        hint leaf_index = stack[0]
        call tasmlib_io_read_secin___bfe
        dup 0
        push -17
        write_mem 1
        pop 1
        hint timestamp = stack[0]
        push -17
        read_mem 1
        pop 1
        call encode_BField
        call tasm_langs_hash_varlen
        hint leaf = stack[0..5]
        push 3
        hint tree_height = stack[0]
        push -7
        read_mem 5
        pop 1
        dup 5
        dup 13
        dup 12
        dup 12
        dup 12
        dup 12
        dup 12
        call tasmlib_hashing_merkle_verify
        call tasmlib_io_read_secin___bfe
        hint input_utxos_pointer = stack[0]

        /* Audit preloaded data */
        // ... *input_utxos_pointer
        dup 0
        call {audit_preloaded_data}
        // ... *input_utxos_pointer witness_size

        pop 1
        // ... *input_utxos_pointer

        call tasmlib_io_read_secin___bfe
        split
        hint _output_utxos_pointer = stack[0..2]
        dup 2
        hint input_salted_utxos = stack[0]
        dup 0
        call tasm_langs_hash_varlen_boxed_value___SaltedUtxos
        hint input_salted_utxos_digest = stack[0..5]
        dup 4
        dup 4
        dup 4
        dup 4
        dup 4
        push -12
        read_mem 5
        pop 1
        call tasmlib_hashing_eq_digest
        assert
        dup 5
        addi 4
        hint input_utxos = stack[0]
        push 0
        hint i = stack[0]
        call _binop_Lt__LboolR_bool_32_while_loop
        pop 5
        pop 5
        pop 5
        pop 5
        pop 5
        pop 5
        pop 5
        pop 4
        return
        _binop_Eq__LboolR_bool_49_then:
        pop 1
        dup 0
        addi 1
        hint state = stack[0]
        dup 0
        read_mem 1
        pop 1
        push 1
        eq
        assert
        dup 0
        push 0
        push 1
        mul
        push 1
        add
        push 00000000001073741824
        dup 1
        lt
        assert
        add
        read_mem 1
        pop 1
        hint release_date = stack[0]
        dup 0
        split
        push -17
        read_mem 1
        pop 1
        split
        swap 3
        swap 1
        swap 3
        swap 2
        call tasmlib_arithmetic_u64_lt
        assert
        pop 1
        pop 1
        push 0
        return
        _binop_Eq__LboolR_bool_49_else:
        return
        _v2_old_hash_then:
        pop 1
        dup 5
        addi 1
        dup 0
        read_mem 1
        pop 1
        push 1
        eq
        assert
        dup 0
        push 0
        push 1
        mul
        push 1
        add
        push 00000000001073741824
        dup 1
        lt
        assert
        add
        read_mem 1
        pop 1
        // release_date += mem[-18] * 31_556_736_000  (+1 year iff target UTXO)
        push -18
        read_mem 1
        pop 1
        push 31556736000
        mul
        add
        dup 0
        split
        push -17
        read_mem 1
        pop 1
        split
        swap 3
        swap 1
        swap 3
        swap 2
        call tasmlib_arithmetic_u64_lt
        assert
        pop 1
        pop 1
        push 0
        return
        _v2_old_hash_else:
        return
        _binop_Lt__LboolR_bool_42_while_loop:
        dup 0
        dup 2
        read_mem 1
        pop 1
        swap 1
        lt
        push 0
        eq
        skiz
        return
        dup 1
        push 1
        add
        dup 1
        call tasm_langs_dynamic_list_element_finder
        pop 1
        addi 1
        hint coin = stack[0]
        dup 0
        read_mem 1
        push 00000000001073741824
        dup 2
        lt
        assert
        addi 2
        add
        push 4
        add
        read_mem 5
        pop 1
        // V2: check OLD_HASH first; if match, enforce +1 year extension.
        dup 4
        dup 4
        dup 4
        dup 4
        dup 4
        push 12484740501891840491
        push 5280486431890426245
        push 4809053857285865793
        push 14845021226026139948
        push 11493081001297792331
        call tasmlib_hashing_eq_digest
        push 1
        swap 1
        skiz
        call _v2_old_hash_then
        skiz
        call _v2_old_hash_else
        push -2
        read_mem 5
        pop 1
        call tasmlib_hashing_eq_digest
        push 1
        swap 1
        skiz
        call _binop_Eq__LboolR_bool_49_then
        skiz
        call _binop_Eq__LboolR_bool_49_else
        dup 1
        push 1
        call tasmlib_arithmetic_u32_safeadd
        swap 2
        pop 1
        pop 1
        recurse
        _binop_Lt__LboolR_bool_32_while_loop:
        dup 0
        dup 2
        read_mem 1
        pop 1
        swap 1
        lt
        push 0
        eq
        skiz
        return
        dup 1
        push 1
        add
        dup 1
        call tasm_langs_dynamic_list_element_finder
        pop 1
        // V2: set the per-UTXO target flag in mem[-18] before walking its coins
        call _v2_compute_target_flag
        addi 1
        addi 1
        hint coins = stack[0]
        push 0
        hint j = stack[0]
        call _binop_Lt__LboolR_bool_42_while_loop
        dup 2
        push 1
        call tasmlib_arithmetic_u32_safeadd
        swap 3
        pop 1
        pop 1
        pop 1
        recurse
        encode_BField:
        call tasmlib_memory_dyn_malloc
        push 1
        swap 1
        write_mem 1
        write_mem 1
        push -2
        add
        return
        tasm_langs_dynamic_list_element_finder:
        dup 0
        push 0
        eq
        skiz
        return
        swap 1
        read_mem 1
        push 00000000001073741824
        dup 2
        lt
        assert
        addi 2
        add
        swap 1
        addi -1
        recurse
        tasm_langs_hash_varlen:
        read_mem 1
        push 2
        add
        swap 1
        call tasmlib_hashing_algebraic_hasher_hash_varlen
        return
        tasm_langs_hash_varlen_boxed_value___SaltedUtxos:
        dup 0
        push 0
        addi 3
        swap 1
        addi 3
        swap 1
        dup 1
        read_mem 1
        pop 1
        push 00000000001073741824
        dup 1
        lt
        assert
        addi 1
        dup 2
        dup 1
        add
        swap 3
        pop 1
        add
        swap 1
        pop 1
        call tasmlib_hashing_algebraic_hasher_hash_varlen
        return
        tasmlib_arithmetic_u32_safeadd:
        hint input_lhs: u32 = stack[0]
        hint input_rhs: u32 = stack[1]
        add
        dup 0
        split
        pop 1
        push 0
        eq
        assert
        return
        tasmlib_arithmetic_u64_lt:
        hint lhs: u64 = stack[0..2]
        hint rhs: u64 = stack[2..4]
        swap 3
        swap 2
        dup 2
        dup 2
        lt
        swap 4
        lt
        swap 2
        eq
        mul
        add
        return
        tasmlib_hashing_absorb_multiple:
        hint len: u32 = stack[0]
        hint _sequence: void_pointer = stack[1]
        dup 0
        push 10
        swap 1
        div_mod
        swap 1
        pop 1
        swap 1
        dup 1
        push -1
        mul
        dup 3
        add
        add
        swap 1
        swap 2
        push 0
        push 0
        push 0
        push 0
        swap 4
        call tasmlib_hashing_absorb_multiple_hash_all_full_chunks
        pop 5
        push -1
        add
        push 9
        dup 2
        push -1
        mul
        add
        call tasmlib_hashing_absorb_multiple_pad_varnum_zeros
        pop 1
        push 1
        swap 2
        dup 1
        add
        call tasmlib_hashing_absorb_multiple_read_remainder
        pop 2
        sponge_absorb
        return
        tasmlib_hashing_absorb_multiple_hash_all_full_chunks:
        dup 5
        dup 1
        eq
        skiz
        return
        sponge_absorb_mem
        recurse
        tasmlib_hashing_absorb_multiple_pad_varnum_zeros:
        dup 0
        push 0
        eq
        skiz
        return
        push 0
        swap 3
        swap 2
        swap 1
        push -1
        add
        recurse
        tasmlib_hashing_absorb_multiple_read_remainder:
        dup 1
        dup 1
        eq
        skiz
        return
        read_mem 1
        swap 1
        swap 2
        swap 1
        recurse
        tasmlib_hashing_algebraic_hasher_hash_varlen:
        hint length: u32 = stack[0]
        hint _addr: void_pointer = stack[1]
        sponge_init
        call tasmlib_hashing_absorb_multiple
        sponge_squeeze
        swap 5
        pop 1
        swap 5
        pop 1
        swap 5
        pop 1
        swap 5
        pop 1
        swap 5
        pop 1
        return
        tasmlib_hashing_eq_digest:
        hint input_a4: digest = stack[0..5]
        hint input_b4: digest = stack[5..10]
        swap 6
        eq
        swap 6
        eq
        swap 6
        eq
        swap 6
        eq
        swap 2
        eq
        mul
        mul
        mul
        mul
        return
        tasmlib_hashing_merkle_verify:
        hint leaf: digest = stack[0..5]
        hint leaf_index: u32 = stack[5]
        hint tree_height: u32 = stack[6]
        hint root: digest = stack[7..12]
        dup 6
        push 2
        pow
        dup 0
        dup 7
        lt
        assert
        dup 6
        add
        swap 6
        pop 1
        dup 6
        skiz
        call tasmlib_hashing_merkle_verify_tree_height_is_not_zero
        swap 2
        swap 4
        swap 6
        pop 1
        swap 2
        swap 4
        pop 1
        assert_vector
        pop 5
        return
        tasmlib_hashing_merkle_verify_tree_height_is_not_zero:
        push 1
        swap 7
        pop 1
        call tasmlib_hashing_merkle_verify_traverse_tree
        return
        tasmlib_hashing_merkle_verify_traverse_tree:
        merkle_step
        recurse_or_return
        tasmlib_io_read_secin___bfe:
        divine 1
        return
        tasmlib_io_read_stdin___digest:
        read_io 5
        return
        tasmlib_memory_dyn_malloc:
        push -1
        read_mem 1
        pop 1
        dup 0
        push 0
        eq
        skiz
        call tasmlib_memory_dyn_malloc_initialize
        push 00000000002147483647
        dup 1
        lt
        assert
        dup 0
        push 1
        add
        push -1
        write_mem 1
        pop 1
        push 00000000004294967296
        mul
        return
        tasmlib_memory_dyn_malloc_initialize:
        pop 1
        push 1
        return
        tasmlib_verifier_own_program_digest:
        dup 15
        dup 15
        dup 15
        dup 15
        dup 15
        return
        };

        (library, code)
    }
}

impl ConsensusProgram for TimeLockV2 {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        Self::library_and_code_for_targets(&Self::target_utxo_digests())
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

impl TypeScript for TimeLockV2 {
    type State = Timestamp;
}

#[derive(Debug, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct TimeLockV2Witness {
    /// One timestamp for every input UTXO. Inputs that do not have a time lock are
    /// assigned timestamp 0, which is automatically satisfied.
    release_dates: Vec<Timestamp>,
    input_utxos: SaltedUtxos,
    transaction_kernel: TransactionKernel,
}

type TimeLockV2WitnessMemory = SaltedUtxos;

impl SecretWitness for TimeLockV2Witness {
    fn nondeterminism(&self) -> NonDeterminism {
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        let input_salted_utxos_address = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let output_salted_utxos_address = encode_to_memory::<TimeLockV2WitnessMemory>(
            &mut memory,
            input_salted_utxos_address,
            &self.input_utxos,
        );
        let individual_tokens = vec![
            self.transaction_kernel.timestamp.0,
            input_salted_utxos_address,
            output_salted_utxos_address,
        ];
        let mast_path = self
            .transaction_kernel
            .mast_path(TransactionKernelField::Timestamp)
            .clone();
        NonDeterminism::new(individual_tokens)
            .with_digests(mast_path)
            .with_ram(memory)
    }

    fn standard_input(&self) -> PublicInput {
        self.type_script_standard_input()
    }

    fn program(&self) -> Program {
        TimeLockV2.program()
    }
}

impl TypeScriptWitness for TimeLockV2Witness {
    fn transaction_kernel(&self) -> TransactionKernel {
        self.transaction_kernel.clone()
    }

    fn salted_input_utxos(&self) -> SaltedUtxos {
        self.input_utxos.clone()
    }

    fn salted_output_utxos(&self) -> SaltedUtxos {
        SaltedUtxos::empty()
    }

    fn type_script_and_witness(&self) -> TypeScriptAndWitness {
        TypeScriptAndWitness::new_with_nondeterminism(TimeLockV2.program(), self.nondeterminism())
    }

    fn new(
        transaction_kernel: TransactionKernel,
        salted_input_utxos: SaltedUtxos,
        _salted_output_utxos: SaltedUtxos,
    ) -> Self {
        let release_dates = salted_input_utxos
            .utxos
            .iter()
            .map(TimeLockV2::extract_release_date)
            .collect_vec();

        Self {
            release_dates,
            input_utxos: salted_input_utxos,
            transaction_kernel,
        }
    }
}

impl From<PrimitiveWitness> for TimeLockV2Witness {
    fn from(primitive_witness: PrimitiveWitness) -> Self {
        let release_dates = primitive_witness
            .input_utxos
            .utxos
            .iter()
            .map(TimeLockV2::extract_release_date)
            .collect_vec();
        let transaction_kernel = primitive_witness.kernel;
        let input_utxos = primitive_witness.input_utxos.clone();

        Self {
            release_dates,
            input_utxos,
            transaction_kernel,
        }
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod neptune_arbitrary {
    use num_traits::CheckedSub;
    use proptest::arbitrary::Arbitrary;
    use proptest::collection::vec;
    use proptest::strategy::BoxedStrategy;
    use proptest::strategy::Strategy;
    use proptest_arbitrary_interop::arb;

    use super::super::native_currency_amount::NativeCurrencyAmount;
    use super::*;
    use crate::protocol::consensus::transaction::announcement::Announcement;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;

    impl Arbitrary for TimeLockV2Witness {
        /// Parameters are:
        ///  - release_dates : `Vec<u64>` One release date per input UTXO. 0 if the time lock
        ///    coin is absent.
        ///  - num_outputs : usize Number of outputs.
        ///  - num_announcements : usize Number of announcements.
        ///  - transaction_timestamp: Timestamp determining when the transaction takes place.
        type Parameters = (Vec<Timestamp>, usize, usize, Timestamp);

        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
            let (release_dates, num_outputs, num_announcements, transaction_timestamp) = parameters;
            let num_inputs = release_dates.len();
            (
                vec(arb::<Digest>(), num_inputs),
                vec(NativeCurrencyAmount::arbitrary_non_negative(), num_inputs),
                vec(arb::<Digest>(), num_outputs),
                vec(NativeCurrencyAmount::arbitrary_non_negative(), num_outputs),
                vec(arb::<Announcement>(), num_announcements),
                NativeCurrencyAmount::arbitrary_coinbase(),
                NativeCurrencyAmount::arbitrary_non_negative(),
            )
                .prop_flat_map(
                    move |(
                        input_address_seeds,
                        input_amounts,
                        output_address_seeds,
                        mut output_amounts,
                        announcements,
                        maybe_coinbase,
                        mut fee,
                    )| {
                        // generate inputs
                        let (mut input_utxos, input_lock_scripts_and_witnesses) =
                            PrimitiveWitness::transaction_inputs_from_address_seeds_and_amounts(
                                &input_address_seeds,
                                &input_amounts,
                            );
                        let total_inputs = input_amounts.into_iter().sum::<NativeCurrencyAmount>();

                        // add time locks to input UTXOs (changes Utxo hash)
                        for (utxo, release_date) in input_utxos.iter_mut().zip(release_dates.iter())
                        {
                            if !release_date.is_zero() {
                                let time_lock_coin = TimeLockV2::until(*release_date);
                                let mut coins = utxo.coins().to_vec();
                                coins.push(time_lock_coin);
                                *utxo = Utxo::new(utxo.lock_script_hash(), coins);
                            }
                        }

                        // generate valid output amounts
                        PrimitiveWitness::find_balanced_output_amounts_and_fee(
                            total_inputs,
                            maybe_coinbase,
                            &mut output_amounts,
                            &mut fee,
                        );

                        // generate output UTXOs
                        let output_utxos =
                            PrimitiveWitness::valid_tx_outputs_from_amounts_and_address_seeds(
                                &output_amounts,
                                &output_address_seeds,
                                None,
                            );

                        // generate primitive transaction witness and time lock witness from there
                        PrimitiveWitness::arbitrary_primitive_witness_with(
                            &input_utxos,
                            &input_lock_scripts_and_witnesses,
                            &output_utxos,
                            &announcements,
                            NativeCurrencyAmount::zero(),
                            maybe_coinbase,
                        )
                        .prop_map(move |mut transaction_primitive_witness| {
                            let modified_kernel = TransactionKernelModifier::default()
                                .timestamp(transaction_timestamp)
                                .modify(transaction_primitive_witness.kernel);

                            transaction_primitive_witness.kernel = modified_kernel;
                            TimeLockV2Witness::from(transaction_primitive_witness)
                        })
                        .boxed()
                    },
                )
                .boxed()
        }
    }

    /// Generate a `Strategy` for a [`PrimitiveWitness`] with the given numbers of
    /// inputs, outputs, and announcements, with active timelocks.
    ///
    /// The UTXOs are timelocked with a release date set between `now` and six
    /// months from `now`.
    ///
    // Public bc used in benchmarks.
    #[doc(hidden)]
    pub fn arbitrary_primitive_witness_with_active_timelocks(
        num_inputs: usize,
        num_outputs: usize,
        num_announcements: usize,
        now: Timestamp,
    ) -> BoxedStrategy<PrimitiveWitness> {
        vec(
            Timestamp::arbitrary_between(now, now + Timestamp::months(6)),
            num_inputs + num_outputs,
        )
        .prop_flat_map(move |release_dates| {
            arbitrary_primitive_witness_with_timelocks(
                num_inputs,
                num_outputs,
                num_announcements,
                now,
                release_dates,
            )
        })
        .boxed()
    }

    /// Generate a `Strategy` for a [`PrimitiveWitness`] with the given numbers of
    /// inputs, outputs, and announcements, with expired timelocks.
    ///
    /// The UTXOs are timelocked with a release date set between six months in the
    /// past relative to `now` and `now`.
    ///
    // Public bc used in benchmarks.
    #[doc(hidden)]
    pub fn arbitrary_primitive_witness_with_expired_timelocks(
        num_inputs: usize,
        num_outputs: usize,
        num_announcements: usize,
        now: Timestamp,
    ) -> BoxedStrategy<PrimitiveWitness> {
        vec(
            Timestamp::arbitrary_between(now - Timestamp::months(6), now - Timestamp::millis(1)),
            num_inputs + num_outputs,
        )
        .prop_flat_map(move |release_dates| {
            arbitrary_primitive_witness_with_timelocks(
                num_inputs,
                num_outputs,
                num_announcements,
                now,
                release_dates,
            )
        })
        .boxed()
    }

    fn arbitrary_primitive_witness_with_timelocks(
        num_inputs: usize,
        num_outputs: usize,
        num_announcements: usize,
        now: Timestamp,
        release_dates: Vec<Timestamp>,
    ) -> BoxedStrategy<PrimitiveWitness> {
        (
            NativeCurrencyAmount::arbitrary_non_negative(),
            vec(arb::<Digest>(), num_inputs),
            vec(arb::<u64>(), num_inputs),
            vec(arb::<Digest>(), num_outputs),
            vec(arb::<u64>(), num_outputs),
            vec(arb::<Announcement>(), num_announcements),
            arb::<u64>(),
            arb::<Option<u64>>(),
        )
            .prop_flat_map(
                move |(
                    total_amount,
                    input_address_seeds,
                    input_dist,
                    output_address_seeds,
                    output_dist,
                    announcements,
                    fee_dist,
                    maybe_coinbase_dist,
                )| {
                    let maybe_coinbase_dist = if num_inputs.is_zero() {
                        maybe_coinbase_dist
                    } else {
                        None
                    };

                    // distribute total amount across inputs (+ coinbase)
                    let mut input_denominator = input_dist.iter().map(|u| *u as f64).sum::<f64>();
                    if let Some(d) = maybe_coinbase_dist {
                        input_denominator += d as f64;
                    }
                    let input_weights = input_dist
                        .into_iter()
                        .map(|u| (u as f64) / input_denominator)
                        .collect_vec();
                    let mut input_amounts = input_weights
                        .into_iter()
                        .map(|w| total_amount.to_nau_f64() * w)
                        .map(|f| NativeCurrencyAmount::try_from(f).unwrap())
                        .collect_vec();
                    let maybe_coinbase = if maybe_coinbase_dist.is_some()
                        || input_amounts.is_empty()
                    {
                        Some(
                            total_amount
                                .checked_sub(
                                    &input_amounts.iter().copied().sum::<NativeCurrencyAmount>(),
                                )
                                .unwrap(),
                        )
                    } else {
                        let sum_of_all_but_last = input_amounts
                            .iter()
                            .rev()
                            .skip(1)
                            .copied()
                            .sum::<NativeCurrencyAmount>();
                        *input_amounts.last_mut().unwrap() =
                            total_amount.checked_sub(&sum_of_all_but_last).unwrap();
                        None
                    };

                    // distribute total amount across outputs
                    let output_denominator =
                        output_dist.iter().map(|u| *u as f64).sum::<f64>() + (fee_dist as f64);
                    let output_weights = output_dist
                        .into_iter()
                        .map(|u| (u as f64) / output_denominator)
                        .collect_vec();
                    let output_amounts = output_weights
                        .into_iter()
                        .map(|w| total_amount.to_nau_f64() * w)
                        .map(|f| NativeCurrencyAmount::try_from(f).unwrap())
                        .collect_vec();
                    let total_outputs =
                        output_amounts.iter().copied().sum::<NativeCurrencyAmount>();
                    let fee = total_amount.checked_sub(&total_outputs).unwrap();

                    let (mut input_utxos, input_lock_scripts_and_witnesses) =
                        PrimitiveWitness::transaction_inputs_from_address_seeds_and_amounts(
                            &input_address_seeds,
                            &input_amounts,
                        );
                    let total_inputs = input_amounts.iter().copied().sum::<NativeCurrencyAmount>();

                    assert_eq!(
                        total_inputs + maybe_coinbase.unwrap_or(NativeCurrencyAmount::coins(0)),
                        total_outputs + fee
                    );
                    let mut output_utxos =
                        PrimitiveWitness::valid_tx_outputs_from_amounts_and_address_seeds(
                            &output_amounts,
                            &output_address_seeds,
                            None,
                        );
                    let mut counter = 0usize;
                    for utxo in &mut input_utxos {
                        let release_date = release_dates[counter];
                        let time_lock = TimeLockV2::until(release_date);
                        let mut coins = utxo.coins().to_vec();
                        coins.push(time_lock);
                        *utxo = Utxo::new(utxo.lock_script_hash(), coins);
                        counter += 1;
                    }
                    for utxo in &mut output_utxos {
                        let mut coins = utxo.coins().to_vec();
                        coins.push(TimeLockV2::until(release_dates[counter]));
                        *utxo = Utxo::new(utxo.lock_script_hash(), coins);
                        counter += 1;
                    }

                    let merge_bit = false;
                    PrimitiveWitness::arbitrary_primitive_witness_with_timestamp_and(
                        &input_utxos,
                        &input_lock_scripts_and_witnesses,
                        &output_utxos,
                        &announcements,
                        fee,
                        maybe_coinbase,
                        now,
                        merge_bit,
                    )
                    .prop_map(move |primitive_witness_template| {
                        let mut primitive_witness = primitive_witness_template.clone();
                        let modified_kernel = TransactionKernelModifier::default()
                            .timestamp(now)
                            .modify(primitive_witness.kernel);

                        primitive_witness.kernel = modified_kernel;
                        primitive_witness
                    })
                },
            )
            .boxed()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::Arbitrary;
    use proptest::prelude::Strategy;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::strategy::Just;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::twenty_first::prelude::Tip5;
    use test_strategy::proptest;

    use super::neptune_arbitrary::arbitrary_primitive_witness_with_active_timelocks;
    use super::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;
    use super::*;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

    /// Shared Rust reference for [`TimeLockV2`], parameterized by the target set
    /// so tests can exercise the digest match against a constructible UTXO.
    #[expect(clippy::needless_return)]
    fn time_lock_v2_source(target_utxo_digests: &[Digest]) {
            // get in the current program's hash digest
            let self_digest: Digest = tasm::own_program_digest();

            // read standard input:
            //  - transaction kernel mast hash
            //  - input salted utxos digest
            //  - output salted utxos digest
            // (All type scripts take this triple as input.)
            let tx_kernel_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let input_utxos_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let _output_utxos_digest: Digest = tasm::tasmlib_io_read_stdin___digest();

            // divine the timestamp and authenticate it against the kernel mast hash
            let leaf_index: u32 = 5;
            let timestamp: BFieldElement = tasm::tasmlib_io_read_secin___bfe();
            let leaf: Digest = Tip5::hash_varlen(&timestamp.encode());
            let tree_height: u32 = 3;
            tasm::tasmlib_hashing_merkle_verify(tx_kernel_digest, leaf_index, leaf, tree_height);

            // get pointers to objects living in nondeterministic memory:
            //  - input Salted UTXOs
            let input_utxos_pointer: u64 = tasm::tasmlib_io_read_secin___bfe().value();

            // it's important to read the outputs digest too, but we actually don't care about
            // the output UTXOs (in this type script)
            let _output_utxos_pointer: u64 = tasm::tasmlib_io_read_secin___bfe().value();

            // authenticate salted input UTXOs against the digest that was read from stdin
            let input_salted_utxos: SaltedUtxos =
                tasm::decode_from_memory(BFieldElement::new(input_utxos_pointer));
            let input_salted_utxos_digest: Digest = Tip5::hash(&input_salted_utxos);
            assert_eq!(input_salted_utxos_digest, input_utxos_digest);

            // V2: also recognise coins still tagged with the legacy TimeLock hash
            // and enforce a +1 year extension on their release dates.
            let old_timelock_hash: Digest = Digest([
                BFieldElement::new(11493081001297792331),
                BFieldElement::new(14845021226026139948),
                BFieldElement::new(4809053857285865793),
                BFieldElement::new(5280486431890426245),
                BFieldElement::new(12484740501891840491),
            ]);
            // V2 DIGEST FILTER: a UTXO whose Tip5::hash(&Utxo) matches one of the
            // targets gets a +1 year extension on its legacy-TimeLock release date.
            let extension_ms: u64 = TimeLockV2::EXTENSION_MS;

            // iterate over inputs
            let input_utxos = input_salted_utxos.utxos;
            let mut i = 0;
            while i < input_utxos.len() {
                // is this UTXO one of the +1 year targets?
                let utxo_digest: Digest = Tip5::hash(&input_utxos[i]);
                let mut is_target: u64 = 0;
                let mut k: usize = 0;
                while k < target_utxo_digests.len() {
                    if utxo_digest == target_utxo_digests[k] {
                        is_target = 1;
                    }
                    k += 1;
                }

                // get coins
                let coins = input_utxos[i].coins();

                // if this typescript is present
                let mut j: usize = 0;
                while j < coins.len() {
                    let coin: &Coin = &coins[j];
                    if coin.type_script_hash == old_timelock_hash {
                        let state: &Vec<BFieldElement> = &coin.state;
                        assert!(state.len() == 1);
                        let release_date: BFieldElement = state[0];
                        let rd: u64 = release_date.value();
                        let addend: u64 = is_target * extension_ms;
                        assert!(rd + addend < timestamp.value());
                    }
                    if coin.type_script_hash == self_digest {
                        // extract state
                        let state: &Vec<BFieldElement> = &coin.state;

                        // assert format
                        assert!(state.len() == 1);

                        // extract timestamp
                        let release_date: BFieldElement = state[0];

                        // test time lock
                        assert!(release_date.value() < timestamp.value());
                    }
                    j += 1;
                }
                i += 1;
            }

            return;
    }

    impl ConsensusProgramSpecification for TimeLockV2 {
        fn source(&self) {
            time_lock_v2_source(&TimeLockV2::target_utxo_digests());
        }
    }

    /// Test-only TimeLockV2 variant with a custom target set, so the digest
    /// match + the +1 year extension can be exercised against a UTXO whose
    /// preimage we control (the production targets are real UTXOs we can't forge).
    #[derive(Debug)]
    struct TimeLockV2WithTargets(Vec<Digest>);

    impl ConsensusProgram for TimeLockV2WithTargets {
        fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
            TimeLockV2::library_and_code_for_targets(&self.0)
        }

        fn hash(&self) -> Digest {
            self.program().hash()
        }
    }

    impl ConsensusProgramSpecification for TimeLockV2WithTargets {
        fn source(&self) {
            time_lock_v2_source(&self.0);
        }
    }

    #[proptest(cases = 20)]
    fn test_unlocked(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_announcements: usize,
        #[strategy(vec(Just(Timestamp::zero()), #_num_inputs))] _release_dates: Vec<Timestamp>,
        #[strategy(Just::<Timestamp>(#_release_dates.iter().copied().min().unwrap()))]
        _transaction_timestamp: Timestamp,
        #[strategy(
            TimeLockV2Witness::arbitrary_with((
                #_release_dates,
                #_num_outputs,
                #_num_announcements,
                #_transaction_timestamp,
            ))
        )]
        time_lock_witness: TimeLockV2Witness,
    ) {
        let rust_result = TimeLockV2.run_rust(
            &time_lock_witness.standard_input(),
            time_lock_witness.nondeterminism(),
        );
        prop_assert!(
            rust_result.is_ok(),
            "time lock program did not halt gracefully"
        );
        let tasm_result = TimeLockV2.run_tasm(
            &time_lock_witness.standard_input(),
            time_lock_witness.nondeterminism(),
        );
        prop_assert!(
            tasm_result.is_ok(),
            "time lock program did not halt gracefully"
        );
        prop_assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }

    #[test]
    fn tx_timestamp_same_as_release_time_must_fail() {
        // Verify use of `>`, not `>=`.
        let release_date = Timestamp::now();
        let mut test_runner = TestRunner::deterministic();
        let time_lock_witness =
            TimeLockV2Witness::arbitrary_with((vec![release_date], 1, 0, release_date))
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        assert!(
            TimeLockV2 {}
                .run_rust(
                    &time_lock_witness.standard_input(),
                    time_lock_witness.nondeterminism(),
                )
                .is_err(),
            "time lock program failed to panic"
        );
        assert!(
            TimeLockV2 {}
                .run_tasm(
                    &time_lock_witness.standard_input(),
                    time_lock_witness.nondeterminism(),
                )
                .is_err(),
            "time lock program failed to panic"
        );
    }

    #[proptest(cases = 20)]
    fn test_locked(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_announcements: usize,
        #[strategy(
            vec(
                Timestamp::arbitrary_between(
                    Timestamp::now() - Timestamp::days(7),
                    Timestamp::now() - Timestamp::days(1),
                ),
                #_num_inputs,
            )
        )]
        _release_dates: Vec<Timestamp>,
        #[strategy(Just::<Timestamp>(#_release_dates.iter().copied().max().unwrap()))]
        _tx_timestamp: Timestamp,
        #[strategy(
            TimeLockV2Witness::arbitrary_with((
                #_release_dates,
                #_num_outputs,
                #_num_announcements,
                #_tx_timestamp,
            ))
        )]
        time_lock_witness: TimeLockV2Witness,
    ) {
        println!("now: {}", Timestamp::now());
        prop_assert!(
            TimeLockV2 {}
                .run_rust(
                    &time_lock_witness.standard_input(),
                    time_lock_witness.nondeterminism(),
                )
                .is_err(),
            "time lock program failed to panic"
        );
        prop_assert!(
            TimeLockV2 {}
                .run_tasm(
                    &time_lock_witness.standard_input(),
                    time_lock_witness.nondeterminism(),
                )
                .is_err(),
            "time lock program failed to panic"
        );
    }

    #[proptest(cases = 20)]
    fn test_released(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_announcements: usize,
        #[strategy(
            vec(
                Timestamp::arbitrary_between(
                    Timestamp::now() - Timestamp::days(7),
                    Timestamp::now() - Timestamp::days(1),
                ),
                #_num_inputs,
            )
        )]
        _release_dates: Vec<Timestamp>,
        #[strategy(Just::<Timestamp>(#_release_dates.iter().copied().max().unwrap()))]
        _tx_timestamp: Timestamp,
        #[strategy(
            TimeLockV2Witness::arbitrary_with((
                #_release_dates,
                #_num_outputs,
                #_num_announcements,
                #_tx_timestamp + Timestamp::days(1),
            ))
        )]
        time_lock_witness: TimeLockV2Witness,
    ) {
        println!("now: {}", Timestamp::now());
        let rust_result = TimeLockV2.run_rust(
            &time_lock_witness.standard_input(),
            time_lock_witness.nondeterminism(),
        );
        prop_assert!(
            rust_result.is_ok(),
            "time lock program did not halt gracefully"
        );
        let tasm_result = TimeLockV2.run_tasm(
            &time_lock_witness.standard_input(),
            time_lock_witness.nondeterminism(),
        );
        prop_assert!(
            tasm_result.is_ok(),
            "time lock program did not halt gracefully"
        );
        prop_assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }

    #[proptest(cases = 5)]
    fn primitive_witness_with_active_timelocks_is_invalid(
        #[strategy(arb::<Timestamp>())] _now: Timestamp,
        #[strategy(arbitrary_primitive_witness_with_active_timelocks(2, 2, 2, #_now))]
        primitive_witness: PrimitiveWitness,
    ) {
        // Negative test: Primitive witness spending inputs that are timelocked
        // must fail to validate.
        let rt = crate::tests::tokio_runtime();
        prop_assert!(rt.block_on(primitive_witness.validate()).is_err());
    }

    #[proptest(cases = 10)]
    fn arbitrary_primitive_witness_with_active_timelocks_fails(
        #[strategy(arb::<Timestamp>())] _now: Timestamp,
        #[strategy(arbitrary_primitive_witness_with_active_timelocks(2, 2, 2, #_now))]
        primitive_witness: PrimitiveWitness,
    ) {
        let time_lock_witness = TimeLockV2Witness::from(primitive_witness);

        prop_assert!(
            TimeLockV2 {}
                .run_rust(
                    &time_lock_witness.standard_input(),
                    time_lock_witness.nondeterminism(),
                )
                .is_err(),
            "time lock program failed to panic"
        );
        prop_assert!(
            TimeLockV2 {}
                .run_tasm(
                    &time_lock_witness.standard_input(),
                    time_lock_witness.nondeterminism(),
                )
                .is_err(),
            "time lock program failed to panic"
        );
    }

    #[proptest(cases = 10)]
    fn arbitrary_primitive_witness_with_expired_timelocks_passes(
        #[strategy(arb::<Timestamp>())] _now: Timestamp,
        #[strategy(arbitrary_primitive_witness_with_expired_timelocks(2, 2, 2, #_now))]
        primitive_witness: PrimitiveWitness,
    ) {
        let time_lock_witness = TimeLockV2Witness::from(primitive_witness);

        let rust_result = TimeLockV2.run_rust(
            &time_lock_witness.standard_input(),
            time_lock_witness.nondeterminism(),
        );
        prop_assert!(
            rust_result.is_ok(),
            "time lock program did not halt gracefully"
        );
        let tasm_result = TimeLockV2.run_tasm(
            &time_lock_witness.standard_input(),
            time_lock_witness.nondeterminism(),
        );
        prop_assert!(
            tasm_result.is_ok(),
            "time lock program did not halt gracefully"
        );
        prop_assert_eq!(tasm_result.unwrap(), rust_result.unwrap());
    }

    // ============================================================
    // OLD_HASH branch tests (step 2c of the +1 year timelock fork)
    // ============================================================
    // These tests construct a witness whose input UTXOs hold a coin tagged
    // with the LEGACY TimeLock hash (OLD_HASH). The TimeLockV2 program must
    // enforce `release_date + 1 year < timestamp` on such coins, regardless
    // of whether their `release_date` has already passed under V1 rules.
    //
    // Construction strategy: start from an arbitrary V2 witness, then swap
    // the V2 coin hash for OLD_HASH on every input UTXO. The TimeLockV2
    // TASM/Rust shadow only inspects salted_input_utxos (read from memory)
    // and the kernel timestamp - both controlled here - so this swap suffices
    // to exercise the OLD_HASH branch in isolation.
    fn make_witness_with_old_hash_coins(
        release_date: Timestamp,
        tx_timestamp: Timestamp,
    ) -> TimeLockV2Witness {
        use proptest::strategy::Strategy;
        use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::protocol::consensus::type_scripts::time_lock::TimeLock;

        let mut test_runner = TestRunner::deterministic();
        // Seed with a deterministic V2 witness; we will overwrite the timelock
        // coins and tx timestamp ourselves so the strategy's choices for those
        // do not matter.
        let mut pw = arbitrary_primitive_witness_with_active_timelocks(1, 1, 0, release_date)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let new_v2_hash = TimeLockV2.hash();
        let old_hash = TimeLock.hash();
        let rewritten_utxos: Vec<Utxo> = pw
            .input_utxos
            .utxos
            .iter()
            .map(|utxo| {
                let rewritten_coins: Vec<Coin> = utxo
                    .coins()
                    .iter()
                    .map(|coin| {
                        if coin.type_script_hash == new_v2_hash {
                            // Replace V2 coin with an OLD_HASH coin at the chosen release_date.
                            Coin {
                                type_script_hash: old_hash,
                                state: vec![release_date.0],
                            }
                        } else {
                            coin.clone()
                        }
                    })
                    .collect();
                Utxo::new(utxo.lock_script_hash(), rewritten_coins)
            })
            .collect();
        pw.input_utxos = SaltedUtxos {
            utxos: rewritten_utxos,
            salt: pw.input_utxos.salt,
        };

        pw.kernel = TransactionKernelModifier::default()
            .timestamp(tx_timestamp)
            .modify(pw.kernel);

        TimeLockV2Witness::from(pw)
    }

    /// Target digests covering every input UTXO of the witness, so each
    /// OLD_HASH coin is treated as a +1 year target.
    fn targets_covering(witness: &TimeLockV2Witness) -> Vec<Digest> {
        witness
            .input_utxos
            .utxos
            .iter()
            .map(|utxo| Tip5::hash(utxo))
            .collect()
    }

    // A digest that matches no real UTXO (used as a "not a target" control).
    fn non_matching_target() -> Vec<Digest> {
        vec![Digest([
            BFieldElement::new(1),
            BFieldElement::new(2),
            BFieldElement::new(3),
            BFieldElement::new(4),
            BFieldElement::new(5),
        ])]
    }

    #[test]
    fn v2_non_target_old_hash_coin_uses_plain_timelock() {
        // The real TimeLockV2 program: arbitrary UTXOs are NOT among the targets,
        // so the +1 year extension never applies and the plain V1 lock holds:
        // spendable iff release_date < timestamp.

        // (a) released: release_date in the past, tx now -> accepted.
        let witness = make_witness_with_old_hash_coins(
            Timestamp::now() - Timestamp::days(1),
            Timestamp::now(),
        );
        assert!(TimeLockV2
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .is_ok());
        assert!(TimeLockV2
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .is_ok());

        // (b) still locked: release_date in the future, tx now -> rejected.
        let witness = make_witness_with_old_hash_coins(
            Timestamp::now() + Timestamp::days(1),
            Timestamp::now(),
        );
        assert!(TimeLockV2
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .is_err());
        assert!(TimeLockV2
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .is_err());
    }

    #[test]
    fn v2_target_utxo_rejected_within_one_year_extension() {
        // release_date now, tx at release_date + 1y - 1ms. Under the plain lock
        // this would be spendable; because the UTXO IS a target, the +1 year
        // extension pushes the effective release date past the timestamp -> reject.
        let release_date = Timestamp::now();
        let tx_timestamp = release_date + Timestamp::years(1) - Timestamp::millis(1);
        let witness = make_witness_with_old_hash_coins(release_date, tx_timestamp);

        // Sanity: a non-target program accepts (plain lock already expired).
        let control = TimeLockV2WithTargets(non_matching_target());
        assert!(control
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .is_ok());
        assert!(control
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .is_ok());

        // With the UTXO as a target, both reference and TASM must reject.
        let prog = TimeLockV2WithTargets(targets_covering(&witness));
        assert!(prog
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .is_err());
        assert!(prog
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .is_err());
    }

    #[test]
    fn v2_target_utxo_accepted_after_one_year_extension() {
        // release_date two years ago, tx now: effective release (release_date+1y)
        // is one year ago, so even a target UTXO is spendable.
        let release_date = Timestamp::now() - Timestamp::years(2);
        let tx_timestamp = Timestamp::now();
        let witness = make_witness_with_old_hash_coins(release_date, tx_timestamp);

        let prog = TimeLockV2WithTargets(targets_covering(&witness));
        let rust_result = prog.run_rust(&witness.standard_input(), witness.nondeterminism());
        let tasm_result = prog.run_tasm(&witness.standard_input(), witness.nondeterminism());
        assert!(rust_result.is_ok(), "rust shadow: {:?}", rust_result);
        assert!(tasm_result.is_ok(), "tasm: {:?}", tasm_result);
        assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }

    #[test]
    fn v2_target_utxo_rejected_exactly_at_extension_boundary() {
        // timestamp == release_date + 1y exactly must FAIL (strict `<`).
        let release_date = Timestamp::now();
        let tx_timestamp = release_date + Timestamp::years(1);
        let witness = make_witness_with_old_hash_coins(release_date, tx_timestamp);

        let prog = TimeLockV2WithTargets(targets_covering(&witness));
        assert!(prog
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .is_err());
        assert!(prog
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .is_err());
    }

    test_program_snapshot!(
        TimeLockV2,
        // TimeLockV2 hash. Frozen for the +1 year timelock hard fork. Differs from
        // TimeLock.hash(): V2 inserts an OLD_HASH check plus a Tip5(&Utxo) digest
        // filter that grants a +1 year extension to the target UTXOs. Used as
        // NEW_HASH by CollectTypeScriptsV2's remap and SingleProofV2's claim gen.
        "ac58ee89b7d8635d29b257a9ab3c34e7dcf54de25f3d43d7d0fa562ee1156803d7cbe98e874d1c16"
    );
}
