use std::collections::HashMap;
use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::library::Library;
use tasm_lib::list::contains::Contains;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use triton_vm::prelude::NonDeterminism;
use triton_vm::prelude::PublicInput;

use crate::prelude::triton_vm;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
use crate::protocol::consensus::transaction::utxo::Coin;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::tasm::push_digest_reversed;
use crate::protocol::proof_abstractions::SecretWitness;

/// Maximum number of inputs/outputs allowed. Number of UTXOs must be strictly
/// less than this number.
const MAX_NUM_INPUTS_AND_OUTPUTS: usize = 100_000;

/// Maximum number of coins per UTXO allowed. Number of coins must be strictly
/// less than this number.
const MAX_NUM_COINS_PER_UTXOS: usize = 100_000;

/// The V3 remap table — single source of truth.
///
/// Coins committed before the `UpgradeVM` hard fork carry pre-v3 type-script
/// hashes that no runnable program reproduces. Each entry maps such a hash onto
/// its current counterpart so the SingleProof layer demands a satisfiable proof:
///   legacy NativeCurrency        -> NativeCurrency.hash()
///   current + legacy TimeLock    -> TimeLockV2.hash()
///   legacy TimeLockV2            -> TimeLockV2.hash()
///
/// Consumed in lockstep by three mirrors that must agree: the host-side
/// [`CollectTypeScriptsV2Witness::output`], the TASM `v2_remap_block`, and the
/// rust `source()` shadow. Order is load-bearing for the TASM (it sets the
/// chained comparison order); the targets are distinct from every old hash, so
/// the chaining is order-independent for correctness.
fn v3_remap_pairs() -> [(Digest, Digest); 4] {
    [
        (NativeCurrency::legacy_type_script_hash(), NativeCurrency.hash()),
        (TimeLock.hash(), TimeLockV2.hash()),
        (TimeLock::legacy_type_script_hash(), TimeLockV2.hash()),
        (TimeLockV2::legacy_type_script_hash(), TimeLockV2.hash()),
    ]
}

/// Fold a collected type-script hash onto its current counterpart per
/// [`v3_remap_pairs`]; identity if unrecognised.
fn v3_remap(hash: Digest) -> Digest {
    v3_remap_pairs()
        .into_iter()
        .find_map(|(old, new)| (old == hash).then_some(new))
        .unwrap_or(hash)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct CollectTypeScriptsV2Witness {
    salted_input_utxos: SaltedUtxos,
    salted_output_utxos: SaltedUtxos,
}

impl SecretWitness for CollectTypeScriptsV2Witness {
    fn standard_input(&self) -> PublicInput {
        [&self.salted_input_utxos, &self.salted_output_utxos]
            .map(|utxos| Tip5::hash(utxos).reversed().values().to_vec())
            .concat()
            .into()
    }

    fn output(&self) -> Vec<BFieldElement> {
        // V3: collect type-script hashes from input + output UTXOs, folding every
        // recognised pre-UpgradeVM hash onto its current counterpart via the
        // shared `v3_remap` table. Host-side mirror of the TASM remap performed
        // in push_digest_from_coin_to_list.
        let type_script_hashes = Utxo::type_script_hashes(
            self.salted_input_utxos
                .utxos
                .iter()
                .chain(&self.salted_output_utxos.utxos),
        );
        let mut deduped: Vec<Digest> = vec![];
        for hash in type_script_hashes {
            let remapped = v3_remap(hash);
            if !deduped.contains(&remapped) {
                deduped.push(remapped);
            }
        }
        deduped.into_iter().flat_map(|d| d.values()).collect_vec()
    }

    fn program(&self) -> Program {
        CollectTypeScriptsV2.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

        NonDeterminism::default().with_ram(memory)
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct CollectTypeScriptsV2;

impl CollectTypeScriptsV2 {
    // cannot be triggered
    const EMPTY_TYPE_SCRIPT_HASH_LIST: i128 = 1_000_510;

    // cannot be triggered
    const FIRST_TYPE_SCRIPT_HASH_NOT_NATIVE_CURRENCY: i128 = 1_000_511;

    // cannot be triggered
    const SALTED_UTXOS_TOO_SMALL: i128 = 1_000_512;

    const NON_INTEGRAL_SALTED_UTXOS: i128 = 1_000_513;

    const TOO_MANY_INPUTS_OR_OUTPUTS: i128 = 1_000_514;

    const TOO_MANY_COINS: i128 = 1_000_515;
}

impl ConsensusProgram for CollectTypeScriptsV2 {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let field_with_size_salted_input_utxos =
            field_with_size!(CollectTypeScriptsV2Witness::salted_input_utxos);
        let field_with_size_salted_output_utxos =
            field_with_size!(CollectTypeScriptsV2Witness::salted_output_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_coins = field!(Utxo::coins);
        let field_type_script_hash = field!(Coin::type_script_hash);
        let contains = library.import(Box::new(Contains::new(DataType::Digest)));
        let new_list = library.import(Box::new(New));
        let push_digest = library.import(Box::new(Push::new(DataType::Digest)));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let eq_digest = DataType::Digest.compare();

        let collect_type_script_hashes_from_utxos =
            "neptune_consensus_transaction_collect_type_script_hashes_from_utxo".to_string();
        let collect_type_script_hashes_from_coins =
            "neptune_consensus_transaction_collect_type_script_hashes_from_coin".to_string();
        let push_digest_from_coin_to_list =
            "neptune_consensus_transaction_push_digest_to_list".to_string();
        let write_all_digests = "netpune_consensus_transaction_write_all_digests".to_string();
        let remap_to_native_currency_hash =
            "neptune_consensus_transaction_v3_remap_to_native_currency_hash".to_string();
        let remap_to_timelock_v2_hash =
            "neptune_consensus_transaction_v3_remap_to_timelock_v2_hash".to_string();
        let v2_remap_no_op = "neptune_consensus_transaction_v2_remap_no_op".to_string();

        // V3 REMAP: coins committed before the UpgradeVM hard fork carry pre-v3
        // type-script hashes that no runnable program reproduces. Fold each onto
        // its current counterpart so the SingleProof layer demands a satisfiable
        // proof:
        //   legacy NativeCurrency       -> NativeCurrency.hash()
        //   legacy + current TimeLock   -> TimeLockV2.hash()
        //   legacy TimeLockV2           -> TimeLockV2.hash()
        // Each hash is pushed in reverse value order (see `push_digest_reversed`)
        // so values()[0] ends on the stack top, matching what read_mem 5; pop 1
        // produces for digests in memory.
        let push_native_currency_hash = push_digest_reversed(NativeCurrency.hash());
        let push_timelock_v2_hash = push_digest_reversed(TimeLockV2.hash());

        // In-place remap applied to a `[digest]` on the stack top: compare it
        // against each recognised pre-v3 hash and, on a match, swap in the
        // current counterpart. Targets are distinct from every old hash, so the
        // comparisons can be chained order-independently. Reused verbatim at the
        // de-duplication check and the list-push site below.
        let make_remap_compare = |push_old: &[LabelledInstruction], target_label: &str| {
            let mut block = triton_asm! {
                // _ [digest]
                dup 4 dup 4 dup 4 dup 4 dup 4
            };
            block.extend_from_slice(push_old);
            block.extend(triton_asm! {
                {&eq_digest}
                // _ [digest] (digest == old)
                push 1
                swap 1
                skiz call {target_label}
                skiz call {v2_remap_no_op}
                // _ [digest_or_remapped]
            });
            block
        };
        // Build the chained comparison from the shared `v3_remap_pairs` table so
        // the TASM, the host `output()`, and the rust `source()` can never drift.
        // The target subroutine is picked from the pair's target hash.
        let mut v2_remap_block: Vec<LabelledInstruction> = vec![];
        for (old_hash, target_hash) in v3_remap_pairs() {
            let target_label = if target_hash == NativeCurrency.hash() {
                &remap_to_native_currency_hash
            } else {
                &remap_to_timelock_v2_hash
            };
            v2_remap_block.extend(make_remap_compare(&push_digest_reversed(old_hash), target_label));
        }
        let authenticate_salted_utxos_and_collect_hashes = triton_asm! {
            // BEFORE:
            // _ *ctsw *type_script_hashes *salted_utxos size

            dup 1 swap 1
            // _ *ctsw *type_script_hashes *salted_utxos *salted_utxos size


            /* Sanity check: Ensure salted utxos struct not too small */
            dup 0
            push 2
            lt
            assert error_id {Self::SALTED_UTXOS_TOO_SMALL}
            // _ *ctsw *type_script_hashes *salted_utxos *salted_utxos size


            call {hash_varlen}
            // _ *ctsw *type_script_hashes *salted_utxos [salted_utxos_hash]

            read_io 5
            // _ *ctsw *type_script_hashes *salted_utxos [salted_utxos_hash] [sud]

            {&eq_digest}
            assert error_id {Self::NON_INTEGRAL_SALTED_UTXOS}
            // _ *ctsw *type_script_hashes *salted_utxos

            /* Verify not too many UTXOs */
            {&field_utxos}
            // _ *ctsw *type_script_hashes *utxos_li

            read_mem 1 addi 2
            // _ *ctsw *type_script_hashes N *utxos[0]_si

            push {MAX_NUM_INPUTS_AND_OUTPUTS}
            dup 2
            lt
            // _ *ctsw *type_script_hashes N *utxos[0]_si (max_num_puts > N)

            assert error_id {Self::TOO_MANY_INPUTS_OR_OUTPUTS}
            // _ *ctsw *type_script_hashes N *utxos[0]_si

            push 0 swap 1
            // _ *ctsw *type_script_hashes N 0 *utxos[0]_si

            call {collect_type_script_hashes_from_utxos}
            // _ *ctsw *type_script_hashes N N *utxos[N]_si

            /* Ensure pointer is inside allowed ND-memory region */
            pop_count

            pop 3
            // _ *ctsw *type_script_hashes
        };

        let push_native_currency_hash_to_stack = NativeCurrency
            .hash()
            .values()
            .iter()
            .rev()
            .map(|elem| triton_instr!(push elem.value()))
            .collect_vec();

        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            CollectTypeScriptsV2Witness,
        >::default()));
        let payload = triton_asm! {

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *ctsw

            dup 0
            call {audit_preloaded_data}
            // _ *ctsw witness_size

            pop 1
            // _ *ctsw

            call {new_list}
            // _ *ctsw *type_script_hashes

            /* Push native currency hash which must always be present */
            dup 0
            {&push_native_currency_hash_to_stack}
            call {push_digest}
            // _ *ctsw *type_script_hashes

            dup 1 {&field_with_size_salted_input_utxos}
            // _ *ctsw *type_script_hashes *salted_input_utxos size

            {&authenticate_salted_utxos_and_collect_hashes}
            // _ *ctsw *type_script_hashes

            dup 1 {&field_with_size_salted_output_utxos}
            // _ *ctsw *type_script_hashes *salted_output_utxos size

            {&authenticate_salted_utxos_and_collect_hashes}
            // _ *ctsw *type_script_hashes

            read_mem 1 addi 2 swap 1
            // _ *ctsw *type_script_hashes[0] len


            /* Sanity checks of generated list of type script hashes */
            dup 0
            push 0
            lt
            assert error_id {Self::EMPTY_TYPE_SCRIPT_HASH_LIST}
            // _ *ctsw *type_script_hashes[0] len

            dup 1
            addi {Digest::LEN-1}
            read_mem {Digest::LEN}
            pop 1
            // _ *ctsw *type_script_hashes[0] len [hashes[0]]

            {&push_native_currency_hash_to_stack}
            // _ *ctsw *type_script_hashes[0] len [hashes[0]] [native_currency_hash]

            {&DataType::Digest.compare()}
            assert error_id {Self::FIRST_TYPE_SCRIPT_HASH_NOT_NATIVE_CURRENCY}
            // _ *ctsw *type_script_hashes[0] len


            /* Write all hashes to std-out */
            push {Digest::LEN} mul
            // _ *ctsw *type_script_hashes[0] size

            dup 1 add
            // _ *ctsw *type_script_hashes[0] *type_script_hashes[N+1]

            call {write_all_digests}
            // _ *ctsw *type_script_hashes[N+1] *type_script_hashes[N+1]

            pop 3
            // _

            halt

            // INVARIANT: _ *type_script_hashes N i *utxos[i]_si
            {collect_type_script_hashes_from_utxos}:
                dup 2 dup 2 eq
                // _ *type_script_hashes N i *utxos[i]_si (N==i)

                skiz return
                // _ *type_script_hashes N i *utxos[i]_si

                dup 0 addi 1 {&field_coins}
                // _ *type_script_hashes N i *utxos[i]_si *coins

                read_mem 1 addi 2
                // _ *type_script_hashes N i *utxos[i]_si len *coins[0]_si

                /* Verify not too many coins */
                push {MAX_NUM_COINS_PER_UTXOS}
                dup 2
                lt
                // _ *type_script_hashes N i *utxos[i]_si len *coins[0]_si (max_num_coins > len)

                assert error_id {Self::TOO_MANY_COINS}
                // _ *type_script_hashes N i *utxos[i]_si len *coins[0]_si

                push 0 swap 1
                // _ *type_script_hashes N i *utxos[i]_si len 0 *coins[0]_si

                call {collect_type_script_hashes_from_coins}
                // _ *type_script_hashes N i *utxos[i]_si len len *coins[len]_si


                /* Ensure pointer is inside allowed ND-memory region */
                pop_count


                pop 3
                // _ *type_script_hashes N i *utxos[i]_si

                read_mem 1 addi 2
                // _ *type_script_hashes N i size *utxos[i]

                /* Ensure forward jump, by ensuring size is u32 */
                dup 1
                pop_count
                pop 1

                add
                // _ *type_script_hashes N i *utxos[i+1]_si

                swap 1 addi 1 swap 1
                // _ *type_script_hashes N (i+1) *utxos[i+1]_si

                recurse

            // INVARIANT: _ *type_script_hashes * * * len j *coin[j]_si
            {collect_type_script_hashes_from_coins}:
                dup 2 dup 2 eq
                // _ *type_script_hashes * * * len j *coin[j]_si (len==j)

                skiz return
                // _ *type_script_hashes * * * len j *coin[j]_si

                read_mem 1 addi 2
                // _ *type_script_hashes * * * len j size *coin[j]

                dup 7 dup 0 dup 2 {&field_type_script_hash}
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes *type_script_hashes *digest

                addi {Digest::LEN-1} read_mem {Digest::LEN} pop 1
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes *type_script_hashes [digest]

                /* V3 REMAP: fold every recognised pre-v3 type-script hash onto
                   its current counterpart before the de-duplication check, so
                   legacy-tagged coins collapse onto the live program hash
                   instead of each pushing a duplicate. */
                {&v2_remap_block}
                /* end V3 REMAP */

                call {contains}
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes ([digest] in type_script_hashes)

                push 0 eq
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes ([digest] not in type_script_hashes)

                skiz call {push_digest_from_coin_to_list}
                // _ *type_script_hashes * * * len j size *coin[j] garbage

                /* Ensure forward jump, by ensuring size is u32 */
                dup 2
                pop_count
                pop 2
                // _ *type_script_hashes * * * len j size *coin[j]

                add
                // _ *type_script_hashes * * * len j *coin[j+1]_si

                swap 1 addi 1 swap 1
                // _ *type_script_hashes * * * len (j+1) *coin[j+1]_si

                recurse

            // BEFORE: _ *coin[j] *type_script_hashes
            // AFTER:  _ *coin[j] *
            //
            // After reading the coin's type_script_hash, fold it through the v3
            // remap (`v3_remap_pairs`): every recognized pre-v3 hash — legacy
            // NativeCurrency, current TimeLock, legacy TimeLock, legacy TimeLockV2
            // — is swapped for its current program hash before appending, so the
            // list holds only live program hashes. The host-side mirror lives in
            // CollectTypeScriptsV2Witness::output().
            {push_digest_from_coin_to_list}:
                dup 1
                // _ *coin[j] *type_script_hashes *coin[j]

                {&field_type_script_hash}
                // _ *coin[j] *type_script_hashes *digest

                addi {Digest::LEN-1} read_mem {Digest::LEN} pop 1
                // _ *coin[j] *type_script_hashes [digest]

                /* V3 REMAP: fold recognised pre-v3 hashes onto current ones
                   before appending, so the list holds only live program hashes. */
                {&v2_remap_block}
                // _ *coin[j] *type_script_hashes [digest_or_remapped]
                /* end V3 REMAP */

                call {push_digest}
                // _ *coin[j]

                push {0x2b00b5}

                return

            // V3: if invoked, replace the matched old digest with the current
            // NativeCurrency hash.
            // BEFORE: _ ... [old_digest] 1
            // AFTER:  _ ... [native_currency_hash] 0
            {remap_to_native_currency_hash}:
                pop 1
                pop 5
                {&push_native_currency_hash}
                push 0
                return

            // V3: if invoked, replace the matched old digest with the current
            // TimeLockV2 hash.
            // BEFORE: _ ... [old_digest] 1
            // AFTER:  _ ... [timelock_v2_hash] 0
            {remap_to_timelock_v2_hash}:
                pop 1
                pop 5
                {&push_timelock_v2_hash}
                push 0
                return

            // V3: invoked when the digest did not match this rule's old hash.
            // The outer skiz dance already left the digest in place: no-op.
            {v2_remap_no_op}:
                return

            // INVARIANT: _ *type_script_hashes[i] *type_script_hashes[N+1]
            {write_all_digests}:

                dup 1 dup 1 eq
                // _ *type_script_hashes[i] *type_script_hashes[N+1] (i==N+1)

                skiz return
                // _ *type_script_hashes[i] *type_script_hashes[N+1]

                dup 1 addi {Digest::LEN-1} read_mem {Digest::LEN}
                // _ *type_script_hashes[i] *type_script_hashes[N+1] [type_script_hashes[i]] (*type_script_hashes[i]-1)

                addi {Digest::LEN+1} swap 7 pop 1
                // _ *type_script_hashes[i+1] *type_script_hashes[N+1] [type_script_hashes[i]]

                write_io 5
                // _ *type_script_hashes[i+1] *type_script_hashes[N+1]

                recurse

        };

        let code = triton_asm! {
            {&payload}
            {&library.all_imports()}
        };

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

impl From<&PrimitiveWitness> for CollectTypeScriptsV2Witness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            salted_input_utxos: primitive_witness.input_utxos.clone(),
            salted_output_utxos: primitive_witness.output_utxos.clone(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestCaseError;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
    use tasm_lib::triton_vm;
    use tasm_lib::triton_vm::stark::Stark;
    use test_strategy::proptest;

    use super::*;
    use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::consensus::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_active_timelocks;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;

    impl ConsensusProgramSpecification for CollectTypeScriptsV2 {
        fn source(&self) {
            let siu_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let sou_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let start_address: BFieldElement =
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
            let ctsw: CollectTypeScriptsV2Witness = tasm::decode_from_memory(start_address);

            // divine in the salted input UTXOs with hash
            let salted_input_utxos: &SaltedUtxos = &ctsw.salted_input_utxos;
            let input_utxos: &Vec<Utxo> = &salted_input_utxos.utxos;

            assert!(input_utxos.len() < MAX_NUM_INPUTS_AND_OUTPUTS);

            // verify that the divined data matches with the explicit input digest
            let salted_input_utxos_hash: Digest = Tip5::hash(salted_input_utxos);
            assert_eq!(siu_digest, salted_input_utxos_hash);

            // divine in the salted output UTXOs with hash
            let salted_output_utxos: &SaltedUtxos = &ctsw.salted_output_utxos;
            let output_utxos: &Vec<Utxo> = &salted_output_utxos.utxos;

            assert!(output_utxos.len() < MAX_NUM_INPUTS_AND_OUTPUTS);

            // verify that the divined data matches with the explicit input digest
            let salted_output_utxos_hash: Digest = Tip5::hash(salted_output_utxos);
            assert_eq!(sou_digest, salted_output_utxos_hash);

            // V3: every coin still tagged with a recognised pre-UpgradeVM hash
            // gets folded onto its current counterpart (shared `v3_remap` table)
            // before being appended. Mirrors the TASM remap in
            // push_digest_from_coin_to_list.

            // iterate over all input UTXOs and collect the type script hashes
            // Because of fees, the native currency type script must *always*
            // be present.
            let mut type_script_hashes: Vec<Digest> = vec![NativeCurrency.hash()];
            let mut i = 0;
            while i < input_utxos.len() {
                let utxo: &Utxo = &input_utxos[i];

                let num_coins = utxo.coins().len();
                assert!(num_coins < MAX_NUM_COINS_PER_UTXOS);

                let mut j = 0;
                while j < num_coins {
                    let coin: &Coin = &utxo.coins()[j];
                    let remapped = v3_remap(coin.type_script_hash);
                    if !type_script_hashes.contains(&remapped) {
                        type_script_hashes.push(remapped);
                    }
                    j += 1;
                }

                i += 1;
            }

            // iterate over all output UTXOs and collect the type script hashes
            i = 0;
            while i < output_utxos.len() {
                let utxo: &Utxo = &output_utxos[i];

                let num_coins = utxo.coins().len();
                assert!(num_coins < MAX_NUM_COINS_PER_UTXOS);

                let mut j = 0;
                while j < num_coins {
                    let coin: &Coin = &utxo.coins()[j];
                    let remapped = v3_remap(coin.type_script_hash);
                    if !type_script_hashes.contains(&remapped) {
                        type_script_hashes.push(remapped);
                    }
                    j += 1;
                }

                i += 1;
            }

            // output all type script hashes
            i = 0;
            while i < type_script_hashes.len() {
                tasm::tasmlib_io_write_to_stdout___digest(type_script_hashes[i]);
                i += 1;
            }
        }
    }

    fn prop(primitive_witness: PrimitiveWitness) -> std::result::Result<(), TestCaseError> {
        let collect_type_scripts_witness = CollectTypeScriptsV2Witness::from(&primitive_witness);

        let expected_output = collect_type_scripts_witness.output();

        let rust_result = CollectTypeScriptsV2
            .run_rust(
                &collect_type_scripts_witness.standard_input(),
                collect_type_scripts_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(expected_output, rust_result.clone());

        let tasm_result = CollectTypeScriptsV2
            .run_tasm(
                &collect_type_scripts_witness.standard_input(),
                collect_type_scripts_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(rust_result, tasm_result);

        Ok(())
    }

    #[proptest(cases = 8)]
    fn native_currency_type_script_is_present_when_num_puts_are_zero(
        #[strategy(0usize..5)] _num_pub_announcements: usize,
        #[strategy(
            PrimitiveWitness::arbitrary_with_size_numbers(Some(0), 0, #_num_pub_announcements)
        )]
        primitive_witness: PrimitiveWitness,
    ) {
        let collect_type_scripts = CollectTypeScriptsV2Witness::from(&primitive_witness);
        let tasm_result = CollectTypeScriptsV2
            .run_tasm(
                &collect_type_scripts.standard_input(),
                collect_type_scripts.nondeterminism(),
            )
            .unwrap();
        assert_eq!(NativeCurrency.hash().values().to_vec(), tasm_result);
    }

    #[proptest(cases = 8)]
    fn native_currency_type_script_is_always_present(
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(
            PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, 2)
        )]
        primitive_witness: PrimitiveWitness,
    ) {
        let collect_type_scripts = CollectTypeScriptsV2Witness::from(&primitive_witness);
        let tasm_result = CollectTypeScriptsV2
            .run_tasm(
                &collect_type_scripts.standard_input(),
                collect_type_scripts.nondeterminism(),
            )
            .unwrap();

        // additionally (besides presence) verify the native currency hash comes
        // first
        assert_eq!(
            NativeCurrency.hash().values().to_vec(),
            tasm_result.into_iter().take(5).collect_vec()
        );
    }

    #[test]
    fn legacy_native_currency_coin_is_remapped_to_current_hash() {
        // PROVES THE UpgradeVM-FORK COLLECT-TYPE-SCRIPTS BUG (expected to FAIL
        // until the native-currency legacy-hash remap lands).
        //
        // A pre-fork native-currency coin carries
        // `NativeCurrency::legacy_type_script_hash()`. CollectTypeScriptsV2 must
        // fold that legacy hash into the current `NativeCurrency.hash()` — just
        // like it already remaps legacy TimeLock -> TimeLockV2 — so the
        // SingleProof layer demands a proof for a program we can actually run.
        //
        // Today there is no native-currency remap, so the legacy hash is
        // collected verbatim as a *distinct* type-script hash, for which no
        // satisfiable type-script proof exists post-fork.
        let amount = NativeCurrencyAmount::from_nau(100);
        let legacy_hash = NativeCurrency::legacy_type_script_hash();
        let input = Utxo::new(
            Digest::default(),
            amount.to_native_coins_with_type_script_hash(legacy_hash),
        );
        let witness = CollectTypeScriptsV2Witness {
            salted_input_utxos: SaltedUtxos {
                utxos: vec![input],
                salt: Default::default(),
            },
            salted_output_utxos: SaltedUtxos::empty(),
        };

        let tasm_result = CollectTypeScriptsV2
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();

        let current_values = NativeCurrency.hash().values().to_vec();
        let legacy_values = legacy_hash.values().to_vec();

        assert!(
            tasm_result
                .windows(Digest::LEN)
                .any(|window| window == current_values),
            "current native-currency hash must be present"
        );
        assert!(
            !tasm_result
                .windows(Digest::LEN)
                .any(|window| window == legacy_values),
            "legacy native-currency hash must be remapped, not collected verbatim"
        );
    }

    /// Asserts CollectTypeScriptsV2 folds a pre-v3 timelock coin into the
    /// current `TimeLockV2.hash()` instead of collecting its legacy hash
    /// verbatim. Shared by the legacy-TimeLock and legacy-TimeLockV2 cases.
    fn assert_legacy_timelock_hash_is_remapped(legacy_hash: Digest) {
        let coin = Coin {
            type_script_hash: legacy_hash,
            state: vec![bfe!(0)],
        };
        let input = Utxo::new(Digest::default(), vec![coin]);
        let witness = CollectTypeScriptsV2Witness {
            salted_input_utxos: SaltedUtxos {
                utxos: vec![input],
                salt: Default::default(),
            },
            salted_output_utxos: SaltedUtxos::empty(),
        };

        let tasm_result = CollectTypeScriptsV2
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();

        let target_values = TimeLockV2.hash().values().to_vec();
        let legacy_values = legacy_hash.values().to_vec();

        assert!(
            tasm_result
                .windows(Digest::LEN)
                .any(|window| window == target_values),
            "pre-v3 timelock coin must be remapped to current TimeLockV2 hash"
        );
        assert!(
            !tasm_result
                .windows(Digest::LEN)
                .any(|window| window == legacy_values),
            "legacy timelock hash must be remapped, not collected verbatim"
        );
    }

    #[test]
    fn legacy_timelock_coin_is_remapped_to_current_timelock_v2_hash() {
        // PROVES THE UpgradeVM-FORK BREAK for pre-v3 TimeLock coins (expected to
        // FAIL until the remap keys off the legacy hashes).
        //
        // On-chain pre-v3 TimeLock coins carry
        // `TimeLock::legacy_type_script_hash()` (4b4d2519…). The existing remap
        // only matches the *current* `TimeLock.hash()` (b35f7f6d…) — a post-v3
        // value no pre-fork coin carries — so the legacy hash is collected
        // verbatim and no satisfiable type-script proof exists for it.
        assert_legacy_timelock_hash_is_remapped(TimeLock::legacy_type_script_hash());
    }

    #[test]
    fn legacy_timelock_v2_coin_is_remapped_to_current_timelock_v2_hash() {
        // PROVES THE UpgradeVM-FORK BREAK for pre-v3 TimeLockV2 coins (expected
        // to FAIL until the remap keys off the legacy hashes).
        //
        // On-chain pre-v3 TimeLockV2 coins carry
        // `TimeLockV2::legacy_type_script_hash()` (ac58ee89…); the current
        // `TimeLockV2.hash()` is the post-v3 0fd038a5…. The existing remap does
        // not touch the legacy TimeLockV2 hash at all, so it is collected
        // verbatim.
        assert_legacy_timelock_hash_is_remapped(TimeLockV2::legacy_type_script_hash());
    }

    #[test]
    fn all_old_hashes_in_one_witness_remap_and_dedup_consistently() {
        // The full remap exercised on a SINGLE witness carrying every old hash the
        // v3 remap recognizes — legacy NativeCurrency, current TimeLock, legacy
        // TimeLock, and legacy TimeLockV2 — plus a duplicate, spread across two
        // UTXOs. The arbitrary proptests never produce legacy-tagged coins and the
        // other unit tests use one old hash in isolation, so this is the only test
        // that pins (a) host `output()` == rust shadow == TASM on legacy inputs,
        // (b) the chained remap + dedup collapsing to exactly {NativeCurrency,
        // TimeLockV2}, and (c) no old hash surviving verbatim.
        let nc_amount = NativeCurrencyAmount::from_nau(100);
        let timelock_coin = |h: Digest| Coin {
            type_script_hash: h,
            state: vec![bfe!(0)],
        };

        let utxo0 = Utxo::new(
            Digest::default(),
            nc_amount
                .to_native_coins_with_type_script_hash(NativeCurrency::legacy_type_script_hash())
                .into_iter()
                .chain([timelock_coin(TimeLock::legacy_type_script_hash())])
                .collect_vec(),
        );
        let utxo1 = Utxo::new(
            Digest::default(),
            vec![
                timelock_coin(TimeLock.hash()), // current TimeLock -> TimeLockV2
                timelock_coin(TimeLockV2::legacy_type_script_hash()), // legacy V2 -> TimeLockV2
                timelock_coin(TimeLock::legacy_type_script_hash()), // duplicate
            ],
        );

        let witness = CollectTypeScriptsV2Witness {
            salted_input_utxos: SaltedUtxos {
                utxos: vec![utxo0, utxo1],
                salt: Default::default(),
            },
            salted_output_utxos: SaltedUtxos::empty(),
        };

        let expected_output = witness.output();
        let rust_result = CollectTypeScriptsV2
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
        assert_eq!(
            expected_output, rust_result,
            "host output() must match the rust shadow on legacy inputs"
        );
        let tasm_result = CollectTypeScriptsV2
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
        assert_eq!(
            rust_result, tasm_result,
            "rust shadow must match TASM on legacy inputs"
        );

        // Deduped to exactly {NativeCurrency, TimeLockV2}: two digests.
        assert_eq!(
            tasm_result.len(),
            2 * Digest::LEN,
            "remap must dedup to exactly two type scripts, got {:?}",
            tasm_result
        );
        for present in [NativeCurrency.hash(), TimeLockV2.hash()] {
            let values = present.values().to_vec();
            assert!(
                tasm_result.windows(Digest::LEN).any(|w| w == values),
                "remapped target must be present: {present}"
            );
        }
        for old in [
            NativeCurrency::legacy_type_script_hash(),
            TimeLock::legacy_type_script_hash(),
            TimeLockV2::legacy_type_script_hash(),
            TimeLock.hash(),
        ] {
            let values = old.values().to_vec();
            assert!(
                !tasm_result.windows(Digest::LEN).any(|w| w == values),
                "old hash must be remapped, not collected verbatim: {old}"
            );
        }
    }

    #[proptest(cases = 8)]
    fn derived_witness_generates_accepting_program_proptest(
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(
            PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, 2)
        )]
        primitive_witness: PrimitiveWitness,
    ) {
        prop(primitive_witness)?;
    }

    #[proptest(cases = 8)]
    fn derived_witness_with_timelocks_generates_accepting_program_proptest(
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(arb())] _now: Timestamp,
        #[strategy(
            arbitrary_primitive_witness_with_active_timelocks(#_num_inputs, #_num_outputs, 2, #_now)
        )]
        primitive_witness: PrimitiveWitness,
    ) {
        prop(primitive_witness)?;
    }

    #[test]
    fn small_transaction_unit() {
        for num_inputs in 0..=2 {
            for num_outputs in 0..=2 {
                let mut test_runner = TestRunner::deterministic();
                let primitive_witness =
                    PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), num_outputs, 2)
                        .new_tree(&mut test_runner)
                        .unwrap()
                        .current();
                prop(primitive_witness).unwrap();
            }
        }
    }

    #[test]
    fn derived_edge_case_witnesses_with_timelock_generate_accepting_programs_unit() {
        let mut test_runner = TestRunner::deterministic();
        let deterministic_now = arb::<Timestamp>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let primitive_witness =
            arbitrary_primitive_witness_with_active_timelocks(1, 1, 2, deterministic_now)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        prop(primitive_witness).unwrap();
    }

    #[test]
    fn disallow_too_many_coins() {
        let too_many_coins = Utxo::dummy_with_num_coins(MAX_NUM_COINS_PER_UTXOS);
        let too_many_coins = SaltedUtxos {
            utxos: vec![too_many_coins],
            salt: [bfe!(0); 3],
        };

        let too_many_coins_in_input = CollectTypeScriptsV2Witness {
            salted_input_utxos: too_many_coins.clone(),
            salted_output_utxos: SaltedUtxos::empty(),
        };
        let too_many_coins_in_output = CollectTypeScriptsV2Witness {
            salted_input_utxos: SaltedUtxos::empty(),
            salted_output_utxos: too_many_coins,
        };

        for witness in [too_many_coins_in_input, too_many_coins_in_output] {
            CollectTypeScriptsV2
                .test_assertion_failure(
                    witness.standard_input(),
                    witness.nondeterminism(),
                    &[CollectTypeScriptsV2::TOO_MANY_COINS],
                )
                .unwrap();
        }
    }

    #[test]
    fn disallow_too_many_inputs_and_too_many_outputs() {
        let an_input_utxo = Utxo::empty_dummy();
        let too_many_utxos = SaltedUtxos {
            utxos: vec![an_input_utxo; MAX_NUM_INPUTS_AND_OUTPUTS],
            salt: [bfe!(0); 3],
        };

        let too_many_inputs = CollectTypeScriptsV2Witness {
            salted_input_utxos: too_many_utxos.clone(),
            salted_output_utxos: SaltedUtxos::empty(),
        };
        let too_many_outputs = CollectTypeScriptsV2Witness {
            salted_input_utxos: SaltedUtxos::empty(),
            salted_output_utxos: too_many_utxos,
        };

        for witness in [too_many_inputs, too_many_outputs] {
            CollectTypeScriptsV2
                .test_assertion_failure(
                    witness.standard_input(),
                    witness.nondeterminism(),
                    &[CollectTypeScriptsV2::TOO_MANY_INPUTS_OR_OUTPUTS],
                )
                .unwrap();
        }
    }

    #[test]
    fn collect_type_scripts_proof_generation() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let collect_type_scripts = CollectTypeScriptsV2Witness::from(&primitive_witness);
        let tasm_result = CollectTypeScriptsV2
            .run_tasm(
                &collect_type_scripts.standard_input(),
                collect_type_scripts.nondeterminism(),
            )
            .unwrap();

        assert_eq!(
            collect_type_scripts.output(),
            tasm_result.clone(),
            "incorrect output"
        );

        let claim = collect_type_scripts.claim();
        let proof = triton_vm::prove(
            Stark::default(),
            &claim,
            CollectTypeScriptsV2.program(),
            collect_type_scripts.nondeterminism(),
        )
        .expect("could not produce proof");
        assert!(
            triton_vm::verify(Stark::default(), &claim, &proof),
            "proof fails"
        );
    }

    test_program_snapshot!(
        CollectTypeScriptsV2,
        // CTS_V2_HASH frozen after step 3 of the +1 year timelock hard fork.
        // Differs from CollectTypeScripts.hash() because V2 remaps any coin
        // tagged with the legacy TimeLock hash to TimeLockV2.hash() before
        // both the de-duplication check and the list push. Used by
        // SingleProofV2's GenerateCollectTypeScriptsClaim (phase 6).
        "253714df987bb7ff9c017de9cd25683274ec0597f9879a31dfc6a7faac10a7e32ca2fc8e26316575"
    );
}
