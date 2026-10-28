use std::collections::HashMap;
use std::sync::OnceLock;

use tasm_lib::data_type::DataType;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use crate::protocol::consensus::bridge::deposit_announcement::is_deposit_tagged;
use crate::protocol::consensus::bridge::deposit_announcement::BRIDGE_DEPOSIT_ANNOUNCEMENT_LEN;
use crate::protocol::consensus::bridge::deposit_announcement::BRIDGE_DEPOSIT_TAG;
use crate::protocol::consensus::bridge::deposit_announcement::DEPOSIT_RECEIVER_DOMAIN;
use crate::protocol::consensus::bridge::deposit_announcement::MIN_BRIDGE_AMOUNT;
use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;

/// Error IDs for assertion failures.
const SALTED_OUTPUTS_HASH_MISMATCH: i128 = 6_600_002;
const DEPOSIT_COMMITMENT_MISMATCH: i128 = 6_600_003;
const DEPOSIT_ANNOUNCEMENT_LENGTH_MISMATCH: i128 = 6_600_004;
const INVALID_ACCOUNT_PREFIX: i128 = 6_600_005;
const INVALID_ACCOUNT_SUFFIX_LO: i128 = 6_600_006;
const INVALID_ACCOUNT_SUFFIX_HI: i128 = 6_600_007;
const DEPOSIT_BELOW_MINIMUM: i128 = 6_600_008;
const DEPOSIT_OUTPUT_MISSING: i128 = 6_600_009;
const DEPOSIT_RECEIVER_NOT_BOUND: i128 = 6_600_010;

/// Program-written scratch, below every nondeterministically initialized region.
const SOH_ADDR: u64 = 49_980;
const TXKMH_ADDR: u64 = 49_990;
const UTXO_ENCODING_ADDR: u64 = 54_000;
/// The 8 input elements of
/// [`deposit_receiver_preimage`](crate::protocol::consensus::bridge::deposit_announcement::deposit_receiver_preimage).
const RECEIVER_PREIMAGE_INPUT_ADDR: u64 = 54_100;

/// One window per ND region, larger than any block: no overlap, no scratch in authenticated data.
const RAM_WINDOW: u64 = 1 << 28;
const ANNOUNCEMENTS_BASE_ADDR: u64 = RAM_WINDOW;
const OUTPUT_UTXOS_BASE_ADDR: u64 = 2 * RAM_WINDOW;
/// The kernel's outputs, authenticated against the txk Outputs leaf.
const OUTPUTS_BASE_ADDR: u64 = 3 * RAM_WINDOW;
const _: () =
    assert!((ConsensusRuleSet::LeviathanSettlement.max_block_size() as u64) <= RAM_WINDOW);
const _: () = assert!(UTXO_ENCODING_ADDR + 19 < RECEIVER_PREIMAGE_INPUT_ADDR);
const _: () = assert!(RECEIVER_PREIMAGE_INPUT_ADDR + 8 < RAM_WINDOW);

/// Lazily compute the bridge_lock_script() lock script hash.
fn bridge_lock_hash() -> Digest {
    static HASH: OnceLock<Digest> = OnceLock::new();
    *HASH.get_or_init(|| bridge_lock_script().hash())
}

fn native_currency_hash() -> Digest {
    static HASH: OnceLock<Digest> = OnceLock::new();
    *HASH.get_or_init(|| NativeCurrency.hash())
}

/// Bridge deposit announcement validator.
///
/// Single-pass loop over all announcements, validating deposit announcements.
///
/// For [`BRIDGE_DEPOSIT_TAG`] announcements:
/// 1. Extract amount, utxo_commitment, sender_randomness, receiver_preimage
/// 2. Assert `receiver_preimage == deposit_receiver_preimage(account_id, sender_randomness)`
/// 3. Construct expected bridge UTXO encoding (bridge_lock + NativeCurrency coin)
/// 4. Hash → `item`, compute `canonical_commitment = commit(item, sender_randomness, hash(receiver_preimage))`
/// 5. Assert `canonical_commitment == utxo_commitment`
#[derive(Debug, Clone, Copy)]
pub struct BridgeDepositAnnouncementValidator;

impl ConsensusProgram for BridgeDepositAnnouncementValidator {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        const UTXO_ENCODING_LEN: u64 = 19;

        let mut library = Library::new();
        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let commit_snippet =
            library.import(Box::new(tasm_lib::neptune::mutator_set::commit::Commit));
        let i128_lt = library.import(Box::new(tasm_lib::arithmetic::i128::lt::Lt));
        let push_min_amount = MIN_BRIDGE_AMOUNT.push_to_stack();

        let mast_height = TransactionKernel::MAST_HEIGHT;
        let ann_field_index = TransactionKernelField::Announcements as u32;
        let outputs_field_index = TransactionKernelField::Outputs as u32;
        let compare_digests = DataType::Digest.compare();
        let find_output = "neptune_bav_find_output";

        let blh = bridge_lock_hash();
        let [bl0, bl1, bl2, bl3, bl4] = blh.values();
        let nch = native_currency_hash();
        let [nc0, nc1, nc2, nc3, nc4] = nch.values();

        let walk_ann_loop = "neptune_bav_walk_ann_loop";
        let validate_deposit = "neptune_bav_validate_deposit";

        let code = triton_asm! {
            // =====================================================
            // Public input: txk_mast_hash (5 BFEs, reversed),
            //               salted_outputs_hash (5 BFEs, reversed)
            // =====================================================

            // Step 1: Read txk_mast_hash from public input and store
            read_io 5
            push {TXKMH_ADDR}
            write_mem 5
            pop 1

            // Step 2: Read salted_outputs_hash from public input and store
            read_io 5
            push {SOH_ADDR}
            write_mem 5
            pop 1

            // Step 3: Authenticate announcements against kernel MAST
            push {TXKMH_ADDR + 4}
            read_mem 5
            pop 1

            push {mast_height}
            push {ann_field_index}

            push {ANNOUNCEMENTS_BASE_ADDR}
            read_mem 1
            pop 1

            push {ANNOUNCEMENTS_BASE_ADDR + 1}
            swap 1

            call {hash_varlen}
            call {merkle_verify}

            // Step 3b: Authenticate the kernel's outputs (addition records)
            push {TXKMH_ADDR + 4}
            read_mem 5
            pop 1
            push {mast_height}
            push {outputs_field_index}
            push {OUTPUTS_BASE_ADDR}
            read_mem 1
            pop 1
            push {OUTPUTS_BASE_ADDR + 1}
            swap 1
            call {hash_varlen}
            call {merkle_verify}

            // Step 4: Authenticate salted output UTXOs via hash comparison
            push {OUTPUT_UTXOS_BASE_ADDR}
            read_mem 1
            pop 1

            push {OUTPUT_UTXOS_BASE_ADDR + 1}
            swap 1

            call {hash_varlen}

            push {SOH_ADDR + 4}
            read_mem 5
            pop 1

            assert_vector error_id {SALTED_OUTPUTS_HASH_MISMATCH}
            pop 5

            // Step 5: Pre-write static parts of UTXO encoding (for deposits)
            push 13
            push {UTXO_ENCODING_ADDR}
            write_mem 1

            push 1
            swap 1 write_mem 1

            push 11
            swap 1 write_mem 1

            push 5
            swap 1 write_mem 1

            push 4
            swap 1 write_mem 1

            // Skip amount slots [5-8]
            addi 4

            // Write type_script_hash (NativeCurrency) at offsets 9-13
            push {nc0}
            swap 1 write_mem 1
            push {nc1}
            swap 1 write_mem 1
            push {nc2}
            swap 1 write_mem 1
            push {nc3}
            swap 1 write_mem 1
            push {nc4}
            swap 1 write_mem 1

            // Write lock_script_hash (bridge_lock) at offsets 14-18
            push {bl0}
            swap 1 write_mem 1
            push {bl1}
            swap 1 write_mem 1
            push {bl2}
            swap 1 write_mem 1
            push {bl3}
            swap 1 write_mem 1
            push {bl4}
            swap 1 write_mem 1

            pop 1

            // Step 6: Walk announcements, validate deposits and withdrawals
            push {ANNOUNCEMENTS_BASE_ADDR + 1}
            read_mem 1
            pop 1

            push {ANNOUNCEMENTS_BASE_ADDR + 2}
            swap 1

            call {walk_ann_loop}

            pop 2

            halt

            // =====================================================
            // walk_ann_loop: iterate announcements, dispatch by tag
            // Stack: _ *cursor num_remaining
            // =====================================================
            {walk_ann_loop}:
                dup 0
                push 0 eq
                skiz return

                // Read encoded_len at *cursor
                dup 1
                read_mem 1 pop 1
                // _ *cursor num_remaining encoded_len

                // --- Check for deposit tag ---
                dup 2 addi 3
                read_mem 1 pop 1
                // _ *cursor num_remaining encoded_len tag

                push {BRIDGE_DEPOSIT_TAG}
                eq
                // _ *cursor num_remaining encoded_len is_deposit

                skiz call {validate_deposit}
                // _ *cursor num_remaining encoded_len

                // Advance cursor: *cursor += 1 + encoded_len
                addi 1
                dup 2 add
                swap 2 pop 1

                // Decrement count
                addi -1

                recurse

            // =====================================================
            // validate_deposit: validate one deposit announcement
            // Stack: _ *cursor num_remaining encoded_len
            // =====================================================
            {validate_deposit}:
                // Verify msg_len == BRIDGE_DEPOSIT_ANNOUNCEMENT_LEN
                dup 2
                addi 2
                read_mem 1 pop 1

                push {BRIDGE_DEPOSIT_ANNOUNCEMENT_LEN}
                eq
                assert error_id {DEPOSIT_ANNOUNCEMENT_LENGTH_MISMATCH}

                // === Validate Leviathan AccountId (suffix at cursor+4, prefix at cursor+5) ===
                // On-chain layout: [suffix, prefix] to match Leviathan's try_from_elements(suffix, prefix).
                // Mirrors Leviathan's `account_id::validate` (v1 is the only version it accepts):
                //   prefix: version (lower 4 bits) must be 1; other bits are unconstrained

                // Check suffix (at cursor+4): lower 8 bits zero and MSB clear
                dup 2
                addi 4
                read_mem 1 pop 1
                // _ *c nr el suffix
                split
                // _ *c nr el s_hi s_lo  (st0=s_lo, st1=s_hi)
                push 256
                swap 1
                div_mod
                // div_mod: n=st0=s_lo, d=st1=256 → r=s_lo%256 (st0), q=s_lo/256 (st1)
                // _ *c nr el s_hi q r
                push 0 eq
                assert error_id {INVALID_ACCOUNT_SUFFIX_LO}
                pop 1
                // _ *c nr el s_hi

                // MSB clear: s_hi < 2^31
                push 2147483648
                swap 1
                // _ *c nr el 2^31 s_hi
                lt
                // lt: a=st0=s_hi, b=st1=2^31 → (s_hi < 2^31)
                assert error_id {INVALID_ACCOUNT_SUFFIX_HI}
                // _ *c nr el

                // Check prefix (at cursor+5) version: lower 4 bits must be 1
                dup 2
                addi 5
                read_mem 1 pop 1
                // _ *c nr el prefix
                split
                // _ *c nr el p_hi p_lo  (st0=p_lo, st1=p_hi)
                push 16
                swap 1
                div_mod
                // div_mod: n=st0=p_lo, d=st1=16 → r=p_lo%16 (st0), q=p_lo/16 (st1)
                // _ *c nr el p_hi q r
                push 1 eq
                assert error_id {INVALID_ACCOUNT_PREFIX}
                pop 2
                // _ *c nr el

                // === The receiver preimage binds the account, so a copied commitment mints to it ===
                dup 2 addi 17 read_mem 5 pop 1
                push {RECEIVER_PREIMAGE_INPUT_ADDR + 3} write_mem 5 pop 1
                dup 2 addi 5 read_mem 2 pop 1
                push {RECEIVER_PREIMAGE_INPUT_ADDR + 1} write_mem 2 pop 1
                push {DEPOSIT_RECEIVER_DOMAIN}
                push {RECEIVER_PREIMAGE_INPUT_ADDR} write_mem 1 pop 1
                push {RECEIVER_PREIMAGE_INPUT_ADDR} push 8 call {hash_varlen}
                // _ *c nr el [derived; 5]
                dup 7 addi 22 read_mem 5 pop 1
                assert_vector error_id {DEPOSIT_RECEIVER_NOT_BOUND}
                pop 5
                // _ *c nr el

                // === Step A: Hash receiver_preimage → receiver_digest ===
                // Digest::hash() = Tip5::hash_pair(self, ALL_ZERO)
                // In Triton VM: push [0;5] then [preimage;5], then `hash`
                push 0 push 0 push 0 push 0 push 0
                dup 7
                addi 22
                read_mem 5 pop 1
                hash
                // _ *cursor num_remaining encoded_len [rd; 5]

                // === Step B: Read sender_randomness (cursor+13..17) ===
                dup 7
                addi 17
                read_mem 5 pop 1
                // _ *cursor num_remaining encoded_len [rd; 5] [sr; 5]

                // === Step C: Convert amount and hash UTXO encoding → item ===
                dup 12
                addi 6
                read_mem 1 pop 1

                split

                push {UTXO_ENCODING_ADDR + 5}
                write_mem 2
                pop 1

                dup 12
                addi 7
                read_mem 1 pop 1

                split

                push {UTXO_ENCODING_ADDR + 7}
                write_mem 2
                pop 1

                // amount >= MIN_BRIDGE_AMOUNT (amount limbs are now at UTXO_ENCODING_ADDR+5..+8)
                {&push_min_amount}
                push {UTXO_ENCODING_ADDR + 8}
                read_mem 4
                pop 1
                call {i128_lt}
                push 0 eq
                assert error_id {DEPOSIT_BELOW_MINIMUM}
                // _ *cursor num_remaining encoded_len [rd; 5] [sr; 5]

                push {UTXO_ENCODING_ADDR}
                push {UTXO_ENCODING_LEN}
                call {hash_varlen}
                // _ *cursor num_remaining encoded_len [rd; 5] [sr; 5] [item; 5]

                // === Step D: Call Commit ===
                call {commit_snippet}
                // _ *cursor num_remaining encoded_len [cc; 5]

                // === Step E: Read utxo_commitment from announcement (cursor+8..12) ===
                dup 7
                addi 12
                read_mem 5 pop 1

                // === Assert cc == uc ===
                assert_vector error_id {DEPOSIT_COMMITMENT_MISMATCH}
                // _ *cursor num_remaining encoded_len [cc; 5]

                // === The locked UTXO must be one of the tx's outputs ===
                push {OUTPUTS_BASE_ADDR + 1} read_mem 1 pop 1
                push {OUTPUTS_BASE_ADDR + 2}
                call {find_output}
                pop 2
                pop 5

                return

            // _ [cc; 5] n *ar -> _ [cc; 5] n' *ar' at the first output equal to cc; fails if none
            {find_output}:
                dup 1 push 0 eq push 0 eq
                assert error_id {DEPOSIT_OUTPUT_MISSING}
                dup 6 dup 6 dup 6 dup 6 dup 6
                dup 5 addi {Digest::LEN as u64 - 1} read_mem {Digest::LEN} pop 1
                {&compare_digests}
                skiz return
                addi {Digest::LEN as u64}
                swap 1 addi -1 swap 1
                recurse

            {&library.all_imports()}
        };

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();
        *HASH.get_or_init(|| self.program().hash())
    }
}

/// Witness for the combined bridge announcement validator.
#[derive(Debug)]
pub struct BridgeDepositAnnouncementValidatorWitness {
    pub transaction_kernel: TransactionKernel,
    pub salted_output_utxos: SaltedUtxos,
}

impl SecretWitness for BridgeDepositAnnouncementValidatorWitness {
    fn nondeterminism(&self) -> NonDeterminism {
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();

        // Store announcements encoding at ANNOUNCEMENTS_BASE_ADDR
        let ann_enc = self.transaction_kernel.announcements.encode();
        memory.insert(
            BFieldElement::new(ANNOUNCEMENTS_BASE_ADDR),
            BFieldElement::new(ann_enc.len() as u64),
        );
        for (i, &v) in ann_enc.iter().enumerate() {
            memory.insert(
                BFieldElement::new(ANNOUNCEMENTS_BASE_ADDR + 1 + i as u64),
                v,
            );
        }

        // Store salted output UTXOs encoding at OUTPUT_UTXOS_BASE_ADDR
        let out_enc = self.salted_output_utxos.encode();
        memory.insert(
            BFieldElement::new(OUTPUT_UTXOS_BASE_ADDR),
            BFieldElement::new(out_enc.len() as u64),
        );
        for (i, &v) in out_enc.iter().enumerate() {
            memory.insert(BFieldElement::new(OUTPUT_UTXOS_BASE_ADDR + 1 + i as u64), v);
        }

        let outputs_enc = self.transaction_kernel.outputs.encode();
        memory.insert(
            BFieldElement::new(OUTPUTS_BASE_ADDR),
            BFieldElement::new(outputs_enc.len() as u64),
        );
        for (i, &v) in outputs_enc.iter().enumerate() {
            memory.insert(BFieldElement::new(OUTPUTS_BASE_ADDR + 1 + i as u64), v);
        }

        let digests = [
            self.transaction_kernel
                .mast_path(TransactionKernelField::Announcements),
            self.transaction_kernel
                .mast_path(TransactionKernelField::Outputs),
        ]
        .concat();

        NonDeterminism::new(vec![])
            .with_ram(memory)
            .with_digests(digests)
    }

    fn standard_input(&self) -> PublicInput {
        let txkmh = self.transaction_kernel.mast_hash().reversed().values();
        let soh = Tip5::hash(&self.salted_output_utxos).reversed().values();
        PublicInput::new([txkmh, soh].concat())
    }

    fn output(&self) -> Vec<BFieldElement> {
        vec![]
    }

    fn program(&self) -> Program {
        BridgeDepositAnnouncementValidator.program()
    }
}

impl From<&crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness>
    for BridgeDepositAnnouncementValidatorWitness
{
    fn from(
        pw: &crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness,
    ) -> Self {
        Self {
            transaction_kernel: pw.kernel.clone(),
            salted_output_utxos: pw.output_utxos.clone(),
        }
    }
}

/// Count the number of bridge deposit announcements in a list.
pub fn count_deposit_announcements(
    announcements: &[crate::protocol::consensus::transaction::announcement::Announcement],
) -> usize {
    announcements
        .iter()
        .filter(|a| is_deposit_tagged(a))
        .count()
}

/// Count the number of bridge lock UTXOs in a list.
pub fn count_bridge_lock_utxos(utxos: &[Utxo]) -> usize {
    let blh = bridge_lock_hash();
    utxos.iter().filter(|u| u.lock_script_hash() == blh).count()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::protocol::consensus::bridge::deposit_announcement::deposit_receiver_preimage;
    use crate::protocol::consensus::bridge::deposit_announcement::BridgeDepositData;
    use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
    use crate::protocol::consensus::transaction::announcement::Announcement;
    use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::commit;

    impl ConsensusProgramSpecification for BridgeDepositAnnouncementValidator {
        fn source(&self) {
            todo!()
        }
    }

    /// Large amount above MIN_BRIDGE_AMOUNT with nonzero hi word.
    const BIG: i128 = 10_000_000_000_000_000_000_000_000_000_000i128;

    /// A kernel whose outputs are exactly the locked UTXOs its deposits announce.
    fn make_kernel(announcements: Vec<Announcement>) -> TransactionKernel {
        let outputs = announcements
            .iter()
            .filter_map(BridgeDepositData::from_announcement)
            .map(|d| AdditionRecord::new(Digest::new(d.utxo_commitment)))
            .collect();
        make_kernel_with_outputs(announcements, outputs)
    }

    fn make_kernel_with_outputs(
        announcements: Vec<Announcement>,
        outputs: Vec<AdditionRecord>,
    ) -> TransactionKernel {
        TransactionKernelProxy {
            inputs: vec![],
            outputs,
            announcements,
            fee: NativeCurrencyAmount::coins(0),
            coinbase: None,
            timestamp: Timestamp::now(),
            mutator_set_hash: Digest::default(),
            merge_bit: false,
        }
        .into_kernel()
    }

    fn make_salted_utxos(utxos: Vec<Utxo>) -> SaltedUtxos {
        SaltedUtxos {
            utxos,
            salt: [BFieldElement::new(0); 3],
        }
    }

    fn make_bridge_utxo(amount: NativeCurrencyAmount) -> Utxo {
        let lock_script = bridge_lock_script();
        Utxo::new(lock_script.hash(), amount.to_native_coins())
    }

    /// `[suffix, prefix]` of real ids from miden-protocol 0.17 `AccountId::new` (private,
    /// public, public + asset callbacks); each accepted by `AccountId::try_from_elements`.
    const LEVIATHAN_V1_ACCOUNT_IDS: [[u64; 2]; 3] = [
        [0x7db0_664f_500c_4c00, 0x6942_9324_3acf_dec1],
        [0x0bda_0b7e_3c48_c100, 0xf7b2_4712_1dc5_db91],
        [0x0195_fbfb_9a0b_c800, 0xec4f_3f95_359e_8bf1],
    ];

    /// A pre-0.17 (version 0) id, which miden-protocol 0.17 rejects.
    const LEVIATHAN_V0_ACCOUNT_ID: [u64; 2] = [0x3deb_3f98_cbb6_ba00, 0xa3b3_3575_1786_7920];

    fn account_id(id: [u64; 2]) -> [BFieldElement; 2] {
        id.map(BFieldElement::new)
    }

    fn valid_account_id() -> [BFieldElement; 2] {
        account_id(LEVIATHAN_V1_ACCOUNT_IDS[0])
    }

    fn make_deposit_announcement(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
    ) -> Announcement {
        let receiver_preimage = deposit_receiver_preimage(valid_account_id(), sender_randomness);
        let lock_script_hash = bridge_lock_script().hash();
        let utxo = Utxo::new(lock_script_hash, amount.to_native_coins());
        let item = Tip5::hash(&utxo);
        let receiver_digest = receiver_preimage.hash();
        let addition_record = commit(item, sender_randomness, receiver_digest);
        let utxo_commitment = addition_record.canonical_commitment.values();

        let data = BridgeDepositData {
            account_id: valid_account_id(),
            amount,
            utxo_commitment,
            sender_randomness: sender_randomness.values(),
            receiver_preimage: receiver_preimage.values(),
        };
        data.to_announcement()
    }

    fn make_witness(
        kernel: &TransactionKernel,
        salted_utxos: SaltedUtxos,
    ) -> BridgeDepositAnnouncementValidatorWitness {
        BridgeDepositAnnouncementValidatorWitness {
            transaction_kernel: kernel.clone(),
            salted_output_utxos: salted_utxos,
        }
    }

    // ========================== Deposit tests ==========================

    #[test]
    fn no_announcements_passes() {
        let kernel = make_kernel(vec![]);
        let utxos = make_salted_utxos(vec![]);
        let witness = make_witness(&kernel, utxos);
        let result = BridgeDepositAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism());
        assert!(result.is_ok(), "No announcements should pass");
    }

    #[test]
    fn one_deposit_correct_commitment() {
        let amount = NativeCurrencyAmount::from_nau(BIG);
        let sr = Digest::new([BFieldElement::new(111); 5]);
        let ann = make_deposit_announcement(amount, sr);
        let utxo = make_bridge_utxo(amount);
        let kernel = make_kernel(vec![ann]);
        let utxos = make_salted_utxos(vec![utxo]);
        let witness = make_witness(&kernel, utxos);
        let result = BridgeDepositAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism());
        assert!(
            result.is_ok(),
            "One deposit with correct commitment should pass"
        );
    }

    #[test]
    fn deposit_wrong_commitment_fails() {
        let amount = NativeCurrencyAmount::from_nau(BIG);
        let data = BridgeDepositData {
            account_id: valid_account_id(),
            amount,
            utxo_commitment: [BFieldElement::new(99); 5],
            sender_randomness: [BFieldElement::new(0); 5],
            receiver_preimage: deposit_receiver_preimage(valid_account_id(), Digest::default())
                .values(),
        };
        let ann = data.to_announcement();
        let utxo = make_bridge_utxo(amount);
        let kernel = make_kernel(vec![ann]);
        let utxos = make_salted_utxos(vec![utxo]);
        let witness = make_witness(&kernel, utxos);
        let result = BridgeDepositAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism());
        assert!(result.is_err(), "Wrong utxo_commitment must fail");
    }

    #[test]
    fn deposit_wrong_amount_fails() {
        let real_amount = NativeCurrencyAmount::from_nau(BIG);
        let sr = Digest::new([BFieldElement::new(42); 5]);
        let rp = deposit_receiver_preimage(valid_account_id(), sr);

        let lock_script_hash = bridge_lock_script().hash();
        let utxo = Utxo::new(lock_script_hash, real_amount.to_native_coins());
        let item = Tip5::hash(&utxo);
        let rd = rp.hash();
        let real_commitment = commit(item, sr, rd);

        let data = BridgeDepositData {
            account_id: valid_account_id(),
            amount: NativeCurrencyAmount::from_nau(BIG + 1),
            utxo_commitment: real_commitment.canonical_commitment.values(),
            sender_randomness: sr.values(),
            receiver_preimage: rp.values(),
        };
        let ann = data.to_announcement();
        let kernel = make_kernel(vec![ann]);
        let utxos = make_salted_utxos(vec![make_bridge_utxo(real_amount)]);
        let witness = make_witness(&kernel, utxos);
        BridgeDepositAnnouncementValidator
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[DEPOSIT_COMMITMENT_MISMATCH],
            )
            .unwrap();
    }

    #[test]
    fn two_deposits_correct_commitments() {
        let a1 = NativeCurrencyAmount::from_nau(BIG);
        let a2 = NativeCurrencyAmount::from_nau(BIG + 100);
        let sr1 = Digest::new([BFieldElement::new(11); 5]);
        let sr2 = Digest::new([BFieldElement::new(22); 5]);
        let ann1 = make_deposit_announcement(a1, sr1);
        let ann2 = make_deposit_announcement(a2, sr2);
        let u1 = make_bridge_utxo(a1);
        let u2 = make_bridge_utxo(a2);
        let kernel = make_kernel(vec![ann1, ann2]);
        let utxos = make_salted_utxos(vec![u1, u2]);
        let witness = make_witness(&kernel, utxos);
        let result = BridgeDepositAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism());
        assert!(
            result.is_ok(),
            "Two deposits with correct commitments should pass"
        );
    }

    #[test]
    fn deposit_announcing_another_account_fails() {
        let amount = NativeCurrencyAmount::from_nau(BIG);
        let honest = BridgeDepositData::from_announcement(&make_deposit_announcement(
            amount,
            Digest::new([BFieldElement::new(111); 5]),
        ))
        .unwrap();
        let copy = BridgeDepositData {
            account_id: account_id(LEVIATHAN_V1_ACCOUNT_IDS[1]),
            ..honest
        };
        let kernel = make_kernel(vec![copy.to_announcement()]);
        let witness = make_witness(&kernel, make_salted_utxos(vec![make_bridge_utxo(amount)]));
        BridgeDepositAnnouncementValidator
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[DEPOSIT_RECEIVER_NOT_BOUND],
            )
            .unwrap();
    }

    // ========================== Mixed tests ==========================

    #[test]
    fn mixed_deposit_and_non_bridge() {
        let amount = NativeCurrencyAmount::from_nau(BIG);
        let sr = Digest::new([BFieldElement::new(55); 5]);
        let deposit_ann = make_deposit_announcement(amount, sr);

        let normal_ann = Announcement::new(vec![BFieldElement::new(999999)]);
        let bridge_utxo = make_bridge_utxo(amount);

        let kernel = make_kernel(vec![normal_ann, deposit_ann]);
        let utxos = make_salted_utxos(vec![bridge_utxo]);
        let witness = make_witness(&kernel, utxos);
        let result = BridgeDepositAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism());
        assert!(result.is_ok(), "Mixed deposit + normal should pass");
    }

    #[test]
    fn non_bridge_tag_ignored() {
        let ann = Announcement::new(vec![BFieldElement::new(999999)]);
        let kernel = make_kernel(vec![ann]);
        let utxos = make_salted_utxos(vec![]);
        let witness = make_witness(&kernel, utxos);
        let result = BridgeDepositAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism());
        assert!(result.is_ok(), "Non-bridge tag should be ignored");
    }

    // ========================== Account ID validation tests ==========================

    /// Helper: build a deposit announcement with a specific account_id and correct commitment.
    fn make_deposit_with_account_id(
        account_id: [BFieldElement; 2],
        amount: NativeCurrencyAmount,
        sr: Digest,
    ) -> Announcement {
        let rp = deposit_receiver_preimage(account_id, sr);
        let lock_script_hash = bridge_lock_script().hash();
        let utxo = Utxo::new(lock_script_hash, amount.to_native_coins());
        let item = Tip5::hash(&utxo);
        let rd = rp.hash();
        let addition_record = commit(item, sr, rd);
        let data = BridgeDepositData {
            account_id,
            amount,
            utxo_commitment: addition_record.canonical_commitment.values(),
            sender_randomness: sr.values(),
            receiver_preimage: rp.values(),
        };
        data.to_announcement()
    }

    fn account_id_witness(
        account_id: [BFieldElement; 2],
    ) -> BridgeDepositAnnouncementValidatorWitness {
        deposit_witness(account_id, NativeCurrencyAmount::from_nau(BIG))
    }

    fn deposit_witness(
        account_id: [BFieldElement; 2],
        amount: NativeCurrencyAmount,
    ) -> BridgeDepositAnnouncementValidatorWitness {
        let sr = Digest::new([BFieldElement::new(111); 5]);
        let ann = make_deposit_with_account_id(account_id, amount, sr);
        let kernel = make_kernel(vec![ann]);
        make_witness(&kernel, make_salted_utxos(vec![make_bridge_utxo(amount)]))
    }

    fn assert_account_id_rejected(account_id: [BFieldElement; 2], error_id: i128) {
        let witness = account_id_witness(account_id);
        BridgeDepositAnnouncementValidator
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[error_id],
            )
            .unwrap();
    }

    #[test]
    fn real_leviathan_v1_account_ids_pass() {
        for id in LEVIATHAN_V1_ACCOUNT_IDS {
            let witness = account_id_witness(account_id(id));
            BridgeDepositAnnouncementValidator
                .run_tasm(&witness.standard_input(), witness.nondeterminism())
                .unwrap_or_else(|e| panic!("v1 id {id:x?} must pass: {e:?}"));
        }
    }

    #[test]
    fn v0_account_id_fails() {
        assert_account_id_rejected(account_id(LEVIATHAN_V0_ACCOUNT_ID), INVALID_ACCOUNT_PREFIX);
    }

    #[test]
    fn other_prefix_versions_fail() {
        let [suffix, prefix] = LEVIATHAN_V1_ACCOUNT_IDS[0];
        for version in (0..16).filter(|v| *v != 1) {
            let bad_prefix = (prefix & !0xf) | version;
            assert_account_id_rejected(account_id([suffix, bad_prefix]), INVALID_ACCOUNT_PREFIX);
        }
    }

    #[test]
    fn invalid_suffix_lower_byte_fails() {
        let [suffix, prefix] = LEVIATHAN_V1_ACCOUNT_IDS[0];
        assert_account_id_rejected(
            account_id([suffix | 0x01, prefix]),
            INVALID_ACCOUNT_SUFFIX_LO,
        );
    }

    #[test]
    fn invalid_suffix_msb_set_fails() {
        let [suffix, prefix] = LEVIATHAN_V1_ACCOUNT_IDS[0];
        assert_account_id_rejected(
            account_id([suffix | (1 << 63), prefix]),
            INVALID_ACCOUNT_SUFFIX_HI,
        );
    }

    #[test]
    fn minimum_amount_passes() {
        let witness = deposit_witness(valid_account_id(), MIN_BRIDGE_AMOUNT);
        BridgeDepositAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
    }

    #[test]
    fn below_minimum_amount_fails() {
        // One nau short; the default faucet mint fee (500 of the 10^6 WXNT units per coin); one nau.
        let below = [
            MIN_BRIDGE_AMOUNT.to_nau() - 1,
            MIN_BRIDGE_AMOUNT.to_nau() / 1_000_000 * 500,
            1,
        ];
        for nau in below {
            let witness = deposit_witness(valid_account_id(), NativeCurrencyAmount::from_nau(nau));
            BridgeDepositAnnouncementValidator
                .test_assertion_failure(
                    witness.standard_input(),
                    witness.nondeterminism(),
                    &[DEPOSIT_BELOW_MINIMUM],
                )
                .unwrap();
        }
    }

    fn lock_witness(outputs: Vec<AdditionRecord>) -> BridgeDepositAnnouncementValidatorWitness {
        let amount = NativeCurrencyAmount::from_nau(BIG);
        let ann = make_deposit_announcement(amount, Digest::new([BFieldElement::new(111); 5]));
        let kernel = make_kernel_with_outputs(vec![ann], outputs);
        make_witness(&kernel, make_salted_utxos(vec![make_bridge_utxo(amount)]))
    }

    /// A well-formed lock whose UTXO is not among the tx's outputs mints nothing.
    #[test]
    fn lock_without_its_output_fails() {
        for outputs in [
            vec![],
            vec![AdditionRecord::new(Digest::new([BFieldElement::new(9); 5]))],
        ] {
            let witness = lock_witness(outputs);
            BridgeDepositAnnouncementValidator
                .test_assertion_failure(
                    witness.standard_input(),
                    witness.nondeterminism(),
                    &[DEPOSIT_OUTPUT_MISSING],
                )
                .unwrap();
        }
    }

    #[test]
    fn lock_found_among_other_outputs() {
        let amount = NativeCurrencyAmount::from_nau(BIG);
        let ann = make_deposit_announcement(amount, Digest::new([BFieldElement::new(111); 5]));
        let locked = Digest::new(
            BridgeDepositData::from_announcement(&ann)
                .unwrap()
                .utxo_commitment,
        );
        let other = AdditionRecord::new(Digest::new([BFieldElement::new(9); 5]));
        let witness = lock_witness(vec![other, AdditionRecord::new(locked), other]);
        BridgeDepositAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
    }

    /// Large announcements must not reach other RAM regions or the scratch writes.
    #[test]
    fn deposit_behind_large_announcements_is_validated() {
        let amount = NativeCurrencyAmount::from_nau(BIG);
        let padding = Announcement::new(vec![BFieldElement::new(7); 20_000]);
        let utxos = make_salted_utxos(vec![make_bridge_utxo(amount); 500]);

        let honest = make_deposit_announcement(amount, Digest::new([BFieldElement::new(111); 5]));
        let honest_kernel = make_kernel(vec![padding.clone(), honest]);
        let honest_witness = make_witness(&honest_kernel, utxos.clone());
        BridgeDepositAnnouncementValidator
            .run_tasm(
                &honest_witness.standard_input(),
                honest_witness.nondeterminism(),
            )
            .unwrap();

        let forged = BridgeDepositData {
            account_id: valid_account_id(),
            amount,
            utxo_commitment: [BFieldElement::new(99); 5],
            sender_randomness: [BFieldElement::new(0); 5],
            receiver_preimage: deposit_receiver_preimage(valid_account_id(), Digest::default())
                .values(),
        }
        .to_announcement();
        let forged_kernel = make_kernel(vec![padding, forged]);
        let forged_witness = make_witness(&forged_kernel, utxos);
        BridgeDepositAnnouncementValidator
            .test_assertion_failure(
                forged_witness.standard_input(),
                forged_witness.nondeterminism(),
                &[DEPOSIT_COMMITMENT_MISMATCH],
            )
            .unwrap();
    }

    crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot!(
        BridgeDepositAnnouncementValidator,
        "800ab45910872da09b74bf564b7bf3b4e51cf8b1e04d5c81e32bcd2d7158f28533ede4fab36b1fbf"
    );
}
