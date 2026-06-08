use tasm_lib::field;
use tasm_lib::library::StaticAllocation;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::structure::tasm_object::DEFAULT_MAX_DYN_FIELD_SIZE;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use super::test_time_lock_and_maybe_mark::TestTimeLockAndMaybeMark;
use super::total_amount_main_loop::DigestSource;
use crate::protocol::consensus::transaction::utxo::Coin;
use crate::protocol::consensus::type_scripts::amount::read_and_add_amount::ReadAndAddAmount;
use crate::protocol::consensus::type_scripts::amount::TOO_BIG_COIN_FIELD_SIZE_ERROR;
use crate::protocol::proof_abstractions::tasm::push_digest_reversed;
use crate::BFieldElement;

/// Body for inner loop, running over all coins within one UTXO.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AddAllAmountsAndCheckTimeLock {
    pub(crate) digest_source: DigestSource,
    pub(crate) release_date: StaticAllocation,
    /// An optional *additional* type-script hash whose coins are also counted
    /// as native currency, OR'd into the primary `digest_source` match.
    ///
    /// Used by `NativeCurrency` to keep coins committed before the `UpgradeVM`
    /// hard fork — which carry `NativeCurrency::legacy_type_script_hash()` —
    /// spendable after the VM upgrade re-hashed the program. `None` produces
    /// byte-identical code to the pre-remap snippet.
    pub(crate) legacy_digest: Option<Digest>,
}

impl AddAllAmountsAndCheckTimeLock {
    const TIME_LOCK_HASH: Digest = Digest([
        BFieldElement::new(11493081001297792331),
        BFieldElement::new(14845021226026139948),
        BFieldElement::new(4809053857285865793),
        BFieldElement::new(5280486431890426245),
        BFieldElement::new(12484740501891840491),
    ]);
}

impl BasicSnippet for AddAllAmountsAndCheckTimeLock {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U32, "num_coins".to_string()),
            (DataType::U32, "index".to_string()),
            (DataType::VoidPointer, "*coins[j]_si".to_string()),
            (DataType::U128, "amount".to_string()),
            (DataType::U128, "timelocked_amount".to_string()),
            (DataType::U128, "utxo_amount".to_string()),
            (DataType::Bool, "utxo_is_timelocked".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U32, "num_coins".to_string()),
            (DataType::U32, "num_coins".to_string()),
            (DataType::VoidPointer, "*eof".to_string()),
            (DataType::U128, "amount".to_string()),
            (DataType::U128, "timelocked_amount".to_string()),
            (DataType::U128, "utxo_amount'".to_string()),
            (DataType::Bool, "utxo_is_timelocked'".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        // The emitted code differs by `legacy_digest` (the OR-in-legacy-match
        // block). `Library::import` dedups snippets by entrypoint name only, so
        // the name must vary with the digest — otherwise importing two variants
        // into one library would silently reuse whichever was imported first.
        let base = "neptune_type_script_total_amount_and_check_timelock";
        match self.legacy_digest {
            Some(digest) => format!("{base}_legacy_{}", digest.to_hex()),
            None => base.to_string(),
        }
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let test_time_lock_and_maybe_mark = library.import(Box::new(TestTimeLockAndMaybeMark {
            release_date: self.release_date,
        }));
        let read_and_add_amount = library.import(Box::new(ReadAndAddAmount));

        let field_type_script_hash = field!(Coin::type_script_hash);
        let digest_eq = DataType::Digest.compare();

        let get_type_script_digest = match self.digest_source {
            DigestSource::StaticMemory(digest_allocation) => {
                triton_asm! {
                    // _
                    push {digest_allocation.read_address()}
                    read_mem {Digest::LEN}
                    pop 1
                    // _ [own_program_digest]
                }
            }
            DigestSource::Hardcode(harcoded_digest) => push_digest_reversed(harcoded_digest),
        };

        let push_timelock_digest = push_digest_reversed(Self::TIME_LOCK_HASH);

        // V3 REMAP: optionally OR a second (legacy) type-script-hash match into
        // the native-currency check. When `legacy_digest` is `None`, this emits
        // no instructions, keeping the snippet byte-identical for non-remap
        // users (e.g. `GetTotalAndTimeLockedAmounts`).
        let or_in_legacy_match = match self.legacy_digest {
            Some(legacy_digest) => {
                let push_legacy_digest = push_digest_reversed(legacy_digest);
                triton_asm! {
                    // _ M j *coins[j]_si [amount] [tl] [utxo_amount] utxo_is_timelocked is_primary_match
                    dup 14 push 1 add
                    // _ ... is_primary_match *coins[j]
                    {&field_type_script_hash}
                    push {Digest::LEN-1} add read_mem {Digest::LEN} pop 1
                    // _ ... is_primary_match [type_script_hash]
                    {&push_legacy_digest}
                    {&digest_eq}
                    // _ ... is_primary_match (type_script_hash == legacy_digest)
                    add
                    // _ ... (is_primary_match + is_legacy_match)  // matches are mutually exclusive -> {0,1}
                }
            }
            None => triton_asm! {},
        };

        triton_asm! {

            // INVARIANT: _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked
            {self.entrypoint()}:
                hint utxo_amount = stack[1..5]

                // evaluate termination criterion and return if necessary
                dup 15 dup 15 eq
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked (M == j)

                skiz return
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked


                // if coin is native currency, add amount
                dup 13 push 1 add
                hint coins_j = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *coins[j]

                {&field_type_script_hash}
                hint type_script_hash_ptr = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked *type_script_hash

                push {Digest::LEN-1} add read_mem {Digest::LEN} pop 1
                hint type_script_hash : Digest = stack[0..5]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [type_script_hash]

                {&get_type_script_digest}
                hint own_program_digest = stack[0..5]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [type_script_hash] [own_program_digest]

                {&digest_eq}
                hint digests_are_equal = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked (type_script_hash == own_program_digest)

                {&or_in_legacy_match}
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked (matches native currency)

                skiz call {read_and_add_amount}
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked


                // if coin is timelock, test and mark if necessary
                dup 13 push 1 add
                hint coins_j = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked *coins[j]

                {&field_type_script_hash}
                hint type_script_hash_ptr = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount]  [utxo_amount'] utxo_is_timelocked *type_script_hash

                push {Digest::LEN-1} add read_mem {Digest::LEN} pop 1
                hint type_script_hash : Digest = stack[0..5]
                // _ M j *coins[j]_si [amount] [timelocked_amount]  [utxo_amount'] utxo_is_timelocked [type_script_hash]

                {&push_timelock_digest}
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked [type_script_hash] [timelock_digest]

                {&digest_eq}
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked (type_script_hash == timelock_digest)


                // If he coin is a time lock:
                //  - test the state, which encodes a release date, against the
                //    timestamp of the transaction kernel plus the coinbase
                //    timelock period.
                skiz call {test_time_lock_and_maybe_mark}
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked


                // prepare for next iteration
                dup 14 addi 1 swap 15 pop 1
                // _ M (j+1) *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked

                dup 13 read_mem 1 addi 2
                // _ M (j+1) *coins[j]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked size(coins[j]) *coins[j]

                /* Range-check on size */
                push {DEFAULT_MAX_DYN_FIELD_SIZE}
                dup 2
                lt
                assert error_id {TOO_BIG_COIN_FIELD_SIZE_ERROR}
                // _ M (j+1) *coins[j]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked size(coins[j]) *coins[j]

                add
                // _ M (j+1) *coins[j]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked *coins[j+1]_si

                swap 14 pop 1
                // _ M (j+1) *coins[j+1]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked

                recurse
        }
    }
}

#[cfg(test)]
mod test {
    use crate::protocol::consensus::type_scripts::amount::add_all_amounts_and_check_time_lock::AddAllAmountsAndCheckTimeLock;
    use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
    use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

    // Gated: TIME_LOCK_HASH is intentionally left at the pre-UpgradeVM value
    // while coinbase time-locking is disabled (MINING_REWARD_TIME_LOCK_PERIOD
    // == 0) — the time-lock match is a no-op, so the stale hash is harmless.
    // Refresh this to the current `TimeLock.hash()` when re-enabling the rule.
    #[ignore = "coinbase time-lock disabled while MINING_REWARD_TIME_LOCK_PERIOD == 0"]
    #[test]
    fn hardcoded_time_lock_hash_matches_hash_of_time_lock_program() {
        let calculated = TimeLock.hash();
        assert_eq!(
            AddAllAmountsAndCheckTimeLock::TIME_LOCK_HASH,
            calculated,
            "Timelock.hash():\n{}",
            calculated
        );
    }
}
