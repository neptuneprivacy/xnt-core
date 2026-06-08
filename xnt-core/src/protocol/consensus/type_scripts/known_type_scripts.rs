use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::native_currency::NativeCurrency;
use super::native_currency::NativeCurrencyWitness;
use super::native_currency_amount::NativeCurrencyAmount;
use super::time_lock::TimeLock;
use super::time_lock::TimeLockWitness;
use super::time_lock_v2::TimeLockV2;
use super::time_lock_v2::TimeLockV2Witness;
use super::TypeScript;
use super::TypeScriptAndWitness;
use super::TypeScriptWitness;
use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::utxo::Coin;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

pub(crate) fn match_type_script_and_generate_witness(
    type_script_hash: Digest,
    transaction_kernel: TransactionKernel,
    salted_input_utxos: SaltedUtxos,
    salted_output_utxos: SaltedUtxos,
) -> Option<TypeScriptAndWitness> {
    // Legacy (pre-UpgradeVM) hashes map to the SAME V1 program as their current
    // counterpart, so a transaction spending a coin committed before the fork
    // still gets a type-script witness (otherwise this returns None and building
    // the PrimitiveWitness panics). This is the *V1* dispatch: each coin maps to
    // its own program (NativeCurrency / TimeLock / TimeLockV2). The remap that
    // folds TimeLock onto TimeLockV2 is the job of the V2 path
    // ([`match_type_script_and_generate_witness_v2`] + `ProofCollection::produce_v2`,
    // mirroring the on-chain `CollectTypeScriptsV2` remap) and is deliberately
    // NOT done here.
    let type_script_and_witness = if NativeCurrency::is_native_currency(type_script_hash) {
        NativeCurrencyWitness::new(transaction_kernel, salted_input_utxos, salted_output_utxos)
            .type_script_and_witness()
    } else if type_script_hash == TimeLock.hash()
        || type_script_hash == TimeLock::legacy_type_script_hash()
    {
        TimeLockWitness::new(transaction_kernel, salted_input_utxos, salted_output_utxos)
            .type_script_and_witness()
    } else if type_script_hash == TimeLockV2.hash()
        || type_script_hash == TimeLockV2::legacy_type_script_hash()
    {
        TimeLockV2Witness::new(transaction_kernel, salted_input_utxos, salted_output_utxos)
            .type_script_and_witness()
    } else {
        return None;
    };
    Some(type_script_and_witness)
}

/// Post-fork variant of [`match_type_script_and_generate_witness`].
///
/// Identical to the standard dispatch except that coins still tagged with the
/// legacy `TimeLock` hash are matched to a `TimeLockV2` witness. This mirrors
/// the on-chain remap performed by `CollectTypeScriptsV2`: post-fork, the
/// SingleProof claim for the (remapped) `TimeLockV2.hash()` must be backed by
/// a `TimeLockV2` proof even when the coin in question carries the legacy hash.
///
/// Callers should choose between this and the V1 dispatch based on the
/// consensus rule set in effect at the block height being constructed/verified.
pub(crate) fn match_type_script_and_generate_witness_v2(
    type_script_hash: Digest,
    transaction_kernel: TransactionKernel,
    salted_input_utxos: SaltedUtxos,
    salted_output_utxos: SaltedUtxos,
) -> Option<TypeScriptAndWitness> {
    // Post-fork, every time-lock variant (current/legacy TimeLock and TimeLockV2)
    // is governed by TimeLockV2, and the legacy NativeCurrency hash by the
    // current NativeCurrency — mirroring the on-chain remap in
    // `CollectTypeScriptsV2`. Callers normally feed already-remapped (current)
    // hashes here; recognizing the legacy hashes too makes the dispatch robust.
    let type_script_and_witness = if NativeCurrency::is_native_currency(type_script_hash) {
        NativeCurrencyWitness::new(transaction_kernel, salted_input_utxos, salted_output_utxos)
            .type_script_and_witness()
    } else if is_timelock_type_script_hash(type_script_hash) {
        TimeLockV2Witness::new(transaction_kernel, salted_input_utxos, salted_output_utxos)
            .type_script_and_witness()
    } else {
        return None;
    };
    Some(type_script_and_witness)
}

pub(crate) fn is_known_type_script_with_valid_state(coin: &Coin) -> bool {
    NativeCurrency.matches_coin(coin)
        || TimeLock.matches_coin(coin)
        || TimeLockV2.matches_coin(coin)
        || is_legacy_type_script_with_valid_state(coin)
}

/// Recognize coins committed before the `UpgradeVM` fork, which carry the legacy
/// (pre-v3) program hashes. Their state validity is identical to the current
/// programs' (native currency decodes a `NativeCurrencyAmount`; a time lock
/// decodes a `Timestamp`). The on-chain remap makes these spendable, so the
/// wallet must treat them as known/valid — otherwise `Utxo::can_spend_at`
/// classifies them as unknown type scripts and never lists them as available.
fn is_legacy_type_script_with_valid_state(coin: &Coin) -> bool {
    let hash = coin.type_script_hash;
    if hash == NativeCurrency::legacy_type_script_hash() {
        NativeCurrencyAmount::decode(&coin.state).is_ok()
    } else if hash == TimeLock::legacy_type_script_hash()
        || hash == TimeLockV2::legacy_type_script_hash()
    {
        Timestamp::decode(&coin.state).is_ok()
    } else {
        false
    }
}

/// Whether `type_script_hash` is any recognized time-lock program hash: the
/// current or legacy `TimeLock`, or the current or legacy `TimeLockV2`. A coin
/// so tagged locks its UTXO until the `Timestamp` stored in its state. The
/// wallet must recognize the legacy hashes too, so a pre-fork time-locked UTXO
/// is not mistakenly treated as immediately spendable.
pub(crate) fn is_timelock_type_script_hash(type_script_hash: Digest) -> bool {
    type_script_hash == TimeLock.hash()
        || type_script_hash == TimeLock::legacy_type_script_hash()
        || type_script_hash == TimeLockV2.hash()
        || type_script_hash == TimeLockV2::legacy_type_script_hash()
}

/// Map a coin's (possibly legacy) type-script hash to the hash of the V1 program
/// whose witness governs it in the PrimitiveWitness layer: legacy/current
/// NativeCurrency -> `NativeCurrency.hash()`, legacy/current TimeLock ->
/// `TimeLock.hash()`, legacy/current TimeLockV2 -> `TimeLockV2.hash()`.
/// Unrecognized hashes are returned unchanged (so the downstream dispatch still
/// reports them as unknown).
///
/// This is the *V1* fold — it keeps the two sides of a `PrimitiveWitness` aligned
/// (the witnesses are keyed by these hashes, so the hashes collected from coins —
/// which may be legacy — must be folded the same way before they are matched
/// against the witnesses; see [`match_type_script_and_generate_witness`]). It
/// does NOT fold `TimeLock` onto `TimeLockV2`; that remap is the job of the V2
/// path (`CollectTypeScriptsV2` / `produce_v2`), which upgrades the proof.
pub(crate) fn current_program_hash(type_script_hash: Digest) -> Digest {
    if NativeCurrency::is_native_currency(type_script_hash) {
        NativeCurrency.hash()
    } else if type_script_hash == TimeLock.hash()
        || type_script_hash == TimeLock::legacy_type_script_hash()
    {
        TimeLock.hash()
    } else if type_script_hash == TimeLockV2.hash()
        || type_script_hash == TimeLockV2::legacy_type_script_hash()
    {
        TimeLockV2.hash()
    } else {
        type_script_hash
    }
}

pub(crate) fn typescript_name(type_script_hash: Digest) -> &'static str {
    if NativeCurrency::is_native_currency(type_script_hash) {
        "native currency"
    } else if type_script_hash == TimeLock.hash()
        || type_script_hash == TimeLock::legacy_type_script_hash()
    {
        "time lock"
    } else if type_script_hash == TimeLockV2.hash()
        || type_script_hash == TimeLockV2::legacy_type_script_hash()
    {
        "time lock v2"
    } else {
        "unknown"
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;

    use super::*;

    fn a_kernel() -> TransactionKernel {
        let mut runner = TestRunner::deterministic();
        arb::<TransactionKernel>()
            .new_tree(&mut runner)
            .unwrap()
            .current()
    }

    /// A coin committed before the UpgradeVM fork carries a legacy type-script
    /// hash. The V1 witness-generation dispatch must still produce a witness for
    /// it (returning `None` makes building a PrimitiveWitness panic), mapping each
    /// legacy hash onto its own V1 program (the `TimeLock` -> `TimeLockV2` remap
    /// is the V2 path's job, not this one).
    #[test]
    fn legacy_hashes_get_a_type_script_witness() {
        let kernel = a_kernel();
        let inp = SaltedUtxos::empty();
        let out = SaltedUtxos::empty();

        for (legacy, expected_program) in [
            (
                NativeCurrency::legacy_type_script_hash(),
                NativeCurrency.hash(),
            ),
            (TimeLock::legacy_type_script_hash(), TimeLock.hash()),
            (TimeLockV2::legacy_type_script_hash(), TimeLockV2.hash()),
        ] {
            let tsaw = match_type_script_and_generate_witness(
                legacy,
                kernel.clone(),
                inp.clone(),
                out.clone(),
            )
            .expect("legacy hash must produce a type-script witness (v1)");
            assert_eq!(expected_program, tsaw.program.hash());
        }
    }

    #[test]
    fn current_program_hash_folds_legacy_onto_current() {
        // current passes through; legacy folds onto the same V1 program. The
        // TimeLock -> TimeLockV2 remap is the V2 path's job, not this fold's.
        for (input, expected) in [
            (NativeCurrency.hash(), NativeCurrency.hash()),
            (
                NativeCurrency::legacy_type_script_hash(),
                NativeCurrency.hash(),
            ),
            (TimeLock.hash(), TimeLock.hash()),
            (TimeLock::legacy_type_script_hash(), TimeLock.hash()),
            (TimeLockV2.hash(), TimeLockV2.hash()),
            (TimeLockV2::legacy_type_script_hash(), TimeLockV2.hash()),
        ] {
            assert_eq!(expected, current_program_hash(input));
        }
        // an unrecognized hash is returned unchanged
        let unknown = Digest::default();
        assert_eq!(unknown, current_program_hash(unknown));
    }

    /// Post-fork dispatch: legacy NativeCurrency -> NativeCurrency; every legacy
    /// time-lock variant -> TimeLockV2 (mirrors CollectTypeScriptsV2).
    #[test]
    fn legacy_hashes_get_a_v2_type_script_witness() {
        let kernel = a_kernel();
        let inp = SaltedUtxos::empty();
        let out = SaltedUtxos::empty();

        let nc = match_type_script_and_generate_witness_v2(
            NativeCurrency::legacy_type_script_hash(),
            kernel.clone(),
            inp.clone(),
            out.clone(),
        )
        .expect("legacy NC must produce a v2 witness");
        assert_eq!(NativeCurrency.hash(), nc.program.hash());

        for legacy in [
            TimeLock::legacy_type_script_hash(),
            TimeLockV2::legacy_type_script_hash(),
        ] {
            let tsaw = match_type_script_and_generate_witness_v2(
                legacy,
                kernel.clone(),
                inp.clone(),
                out.clone(),
            )
            .expect("legacy time-lock must produce a v2 witness");
            assert_eq!(TimeLockV2.hash(), tsaw.program.hash());
        }
    }
}
