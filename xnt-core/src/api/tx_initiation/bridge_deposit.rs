//! A bridge deposit (lock): XNT into the bridge pool, announced so the faucet mints WXNT on Leviathan.

use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use num_traits::Zero;
use rand::RngExt;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use super::error::CreateTxError;
use crate::api::export::ReceivingAddress;
use crate::api::export::Timestamp;
use crate::application::config::network::Network;
use crate::protocol::consensus::bridge::deposit_announcement::deposit_receiver_preimage;
use crate::protocol::consensus::bridge::deposit_announcement::BridgeDepositData;
use crate::protocol::consensus::bridge::deposit_announcement::MIN_BRIDGE_AMOUNT;
use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::wallet::transaction_input::TxInputList;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::utxo_notification::UtxoNotificationMethod;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// A 9th input doubles a SingleProof's padded height to 2^23, which OOMs a 96 GB prover.
pub const MAX_BRIDGE_DEPOSIT_INPUTS: usize = 8;

/// Locks `amount` from `tx_inputs` into the bridge pool for `leviathan_account_id` ([suffix, prefix]).
#[expect(clippy::too_many_arguments)]
pub fn bridge_deposit_tx_details(
    tx_inputs: TxInputList,
    leviathan_account_id: [u64; 2],
    amount: NativeCurrencyAmount,
    fee: NativeCurrencyAmount,
    change_address: ReceivingAddress,
    timestamp: Timestamp,
    msa: MutatorSetAccumulator,
    network: Network,
) -> Result<(TransactionDetails, BridgeDepositData), CreateTxError> {
    if amount < MIN_BRIDGE_AMOUNT {
        return Err(CreateTxError::BelowBridgeMinimum {
            amount,
            min: MIN_BRIDGE_AMOUNT,
        });
    }
    if fee.is_negative() {
        return Err(CreateTxError::NegativeFee);
    }
    if tx_inputs.len() > MAX_BRIDGE_DEPOSIT_INPUTS {
        return Err(CreateTxError::TooManyInputs {
            needed: tx_inputs.len(),
            max: MAX_BRIDGE_DEPOSIT_INPUTS,
        });
    }
    let spend_amount = amount
        .checked_add(&fee)
        .ok_or(CreateTxError::TotalSpendTooLarge)?;

    let account_id = leviathan_account_id.map(BFieldElement::new);
    let bridge_utxo = Utxo::new_native_currency(bridge_lock_script().hash(), amount);
    let sender_randomness = Digest::new(rand::rng().random());
    let receiver_preimage = deposit_receiver_preimage(account_id, sender_randomness);
    let receiver_digest = receiver_preimage.hash();
    let bridge_output = TxOutput::new(
        bridge_utxo,
        sender_randomness,
        receiver_digest,
        UtxoNotificationMethod::None,
        false,
        false,
    );

    let utxo_commitment = bridge_output
        .addition_record()
        .canonical_commitment
        .values();

    let total_input = tx_inputs.total_native_coins();
    let change_amount =
        total_input
            .checked_sub(&spend_amount)
            .ok_or(CreateTxError::InsufficientFunds {
                requested: spend_amount,
                available: total_input,
            })?;

    let mut outputs = vec![bridge_output];
    if !change_amount.is_zero() {
        let change_output = TxOutput::onchain_native_currency_as_change(
            change_amount,
            Digest::new(rand::rng().random()),
            change_address,
        );
        outputs.push(change_output);
    }

    let deposit = BridgeDepositData {
        account_id,
        amount,
        utxo_commitment,
        sender_randomness: sender_randomness.values(),
        receiver_preimage: receiver_preimage.values(),
    };

    let tx_details =
        TransactionDetails::new(tx_inputs, outputs, fee, None, timestamp, msa, network)
            .with_announcements(vec![deposit.to_announcement()]);
    Ok((tx_details, deposit))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use super::*;
    use crate::protocol::consensus::transaction::lock_script::LockScript;
    use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::transaction::validity::bridge_deposit_announcement_validator::BridgeDepositAnnouncementValidator;
    use crate::protocol::consensus::transaction::validity::bridge_deposit_announcement_validator::BridgeDepositAnnouncementValidatorWitness;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::protocol::proof_abstractions::SecretWitness;
    use crate::state::wallet::unlocked_utxo::UnlockedUtxo;
    use crate::state::wallet::wallet_entropy::WalletEntropy;

    const ACCOUNT_ID: [u64; 2] = [0x7db0_664f_500c_4c00, 0x6942_9324_3acf_dec1];

    fn inputs(n: usize) -> (TxInputList, MutatorSetAccumulator) {
        let lock = LockScript::anyone_can_spend();
        let utxo = Utxo::new_native_currency(lock.hash(), NativeCurrencyAmount::coins(10));
        let pw = PrimitiveWitness::arbitrary_primitive_witness_with(
            &vec![utxo.clone(); n],
            &vec![LockScriptAndWitness::new(lock.program.clone()); n],
            &[utxo],
            &[],
            NativeCurrencyAmount::coins(10 * u32::try_from(n).unwrap() - 10),
            None,
        )
        .new_tree(&mut TestRunner::deterministic())
        .unwrap()
        .current();
        let tx_inputs = pw
            .input_utxos
            .utxos
            .iter()
            .zip(&pw.input_membership_proofs)
            .map(|(input, mp)| {
                UnlockedUtxo::unlock(
                    input.clone(),
                    LockScriptAndWitness::new(lock.program.clone()),
                    mp.clone(),
                )
            })
            .collect::<Vec<_>>();
        (tx_inputs.into(), pw.mutator_set_accumulator)
    }

    fn change_address() -> ReceivingAddress {
        WalletEntropy::devnet_wallet()
            .nth_generation_spending_key(0)
            .to_address()
            .into()
    }

    fn details(
        n: usize,
        amount: NativeCurrencyAmount,
    ) -> Result<(TransactionDetails, BridgeDepositData), CreateTxError> {
        details_paying_change_to(n, amount, change_address())
    }

    fn details_paying_change_to(
        n: usize,
        amount: NativeCurrencyAmount,
        change_address: ReceivingAddress,
    ) -> Result<(TransactionDetails, BridgeDepositData), CreateTxError> {
        let (tx_inputs, msa) = inputs(n);
        bridge_deposit_tx_details(
            tx_inputs,
            ACCOUNT_ID,
            amount,
            NativeCurrencyAmount::coins(1),
            change_address,
            Timestamp::now(),
            msa,
            Network::RegTest,
        )
    }

    /// A deposit of 5 coins (fee 1) from `n` 10-coin inputs.
    pub(crate) fn deposit_witness(n: usize) -> PrimitiveWitness {
        let (tx_details, _) = details(n, NativeCurrencyAmount::coins(5)).unwrap();
        PrimitiveWitness::from_transaction_details(&tx_details)
    }

    /// [`deposit_witness`] whose change goes to a dCTIDH address, as the wallet's does.
    pub(crate) fn deposit_witness_with_dctidh_change(n: usize) -> PrimitiveWitness {
        let change_address = WalletEntropy::devnet_wallet()
            .nth_dctidh_spending_key(0)
            .to_address()
            .into();
        let (tx_details, _) =
            details_paying_change_to(n, NativeCurrencyAmount::coins(5), change_address).unwrap();
        PrimitiveWitness::from_transaction_details(&tx_details)
    }

    #[test]
    fn deposit_announces_its_bridge_output_and_bdav_accepts_it() {
        let (tx_details, deposit) = details(1, NativeCurrencyAmount::coins(5)).unwrap();
        let outputs = tx_details.tx_outputs.iter().collect::<Vec<_>>();
        assert_eq!(outputs.len(), 2, "bridge output and 4 coins change");
        assert_eq!(
            Digest::new(deposit.utxo_commitment),
            outputs[0].addition_record().canonical_commitment
        );
        assert!(deposit.binds_account());
        let pw = PrimitiveWitness::from_transaction_details(&tx_details);
        assert!(pw.kernel.announcements.contains(&deposit.to_announcement()));

        let witness = BridgeDepositAnnouncementValidatorWitness::from(&pw);
        BridgeDepositAnnouncementValidator
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .expect("BDAV accepts the deposit");

        assert_eq!(
            outputs[1].native_currency_amount(),
            NativeCurrencyAmount::coins(4)
        );

        let (exact, _) = details(1, NativeCurrencyAmount::coins(9)).unwrap();
        assert_eq!(
            exact.tx_outputs.len(),
            1,
            "no change output when nothing is left"
        );
    }

    #[test]
    fn identical_deposits_get_distinct_commitments() {
        let (_, first) = details(1, NativeCurrencyAmount::coins(5)).unwrap();
        let (_, second) = details(1, NativeCurrencyAmount::coins(5)).unwrap();
        assert_ne!(first.utxo_commitment, second.utxo_commitment);
        assert!(first.binds_account() && second.binds_account());
    }

    #[test]
    fn accepts_the_minimum_amount_and_the_input_cap() {
        assert!(details(1, MIN_BRIDGE_AMOUNT).is_ok());
        assert!(details(MAX_BRIDGE_DEPOSIT_INPUTS, NativeCurrencyAmount::coins(5)).is_ok());
    }

    #[test]
    fn refuses_small_deposits_too_many_inputs_and_overspending() {
        assert!(matches!(
            details(
                1,
                NativeCurrencyAmount::coins(1)
                    .checked_sub(&NativeCurrencyAmount::from_nau(1))
                    .unwrap()
            ),
            Err(CreateTxError::BelowBridgeMinimum { .. })
        ));
        assert!(matches!(
            details(
                MAX_BRIDGE_DEPOSIT_INPUTS + 1,
                NativeCurrencyAmount::coins(5)
            ),
            Err(CreateTxError::TooManyInputs { needed: 9, max: 8 })
        ));
        assert!(matches!(
            details(1, NativeCurrencyAmount::coins(10)),
            Err(CreateTxError::InsufficientFunds { .. })
        ));
    }
}
