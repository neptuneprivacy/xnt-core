//! implements wallet keys and addresses.
//!
//! naming: it would make more sense for this module to be named 'key' or 'keys'
//! and it will probably be renamed in a future commit.
//!
//! (especially since we now have a key type with no corresponding address)
mod addressable_key;
mod common;
pub mod dctidh_address;
pub mod encrypted_utxo_notification;
pub mod generation_address;
mod receiving_address;
pub mod symmetric_key;

pub use addressable_key::KeyType;
pub use addressable_key::SpendingKey;
pub use common::bfes_to_bytes;
pub use common::ciphertext_from_announcement;
pub use common::receiver_identifier_from_announcement;
pub use common::SubAddress;
pub use generation_address::GenerationSubAddress;
pub use receiving_address::ReceivingAddress;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use generation_address::GenerationReceivingAddress;
    use proptest_arbitrary_interop::arb;
    use symmetric_key::SymmetricKey;
    use test_strategy::proptest;

    use num_traits::Zero;

    use super::*;
    use crate::application::config::network::Network;
    use crate::prelude::twenty_first::prelude::BFieldElement;
    use crate::protocol::consensus::transaction::announcement::Announcement;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::state::Digest;

    /// tests bech32m serialize, deserialize with a symmetric key
    #[proptest]
    fn test_bech32m_conversion_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_bech32m_conversion(SymmetricKey::from_seed(seed).into());
    }

    /// tests bech32m serialize, deserialize with an asymmetric (generation) key
    #[proptest]
    fn test_bech32m_conversion_generation(#[strategy(arb())] seed: Digest) {
        worker::test_bech32m_conversion(GenerationReceivingAddress::derive_from_seed(seed).into());
    }

    #[proptest(cases = 3)]
    fn announced_utxo_with_foreign_lock_script_is_rejected(
        #[strategy(arb())] wallet_entropy: WalletEntropy,
        #[strategy(arb())] foreign_lock_script_hash: Digest,
    ) {
        let keys = [
            SpendingKey::from(wallet_entropy.nth_generation_spending_key(0)),
            SpendingKey::from(wallet_entropy.nth_symmetric_key(0)),
            SpendingKey::from(wallet_entropy.nth_dctidh_spending_key(0)),
        ];
        for key in keys {
            worker::announced_utxo_with_foreign_lock_script_is_rejected(
                key,
                foreign_lock_script_hash,
            )
        }
    }

    /// A payment to a *subaddress* is locked to the base address's lock
    /// script, so the lock-script check in
    /// [`SpendingKey::scan_for_announced_utxos`] must still let it through.
    /// Were it not to, real incoming funds would be silently dropped.
    #[proptest(cases = 3)]
    fn subaddress_payment_is_still_caught(
        #[strategy(arb())] wallet_entropy: WalletEntropy,
        #[strategy(arb())] payment_id: BFieldElement,
    ) {
        // A subaddress' payment id must be non-zero.
        let payment_id = if payment_id.is_zero() {
            BFieldElement::new(1)
        } else {
            payment_id
        };

        let generation_key = wallet_entropy.nth_generation_spending_key(0);
        let generation_subaddress =
            GenerationSubAddress::new(generation_key.to_address(), payment_id).unwrap();

        let dctidh_key = wallet_entropy.nth_dctidh_spending_key(0);
        let dctidh_subaddress =
            dctidh_address::dCTIDHSubAddress::new(dctidh_key.to_address(), payment_id).unwrap();

        let cases: [(SpendingKey, ReceivingAddress); 2] = [
            (generation_key.into(), generation_subaddress.into()),
            (dctidh_key.into(), dctidh_subaddress.into()),
        ];
        for (base_key, subaddress) in cases {
            worker::subaddress_payment_is_still_caught(base_key, subaddress, payment_id);
        }
    }

    mod worker {
        use rand::random;

        use super::*;
        use crate::api::export::NativeCurrencyAmount;
        use crate::api::export::Timestamp;
        use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
        use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::state::wallet::utxo_notification::UtxoNotificationPayload;

        pub fn subaddress_payment_is_still_caught(
            base_key: SpendingKey,
            subaddress: ReceivingAddress,
            payment_id: BFieldElement,
        ) {
            let sender_randomness: Digest = random();

            // Pay to the subaddress exactly as a sender would.
            let utxo = Utxo::new_native_currency(
                subaddress.lock_script_hash(),
                NativeCurrencyAmount::coins(7),
            );
            let payload = UtxoNotificationPayload::new(utxo.clone(), sender_randomness);
            let announcement = subaddress.generate_announcement(payload);

            // The *base* key is the one the wallet scans with.
            let caught = base_key.scan_for_announced_utxos(&kernel_with(vec![announcement]));

            assert_eq!(
                1,
                caught.len(),
                "payment to subaddress must be caught by the base key"
            );
            assert_eq!(utxo, caught[0].utxo);
            assert_eq!(sender_randomness, caught[0].sender_randomness);
            assert_eq!(
                payment_id, caught[0].payment_id,
                "subaddress payment id must survive scanning"
            );
        }

        /// A transaction kernel holding nothing but the given announcements.
        fn kernel_with(announcements: Vec<Announcement>) -> TransactionKernel {
            TransactionKernelProxy {
                inputs: vec![],
                outputs: vec![],
                announcements,
                fee: NativeCurrencyAmount::coins(0),
                coinbase: None,
                timestamp: Timestamp::millis(0),
                mutator_set_hash: Digest::default(),
                merge_bit: false,
            }
            .into_kernel()
        }

        pub fn announced_utxo_with_foreign_lock_script_is_rejected(
            key: SpendingKey,
            foreign_lock_script_hash: Digest,
        ) {
            let sender_randomness: Digest = random();
            let address = key.clone().to_address();
            let kernel_with_announcement = |utxo: Utxo| {
                let payload = UtxoNotificationPayload::new(utxo, sender_randomness);
                let announcement = address.generate_announcement(payload);
                TransactionKernelProxy {
                    inputs: vec![],
                    outputs: vec![],
                    announcements: vec![announcement],
                    fee: NativeCurrencyAmount::coins(0),
                    coinbase: None,
                    timestamp: Timestamp::millis(0),
                    mutator_set_hash: Digest::default(),
                    merge_bit: false,
                }
                .into_kernel()
            };

            let foreign_utxo = Utxo::new_native_currency(
                foreign_lock_script_hash,
                NativeCurrencyAmount::coins(10),
            );
            assert!(
                key.scan_for_announced_utxos(&kernel_with_announcement(foreign_utxo))
                    .is_empty(),
                "announced UTXO with foreign lock script must be rejected"
            );

            let own_utxo = Utxo::new_native_currency(
                address.lock_script_hash(),
                NativeCurrencyAmount::coins(10),
            );
            let caught = key.scan_for_announced_utxos(&kernel_with_announcement(own_utxo));
            assert_eq!(
                1,
                caught.len(),
                "announced UTXO with own lock script must be caught"
            );
        }

        /// tests bech32m serialize, deserialize for [ReceivingAddress]
        pub fn test_bech32m_conversion(receiving_address: ReceivingAddress) {
            // 1. serialize address to bech32m
            let encoded = receiving_address.to_bech32m(Network::Testnet(0)).unwrap();

            // 2. deserialize bech32m back into an address
            let receiving_address_again =
                ReceivingAddress::from_bech32m(&encoded, Network::Testnet(0)).unwrap();

            // 3. verify both addresses match
            assert_eq!(receiving_address, receiving_address_again);
        }
    }
}
