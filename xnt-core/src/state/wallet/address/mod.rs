//! implements wallet keys and addresses.
//!
//! naming: it would make more sense for this module to be named 'key' or 'keys'
//! and it will probably be renamed in a future commit.
//!
//! (especially since we now have a key type with no corresponding address)
mod addressable_key;
mod common;
pub mod ctidh_address;
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

    use super::*;
    use crate::application::config::network::Network;
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

    mod worker {
        use super::*;

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
