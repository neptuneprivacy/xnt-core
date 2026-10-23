//! Wallet and key management

use bip39::{Language, Mnemonic, MnemonicType};
use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
use neptune_privacy::prelude::twenty_first::prelude::Tip5;
use neptune_privacy::state::wallet::address::dctidh_address::legacy_dctidh_cutoff as core_legacy_dctidh_cutoff;
use neptune_privacy::state::wallet::address::SpendingKey as CoreSpendingKey;
use neptune_privacy::state::wallet::secret_key_material::SecretKeyMaterial;
use neptune_privacy::state::wallet::wallet_entropy::WalletEntropy as CoreWalletEntropy;

use super::address::Address;
use super::error::{Result, XntError};
use super::types::{Digest, Network};

/// Wallet entropy - root secret for key derivation
#[derive(Clone)]
pub struct WalletEntropy {
    pub(crate) inner: CoreWalletEntropy,
}

impl WalletEntropy {
    /// Generate a new random wallet with 18-word mnemonic
    pub fn generate() -> Result<Self> {
        let mnemonic = Mnemonic::new(MnemonicType::Words18, Language::English);
        let words: Vec<String> = mnemonic.phrase().split(' ').map(|s| s.to_string()).collect();
        Self::from_words(&words)
    }

    /// Create wallet from mnemonic phrase (space-separated words)
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let words: Vec<String> = mnemonic.split_whitespace().map(|s| s.to_string()).collect();
        Self::from_words(&words)
    }

    /// Create wallet from word list
    pub fn from_words(words: &[String]) -> Result<Self> {
        let inner = CoreWalletEntropy::from_phrase(words)
            .map_err(|e| XntError::InvalidMnemonic(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Get devnet test wallet
    pub fn devnet() -> Self {
        Self {
            inner: CoreWalletEntropy::devnet_wallet(),
        }
    }

    /// Export to mnemonic phrase (space-separated)
    pub fn to_mnemonic(&self) -> String {
        let secret: SecretKeyMaterial = self.inner.clone().into();
        secret.to_phrase().join(" ")
    }

    /// Derive Nth generation spending key
    pub fn derive_spending_key(&self, index: u64) -> SpendingKey {
        let gen_key = self.inner.nth_generation_spending_key(index);
        SpendingKey {
            inner: CoreSpendingKey::Generation(gen_key),
        }
    }

    /// Derive Nth CTIDH spending key (currently CTIDH-512 as implemented
    /// in the `neptune-privacy` core via dCTIDH).
    pub fn derive_dctidh_spending_key(&self, index: u64) -> SpendingKey {
        let dctidh_key = self.inner.nth_dctidh_spending_key(index);
        SpendingKey {
            inner: CoreSpendingKey::dCTIDH(dctidh_key),
        }
    }

    /// Derive the Nth CTIDH spending key using the legacy (pre-v0.3) lock
    /// derivation, for recognising and sweeping funds received at
    /// legacy-format dCTIDH addresses. Not used to derive new addresses.
    pub fn derive_legacy_dctidh_spending_key(&self, index: u64) -> SpendingKey {
        let dctidh_key = self.inner.nth_legacy_dctidh_spending_key(index);
        SpendingKey {
            inner: CoreSpendingKey::dCTIDH(dctidh_key),
        }
    }
}

/// Spending key for signing transactions
#[derive(Clone)]
pub struct SpendingKey {
    pub(crate) inner: CoreSpendingKey,
}

impl SpendingKey {
    /// Get receiving address from spending key.
    ///
    /// Fails for legacy-derivation dCTIDH keys, which are used only for
    /// scanning and spending and have no receiving address.
    pub fn to_address(&self) -> Result<Address> {
        if let CoreSpendingKey::dCTIDH(key) = &self.inner {
            if key.is_legacy() {
                return Err(XntError::InvalidInput(
                    "legacy dCTIDH keys have no receiving address".to_string(),
                ));
            }
        }
        Ok(Address::from_core(self.inner.clone().to_address()))
    }

    /// Get receiver identifier (8 bytes, little-endian u64)
    pub fn receiver_id(&self) -> u64 {
        self.inner.receiver_identifier().value()
    }

    /// Get receiver identifier as hex string
    pub fn receiver_id_hex(&self) -> String {
        format!("{:016x}", self.receiver_id())
    }

    /// Get receiver_id_hash (TIP5 hash of receiver_identifier) for indexer lookups
    pub fn receiver_id_hash(&self) -> Digest {
        let receiver_id: BFieldElement = self.inner.receiver_identifier();
        Digest::from_core(Tip5::hash_varlen(&[receiver_id]))
    }

    /// Get receiver preimage (privacy_preimage) for commitment computation
    ///
    /// For dCTIDH keys this is also the unlock preimage of the key's lock
    /// script: anyone who knows it can spend the UTXOs locked to the key.
    /// Treat it as a spending secret for dCTIDH keys: keep it on the device
    /// that holds the seed, do not log it, send it to a server or store it
    /// unencrypted.
    pub fn receiver_preimage(&self) -> Digest {
        Digest::from_core(self.inner.privacy_preimage())
    }

    /// Get the hash of the lock script this key can satisfy.
    ///
    /// Announced UTXOs whose lock script hash differs from this cannot be
    /// spent by this key and must not be counted towards the balance.
    pub fn lock_script_hash(&self) -> Digest {
        Digest::from_core(self.inner.lock_script_hash())
    }

    /// Returns true if this is a CTIDH spending key.
    pub fn is_dctidh(&self) -> bool {
        matches!(self.inner, CoreSpendingKey::dCTIDH(_))
    }

    /// Returns true if this is a Generation spending key.
    pub fn is_generation(&self) -> bool {
        matches!(self.inner, CoreSpendingKey::Generation(_))
    }

    /// Returns true for dCTIDH keys derived with the legacy (pre-v0.3) lock
    /// derivation, see [WalletEntropy::derive_legacy_dctidh_spending_key].
    ///
    /// UTXOs locked to such a key are sweep-only: move them to a key of the
    /// current format and never count them towards the available balance.
    pub fn is_legacy(&self) -> bool {
        self.inner.is_legacy()
    }

    /// Whether UTXOs locked to this key and confirmed in a block of height
    /// `block_height` are recognized on `network`.
    ///
    /// Always true for keys that are not legacy. For legacy keys true only
    /// below [legacy_dctidh_cutoff], the same rule the node wallet applies.
    pub fn recognizes_utxos_at(&self, network: Network, block_height: u64) -> bool {
        !self.is_legacy()
            || legacy_dctidh_cutoff(network).is_none_or(|cutoff| block_height < cutoff)
    }
}

/// The block height from which UTXOs locked to legacy-format (pre-v0.3) dCTIDH
/// locks are no longer recognized, or `None` if they are recognized at any
/// height.
///
/// Same rule as the node wallet: on main net this is the `UpgradeVMv8`
/// activation height; other networks run `UpgradeVMv8` from genesis and have
/// no cutoff.
pub fn legacy_dctidh_cutoff(network: Network) -> Option<u64> {
    core_legacy_dctidh_cutoff(network.into()).map(u64::from)
}

#[cfg(test)]
mod tests {
    use neptune_privacy::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET;

    use super::*;

    const MAIN_NET_CUTOFF: u64 = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET.value();

    #[test]
    fn legacy_dctidh_cutoff_is_set_on_main_net_only() {
        assert_eq!(Some(MAIN_NET_CUTOFF), legacy_dctidh_cutoff(Network::Main));
        for network in [Network::TestnetMock, Network::RegTest, Network::Testnet] {
            assert_eq!(None, legacy_dctidh_cutoff(network), "{network:?}");
        }
    }

    #[test]
    fn only_legacy_derivation_keys_are_legacy() {
        let wallet = WalletEntropy::devnet();
        let generation = wallet.derive_spending_key(0);
        let current = wallet.derive_dctidh_spending_key(0);
        let legacy = wallet.derive_legacy_dctidh_spending_key(0);

        assert!(!generation.is_legacy());
        assert!(!current.is_legacy());
        assert!(legacy.is_legacy());

        // The legacy key is the pre-v0.3 key: its own receiver identifier and lock
        assert_ne!(current.receiver_id(), legacy.receiver_id());
        assert_ne!(current.lock_script_hash(), legacy.lock_script_hash());
        assert!(legacy.to_address().is_err());
    }

    #[test]
    fn legacy_keys_recognize_utxos_only_below_the_cutoff() {
        let wallet = WalletEntropy::devnet();
        let legacy = wallet.derive_legacy_dctidh_spending_key(1);
        let current = wallet.derive_dctidh_spending_key(1);
        let generation = wallet.derive_spending_key(1);

        assert!(legacy.recognizes_utxos_at(Network::Main, MAIN_NET_CUTOFF - 1));
        assert!(!legacy.recognizes_utxos_at(Network::Main, MAIN_NET_CUTOFF));
        assert!(!legacy.recognizes_utxos_at(Network::Main, u64::MAX));
        assert!(legacy.recognizes_utxos_at(Network::RegTest, u64::MAX));

        for key in [current, generation] {
            assert!(key.recognizes_utxos_at(Network::Main, MAIN_NET_CUTOFF));
            assert!(key.recognizes_utxos_at(Network::Main, u64::MAX));
        }
    }
}
