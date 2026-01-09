//! Wallet and key management

use bip39::{Language, Mnemonic, MnemonicType};
use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
use neptune_privacy::prelude::twenty_first::prelude::Tip5;
use neptune_privacy::state::wallet::address::SpendingKey as CoreSpendingKey;
use neptune_privacy::state::wallet::secret_key_material::SecretKeyMaterial;
use neptune_privacy::state::wallet::wallet_entropy::WalletEntropy as CoreWalletEntropy;

use super::address::Address;
use super::error::{Result, XntError};
use super::types::Digest;

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
}

/// Spending key for signing transactions
#[derive(Clone)]
pub struct SpendingKey {
    pub(crate) inner: CoreSpendingKey,
}

impl SpendingKey {
    /// Get receiving address from spending key
    pub fn to_address(&self) -> Address {
        Address::from_core(self.inner.to_address())
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
    pub fn receiver_preimage(&self) -> Digest {
        Digest::from_core(self.inner.privacy_preimage())
    }
}
