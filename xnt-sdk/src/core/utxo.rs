//! UTXO operations
//!
//! Shared UTXO logic for both FFI and NAPI bindings.

use neptune_privacy::prelude::tasm_lib::prelude::Tip5;
use neptune_privacy::protocol::consensus::transaction::announcement::Announcement;
use neptune_privacy::protocol::consensus::transaction::utxo::Utxo as CoreUtxo;
use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_privacy::protocol::proof_abstractions::timestamp::Timestamp;
use neptune_privacy::state::wallet::address::ciphertext_from_announcement;
use neptune_privacy::state::wallet::address::generation_address::{GENERATION_FLAG, GENERATION_SUBADDR_FLAG};
use neptune_privacy::state::wallet::address::receiver_identifier_from_announcement;

use super::address::Address;
use super::error::{Result, XntError};
use super::types::Digest;
use super::wallet::SpendingKey;

/// UTXO wrapper
#[derive(Clone, Debug)]
pub struct Utxo {
    pub(crate) inner: CoreUtxo,
}

/// Decrypted UTXO result
pub struct DecryptedUtxo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub payment_id: u64,
    pub block_height: u64,
    pub block_digest: Digest,
}

impl Utxo {
    /// Create UTXO for native currency
    pub fn new_native(address: &Address, amount: i128) -> Self {
        let lock_script_hash = address.inner.lock_script_hash();
        let utxo = CoreUtxo::new_native_currency(lock_script_hash, NativeCurrencyAmount::from_nau(amount));
        Self { inner: utxo }
    }

    /// Get native currency amount (in nau)
    pub fn amount(&self) -> i128 {
        self.inner.get_native_currency_amount().to_nau()
    }

    /// Get lock_script_hash
    pub fn lock_script_hash(&self) -> Digest {
        Digest::from_core(self.inner.lock_script_hash())
    }

    /// Get UTXO hash (TIP5 hash for commitment calculation)
    pub fn hash(&self) -> Digest {
        Digest::from_core(Tip5::hash(&self.inner))
    }

    /// Serialize to bytes (bincode)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.inner).map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Deserialize from bytes (bincode)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let inner: CoreUtxo =
            bincode::deserialize(data).map_err(|e| XntError::EncodingError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Get release date if UTXO is timelocked (milliseconds since Unix epoch)
    pub fn release_date(&self) -> Option<u64> {
        self.inner.release_date().map(|ts| ts.0.value())
    }

    /// Check if UTXO is timelocked
    pub fn is_timelocked(&self) -> bool {
        self.inner.release_date().is_some()
    }

    /// Check if UTXO can be spent at given timestamp (milliseconds since Unix epoch)
    pub fn can_spend_at(&self, timestamp_ms: u64) -> bool {
        self.inner.can_spend_at(Timestamp::millis(timestamp_ms))
    }

    /// Add timelock to UTXO (release_date in milliseconds since Unix epoch)
    pub fn with_time_lock(self, release_date_ms: u64) -> Self {
        Self {
            inner: self.inner.with_time_lock(Timestamp::millis(release_date_ms)),
        }
    }

    pub(crate) fn from_core(inner: CoreUtxo) -> Self {
        Self { inner }
    }
}

/// Decrypt announcement with spending key
pub fn decrypt_announcement(
    spending_key: &SpendingKey,
    announcement_bfes: &[neptune_privacy::prelude::twenty_first::prelude::BFieldElement],
) -> Result<DecryptedUtxo> {
    let announcement = Announcement::new(announcement_bfes.to_vec());

    if announcement.message.is_empty() {
        return Err(XntError::InvalidInput("empty announcement".to_string()));
    }

    let key_type = announcement.message[0];
    if key_type != GENERATION_FLAG && key_type != GENERATION_SUBADDR_FLAG {
        return Err(XntError::InvalidInput(
            "not a generation address announcement".to_string(),
        ));
    }

    // Check receiver_id matches
    let ann_receiver_id = receiver_identifier_from_announcement(&announcement)
        .map_err(|e| XntError::InvalidInput(format!("invalid announcement: {e}")))?;

    if ann_receiver_id != spending_key.inner.receiver_identifier() {
        return Err(XntError::InvalidInput("receiver_id mismatch".to_string()));
    }

    // Get ciphertext and decrypt
    let ciphertext = ciphertext_from_announcement(&announcement)
        .map_err(|e| XntError::InvalidInput(format!("invalid announcement: {e}")))?;

    let (utxo, sender_randomness, payment_id) = spending_key
        .inner
        .decrypt(&ciphertext)
        .map_err(|e| XntError::CryptoError(format!("decryption failed: {e}")))?;

    Ok(DecryptedUtxo {
        utxo: Utxo::from_core(utxo),
        sender_randomness: Digest::from_core(sender_randomness),
        payment_id: payment_id.value(),
        block_height: 0, // Not available from announcement
        block_digest: Digest::new(),
    })
}
