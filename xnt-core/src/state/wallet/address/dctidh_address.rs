use aead::Aead;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::anyhow;
use anyhow::ensure;
use anyhow::Result;
use bech32::FromBase32;
use bech32::ToBase32;
use bech32::Variant;
use dctidh512::{derive, keygen, sk_to_pk, PublicKey, SecretKey};
use serde::Deserialize;
use serde::Serialize;
use num_traits::Zero;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::common;
use super::common::deterministically_derive_seed_and_nonce;
use super::common::SubAddress as SubAddressTrait;
use super::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::lock_script::LockScript;
use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::state::wallet::utxo_notification::UtxoNotificationPayload;

/// Key type flag for CTIDH in announcements.
pub(super) const CTIDH_FLAG_U8: u8 = 201;
pub const CTIDH_FLAG: BFieldElement = BFieldElement::new(CTIDH_FLAG_U8 as u64);

/// Key type flag for CTIDH subaddresses (with payment_id) in announcements.
pub(super) const CTIDH_SUBADDR_FLAG_U8: u8 = 202;
pub const CTIDH_SUBADDR_FLAG: BFieldElement = BFieldElement::new(CTIDH_SUBADDR_FLAG_U8 as u64);

/// Bech32m length for 2048-bit: 6 (HRP) + 1 + base32(256) + 6 checksum = 6+1+410+6 = 423.
pub const CTIDH_ADDRESS_MAX_BECH32M_LEN: usize = 430;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct dCTIDHReceivingAddress {
    #[serde(with = "serde_arrays")]
    encryption_key: PublicKey,
    receiver_identifier: BFieldElement,
    receiver_postimage: Digest,
    lock_postimage: Digest,
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for dCTIDHReceivingAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = Digest::arbitrary(u)?;
        Ok(dCTIDHSpendingKey::derive_from_seed(seed).to_address())
    }
}

/// A subaddress combining a base CTIDH receiving address with a payment_id.
///
/// dCTIDHSubAddress = dCTIDHReceivingAddress + payment_id
///
/// The subaddress can be converted to/from (address, payment_id) pair. When
/// encoded as bech32m, it includes both the base address and payment_id.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct dCTIDHSubAddress {
    /// The base receiving address
    base: dCTIDHReceivingAddress,

    /// The payment identifier for this subaddress
    payment_id: BFieldElement,
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for dCTIDHSubAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let base = dCTIDHReceivingAddress::arbitrary(u)?;
        let mut payment_id = BFieldElement::arbitrary(u)?;
        if payment_id.is_zero() {
            payment_id = BFieldElement::new(1);
        }
        Ok(Self::new(base, payment_id).unwrap())
    }
}

impl dCTIDHSubAddress {
    /// Create a new subaddress from a base address and payment_id.
    ///
    /// # Errors
    /// Returns error if payment_id is zero - use base address directly for zero payment_id.
    pub fn new(base: dCTIDHReceivingAddress, payment_id: BFieldElement) -> Result<Self> {
        ensure!(
            !payment_id.is_zero(),
            "payment_id must be non-zero for subaddresses; use base address directly"
        );
        Ok(Self { base, payment_id })
    }

    /// Create a subaddress with an index-derived payment_id.
    ///
    /// # Errors
    /// Returns error if index is zero - use base address directly for zero payment_id.
    pub fn from_index(base: dCTIDHReceivingAddress, index: u64) -> Result<Self> {
        ensure!(index != 0, "index must be non-zero for subaddresses");
        Self::new(base, BFieldElement::new(index))
    }

    /// Get the encryption key (same as base address)
    pub fn encryption_key(&self) -> PublicKey {
        *self.base.encryption_key()
    }

    /// Get payment_id as u64
    pub fn payment_id_u64(&self) -> u64 {
        self.payment_id.value()
    }
}

// Implement bech32m serialization for dCTIDHSubAddress.
// Override the macro implementation to only encode encryption_key + payment_id
// (not the full struct) to keep it compact like base address.
impl dCTIDHSubAddress {
    /// Returns human readable prefix (hrp) for CTIDH subaddress
    pub(super) fn get_hrp(network: Network) -> String {
        format!("xntcta{}", common::network_hrp_char(network))
    }

    /// Encode subaddress as bech32m string.
    ///
    /// Payload: encryption_key (64) + lock postimage (40) + payment_id (8) =
    /// 112 bytes, giving ~193 chars (under 255).
    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        let hrp = Self::get_hrp(network);
        let mut payload = Vec::with_capacity(64 + Digest::LEN * 8 + 8);
        payload.extend_from_slice(&self.base.encryption_key()[..]);
        payload.extend_from_slice(&digest_to_bytes(&self.base.lock_postimage));
        payload.extend_from_slice(&self.payment_id.value().to_le_bytes());

        let variant = Variant::Bech32m;
        let enc = bech32::encode(&hrp, payload.to_base32(), variant)
            .map_err(|e| anyhow!("bech32m encode: {e}"))?;
        ensure!(
            enc.len() <= CTIDH_ADDRESS_MAX_BECH32M_LEN + 20, // Allow some extra for payment_id
            "CTIDH subaddress bech32m length {} exceeds maximum",
            enc.len()
        );
        Ok(enc)
    }

    /// Decode subaddress from bech32m string
    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let expected_hrp = Self::get_hrp(network);
        let (hrp, data, variant) = bech32::decode(encoded)?;

        ensure!(
            variant == Variant::Bech32m,
            "Can only decode bech32m subaddresses.",
        );
        ensure!(
            hrp == expected_hrp,
            "Invalid prefix for CTIDH subaddress. Expected: {expected_hrp}, got: {hrp}",
        );

        let payload = Vec::<u8>::from_base32(&data)?;
        const PK_LEN: usize = 64;
        const POST_LEN: usize = Digest::LEN * 8;
        const EXPECTED_LEN: usize = PK_LEN + POST_LEN + 8;
        ensure!(
            payload.len() == EXPECTED_LEN,
            "CTIDH subaddress payload must be {EXPECTED_LEN} bytes (64 pubkey + 40 postimage + 8 payment_id), got {}",
            payload.len()
        );

        let mut encryption_key = [0u8; 64];
        encryption_key.copy_from_slice(&payload[0..PK_LEN]);
        let postimage = digest_from_bytes(&payload[PK_LEN..PK_LEN + POST_LEN]);
        let payment_id_bytes = &payload[PK_LEN + POST_LEN..EXPECTED_LEN];
        let payment_id_value = u64::from_le_bytes([
            payment_id_bytes[0], payment_id_bytes[1], payment_id_bytes[2], payment_id_bytes[3],
            payment_id_bytes[4], payment_id_bytes[5], payment_id_bytes[6], payment_id_bytes[7],
        ]);

        let base = dCTIDHReceivingAddress::from_parts(encryption_key, postimage);
        let payment_id = BFieldElement::new(payment_id_value);

        Self::new(base, payment_id)
    }
}

impl SubAddressTrait for dCTIDHSubAddress {
    type Base = dCTIDHReceivingAddress;

    fn base(&self) -> &Self::Base {
        &self.base
    }

    fn payment_id(&self) -> BFieldElement {
        self.payment_id
    }

    fn receiver_identifier(&self) -> BFieldElement {
        self.base.receiver_identifier()
    }

    fn split(self) -> (Self::Base, BFieldElement) {
        (self.base, self.payment_id)
    }

    fn flag() -> BFieldElement {
        CTIDH_SUBADDR_FLAG
    }

    fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        let payload_with_id = UtxoNotificationPayload::with_payment_id(
            payload.utxo.clone(),
            payload.sender_randomness,
            self.payment_id,
        );
        self.base.encrypt(&payload_with_id)
    }
}

/// Only seed is persisted; derived fields have [serde(skip)] and are recomputed on deserialize.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct dCTIDHSpendingKey {
    seed: Digest,

    #[serde(skip)]
    receiver_identifier: BFieldElement,

    #[serde(skip)]
    secret_key: SecretKey,

    #[serde(skip)]
    receiver_preimage: Digest,

    #[serde(skip)]
    unlock_key_preimage: Digest,

    /// True only for keys derived with the legacy (pre-v0.3) lock derivation,
    /// used for recognising and sweeping legacy-format UTXOs. Not serialized:
    /// a deserialized key is always a current-scheme key, so legacy keys must
    /// be derived fresh and never round-tripped through serde.
    #[serde(skip)]
    legacy: bool,
}

impl<'de> serde::de::Deserialize<'de> for dCTIDHSpendingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Seed,
        }

        struct FieldVisitor;

        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
            type Value = dCTIDHSpendingKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct dCTIDHSpendingKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let seed = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(dCTIDHSpendingKey::derive_from_seed(seed))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut seed = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Seed => {
                            if seed.is_some() {
                                return Err(serde::de::Error::duplicate_field("seed"));
                            }
                            seed = Some(map.next_value()?);
                        }
                    }
                }
                let seed_digest = seed.ok_or_else(|| serde::de::Error::missing_field("seed"))?;
                Ok(dCTIDHSpendingKey::derive_from_seed(seed_digest))
            }
        }

        const FIELDS: &[&str] = &["seed"];
        deserializer.deserialize_struct("dCTIDHSpendingKey", FIELDS, FieldVisitor)
    }
}

/// Format a CTIDH public key as hex in the same form as dCTIDH's test/demo output
/// (big-endian with "0x" prefix). Use for comparing with dCTIDH test_pubkey_compare or dctidh_demo.
/// Rust's `hex::encode(pk)` is little-endian and has no "0x", so it's 2 chars shorter and reversed.
pub fn public_key_hex_dctidh_format(pk: &PublicKey) -> String {
    let mut s = "0x".to_string();
    for i in (0..pk.len()).rev() {
        s.push_str(&format!("{:02x}", pk[i]));
    }
    s
}

impl std::fmt::Debug for dCTIDHSpendingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Derive public key from secret key for debugging purposes.
        let public_key = sk_to_pk(&self.secret_key).unwrap_or([0u8; 64]);
        // Use little-endian hex (same as hex::encode) for compact Debug.
        // For dCTIDH comparison use public_key_hex_dctidh_format(&public_key).
        f.debug_struct("dCTIDHSpendingKey")
            .field("public_key", &hex::encode(&public_key[..]))
            .finish_non_exhaustive()
    }
}

fn receiver_identifier_from_public_key(pk: &PublicKey) -> BFieldElement {
    let bfes = common::bytes_to_bfes(&pk[..]);
    let hash = Tip5::hash_varlen(&bfes);
    hash.values()[0]
}

/// Derive the lock preimage from the key's secret material, with domain
/// separation. The receiving address carries only `preimage.hash()`.
fn secret_lock_preimage(secret_material: &[BFieldElement]) -> Digest {
    const LOCK_PREIMAGE_DOMAIN: BFieldElement = BFieldElement::new(0xd0_c71d_10c_u64);
    Tip5::hash_varlen(
        &[secret_material.to_vec(), vec![LOCK_PREIMAGE_DOMAIN]].concat(),
    )
}

/// Legacy lock preimage derivation, kept only so the wallet can recognise and
/// sweep dCTIDH UTXOs received at pre-v0.3 (legacy-format) addresses. Never used
/// to derive new receiving addresses.
fn lock_preimage_from_public_key(pk: &PublicKey) -> Digest {
    let bfes = common::bytes_to_bfes(&pk[..]);
    Tip5::hash_varlen(&bfes)
}

/// Encode a [Digest] as exactly 40 bytes (5 little-endian u64 limbs), for the
/// address payload.
fn digest_to_bytes(d: &Digest) -> [u8; Digest::LEN * 8] {
    let mut out = [0u8; Digest::LEN * 8];
    for (i, bfe) in d.values().iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&bfe.value().to_le_bytes());
    }
    out
}

/// Inverse of [digest_to_bytes]. `bytes.len()` must be `Digest::LEN * 8`.
fn digest_from_bytes(bytes: &[u8]) -> Digest {
    let mut limbs = [BFieldElement::new(0); Digest::LEN];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        *limb = BFieldElement::new(u64::from_le_bytes(b));
    }
    Digest::new(limbs)
}

const CTIDH_SK_DOMAIN: &[u8] = b"dctidh512_sk";

/// Domain for deriving ephemeral CTIDH key from payload (deterministic announcement, like Generation).
const CTIDH_EPH_SK_DOMAIN: &[u8] = b"dctidh512_eph_sk";

impl dCTIDHSpendingKey {
    pub fn derive_from_seed(seed: Digest) -> Self {
        let seed_bytes = bincode::serialize(&seed).unwrap();
        let secret_key_bytes =
            common::shake256::<74>(&[seed_bytes.as_slice(), CTIDH_SK_DOMAIN].concat());
        let secret_key: SecretKey = secret_key_bytes;
        let public_key = sk_to_pk(&secret_key).expect("dctidh sk_to_pk from derived sk");
        let receiver_identifier = receiver_identifier_from_public_key(&public_key);
        let receiver_preimage = secret_lock_preimage(&seed.values());
        let unlock_key_preimage = receiver_preimage;
        Self {
            seed,
            receiver_identifier,
            secret_key,
            receiver_preimage,
            unlock_key_preimage,
            legacy: false,
        }
    }

    /// Derive a spending key using the legacy (pre-v0.3) lock derivation. Used
    /// only to recognise and sweep funds received at legacy-format dCTIDH
    /// addresses; it is never surfaced as a receiving address.
    pub fn legacy_from_seed(seed: Digest) -> Self {
        Self::derive_with_legacy_from_seed(seed).1
    }

    /// Derive both the current-scheme key and its legacy-derivation
    /// counterpart for `seed`, computing the public key only once.
    pub fn derive_with_legacy_from_seed(seed: Digest) -> (Self, Self) {
        let seed_bytes = bincode::serialize(&seed).unwrap();
        let secret_key: SecretKey =
            common::shake256::<74>(&[seed_bytes.as_slice(), CTIDH_SK_DOMAIN].concat());
        let public_key = sk_to_pk(&secret_key).expect("dctidh sk_to_pk from derived sk");
        let receiver_identifier = receiver_identifier_from_public_key(&public_key);
        let key = |receiver_preimage: Digest, legacy: bool| Self {
            seed,
            receiver_identifier,
            secret_key,
            receiver_preimage,
            unlock_key_preimage: receiver_preimage,
            legacy,
        };
        (
            key(secret_lock_preimage(&seed.values()), false),
            key(lock_preimage_from_public_key(&public_key), true),
        )
    }

    pub fn from_key_pair(public_key: PublicKey, secret_key: SecretKey) -> Self {
        let receiver_identifier = receiver_identifier_from_public_key(&public_key);
        // Lock preimage from the imported secret key material.
        let receiver_preimage = secret_lock_preimage(&common::bytes_to_bfes(&secret_key));
        Self {
            seed: Digest::new([BFieldElement::new(0); Digest::LEN]),
            receiver_identifier,
            secret_key,
            receiver_preimage,
            unlock_key_preimage: receiver_preimage,
            legacy: false,
        }
    }

    pub fn from_secret_key(secret_key: SecretKey) -> Result<Self, ()> {
        let public_key = sk_to_pk(&secret_key)?;
        Ok(Self::from_key_pair(public_key, secret_key))
    }

    /// Generate a new random key pair. For tests only; wallet keys use [derive_from_seed].
    pub fn keygen() -> Self {
        let (pk, sk) = keygen();
        Self::from_key_pair(pk, sk)
    }

    pub fn seed(&self) -> Digest {
        self.seed
    }

    /// True for keys derived with the legacy lock derivation. Such keys are
    /// used only for scanning and spending and have no receiving address.
    pub fn is_legacy(&self) -> bool {
        self.legacy
    }

    /// Receiving address for this key.
    pub fn to_address(&self) -> dCTIDHReceivingAddress {
        assert!(
            !self.legacy,
            "legacy dCTIDH keys must never be surfaced as receiving addresses"
        );
        let public_key =
            sk_to_pk(&self.secret_key).expect("dctidh sk_to_pk from spending secret key");
        // The address carries the hash of the lock preimage.
        dCTIDHReceivingAddress {
            encryption_key: public_key,
            receiver_identifier: self.receiver_identifier,
            receiver_postimage: self.receiver_preimage.hash(),
            lock_postimage: self.unlock_key_preimage.hash(),
        }
    }

    pub fn receiver_preimage(&self) -> Digest {
        self.receiver_preimage
    }

    pub fn receiver_identifier(&self) -> BFieldElement {
        self.receiver_identifier
    }

    pub fn decrypt(
        &self,
        ciphertext_bfes: &[BFieldElement],
    ) -> Result<(Utxo, Digest, BFieldElement)> {
        // Ephemeral pk is a CTIDH-512 public key (64 bytes). After bytes_to_bfes this
        // yields a small number of BFieldElements; we allow a conservative range and
        // rely on the byte-length check below to enforce exact size.
        const EPHEMERAL_PK_BFE_MIN: usize = 1;
        const EPHEMERAL_PK_BFE_MAX: usize = 32;
        const NONCE_BFE_LEN: usize = 1;

        ensure!(ciphertext_bfes.len() >= 1, "ciphertext too short");
        let pk_bfe_len = ciphertext_bfes[0].value() as usize;
        ensure!(
            pk_bfe_len >= EPHEMERAL_PK_BFE_MIN && pk_bfe_len <= EPHEMERAL_PK_BFE_MAX,
            "invalid ephemeral pk BFE length"
        );
        ensure!(
            ciphertext_bfes.len() >= 1 + pk_bfe_len + NONCE_BFE_LEN,
            "ciphertext too short"
        );
        let pk_bfes = &ciphertext_bfes[1..1 + pk_bfe_len];
        let rest = &ciphertext_bfes[1 + pk_bfe_len..];
        let pk_bytes = common::bfes_to_bytes(pk_bfes)?;
        ensure!(
            pk_bytes.len() == 64,
            "ephemeral public key wrong length (expected 64 bytes, got {})",
            pk_bytes.len()
        );
        let ephemeral_pk: PublicKey = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ephemeral public key wrong length"))?;

        ensure!(
            rest.len() > NONCE_BFE_LEN,
            "ciphertext too short (missing nonce and payload)"
        );
        let (nonce_bfe, ciphertext) = rest.split_at(NONCE_BFE_LEN);
        let nonce_bytes: [u8; 12] = {
            let v = nonce_bfe[0].value();
            let mut b = [0u8; 12];
            b[0..8].copy_from_slice(&v.to_be_bytes());
            b
        };
        let nonce = Nonce::from_slice(&nonce_bytes);

        let shared_secret =
            derive(&ephemeral_pk, &self.secret_key).map_err(|_| anyhow!("CTIDH derive failed"))?;
        let aes_key: [u8; 32] = common::shake256::<32>(&shared_secret);

        let ciphertext_bytes = common::bfes_to_bytes(ciphertext)?;
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let plaintext = cipher
            .decrypt(nonce, ciphertext_bytes.as_ref())
            .map_err(|_| anyhow!("CTIDH payload decryption failed"))?;

        #[derive(serde::Serialize, serde::Deserialize)]
        struct Payload {
            utxo: Utxo,
            sender_randomness: Digest,
            payment_id: BFieldElement,
        }
        let payload: Payload = bincode::deserialize(&plaintext)?;
        Ok((
            payload.utxo,
            payload.sender_randomness,
            payload.payment_id,
        ))
    }

    pub fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        LockScriptAndWitness::standard_hash_lock_from_preimage(self.unlock_key_preimage)
    }
}

impl dCTIDHReceivingAddress {
    /// Reconstruct a receiving address from its wire parts: the encryption
    /// public key and the lock postimage carried in the address.
    fn from_parts(public_key: PublicKey, postimage: Digest) -> Self {
        let receiver_identifier = receiver_identifier_from_public_key(&public_key);
        Self {
            encryption_key: public_key,
            receiver_identifier,
            receiver_postimage: postimage,
            lock_postimage: postimage,
        }
    }

    pub fn encryption_key(&self) -> &PublicKey {
        &self.encryption_key
    }

    pub fn receiver_identifier(&self) -> BFieldElement {
        self.receiver_identifier
    }

    pub fn receiver_postimage(&self) -> Digest {
        self.receiver_postimage
    }

    pub fn spending_lock(&self) -> Digest {
        self.lock_postimage
    }

    pub fn lock_script(&self) -> LockScript {
        LockScript::standard_hash_lock_from_after_image(self.lock_postimage)
    }

    pub(crate) fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        let (seed_32, nonce_bfe) = deterministically_derive_seed_and_nonce(payload);
        let eph_sk_bytes =
            common::shake256::<74>(&[seed_32.as_slice(), CTIDH_EPH_SK_DOMAIN].concat());
        let eph_sk: SecretKey = eph_sk_bytes;
        let eph_pk = sk_to_pk(&eph_sk).expect("dctidh eph sk_to_pk");
        let shared_secret = derive(&self.encryption_key, &eph_sk).expect("CTIDH derive");
        let aes_key: [u8; 32] = common::shake256::<32>(&shared_secret);
        let plaintext = bincode::serialize(&(
            payload.utxo.clone(),
            payload.sender_randomness,
            payload.payment_id,
        ))
        .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let nonce_bytes: [u8; 12] = {
            let v = nonce_bfe.value();
            let mut b = [0u8; 12];
            b[0..8].copy_from_slice(&v.to_be_bytes());
            b
        };
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let pk_bfes = common::bytes_to_bfes(&eph_pk);
        let mut out = vec![BFieldElement::new(pk_bfes.len() as u64)];
        out.extend(pk_bfes);
        out.push(nonce_bfe);
        out.extend(common::bytes_to_bfes(&ciphertext));
        out
    }

    pub(crate) fn generate_announcement(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> Announcement {
        let enc = EncryptedUtxoNotification {
            flag: CTIDH_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };
        enc.into_announcement()
    }

    pub(crate) fn private_utxo_notification(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
        network: Network,
    ) -> String {
        let enc = EncryptedUtxoNotification {
            flag: CTIDH_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };
        enc.into_bech32m(network)
    }

    /// Human-readable prefix for CTIDH addresses: "xntct" + network char (e.g. "xntctm" for mainnet).
    pub(super) fn get_hrp(network: Network) -> String {
        format!("xntct{}", common::network_hrp_char(network))
    }

    /// Encode this receiving address as canonical bech32m string.
    ///
    /// Payload: encryption_key (64 bytes) + lock postimage (40 bytes) = 104
    /// bytes, giving a bech32m string of ~180 chars (well under 255).
    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        let hrp = Self::get_hrp(network);
        let mut payload = Vec::with_capacity(64 + Digest::LEN * 8);
        payload.extend_from_slice(&self.encryption_key[..]);
        payload.extend_from_slice(&digest_to_bytes(&self.lock_postimage));
        let variant = Variant::Bech32m;
        let enc = bech32::encode(&hrp, payload.to_base32(), variant)
            .map_err(|e| anyhow!("bech32m encode: {e}"))?;
        ensure!(
            enc.len() <= CTIDH_ADDRESS_MAX_BECH32M_LEN,
            "CTIDH address bech32m length {} must be <= {}",
            enc.len(),
            CTIDH_ADDRESS_MAX_BECH32M_LEN
        );
        Ok(enc)
    }

    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let expected_hrp = Self::get_hrp(network);
        ensure!(
            encoded.starts_with(&expected_hrp),
            "Invalid HRP for CTIDH address"
        );
        // Long bech32m form: full bech32m.
        let (hrp, data, variant) = bech32::decode(encoded)?;
        ensure!(variant == Variant::Bech32m, "Only bech32m supported");
        ensure!(hrp == expected_hrp, "Invalid HRP for CTIDH address");
        let bytes = Vec::<u8>::from_base32(&data)?;
        const EXPECTED_LEN: usize = 64 + Digest::LEN * 8;
        ensure!(
            bytes.len() == EXPECTED_LEN,
            "CTIDH address payload must be {EXPECTED_LEN} bytes (64 pubkey + 40 postimage), got {}",
            bytes.len()
        );
        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(&bytes[0..64]);
        let postimage = digest_from_bytes(&bytes[64..EXPECTED_LEN]);
        Ok(Self::from_parts(public_key, postimage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::config::network::Network;

}
