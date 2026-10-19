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
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::consensus_rule_set::upgrade_vm_v8_activation_height;
use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET;
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

/// Fixed secret key used only to check that a public key is a valid dCTIDH
/// public key, see [`dCTIDHReceivingAddress::validate_encryption_key`].
static ENCRYPTION_KEY_CHECK_SECRET: std::sync::LazyLock<SecretKey> =
    std::sync::LazyLock::new(|| {
        super::dctidh_sampler::secret_key_from_seed(b"public key check", b"dctidh512_check_sk")
    });

/// The block height from which the wallet no longer recognizes outputs locked
/// to a legacy-format (pre-v0.3) dCTIDH lock, or `None` if it recognizes them
/// at any height.
///
/// On main net this is the `UpgradeVMv8` activation height: outputs at legacy
/// locks are recognized only if they were confirmed in a block below it. Other
/// networks run `UpgradeVMv8` from genesis and have no cutoff, so that funds
/// at legacy locks, and moving them, can be exercised there; unless the
/// process has an activation height above genesis for the network (see
/// [`set_v8_activation_height`]), which is then the cutoff, as on main net.
///
/// [`set_v8_activation_height`]: crate::protocol::consensus::consensus_rule_set::set_v8_activation_height
pub fn legacy_dctidh_cutoff(network: Network) -> Option<BlockHeight> {
    match network {
        Network::Main => Some(BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET),
        Network::TestnetMock | Network::RegTest | Network::Testnet(_) => {
            let activation_height = upgrade_vm_v8_activation_height(network);
            (!activation_height.is_genesis()).then_some(activation_height)
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct dCTIDHReceivingAddress {
    #[serde(with = "serde_arrays")]
    encryption_key: PublicKey,
    receiver_identifier: BFieldElement,
    receiver_postimage: Digest,
    lock_postimage: Digest,
}

/// The serialized fields of a [`dCTIDHReceivingAddress`], read without the
/// checks its `Deserialize` implementation applies. Only for records the
/// wallet wrote itself, see
/// [`ReceivingAddress::deserialize_unchecked`](super::ReceivingAddress::deserialize_unchecked).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename = "dCTIDHReceivingAddress")]
pub(super) struct UncheckedReceivingAddress {
    #[serde(with = "serde_arrays")]
    encryption_key: PublicKey,
    receiver_identifier: BFieldElement,
    receiver_postimage: Digest,
    lock_postimage: Digest,
}

impl From<UncheckedReceivingAddress> for dCTIDHReceivingAddress {
    fn from(fields: UncheckedReceivingAddress) -> Self {
        Self {
            encryption_key: fields.encryption_key,
            receiver_identifier: fields.receiver_identifier,
            receiver_postimage: fields.receiver_postimage,
            lock_postimage: fields.lock_postimage,
        }
    }
}

/// Same serialized layout as the derived implementation. Refuses addresses
/// carrying a legacy-format lock and addresses whose fields do not belong
/// together, i.e., anything [`dCTIDHReceivingAddress::from_bech32m`] would not
/// produce.
impl<'de> Deserialize<'de> for dCTIDHReceivingAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let fields = UncheckedReceivingAddress::deserialize(deserializer)?;
        let address = Self::from_parts(fields.encryption_key, fields.lock_postimage)
            .map_err(serde::de::Error::custom)?;
        if address != Self::from(fields) {
            return Err(serde::de::Error::custom(
                "dCTIDH address fields are inconsistent",
            ));
        }
        Ok(address)
    }
}

/// The serialized fields of a [`dCTIDHSubAddress`], read without checks. See
/// [`UncheckedReceivingAddress`].
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename = "dCTIDHSubAddress")]
pub(super) struct UncheckedSubAddress {
    base: UncheckedReceivingAddress,
    payment_id: BFieldElement,
}

impl From<UncheckedSubAddress> for dCTIDHSubAddress {
    fn from(fields: UncheckedSubAddress) -> Self {
        Self {
            base: fields.base.into(),
            payment_id: fields.payment_id,
        }
    }
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
        let postimage = digest_from_bytes(&payload[PK_LEN..PK_LEN + POST_LEN])?;
        let payment_id = bfe_from_bytes(&payload[PK_LEN + POST_LEN..EXPECTED_LEN])?;

        let base = dCTIDHReceivingAddress::from_parts(encryption_key, postimage)?;

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

    fn encrypt(&self, payload: &UtxoNotificationPayload) -> Result<Vec<BFieldElement>> {
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

/// Whether `lock_postimage` is the legacy-format lock of public key `pk`.
fn is_legacy_lock(pk: &PublicKey, lock_postimage: Digest) -> bool {
    lock_preimage_from_public_key(pk).hash() == lock_postimage
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
///
/// Refuses limbs that are not canonical field elements, so that every digest
/// has exactly one encoding.
fn digest_from_bytes(bytes: &[u8]) -> Result<Digest> {
    let mut limbs = [BFieldElement::new(0); Digest::LEN];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = bfe_from_bytes(chunk)?;
    }
    Ok(Digest::new(limbs))
}

/// Decode a little-endian u64 into a field element. `bytes.len()` must be 8.
/// Refuses values that are not canonical field elements.
fn bfe_from_bytes(bytes: &[u8]) -> Result<BFieldElement> {
    let mut b = [0u8; 8];
    b.copy_from_slice(bytes);
    let value = u64::from_le_bytes(b);
    ensure!(
        value < BFieldElement::P,
        "dCTIDH address payload holds a non-canonical field element"
    );
    Ok(BFieldElement::new(value))
}

const CTIDH_SK_DOMAIN: &[u8] = b"dctidh512_sk";

/// Domain for deriving ephemeral CTIDH key from payload (deterministic announcement, like Generation).
const CTIDH_EPH_SK_DOMAIN: &[u8] = b"dctidh512_eph_sk";

impl dCTIDHSpendingKey {
    pub fn derive_from_seed(seed: Digest) -> Self {
        let seed_bytes = bincode::serialize(&seed).unwrap();
        let secret_key: SecretKey =
            super::dctidh_sampler::secret_key_from_seed(&seed_bytes, CTIDH_SK_DOMAIN);
        debug_assert!(super::dctidh_sampler::is_within_batch_bounds(&secret_key));
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

    /// Derive the spending key that pre-v0.3 releases derived for `seed`. Used
    /// only to recognise and sweep funds received at legacy-format dCTIDH
    /// addresses; it is never surfaced as a receiving address.
    ///
    /// The secret key, public key, receiver identifier and lock are exactly
    /// those of the pre-v0.3 derivation, so the wallet finds and can spend the
    /// UTXOs that were sent to that release's addresses. They differ from those
    /// of [Self::derive_from_seed] for the same seed.
    pub fn legacy_from_seed(seed: Digest) -> Self {
        let seed_bytes = bincode::serialize(&seed).unwrap();
        let secret_key: SecretKey =
            common::shake256::<74>(&[seed_bytes.as_slice(), CTIDH_SK_DOMAIN].concat());
        let public_key = sk_to_pk(&secret_key).expect("dctidh sk_to_pk from derived sk");
        let receiver_identifier = receiver_identifier_from_public_key(&public_key);
        let receiver_preimage = lock_preimage_from_public_key(&public_key);
        Self {
            seed,
            receiver_identifier,
            secret_key,
            receiver_preimage,
            unlock_key_preimage: receiver_preimage,
            legacy: true,
        }
    }

    /// The address that releases before v0.3 handed out for this key, with
    /// the lock of this key. Only for tests: addresses that carry a
    /// legacy-format lock are refused everywhere else.
    #[cfg(test)]
    pub(crate) fn pre_v0_3_address(&self) -> dCTIDHReceivingAddress {
        dCTIDHReceivingAddress {
            encryption_key: sk_to_pk(&self.secret_key).unwrap(),
            receiver_identifier: self.receiver_identifier,
            receiver_postimage: self.receiver_preimage.hash(),
            lock_postimage: self.unlock_key_preimage.hash(),
        }
    }

    /// Derive both the current-scheme key and its legacy-derivation
    /// counterpart for `seed`.
    ///
    /// The two keys share only the seed: their secret keys, public keys and
    /// receiver identifiers differ, so each one recognises its own UTXOs.
    pub fn derive_with_legacy_from_seed(seed: Digest) -> (Self, Self) {
        (Self::derive_from_seed(seed), Self::legacy_from_seed(seed))
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

    /// Build a key from an existing secret key. Fails unless the secret key
    /// stays within the per-batch exponent bounds of the group action, as keys
    /// from [Self::derive_from_seed] and [Self::keygen] do.
    pub fn from_secret_key(secret_key: SecretKey) -> Result<Self, ()> {
        if !super::dctidh_sampler::is_within_batch_bounds(&secret_key) {
            return Err(());
        }
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
    ///
    /// Refuses a legacy-format lock: such addresses are not accepted.
    fn from_parts(public_key: PublicKey, postimage: Digest) -> Result<Self> {
        ensure!(
            !is_legacy_lock(&public_key, postimage),
            "dCTIDH address uses the legacy-format lock, which is no longer accepted; \
             ask the recipient for a new address"
        );
        let receiver_identifier = receiver_identifier_from_public_key(&public_key);
        Ok(Self {
            encryption_key: public_key,
            receiver_identifier,
            receiver_postimage: postimage,
            lock_postimage: postimage,
        })
    }

    /// Check that funds can be sent to this address: the lock is not a
    /// legacy-format lock and the encryption key is a valid dCTIDH public key,
    /// so that UTXO notifications can be encrypted to it.
    ///
    /// The public-key check costs one dCTIDH key derivation (tens of
    /// milliseconds on x86-64, around a second on some other targets), so it
    /// is done where an address becomes a transaction output, not when an
    /// address is decoded.
    pub fn validate_encryption_key(&self) -> Result<()> {
        ensure!(
            !is_legacy_lock(&self.encryption_key, self.lock_postimage),
            "dCTIDH address uses the legacy-format lock, which is no longer accepted"
        );
        derive(&self.encryption_key, &ENCRYPTION_KEY_CHECK_SECRET)
            .map_err(|_| anyhow!("dCTIDH address has an invalid public key"))?;
        Ok(())
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

    /// Encrypt a UTXO notification to this address.
    ///
    /// Fails if the encryption key is not a valid dCTIDH public key.
    pub(crate) fn encrypt(&self, payload: &UtxoNotificationPayload) -> Result<Vec<BFieldElement>> {
        let (seed_32, nonce_bfe) = deterministically_derive_seed_and_nonce(payload);
        let eph_sk: SecretKey =
            super::dctidh_sampler::secret_key_from_seed(&seed_32, CTIDH_EPH_SK_DOMAIN);
        debug_assert!(super::dctidh_sampler::is_within_batch_bounds(&eph_sk));
        let eph_pk =
            sk_to_pk(&eph_sk).map_err(|_| anyhow!("dCTIDH ephemeral key derivation failed"))?;
        let shared_secret = derive(&self.encryption_key, &eph_sk)
            .map_err(|_| anyhow!("dCTIDH address has an invalid public key"))?;
        let aes_key: [u8; 32] = common::shake256::<32>(&shared_secret);
        let plaintext = bincode::serialize(&(
            payload.utxo.clone(),
            payload.sender_randomness,
            payload.payment_id,
        ))?;
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let nonce_bytes: [u8; 12] = {
            let v = nonce_bfe.value();
            let mut b = [0u8; 12];
            b[0..8].copy_from_slice(&v.to_be_bytes());
            b
        };
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| anyhow!("dCTIDH payload encryption failed"))?;

        let pk_bfes = common::bytes_to_bfes(&eph_pk);
        let mut out = vec![BFieldElement::new(pk_bfes.len() as u64)];
        out.extend(pk_bfes);
        out.push(nonce_bfe);
        out.extend(common::bytes_to_bfes(&ciphertext));
        Ok(out)
    }

    pub(crate) fn generate_announcement(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> Result<Announcement> {
        let enc = EncryptedUtxoNotification {
            flag: CTIDH_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload)?,
        };
        Ok(enc.into_announcement())
    }

    pub(crate) fn private_utxo_notification(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
        network: Network,
    ) -> Result<String> {
        let enc = EncryptedUtxoNotification {
            flag: CTIDH_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload)?,
        };
        Ok(enc.into_bech32m(network))
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
        let postimage = digest_from_bytes(&bytes[64..EXPECTED_LEN])?;
        Self::from_parts(public_key, postimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::state::wallet::address::ReceivingAddress;
    use crate::state::wallet::address::SpendingKey;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::transaction_output::TxOutputList;

    const NETWORK: Network = Network::Main;

    fn random_key() -> dCTIDHSpendingKey {
        dCTIDHSpendingKey::derive_from_seed(rand::random())
    }

    /// The address that versions before v0.3 produced for the seed of `key`:
    /// the legacy key's public key with its legacy-format lock.
    fn legacy_format_address(key: &dCTIDHSpendingKey) -> dCTIDHReceivingAddress {
        dCTIDHSpendingKey::legacy_from_seed(key.seed()).pre_v0_3_address()
    }

    /// The bech32m payload of a base address: public key and lock postimage.
    fn base_payload(address: &dCTIDHReceivingAddress) -> Vec<u8> {
        [
            address.encryption_key.as_slice(),
            &digest_to_bytes(&address.lock_postimage),
        ]
        .concat()
    }

    /// Bech32m-encode a payload, without any of the checks of the encoders.
    fn encode(hrp: &str, payload: &[u8]) -> String {
        bech32::encode(hrp, payload.to_base32(), Variant::Bech32m).unwrap()
    }

    fn payment(address: &ReceivingAddress) -> UtxoNotificationPayload {
        let utxo =
            Utxo::new_native_currency(address.lock_script_hash(), NativeCurrencyAmount::coins(1));
        UtxoNotificationPayload::new(utxo, rand::random())
    }

    #[test]
    fn legacy_and_current_lock_of_a_key_differ() {
        let key = random_key();
        let legacy = dCTIDHSpendingKey::legacy_from_seed(key.seed());
        assert!(legacy.is_legacy());
        assert_eq!(
            legacy.receiver_preimage().hash(),
            legacy_format_address(&key).spending_lock()
        );
        assert_ne!(
            key.to_address().spending_lock(),
            legacy_format_address(&key).spending_lock()
        );
    }

    /// The legacy key of a seed is the key that releases before v0.3 derived
    /// for it, so the wallet keeps finding and spending funds sent to their
    /// addresses. The expected values were computed with v0.3 before the
    /// current-format key derivation changed.
    #[test]
    fn legacy_key_matches_the_pre_v0_3_derivation() {
        let seed = Digest::new([1u64, 2, 3, 4, 5].map(BFieldElement::new));
        let legacy = SpendingKey::from(dCTIDHSpendingKey::legacy_from_seed(seed));

        assert!(legacy.is_legacy());
        assert_eq!(
            BFieldElement::new(16_468_899_874_955_363_775),
            legacy.receiver_identifier()
        );
        assert_eq!(
            "397d175b40854ce41dd51aa7d66bb9ad542fb61e6b40f465ab269b90ef90bb926e8b9a08cd6350ee",
            legacy.lock_script_hash().to_hex()
        );
        assert_eq!(
            "bf8530282e498de4beef86fbcbc2bf3015f7d63bc9ceb29315077ca7d7dd88d190a9e30349798fd5",
            legacy.privacy_preimage().to_hex()
        );
    }

    /// Pins the current-format key and address of a fixed seed: a change to
    /// the derivation changes every dCTIDH address this version hands out.
    #[test]
    fn current_key_derivation_is_stable() {
        let seed = Digest::new([1u64, 2, 3, 4, 5].map(BFieldElement::new));
        let key = dCTIDHSpendingKey::derive_from_seed(seed);
        assert!(super::super::dctidh_sampler::is_within_batch_bounds(
            &key.secret_key
        ));
        assert_eq!(
            "xntctm1cj4zs05ys2rcxqv6mtc98fwyqx932nn4ffvp3nz2d82rlsdk47e9jv67xcyr0cn77kes933r7pwk793pktc8r7s2lnlppstlau9m2xuz5skg9phpem6v8da49gt5kffkn3k2xyn5xjtfhzz5dlvedh93vdmf2tra2xqxwwstnckh5",
            key.to_address().to_bech32m(NETWORK).unwrap()
        );

        let key = SpendingKey::from(key);
        assert_eq!(
            BFieldElement::new(6_910_219_607_948_680_251),
            key.receiver_identifier()
        );
        assert_eq!(
            "6caa1163cab345ff1323da873342803e8e87293d2028274385d0f6ce972c89f073923a076bd26917",
            key.lock_script_hash().to_hex()
        );
    }

    #[test]
    fn imported_secret_keys_must_stay_within_the_batch_bounds() {
        assert!(dCTIDHSpendingKey::from_secret_key([7u8; 74]).is_err());
        let derived = dCTIDHSpendingKey::derive_from_seed(rand::random());
        assert!(dCTIDHSpendingKey::from_secret_key(derived.secret_key).is_ok());
    }

    #[test]
    fn current_and_legacy_key_of_a_seed_share_only_the_seed() {
        let seed = rand::random();
        let (current, legacy) = dCTIDHSpendingKey::derive_with_legacy_from_seed(seed);
        assert_eq!(current.seed(), legacy.seed());
        assert_ne!(current.secret_key, legacy.secret_key);
        assert_ne!(current.receiver_identifier, legacy.receiver_identifier);
        assert_ne!(current.receiver_preimage, legacy.receiver_preimage);
        assert!(!current.is_legacy());
        assert!(legacy.is_legacy());
        assert_eq!(
            legacy.receiver_preimage,
            dCTIDHSpendingKey::legacy_from_seed(seed).receiver_preimage
        );
    }

    #[test]
    fn address_with_legacy_lock_is_refused() {
        let key = random_key();
        let legacy = legacy_format_address(&key);

        let base = encode(
            &dCTIDHReceivingAddress::get_hrp(NETWORK),
            &base_payload(&legacy),
        );
        assert!(dCTIDHReceivingAddress::from_bech32m(&base, NETWORK).is_err());
        assert!(ReceivingAddress::from_bech32m(&base, NETWORK).is_err());

        let sub_payload = [base_payload(&legacy), 7u64.to_le_bytes().to_vec()].concat();
        let sub = encode(&dCTIDHSubAddress::get_hrp(NETWORK), &sub_payload);
        assert!(dCTIDHSubAddress::from_bech32m(&sub, NETWORK).is_err());
        assert!(ReceivingAddress::from_bech32m(&sub, NETWORK).is_err());

        // the current-format address of the same key is accepted
        let current = key.to_address().to_bech32m(NETWORK).unwrap();
        assert_eq!(
            key.to_address(),
            dCTIDHReceivingAddress::from_bech32m(&current, NETWORK).unwrap()
        );
    }

    #[test]
    fn deserializing_address_with_legacy_lock_fails() {
        let key = random_key();
        let legacy = legacy_format_address(&key);

        let bytes = bincode::serialize(&legacy).unwrap();
        assert!(bincode::deserialize::<dCTIDHReceivingAddress>(&bytes).is_err());
        let json = serde_json::to_string(&legacy).unwrap();
        assert!(serde_json::from_str::<dCTIDHReceivingAddress>(&json).is_err());

        let receiving_address_bytes = bincode::serialize(&ReceivingAddress::from(legacy)).unwrap();
        assert!(bincode::deserialize::<ReceivingAddress>(&receiving_address_bytes).is_err());

        let sub = dCTIDHSubAddress {
            base: legacy,
            payment_id: BFieldElement::new(7),
        };
        let sub_bytes = bincode::serialize(&sub).unwrap();
        assert!(bincode::deserialize::<dCTIDHSubAddress>(&sub_bytes).is_err());
    }

    #[test]
    fn deserializing_address_with_inconsistent_fields_fails() {
        let address = random_key().to_address();
        let other_identifier = dCTIDHReceivingAddress {
            receiver_identifier: address.receiver_identifier + BFieldElement::new(1),
            ..address
        };
        let other_postimage = dCTIDHReceivingAddress {
            receiver_postimage: rand::random(),
            ..address
        };
        for inconsistent in [other_identifier, other_postimage] {
            let bytes = bincode::serialize(&inconsistent).unwrap();
            assert!(bincode::deserialize::<dCTIDHReceivingAddress>(&bytes).is_err());
        }
    }

    #[test]
    fn serialization_round_trip_is_unchanged() {
        let address = random_key().to_address();
        let bytes = bincode::serialize(&address).unwrap();
        assert_eq!(address, bincode::deserialize(&bytes).unwrap());
        let json = serde_json::to_string(&address).unwrap();
        assert_eq!(address, serde_json::from_str(&json).unwrap());

        // the serialized layout is the one of the unchecked fields
        let unchecked: UncheckedReceivingAddress = bincode::deserialize(&bytes).unwrap();
        assert_eq!(address, dCTIDHReceivingAddress::from(unchecked));

        let sub = dCTIDHSubAddress::new(address, BFieldElement::new(5)).unwrap();
        let sub_bytes = bincode::serialize(&sub).unwrap();
        assert_eq!(sub, bincode::deserialize(&sub_bytes).unwrap());
    }

    #[test]
    fn stored_output_with_legacy_lock_address_stays_readable() {
        // Past transactions stored in the wallet database may name
        // legacy-format addresses as notification targets.
        let legacy = ReceivingAddress::from(legacy_format_address(&random_key()));
        let tx_output = TxOutput::onchain_native_currency(
            NativeCurrencyAmount::coins(1),
            rand::random(),
            legacy.clone(),
            false,
        );

        let bytes = bincode::serialize(&tx_output).unwrap();
        let read_back: TxOutput = bincode::deserialize(&bytes).unwrap();
        assert_eq!(tx_output, read_back);
        assert_eq!(Some(&legacy), read_back.receiving_address());

        // but such an address is not accepted as recipient of a new output
        assert!(legacy.validate_as_recipient().is_err());
    }

    #[test]
    fn non_canonical_field_elements_are_refused() {
        let address = random_key().to_address();
        let base_hrp = dCTIDHReceivingAddress::get_hrp(NETWORK);
        let sub_hrp = dCTIDHSubAddress::get_hrp(NETWORK);

        // a postimage limb at or above the field modulus
        for limb in [BFieldElement::P, u64::MAX] {
            let mut payload = base_payload(&address);
            payload[64..72].copy_from_slice(&limb.to_le_bytes());
            let base_encoded = encode(&base_hrp, &payload);
            assert!(dCTIDHReceivingAddress::from_bech32m(&base_encoded, NETWORK).is_err());

            let sub_payload = [payload, 1u64.to_le_bytes().to_vec()].concat();
            let sub_encoded = encode(&sub_hrp, &sub_payload);
            assert!(dCTIDHSubAddress::from_bech32m(&sub_encoded, NETWORK).is_err());
        }

        // a payment id at or above the field modulus
        for payment_id in [BFieldElement::P, u64::MAX] {
            let payload = [base_payload(&address), payment_id.to_le_bytes().to_vec()].concat();
            let encoded = encode(&sub_hrp, &payload);
            assert!(dCTIDHSubAddress::from_bech32m(&encoded, NETWORK).is_err());
        }

        // the largest canonical payment id is accepted
        let payload = [
            base_payload(&address),
            (BFieldElement::P - 1).to_le_bytes().to_vec(),
        ]
        .concat();
        let encoded = encode(&sub_hrp, &payload);
        let sub = dCTIDHSubAddress::from_bech32m(&encoded, NETWORK).unwrap();
        assert_eq!(BFieldElement::P - 1, sub.payment_id_u64());
    }

    #[test]
    fn invalid_public_key_is_reported_as_error() {
        let postimage: Digest = rand::random();
        let address = dCTIDHReceivingAddress::from_parts([0xff; 64], postimage).unwrap();

        // decoding does not check the public key, which takes a key derivation
        let encoded = address.to_bech32m(NETWORK).unwrap();
        let decoded = ReceivingAddress::from_bech32m(&encoded, NETWORK).unwrap();
        assert_eq!(ReceivingAddress::from(address), decoded);

        assert!(address.validate_encryption_key().is_err());
        assert!(decoded.validate_as_recipient().is_err());
        let subaddress =
            ReceivingAddress::from(dCTIDHSubAddress::new(address, BFieldElement::new(3)).unwrap());
        assert!(subaddress.validate_as_recipient().is_err());

        for recipient in [&decoded, &subaddress] {
            assert!(recipient.generate_announcement(payment(recipient)).is_err());
            assert!(recipient
                .private_notification(payment(recipient), NETWORK)
                .is_err());
        }

        // an output to it gets no announcement, and the output list does not
        // pass validation
        let tx_output = TxOutput::onchain_native_currency(
            NativeCurrencyAmount::coins(1),
            rand::random(),
            decoded,
            false,
        );
        assert!(tx_output.announcement().is_none());
        assert!(TxOutputList::from(vec![tx_output])
            .validate_recipients()
            .is_err());

        // a valid public key passes
        let valid = ReceivingAddress::from(random_key().to_address());
        assert!(valid.validate_as_recipient().is_ok());
        assert!(valid.generate_announcement(payment(&valid)).is_ok());
    }
}
