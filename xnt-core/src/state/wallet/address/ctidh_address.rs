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
use ctidh512::{derive, keygen, sk_to_pk, PublicKey, SecretKey};
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::common;
use super::common::deterministically_derive_seed_and_nonce;
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

/// Bech32m length for 2048-bit: 6 (HRP) + 1 + base32(256) + 6 checksum = 6+1+410+6 = 423.
pub const CTIDH_ADDRESS_MAX_BECH32M_LEN: usize = 430;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CtidhReceivingAddress {
    #[serde(with = "serde_arrays")]
    encryption_key: PublicKey,
    receiver_identifier: BFieldElement,
    receiver_postimage: Digest,
    lock_postimage: Digest,
}

/// Only seed is persisted; derived fields have [serde(skip)] and are recomputed on deserialize.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CtidhSpendingKey {
    seed: Digest,

    #[serde(skip)]
    receiver_identifier: BFieldElement,

    #[serde(skip)]
    secret_key: SecretKey,

    #[serde(skip)]
    receiver_preimage: Digest,

    #[serde(skip)]
    unlock_key_preimage: Digest,
}

impl<'de> serde::de::Deserialize<'de> for CtidhSpendingKey {
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
            type Value = CtidhSpendingKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct CtidhSpendingKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let seed = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(CtidhSpendingKey::derive_from_seed(seed))
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
                Ok(CtidhSpendingKey::derive_from_seed(seed_digest))
            }
        }

        const FIELDS: &[&str] = &["seed"];
        deserializer.deserialize_struct("CtidhSpendingKey", FIELDS, FieldVisitor)
    }
}

/// Format a CTIDH public key as hex in the same form as dCTIDH's test/demo output
/// (big-endian with "0x" prefix). Use for comparing with dCTIDH test_pubkey_compare or ctidh_demo.
/// Rust's `hex::encode(pk)` is little-endian and has no "0x", so it's 2 chars shorter and reversed.
pub fn public_key_hex_dctidh_format(pk: &PublicKey) -> String {
    let mut s = "0x".to_string();
    for i in (0..pk.len()).rev() {
        s.push_str(&format!("{:02x}", pk[i]));
    }
    s
}

impl std::fmt::Debug for CtidhSpendingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Derive public key from secret key for debugging purposes.
        let public_key = sk_to_pk(&self.secret_key).unwrap_or([0u8; 64]);
        // Use little-endian hex (same as hex::encode) for compact Debug.
        // For dCTIDH comparison use public_key_hex_dctidh_format(&public_key).
        f.debug_struct("CtidhSpendingKey")
            .field("public_key", &hex::encode(&public_key[..]))
            .finish_non_exhaustive()
    }
}

fn receiver_identifier_from_public_key(pk: &PublicKey) -> BFieldElement {
    let bfes = common::bytes_to_bfes(&pk[..]);
    let hash = Tip5::hash_varlen(&bfes);
    hash.values()[0]
}

fn lock_preimage_from_public_key(pk: &PublicKey) -> Digest {
    let bfes = common::bytes_to_bfes(&pk[..]);
    Tip5::hash_varlen(&bfes)
}

const CTIDH_SK_DOMAIN: &[u8] = b"ctidh512_sk";

/// Domain for deriving ephemeral CTIDH key from payload (deterministic announcement, like Generation).
const CTIDH_EPH_SK_DOMAIN: &[u8] = b"ctidh512_eph_sk";

impl CtidhSpendingKey {
    pub fn derive_from_seed(seed: Digest) -> Self {
        let seed_bytes = bincode::serialize(&seed).unwrap();
        let secret_key_bytes =
            common::shake256::<74>(&[seed_bytes.as_slice(), CTIDH_SK_DOMAIN].concat());
        let secret_key: SecretKey = secret_key_bytes;
        let public_key = sk_to_pk(&secret_key).expect("ctidh sk_to_pk from derived sk");
        let receiver_identifier = receiver_identifier_from_public_key(&public_key);
        let receiver_preimage = lock_preimage_from_public_key(&public_key);
        let unlock_key_preimage = receiver_preimage;
        Self {
            seed,
            receiver_identifier,
            secret_key,
            receiver_preimage,
            unlock_key_preimage,
        }
    }

    pub fn from_key_pair(public_key: PublicKey, secret_key: SecretKey) -> Self {
        let receiver_identifier = receiver_identifier_from_public_key(&public_key);
        let receiver_preimage = lock_preimage_from_public_key(&public_key);
        Self {
            seed: Digest::new([BFieldElement::new(0); Digest::LEN]),
            receiver_identifier,
            secret_key,
            receiver_preimage,
            unlock_key_preimage: receiver_preimage,
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

    /// Receiving address for this key.
    pub fn to_address(&self) -> CtidhReceivingAddress {
        let public_key =
            sk_to_pk(&self.secret_key).expect("ctidh sk_to_pk from spending secret key");
        CtidhReceivingAddress::from_public_key(public_key)
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

impl CtidhReceivingAddress {
    pub fn from_public_key(public_key: PublicKey) -> Self {
        let receiver_identifier = receiver_identifier_from_public_key(&public_key);
        let preimage = lock_preimage_from_public_key(&public_key);
        let receiver_postimage = preimage.hash();
        let lock_postimage = preimage.hash();
        Self {
            encryption_key: public_key,
            receiver_identifier,
            receiver_postimage,
            lock_postimage,
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
        let eph_pk = sk_to_pk(&eph_sk).expect("ctidh eph sk_to_pk");
        let shared_secret = derive(&self.encryption_key, &eph_sk).expect("CTIDH derive");
        let aes_key: [u8; 32] = common::shake256::<32>(&shared_secret);
        let plaintext = bincode::serialize(&(
            payload.utxo.clone(),
            payload.sender_randomness,
            BFieldElement::new(0),
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
    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        let hrp = Self::get_hrp(network);
        let payload_bytes = &self.encryption_key[..];
        let variant = Variant::Bech32m;
        let enc = bech32::encode(&hrp, payload_bytes.to_base32(), variant)
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
        ensure!(bytes.len() == 64, "CTIDH public key must be 64 bytes");
        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(&bytes);
        Ok(Self::from_public_key(public_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::config::network::Network;

    #[test]
    fn ctidh_address_bech32m_long_format_roundtrip() {
        let key = CtidhSpendingKey::keygen();
        let addr = key.to_address();
        let enc = addr.to_bech32m_long(Network::Testnet(0)).unwrap();
        let (hrp, _, _) = bech32::decode(&enc).unwrap();
        assert!(enc.starts_with(&format!("{}1", hrp)));
        let decoded = CtidhReceivingAddress::from_bech32m(&enc, Network::Testnet(0)).unwrap();
        assert_eq!(addr, decoded);
    }

}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for CtidhReceivingAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let pk: [u8; 256] = u.arbitrary()?;
        Ok(Self::from_public_key(pk))
    }
}
