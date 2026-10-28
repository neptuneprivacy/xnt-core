//! Bridge settlement authority (N-of-M validator signatures).
//!
//! A settlement announcement authorizes moving pool funds, but the aggregate
//! proof does not prove L2 validity. Validity is instead bound to the Leviathan
//! validator set: a settlement is only accepted if at least `threshold` of the
//! `M` authority keys signed its outcome digest. This check runs in
//! `Block::validate`, so every node rejects an unsigned/under-signed settlement
//! exactly as it rejects bad PoW.
//!
//! Scheme = secp256k1 ECDSA over `keccak256(digest)`, matching Leviathan's
//! `ecdsa_k256_keccak` so one operator key covers both chains. The signer uses
//! `SecretKey::sign_prehash`; here we only verify. Not post-quantum - an
//! operator-trust authority, upgradeable to a hash-based (Winternitz) sig later.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::Signature;
use k256::ecdsa::VerifyingKey;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;

/// Serialized length of one authority signature (SEC1 `r || s`, big-endian).
pub const AUTHORITY_SIGNATURE_BYTES: usize = 64;

/// The live bridge authority: `M` verifying keys and a `threshold` (`N`) of
/// them that must sign a settlement for it to be accepted.
#[derive(Debug, Clone)]
pub struct BridgeAuthoritySet {
    verifying_keys: Vec<VerifyingKey>,
    threshold: usize,
    /// Rotation counter (genesis 0, +1 per rotation), folded into
    /// [`Self::commitment`] so a rotation can't be replayed if a set recurs.
    generation: u64,
}

/// Serde-storable form of [`BridgeAuthoritySet`] for bridge state (`VerifyingKey`
/// isn't `Serialize`, so keys are stored SEC1-compressed and re-parsed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredBridgeAuthoritySet {
    pub keys: Vec<Vec<u8>>,
    pub threshold: usize,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthoritySetError {
    #[error("threshold {threshold} exceeds authority key count {keys}")]
    ThresholdTooHigh { threshold: usize, keys: usize },
    #[error("authority set must have a non-zero threshold")]
    ZeroThreshold,
    #[error("invalid authority public key encoding")]
    InvalidKey,
    #[error("authority rotation not signed by a threshold of the current set")]
    Unauthorized,
}

impl BridgeAuthoritySet {
    /// Build from SEC1-compressed public keys and a signature threshold.
    pub fn from_compressed(keys: &[&[u8]], threshold: usize) -> Result<Self, AuthoritySetError> {
        if threshold == 0 {
            return Err(AuthoritySetError::ZeroThreshold);
        }
        if threshold > keys.len() {
            return Err(AuthoritySetError::ThresholdTooHigh {
                threshold,
                keys: keys.len(),
            });
        }
        let verifying_keys = keys
            .iter()
            .map(|k| VerifyingKey::from_sec1_bytes(k).map_err(|_| AuthoritySetError::InvalidKey))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            verifying_keys,
            threshold,
            generation: 0,
        })
    }

    /// Number of distinct authority keys with a matching signature over `digest`.
    fn count_signing_keys(
        &self,
        digest: Digest,
        signatures: &[[u8; AUTHORITY_SIGNATURE_BYTES]],
    ) -> usize {
        let prehash = settlement_signing_prehash(digest);

        let mut satisfied = vec![false; self.verifying_keys.len()];
        for sig_bytes in signatures {
            let Ok(signature) = Signature::from_slice(sig_bytes) else {
                continue;
            };
            for (i, key) in self.verifying_keys.iter().enumerate() {
                if satisfied[i] {
                    continue;
                }
                if key.verify_prehash(&prehash, &signature).is_ok() {
                    satisfied[i] = true;
                    break;
                }
            }
        }

        satisfied.iter().filter(|s| **s).count()
    }

    /// Accept iff at least `threshold` distinct authority keys each have a
    /// matching signature over `digest` among `signatures`.
    pub fn verify_settlement(
        &self,
        digest: Digest,
        signatures: &[[u8; AUTHORITY_SIGNATURE_BYTES]],
    ) -> bool {
        self.count_signing_keys(digest, signatures) >= self.threshold
    }

    /// True iff EVERY key in the set signed `digest`: the new set's proof of
    /// possession at rotation, so authority can't move to keys no one controls.
    pub fn all_keys_signed(
        &self,
        digest: Digest,
        signatures: &[[u8; AUTHORITY_SIGNATURE_BYTES]],
    ) -> bool {
        self.count_signing_keys(digest, signatures) == self.verifying_keys.len()
    }

    /// The signature threshold (`N`).
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The monotonic rotation counter (genesis = 0).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Successor set: `generation` +1, keys canonicalized to compressed and
    /// rejected if duplicated (even across mixed SEC1 encodings of one key).
    pub fn rotated(
        &self,
        new_keys: &[Vec<u8>],
        new_threshold: usize,
    ) -> Result<Self, AuthoritySetError> {
        let key_refs: Vec<&[u8]> = new_keys.iter().map(|k| k.as_slice()).collect();
        let mut next = Self::from_compressed(&key_refs, new_threshold)?;
        next.generation = self.generation + 1;
        // Reject duplicate keys on the CANONICAL (compressed) form so the same
        // key supplied under two SEC1 encodings can't inflate the N-of-M set.
        let mut canonical: Vec<Vec<u8>> = next.to_stored().keys;
        let count = canonical.len();
        canonical.sort();
        canonical.dedup();
        if canonical.len() != count {
            return Err(AuthoritySetError::InvalidKey);
        }
        Ok(next)
    }

    /// Collision-resistant commitment (generation + threshold + keys, length-
    /// prefixed) binding a rotation to the exact set it replaces.
    pub fn commitment(&self) -> Digest {
        let stored = self.to_stored();
        let mut elements = vec![
            BFieldElement::new(stored.generation),
            BFieldElement::new(stored.threshold as u64),
            BFieldElement::new(stored.keys.len() as u64),
        ];
        for key in &stored.keys {
            elements.push(BFieldElement::new(key.len() as u64));
            elements.extend(key.iter().map(|b| BFieldElement::new(u64::from(*b))));
        }
        Tip5::hash_varlen(&elements)
    }

    /// Serialize to the storable (SEC1-compressed) form for bridge state.
    pub fn to_stored(&self) -> StoredBridgeAuthoritySet {
        StoredBridgeAuthoritySet {
            keys: self
                .verifying_keys
                .iter()
                .map(|k| k.to_encoded_point(true).as_bytes().to_vec())
                .collect(),
            threshold: self.threshold,
            generation: self.generation,
        }
    }

    /// Reconstruct from the stored form (same validation as `from_compressed`).
    pub fn from_stored(stored: &StoredBridgeAuthoritySet) -> Result<Self, AuthoritySetError> {
        let key_refs: Vec<&[u8]> = stored.keys.iter().map(|k| k.as_slice()).collect();
        let mut set = Self::from_compressed(&key_refs, stored.threshold)?;
        set.generation = stored.generation;
        Ok(set)
    }
}

/// keccak256 of the settlement digest's 40-byte big-endian encoding - the
/// prehash the authority ECDSA signature is taken over. Shared by the relayer
/// signer so both sides agree byte-for-byte.
pub fn settlement_signing_prehash(digest: Digest) -> [u8; 32] {
    use sha3::Digest as _;
    use sha3::Keccak256;

    let mut preimage = [0u8; Digest::LEN * 8];
    for (i, felt) in digest.values().iter().enumerate() {
        preimage[i * 8..i * 8 + 8].copy_from_slice(&felt.value().to_be_bytes());
    }
    Keccak256::digest(preimage).into()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use super::*;

    fn digest(seed: u64) -> Digest {
        Digest::new([
            BFieldElement::new(seed),
            BFieldElement::new(seed + 1),
            BFieldElement::new(seed + 2),
            BFieldElement::new(seed + 3),
            BFieldElement::new(seed + 4),
        ])
    }

    fn signing_key(scalar: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        SigningKey::from_bytes(&bytes.into()).unwrap()
    }

    fn sign(sk: &SigningKey, d: Digest) -> [u8; AUTHORITY_SIGNATURE_BYTES] {
        let sig: Signature = sk.sign_prehash(&settlement_signing_prehash(d)).unwrap();
        sig.to_bytes().into()
    }

    fn compressed(sk: &SigningKey) -> Vec<u8> {
        sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn one_of_one_accepts_valid_signature() {
        let sk = signing_key(1);
        let set = BridgeAuthoritySet::from_compressed(&[&compressed(&sk)], 1).unwrap();
        let d = digest(100);
        assert!(set.verify_settlement(d, &[sign(&sk, d)]));
    }

    #[test]
    fn rejects_signature_over_wrong_digest() {
        let sk = signing_key(1);
        let set = BridgeAuthoritySet::from_compressed(&[&compressed(&sk)], 1).unwrap();
        assert!(!set.verify_settlement(digest(200), &[sign(&sk, digest(100))]));
    }

    #[test]
    fn rejects_signature_from_non_authority_key() {
        let authority = signing_key(1);
        let outsider = signing_key(7);
        let set = BridgeAuthoritySet::from_compressed(&[&compressed(&authority)], 1).unwrap();
        let d = digest(100);
        assert!(!set.verify_settlement(d, &[sign(&outsider, d)]));
    }

    #[test]
    fn rejects_missing_signatures() {
        let sk = signing_key(1);
        let set = BridgeAuthoritySet::from_compressed(&[&compressed(&sk)], 1).unwrap();
        assert!(!set.verify_settlement(digest(100), &[]));
    }

    #[test]
    fn two_of_three_needs_two_distinct_keys() {
        let a = signing_key(1);
        let b = signing_key(2);
        let c = signing_key(3);
        let set = BridgeAuthoritySet::from_compressed(
            &[&compressed(&a), &compressed(&b), &compressed(&c)],
            2,
        )
        .unwrap();
        let d = digest(100);

        assert!(!set.verify_settlement(d, &[sign(&a, d)]));
        assert!(!set.verify_settlement(d, &[sign(&a, d), sign(&a, d)]));
        assert!(set.verify_settlement(d, &[sign(&a, d), sign(&c, d)]));
    }

    #[test]
    fn stored_round_trip_preserves_verification() {
        let a = signing_key(1);
        let b = signing_key(2);
        let set =
            BridgeAuthoritySet::from_compressed(&[&compressed(&a), &compressed(&b)], 2).unwrap();
        let restored = BridgeAuthoritySet::from_stored(&set.to_stored()).unwrap();
        assert_eq!(set.to_stored(), restored.to_stored());
        assert_eq!(restored.threshold(), 2);
        let d = digest(100);
        assert!(restored.verify_settlement(d, &[sign(&a, d), sign(&b, d)]));
        assert!(!restored.verify_settlement(d, &[sign(&a, d)]));
    }

    #[test]
    fn threshold_must_be_valid() {
        let sk = signing_key(1);
        assert_eq!(
            BridgeAuthoritySet::from_compressed(&[&compressed(&sk)], 0).unwrap_err(),
            AuthoritySetError::ZeroThreshold
        );
        assert_eq!(
            BridgeAuthoritySet::from_compressed(&[&compressed(&sk)], 2).unwrap_err(),
            AuthoritySetError::ThresholdTooHigh {
                threshold: 2,
                keys: 1
            }
        );
    }
}
