//! Bridge authority rotation: replaces the stored authority set with a new one,
//! authorized by `threshold` signatures from the **current** set over a digest
//! bound to the current set's commitment (so it can't be replayed elsewhere).
//! Verified at tip-install (`set_new_tip_internal`), reading current from state.

use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;

use super::authority::AuthoritySetError;
use super::authority::BridgeAuthoritySet;
use super::authority::AUTHORITY_SIGNATURE_BYTES;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;

/// Wire tag: "LEVBR_AR".
pub const AUTHORITY_ROTATION_TAG: u64 = 0x4C45_5642_525F_4152;
/// Domain separator folded into the signed digest so a settlement signature can
/// never be replayed as a rotation signature (and vice-versa): "XNTBRROT".
const ROTATION_SIG_DOMAIN: u64 = 0x584E_5442_5252_4F54;
/// Felts per SEC1 signature (4 bytes packed per felt).
const SIGNATURE_FELTS: usize = AUTHORITY_SIGNATURE_BYTES / 4;

/// A request to replace the bridge authority set with `new_keys` / `threshold`,
/// signed by the current set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRotationAnnouncement {
    pub new_keys: Vec<Vec<u8>>,
    pub new_threshold: usize,
    /// Signatures by the CURRENT set over [`Self::rotation_digest`].
    pub signatures: Vec<[u8; AUTHORITY_SIGNATURE_BYTES]>,
}

impl AuthorityRotationAnnouncement {
    /// Canonical successor set (generation +1, keys canonicalized, dup-free).
    /// Shared by apply and reorg-replay so both persist byte-identical state.
    pub fn new_set_after(
        &self,
        current: &BridgeAuthoritySet,
    ) -> Result<BridgeAuthoritySet, AuthoritySetError> {
        current.rotated(&self.new_keys, self.new_threshold)
    }

    /// Digest the current authority signs, bound to `prev_commitment` (the set
    /// being replaced) so the rotation can't be replayed against another set.
    pub fn rotation_digest(&self, network: Network, prev_commitment: Digest) -> Digest {
        let mut elements = vec![BFieldElement::new(ROTATION_SIG_DOMAIN)];
        elements.push(BFieldElement::new(u64::from(network.id())));
        elements.extend(prev_commitment.values());
        elements.push(BFieldElement::new(self.new_threshold as u64));
        elements.push(BFieldElement::new(self.new_keys.len() as u64));
        for key in &self.new_keys {
            elements.push(BFieldElement::new(key.len() as u64));
            elements.extend(key.iter().map(|b| BFieldElement::new(u64::from(*b))));
        }
        Tip5::hash_varlen(&elements)
    }

    /// Verify ≥ `current.threshold` distinct current keys signed the digest, and
    /// return the new set. The digest binds `current.commitment()` (incl. its
    /// generation), so a rotation can't be replayed on a fork or a recurring set.
    pub fn verify_and_build(
        &self,
        current: &BridgeAuthoritySet,
        network: Network,
    ) -> Result<BridgeAuthoritySet, AuthoritySetError> {
        let new_set = self.new_set_after(current)?;
        let digest = self.rotation_digest(network, current.commitment());
        // Authorized by >= threshold of the CURRENT set, AND every NEW key signs
        // too (proof of possession). Both draw from the same flat signature pool.
        if !current.verify_settlement(digest, &self.signatures)
            || !new_set.all_keys_signed(digest, &self.signatures)
        {
            return Err(AuthoritySetError::Unauthorized);
        }
        Ok(new_set)
    }

    pub fn to_announcement(&self) -> Announcement {
        let mut msg = vec![BFieldElement::new(AUTHORITY_ROTATION_TAG)];
        msg.push(BFieldElement::new(self.new_threshold as u64));
        msg.push(BFieldElement::new(self.new_keys.len() as u64));
        for key in &self.new_keys {
            msg.push(BFieldElement::new(key.len() as u64));
            msg.extend(key.iter().map(|b| BFieldElement::new(u64::from(*b))));
        }
        msg.push(BFieldElement::new(self.signatures.len() as u64));
        for sig in &self.signatures {
            for chunk in sig.chunks_exact(4) {
                let word =
                    u32::from_be_bytes(chunk.try_into().expect("chunks_exact(4) yields 4 bytes"));
                msg.push(BFieldElement::new(u64::from(word)));
            }
        }
        Announcement::new(msg)
    }

    /// Parse from an announcement. Each attacker-controlled count is bounded
    /// against the remaining length before driving capacity/indexing (release
    /// builds have overflow checks off).
    pub fn from_announcement(announcement: &Announcement) -> Option<Self> {
        let msg = &announcement.message;
        if msg.len() < 3 || msg[0].value() != AUTHORITY_ROTATION_TAG {
            return None;
        }
        let new_threshold = msg[1].value() as usize;
        let num_keys = msg[2].value() as usize;
        let mut cursor = 3;

        let mut new_keys = Vec::with_capacity(num_keys.min(msg.len()));
        for _ in 0..num_keys {
            if cursor >= msg.len() {
                return None;
            }
            let key_len = msg[cursor].value() as usize;
            cursor += 1;
            if key_len > msg.len().saturating_sub(cursor) {
                return None;
            }
            let key = msg[cursor..cursor + key_len]
                .iter()
                .map(|f| u8::try_from(f.value()).ok())
                .collect::<Option<Vec<u8>>>()?;
            new_keys.push(key);
            cursor += key_len;
        }

        if cursor >= msg.len() {
            return None;
        }
        let num_sigs = msg[cursor].value() as usize;
        cursor += 1;
        if num_sigs > msg.len().saturating_sub(cursor) / SIGNATURE_FELTS {
            return None;
        }
        let mut signatures = Vec::with_capacity(num_sigs);
        for _ in 0..num_sigs {
            let mut sig = [0u8; AUTHORITY_SIGNATURE_BYTES];
            for (chunk, felt) in sig
                .chunks_exact_mut(4)
                .zip(&msg[cursor..cursor + SIGNATURE_FELTS])
            {
                let word = u32::try_from(felt.value()).ok()?;
                chunk.copy_from_slice(&word.to_be_bytes());
            }
            signatures.push(sig);
            cursor += SIGNATURE_FELTS;
        }

        Some(Self {
            new_keys,
            new_threshold,
            signatures,
        })
    }

    /// Find a rotation announcement among a transaction's announcements.
    pub fn find_in_announcements(announcements: &[Announcement]) -> Option<Self> {
        announcements.iter().find_map(Self::from_announcement)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::Signature;
    use k256::ecdsa::SigningKey;

    use super::*;
    use crate::protocol::consensus::bridge::authority::settlement_signing_prehash;
    use crate::protocol::consensus::bridge::authority::StoredBridgeAuthoritySet;

    fn signing_key(scalar: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        SigningKey::from_bytes(&bytes.into()).unwrap()
    }

    fn compressed(sk: &SigningKey) -> Vec<u8> {
        sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn set(scalars: &[u8], threshold: usize) -> BridgeAuthoritySet {
        set_at_gen(scalars, threshold, 0)
    }

    fn set_at_gen(scalars: &[u8], threshold: usize, generation: u64) -> BridgeAuthoritySet {
        let keys: Vec<Vec<u8>> = scalars
            .iter()
            .map(|s| compressed(&signing_key(*s)))
            .collect();
        BridgeAuthoritySet::from_stored(&StoredBridgeAuthoritySet {
            keys,
            threshold,
            generation,
        })
        .unwrap()
    }

    fn sign(sk: &SigningKey, d: Digest) -> [u8; AUTHORITY_SIGNATURE_BYTES] {
        let sig: Signature = sk.sign_prehash(&settlement_signing_prehash(d)).unwrap();
        sig.to_bytes().into()
    }

    fn rotation(new_scalars: &[u8], new_threshold: usize) -> AuthorityRotationAnnouncement {
        AuthorityRotationAnnouncement {
            new_keys: new_scalars
                .iter()
                .map(|s| compressed(&signing_key(*s)))
                .collect(),
            new_threshold,
            signatures: vec![],
        }
    }

    /// Rotation signed by old-set `signer` AND every new key (proof of
    /// possession), against `current`'s commitment.
    fn signed_rotation(
        current: &BridgeAuthoritySet,
        signer: u8,
        new_scalars: &[u8],
        new_threshold: usize,
    ) -> AuthorityRotationAnnouncement {
        let mut rot = rotation(new_scalars, new_threshold);
        let digest = rot.rotation_digest(Network::RegTest, current.commitment());
        let mut sigs = vec![sign(&signing_key(signer), digest)];
        sigs.extend(new_scalars.iter().map(|s| sign(&signing_key(*s), digest)));
        rot.signatures = sigs;
        rot
    }

    #[test]
    fn valid_rotation_authorized_by_current_set() {
        let current = set(&[1], 1);
        let rot = signed_rotation(&current, 1, &[2, 3], 2);
        let new = rot.verify_and_build(&current, Network::RegTest).unwrap();
        assert_eq!(new.threshold(), 2);
        assert_eq!(new.generation(), 1); // current gen 0 + 1
        assert_eq!(new.to_stored().keys, rot.new_keys);
    }

    #[test]
    fn rejects_replay_after_config_recurs() {
        // Rotation A→B signed when current is A@gen0. After A→B→A the current
        // set is A@gen2; the same announcement must NOT verify again (its digest
        // is bound to gen0's commitment, not gen2's).
        let a0 = set(&[1], 1);
        let rot = signed_rotation(&a0, 1, &[2], 1);
        assert!(rot.verify_and_build(&a0, Network::RegTest).is_ok());
        let a2 = set_at_gen(&[1], 1, 2);
        assert!(rot.verify_and_build(&a2, Network::RegTest).is_err());
    }

    #[test]
    fn rejects_missing_new_key_signature() {
        // Old set signs, but a new key does not prove possession -> reject.
        let current = set(&[1], 1);
        let mut rot = rotation(&[2, 3], 2);
        let digest = rot.rotation_digest(Network::RegTest, current.commitment());
        rot.signatures = vec![sign(&signing_key(1), digest), sign(&signing_key(2), digest)];
        assert!(rot.verify_and_build(&current, Network::RegTest).is_err());
    }

    #[test]
    fn rejects_rotation_not_signed_by_current() {
        let current = set(&[1], 1);
        let rot = signed_rotation(&current, 7, &[2], 1); // outsider signs
        assert!(rot.verify_and_build(&current, Network::RegTest).is_err());
    }

    #[test]
    fn rejects_duplicate_keys_across_mixed_encodings() {
        // Same key once compressed, once uncompressed: must be rejected as a dup
        // even though the raw bytes differ.
        let current = set(&[1], 1);
        let sk = signing_key(2);
        let comp = compressed(&sk);
        let uncomp = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let mut rot = AuthorityRotationAnnouncement {
            new_keys: vec![comp, uncomp],
            new_threshold: 2,
            signatures: vec![],
        };
        rot.signatures = vec![sign(
            &signing_key(1),
            rot.rotation_digest(Network::RegTest, current.commitment()),
        )];
        assert!(rot.verify_and_build(&current, Network::RegTest).is_err());
    }

    #[test]
    fn wire_round_trip() {
        let rot = signed_rotation(&set(&[1], 1), 1, &[2, 3], 2);
        let parsed =
            AuthorityRotationAnnouncement::from_announcement(&rot.to_announcement()).unwrap();
        assert_eq!(parsed, rot);
    }

    #[test]
    fn rejects_two_of_two_with_one_sig() {
        let current = set(&[1, 2], 2);
        let rot = signed_rotation(&current, 1, &[3], 1); // only 1 of 2 signed
        assert!(rot.verify_and_build(&current, Network::RegTest).is_err());
    }
}
