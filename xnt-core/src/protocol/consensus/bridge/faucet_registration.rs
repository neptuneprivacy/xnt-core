//! One-time bridge registration: the Leviathan faucet whose exits settlements may pay, and the
//! bridge state commitment the first settlement proves against.

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;

use super::aggregated_announcement::SIGNATURE_FELTS;
use super::authority::AuthoritySetError;
use super::authority::BridgeAuthoritySet;
use super::authority::AUTHORITY_SIGNATURE_BYTES;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;

/// Wire tag: "LEVBR_RG".
pub const FAUCET_REGISTRATION_TAG: u64 = 0x4C45_5642_525F_5247;
/// Domain separator of the signed digest: "XNTBRREG".
const REGISTRATION_SIG_DOMAIN: u64 = 0x584E_5442_5252_4547;
/// TAG, suffix, prefix, genesis_state_commitment(5), num_signatures.
const FIXED_LEN: usize = 3 + Digest::LEN + 1;

/// A Leviathan account id as its two felts, in the order the aggregate's claim input carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaucetId {
    pub suffix: BFieldElement,
    pub prefix: BFieldElement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRegistration {
    pub faucet_id: FaucetId,
    /// The `prev_state_commitment` the first settlement must carry.
    pub genesis_state_commitment: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaucetRegistrationAnnouncement {
    pub registration: BridgeRegistration,
    /// Signatures by the current authority set over [`Self::registration_digest`].
    pub signatures: Vec<[u8; AUTHORITY_SIGNATURE_BYTES]>,
}

impl FaucetRegistrationAnnouncement {
    /// Bound to the signing set's commitment (incl. its generation), as rotation is.
    pub fn registration_digest(&self, network: Network, authority_commitment: Digest) -> Digest {
        let r = &self.registration;
        let mut elements = vec![BFieldElement::new(REGISTRATION_SIG_DOMAIN)];
        elements.push(BFieldElement::new(u64::from(network.id())));
        elements.extend(authority_commitment.values());
        elements.push(r.faucet_id.suffix);
        elements.push(r.faucet_id.prefix);
        elements.extend(r.genesis_state_commitment.values());
        Tip5::hash_varlen(&elements)
    }

    pub fn verify(
        &self,
        current: &BridgeAuthoritySet,
        network: Network,
    ) -> Result<BridgeRegistration, AuthoritySetError> {
        let digest = self.registration_digest(network, current.commitment());
        if !current.verify_settlement(digest, &self.signatures) {
            return Err(AuthoritySetError::Unauthorized);
        }
        Ok(self.registration)
    }

    pub fn to_announcement(&self) -> Announcement {
        let r = &self.registration;
        let mut msg = vec![
            BFieldElement::new(FAUCET_REGISTRATION_TAG),
            r.faucet_id.suffix,
            r.faucet_id.prefix,
        ];
        msg.extend(r.genesis_state_commitment.values());
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

    /// Parse; the message must be consumed exactly.
    pub fn from_announcement(announcement: &Announcement) -> Option<Self> {
        let msg = &announcement.message;
        if msg.len() < FIXED_LEN || !Self::is_registration_tagged(announcement) {
            return None;
        }
        let faucet_id = FaucetId {
            suffix: msg[1],
            prefix: msg[2],
        };
        let genesis_state_commitment = Digest::new(msg[3..3 + Digest::LEN].try_into().ok()?);
        let num_sigs = usize::try_from(msg[FIXED_LEN - 1].value()).ok()?;
        let sig_felts = &msg[FIXED_LEN..];
        if num_sigs.checked_mul(SIGNATURE_FELTS)? != sig_felts.len() {
            return None;
        }
        let signatures = sig_felts
            .chunks_exact(SIGNATURE_FELTS)
            .map(|felts| {
                let mut sig = [0u8; AUTHORITY_SIGNATURE_BYTES];
                for (chunk, felt) in sig.chunks_exact_mut(4).zip(felts) {
                    chunk.copy_from_slice(&u32::try_from(felt.value()).ok()?.to_be_bytes());
                }
                Some(sig)
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            registration: BridgeRegistration {
                faucet_id,
                genesis_state_commitment,
            },
            signatures,
        })
    }

    pub fn is_registration_tagged(announcement: &Announcement) -> bool {
        announcement.message.first() == Some(&BFieldElement::new(FAUCET_REGISTRATION_TAG))
    }

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

    fn set_at_gen(scalars: &[u8], threshold: usize, generation: u64) -> BridgeAuthoritySet {
        let keys = scalars
            .iter()
            .map(|s| {
                signing_key(*s)
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec()
            })
            .collect();
        BridgeAuthoritySet::from_stored(&StoredBridgeAuthoritySet {
            keys,
            threshold,
            generation,
        })
        .unwrap()
    }

    fn registration() -> BridgeRegistration {
        BridgeRegistration {
            faucet_id: FaucetId {
                suffix: BFieldElement::new(0x1234_5600),
                prefix: BFieldElement::new(0xABCD_0021),
            },
            genesis_state_commitment: Tip5::hash_varlen(&[BFieldElement::new(7)]),
        }
    }

    fn signed(current: &BridgeAuthoritySet, signers: &[u8]) -> FaucetRegistrationAnnouncement {
        let mut reg = FaucetRegistrationAnnouncement {
            registration: registration(),
            signatures: vec![],
        };
        let prehash = settlement_signing_prehash(
            reg.registration_digest(Network::RegTest, current.commitment()),
        );
        reg.signatures = signers
            .iter()
            .map(|s| {
                let sig: Signature = signing_key(*s).sign_prehash(&prehash).unwrap();
                sig.to_bytes().into()
            })
            .collect();
        reg
    }

    #[test]
    fn threshold_of_current_set_verifies() {
        let current = set_at_gen(&[1, 2, 3], 2, 0);
        assert_eq!(
            signed(&current, &[1, 3]).verify(&current, Network::RegTest),
            Ok(registration())
        );
    }

    #[test]
    fn rejects_below_threshold_and_outsiders() {
        let current = set_at_gen(&[1, 2, 3], 2, 0);
        assert!(signed(&current, &[1])
            .verify(&current, Network::RegTest)
            .is_err());
        assert!(signed(&current, &[7, 8])
            .verify(&current, Network::RegTest)
            .is_err());
    }

    #[test]
    fn signatures_bind_the_set_generation() {
        let gen0 = set_at_gen(&[1], 1, 0);
        let reg = signed(&gen0, &[1]);
        assert!(reg
            .verify(&set_at_gen(&[1], 1, 1), Network::RegTest)
            .is_err());
    }

    #[test]
    fn signatures_bind_faucet_and_genesis_commitment() {
        let current = set_at_gen(&[1], 1, 0);
        let mut other_faucet = signed(&current, &[1]);
        other_faucet.registration.faucet_id.prefix = BFieldElement::new(1);
        assert!(other_faucet.verify(&current, Network::RegTest).is_err());
        let mut other_genesis = signed(&current, &[1]);
        other_genesis.registration.genesis_state_commitment = Digest::default();
        assert!(other_genesis.verify(&current, Network::RegTest).is_err());
    }

    #[test]
    fn wire_round_trip() {
        let reg = signed(&set_at_gen(&[1, 2], 2, 0), &[1, 2]);
        let parsed = FaucetRegistrationAnnouncement::from_announcement(&reg.to_announcement());
        assert_eq!(parsed, Some(reg));
    }

    #[test]
    fn rejects_malformed_messages() {
        let reg = signed(&set_at_gen(&[1], 1, 0), &[1]);
        let ann = reg.to_announcement();

        let mut trailing = ann.clone();
        trailing.message.push(BFieldElement::new(0));
        assert!(FaucetRegistrationAnnouncement::from_announcement(&trailing).is_none());

        let mut truncated = ann.clone();
        truncated.message.pop();
        assert!(FaucetRegistrationAnnouncement::from_announcement(&truncated).is_none());

        let mut wide_felt = ann.clone();
        wide_felt.message[FIXED_LEN] = BFieldElement::new(1 << 32);
        assert!(FaucetRegistrationAnnouncement::from_announcement(&wide_felt).is_none());

        let mut huge_count = ann;
        huge_count.message[FIXED_LEN - 1] = BFieldElement::new(u64::MAX >> 1);
        assert!(FaucetRegistrationAnnouncement::from_announcement(&huge_count).is_none());
    }
}
