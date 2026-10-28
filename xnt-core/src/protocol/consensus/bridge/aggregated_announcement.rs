//! Leviathan aggregated proof (settlement) announcement format.
//!
//! The relayer submits one per epoch. BAAV (`BridgeAggregatedAnnouncementValidator`)
//! `stark_verify`s a Triton proof of the Leviathan verifier's run and pays each exit record, after
//! checking that folding the records into the exit chain from the previous epoch's `exit_acc` gives
//! `exit_root`.
//!
//! ```text
//! [TAG,
//!  prev_state_commitment(5), new_state_commitment(5), exit_root(5),
//!  faucet_suffix, faucet_prefix,
//!  prev_state_preimage(19),
//!  num_burns, burn(16) * num_burns,
//!  0 | 1 change_sender_randomness(5),
//!  num_signatures, signature(16) * num_signatures]
//! ```
//!
//! The faucet id is the one the Leviathan proof opened; the ingest gate requires it to be the registered
//! one. A burn is the Leviathan faucet's exit record `[ri, pd(5), lsh(5), amount, serial(4)]`; the
//! payout's sender randomness is `Tip5::hash_varlen(serial)`.
//!
//! Neither the Leviathan verifier program nor the Leviathan proof is carried: BAAV pins the program's digest
//! (`EXPECTED_VP_HASH`) and only the settlement's prover needs the program and the proof. The Leviathan
//! proof is not published on chain; the relayer may publish it off chain.

use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::application::config::network::Network;
use crate::application::loops::peer_loop::MAX_ANNOUNCEMENT_MESSAGE_SIZE;
use crate::protocol::consensus::bridge::authority::AUTHORITY_SIGNATURE_BYTES;
use crate::protocol::consensus::bridge::faucet_registration::FaucetId;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::validity::bridge_aggregated_announcement_validator::LEVIATHAN_UNIT_TO_NAU;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// A signature occupies 16 felts on the wire: 64 bytes packed 4-per-felt (u32
/// big-endian), so each felt stays below the field modulus.
pub const SIGNATURE_FELTS: usize = AUTHORITY_SIGNATURE_BYTES / 4;

/// Domain separator prefixed to the settlement signing preimage ("XNTBRSET"),
/// so an authority signature can never be replayed as some other message.
const SETTLEMENT_SIG_DOMAIN: u64 = 0x584E_5442_5253_4554;

/// Well-known tag identifying a Leviathan aggregated proof announcement.
/// "LEVBR_AG" as u64.
pub const AGGREGATED_ANNOUNCEMENT_TAG: u64 = 0x4C45_5642_525F_4147;

pub const BURN_RECORD_LEN: usize = 16;

pub const STATE_PREIMAGE_LEN: usize = 19;

/// Most burns one settlement pays. BAAV's burn RAM region is sized for it.
pub const MAX_BURNS_PER_SETTLEMENT: usize = 4096;

const FIXED_HEADER_LEN: usize = 1 + 3 * Digest::LEN + 2 + STATE_PREIMAGE_LEN;

/// Most burns a settlement with `num_signatures` signatures carries and still fits the peers' relay
/// limit, counting the change; a larger one only reaches a block through a composer directly.
pub fn max_relayed_burns(num_signatures: usize) -> usize {
    let without_burns =
        FIXED_HEADER_LEN + 1 + 1 + Digest::LEN + 1 + num_signatures * SIGNATURE_FELTS;
    MAX_ANNOUNCEMENT_MESSAGE_SIZE.saturating_sub(without_burns) / BURN_RECORD_LEN
}

/// One exit the Leviathan faucet recorded when it consumed a burn note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurnRecord {
    /// Recipient's receiver identifier (UTXO indexing fingerprint).
    pub receiver_identifier: BFieldElement,
    /// Recipient's privacy digest (= privacy_preimage.hash()) for the AdditionRecord commitment.
    pub privacy_digest: Digest,
    pub lock_script_hash: Digest,
    /// Burned WXNT net of the burn fee, in base units (1 WXNT = 1_000_000).
    pub amount: u64,
    pub serial: [BFieldElement; 4],
}

impl BurnRecord {
    /// `[ri, pd(5), lsh(5), amount, serial(4)]`, the faucet's exit-log layout.
    pub fn to_elements(&self) -> [BFieldElement; BURN_RECORD_LEN] {
        let mut e = [BFieldElement::new(0); BURN_RECORD_LEN];
        e[0] = self.receiver_identifier;
        e[1..6].copy_from_slice(&self.privacy_digest.values());
        e[6..11].copy_from_slice(&self.lock_script_hash.values());
        e[11] = BFieldElement::new(self.amount);
        e[12..].copy_from_slice(&self.serial);
        e
    }

    fn from_elements(e: &[BFieldElement]) -> Option<Self> {
        Some(Self {
            receiver_identifier: e[0],
            privacy_digest: Digest::new(e[1..6].try_into().ok()?),
            lock_script_hash: Digest::new(e[6..11].try_into().ok()?),
            amount: e[11].value(),
            serial: e[12..16].try_into().ok()?,
        })
    }

    pub fn sender_randomness(&self) -> Digest {
        Tip5::hash_varlen(&self.serial)
    }

    /// The XNT this record pays out, `None` on overflow.
    pub fn payout(&self) -> Option<NativeCurrencyAmount> {
        let nau = u128::from(self.amount).checked_mul(LEVIATHAN_UNIT_TO_NAU)?;
        Some(NativeCurrencyAmount::from_nau(i128::try_from(nau).ok()?))
    }

    /// The exit chain after this record: `Tip5::hash_varlen(acc || record)`.
    pub fn fold_into(&self, acc: Digest) -> Digest {
        let mut input = acc.values().to_vec();
        input.extend(self.to_elements());
        Tip5::hash_varlen(&input)
    }
}

/// The aggregate's state commitment preimage: `account_root(4) || nullifier_root(4) ||
/// note_root(4) || block_num || exit_acc(5) || exit_count`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatePreimage(pub [BFieldElement; STATE_PREIMAGE_LEN]);

impl StatePreimage {
    pub fn commitment(&self) -> Digest {
        Tip5::hash_varlen(&self.0)
    }

    pub fn exit_acc(&self) -> Digest {
        Digest::new(std::array::from_fn(|i| self.0[13 + i]))
    }

    pub fn exit_count(&self) -> BFieldElement {
        self.0[18]
    }
}

/// Parsed Leviathan aggregated proof announcement data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedAnnouncementData {
    /// State commitment before this epoch (Tip5 digest).
    pub prev_state_commitment: Digest,
    /// State commitment after this epoch (Tip5 digest).
    pub new_state_commitment: Digest,
    /// The faucet's exit chain at the end of the epoch.
    pub exit_root: Digest,
    pub faucet_id: FaucetId,
    /// Preimage of `prev_state_commitment`, from which BAAV takes the previous `exit_acc`. Ignored
    /// while `prev_state_commitment` is the zero digest.
    pub prev_state_preimage: StatePreimage,
    /// The epoch's exit records, in exit-log order.
    pub burns: Vec<BurnRecord>,
    /// Sender randomness for the change output, if pool selection produced one.
    /// Needed by every node to reconstruct the change PoolEntry.
    pub change_sender_randomness: Option<Digest>,
    /// Authority (N-of-M validator) signatures over `settlement_digest()`.
    /// Each is SEC1 `r || s` (64 bytes). `Block::validate` rejects the block
    /// unless `threshold` of the network authority keys are covered.
    pub authority_signatures: Vec<[u8; AUTHORITY_SIGNATURE_BYTES]>,
}

impl AggregatedAnnouncementData {
    /// Encode as a Neptune transaction announcement.
    pub fn to_announcement(&self) -> Announcement {
        let mut msg = vec![BFieldElement::new(AGGREGATED_ANNOUNCEMENT_TAG)];
        msg.extend(self.prev_state_commitment.values());
        msg.extend(self.new_state_commitment.values());
        msg.extend(self.exit_root.values());
        msg.push(self.faucet_id.suffix);
        msg.push(self.faucet_id.prefix);
        msg.extend(self.prev_state_preimage.0);

        msg.push(BFieldElement::new(self.burns.len() as u64));
        for burn in &self.burns {
            msg.extend(burn.to_elements());
        }

        match self.change_sender_randomness {
            Some(sr) => {
                msg.push(BFieldElement::new(1));
                msg.extend(sr.values());
            }
            None => msg.push(BFieldElement::new(0)),
        }

        msg.push(BFieldElement::new(self.authority_signatures.len() as u64));
        for sig in &self.authority_signatures {
            for chunk in sig.chunks_exact(4) {
                let word =
                    u32::from_be_bytes(chunk.try_into().expect("chunks_exact(4) yields 4 bytes"));
                msg.push(BFieldElement::new(u64::from(word)));
            }
        }

        Announcement::new(msg)
    }

    /// Digest the authority signs: the payout fields only (state chain, exit
    /// root, faucet id, each burn), excluding the proof and signatures.
    ///
    /// `change_sender_randomness` is excluded on purpose - the change returns to
    /// the unspendable pool lock and the BAAV proof binds it independently, so it
    /// needs no authority attestation, and excluding it lets the signer rebuild
    /// this digest from Leviathan state alone (it can't see Neptune pool selection).
    /// `prev_state_preimage` is excluded too: BAAV checks it hashes to `prev_state_commitment`.
    /// The network id keeps a signature from replaying on another network.
    pub fn settlement_digest(&self, network: Network) -> Digest {
        let mut elements = vec![BFieldElement::new(SETTLEMENT_SIG_DOMAIN)];
        elements.push(BFieldElement::new(u64::from(network.id())));
        elements.extend(self.prev_state_commitment.values());
        elements.extend(self.new_state_commitment.values());
        elements.extend(self.exit_root.values());
        elements.push(self.faucet_id.suffix);
        elements.push(self.faucet_id.prefix);
        for burn in &self.burns {
            elements.extend(burn.to_elements());
        }
        Tip5::hash_varlen(&elements)
    }

    /// Parse from a Neptune transaction announcement. Every length is attacker-controlled, so all
    /// offsets are checked; the message must be consumed exactly.
    pub fn from_announcement(announcement: &Announcement) -> Option<Self> {
        let msg = &announcement.message;
        if msg.len() < FIXED_HEADER_LEN || msg[0].value() != AGGREGATED_ANNOUNCEMENT_TAG {
            return None;
        }
        let digest_at = |i: usize| -> Option<Digest> {
            Some(Digest::new(msg.get(i..i + Digest::LEN)?.try_into().ok()?))
        };
        let prev_state_commitment = digest_at(1)?;
        let new_state_commitment = digest_at(6)?;
        let exit_root = digest_at(11)?;
        let faucet_id = FaucetId {
            suffix: msg[16],
            prefix: msg[17],
        };
        let prev_state_preimage = StatePreimage(msg[18..FIXED_HEADER_LEN].try_into().ok()?);
        let mut cursor = FIXED_HEADER_LEN;

        let num_burns = usize::try_from(msg.get(cursor)?.value()).ok()?;
        if num_burns > MAX_BURNS_PER_SETTLEMENT {
            return None;
        }
        cursor += 1;
        let burns_end = cursor.checked_add(num_burns.checked_mul(BURN_RECORD_LEN)?)?;
        let burns = msg
            .get(cursor..burns_end)?
            .chunks_exact(BURN_RECORD_LEN)
            .map(BurnRecord::from_elements)
            .collect::<Option<Vec<_>>>()?;
        cursor = burns_end;

        let change_sender_randomness = match msg.get(cursor)?.value() {
            0 => {
                cursor += 1;
                None
            }
            1 => {
                let sr = digest_at(cursor + 1)?;
                cursor += 1 + Digest::LEN;
                Some(sr)
            }
            _ => return None,
        };

        let num_sigs = usize::try_from(msg.get(cursor)?.value()).ok()?;
        cursor += 1;
        let sigs_end = cursor.checked_add(num_sigs.checked_mul(SIGNATURE_FELTS)?)?;
        let mut authority_signatures = Vec::with_capacity(num_sigs.min(msg.len()));
        for felts in msg.get(cursor..sigs_end)?.chunks_exact(SIGNATURE_FELTS) {
            let mut sig = [0u8; AUTHORITY_SIGNATURE_BYTES];
            for (chunk, felt) in sig.chunks_exact_mut(4).zip(felts) {
                let word = u32::try_from(felt.value()).ok()?;
                chunk.copy_from_slice(&word.to_be_bytes());
            }
            authority_signatures.push(sig);
        }
        if sigs_end != msg.len() {
            return None;
        }

        Some(Self {
            prev_state_commitment,
            new_state_commitment,
            exit_root,
            faucet_id,
            prev_state_preimage,
            burns,
            change_sender_randomness,
            authority_signatures,
        })
    }

    /// Pays no exits and keeps the state, so it can only move pool inputs into pool change.
    pub fn is_pool_consolidation(&self) -> bool {
        self.burns.is_empty()
            && self.prev_state_commitment == self.new_state_commitment
            && self.exit_root == Digest::default()
            && self.change_sender_randomness.is_some()
    }

    /// Whether `announcement` claims to be a settlement: non-empty, first felt is the tag. A block
    /// may carry at most one, and it must parse; BAAV binds the first one in its tx.
    pub fn is_settlement_tagged(announcement: &Announcement) -> bool {
        announcement.message.first() == Some(&BFieldElement::new(AGGREGATED_ANNOUNCEMENT_TAG))
    }

    /// Search a list of announcements for an aggregated proof announcement.
    pub fn find_in_announcements(announcements: &[Announcement]) -> Option<Self> {
        announcements.iter().find_map(Self::from_announcement)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn test_digest(seed: u64) -> Digest {
        Digest::new([
            BFieldElement::new(seed),
            BFieldElement::new(seed + 1),
            BFieldElement::new(seed + 2),
            BFieldElement::new(seed + 3),
            BFieldElement::new(seed + 4),
        ])
    }

    fn serial(seed: u64) -> [BFieldElement; 4] {
        [0, 1, 2, 3].map(|i| BFieldElement::new(seed + i))
    }

    fn burn(seed: u64) -> BurnRecord {
        BurnRecord {
            receiver_identifier: BFieldElement::new(seed),
            privacy_digest: test_digest(seed + 10),
            lock_script_hash: test_digest(seed + 20),
            amount: seed,
            serial: serial(seed + 30),
        }
    }

    fn base(prev: u64, new: u64) -> AggregatedAnnouncementData {
        AggregatedAnnouncementData {
            prev_state_commitment: test_digest(prev),
            new_state_commitment: test_digest(new),
            exit_root: Digest::default(),
            faucet_id: test_faucet(),
            prev_state_preimage: StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
            burns: vec![],
            change_sender_randomness: None,
            authority_signatures: vec![],
        }
    }

    fn test_faucet() -> FaucetId {
        FaucetId {
            suffix: BFieldElement::new(0x1234_5600),
            prefix: BFieldElement::new(0xABCD_0021),
        }
    }

    fn sample_sig(seed: u8) -> [u8; AUTHORITY_SIGNATURE_BYTES] {
        let mut sig = [0u8; AUTHORITY_SIGNATURE_BYTES];
        for (i, byte) in sig.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        sig
    }

    #[test]
    fn roundtrip_no_burns_no_proof() {
        let data = base(10, 20);
        let parsed =
            AggregatedAnnouncementData::from_announcement(&data.to_announcement()).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn roundtrip_with_proof_burns_change_and_signatures() {
        let data = AggregatedAnnouncementData {
            prev_state_commitment: test_digest(100),
            new_state_commitment: test_digest(200),
            exit_root: test_digest(300),
            faucet_id: test_faucet(),
            prev_state_preimage: StatePreimage(std::array::from_fn(|i| {
                BFieldElement::new(i as u64)
            })),
            burns: vec![
                BurnRecord {
                    receiver_identifier: BFieldElement::new(1000),
                    privacy_digest: test_digest(1500),
                    lock_script_hash: test_digest(2000),
                    amount: 15_000_000,
                    serial: serial(5000),
                },
                BurnRecord {
                    receiver_identifier: BFieldElement::new(3000),
                    privacy_digest: test_digest(3500),
                    lock_script_hash: test_digest(4000),
                    amount: 25_000_000,
                    serial: serial(6000),
                },
            ],
            change_sender_randomness: Some(test_digest(7000)),
            authority_signatures: vec![sample_sig(1), sample_sig(200)],
        };

        let parsed =
            AggregatedAnnouncementData::from_announcement(&data.to_announcement()).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn wrong_tag_returns_none() {
        let mut ann = base(0, 0).to_announcement();
        ann.message[0] = BFieldElement::new(0);
        assert!(AggregatedAnnouncementData::from_announcement(&ann).is_none());
    }

    #[test]
    fn too_short_returns_none() {
        let ann = Announcement::new(vec![BFieldElement::new(AGGREGATED_ANNOUNCEMENT_TAG)]);
        assert!(AggregatedAnnouncementData::from_announcement(&ann).is_none());
    }

    #[test]
    fn truncated_burns_return_none() {
        let mut data = base(0, 0);
        data.burns = vec![burn(1), burn(2)];
        let mut ann = data.to_announcement();
        ann.message.truncate(FIXED_HEADER_LEN + 10);
        assert!(AggregatedAnnouncementData::from_announcement(&ann).is_none());
    }

    #[test]
    fn find_in_announcements_works() {
        let mut data = base(10, 20);
        data.burns = vec![burn(1)];
        let other = Announcement::new(vec![BFieldElement::new(999)]);
        let found =
            AggregatedAnnouncementData::find_in_announcements(&[other, data.to_announcement()])
                .unwrap();
        assert_eq!(found, data);
    }

    #[test]
    fn adversarial_counts_return_none_not_panic() {
        // A huge signature count must not overflow the size math into a
        // bogus allocation / out-of-bounds slice - it must parse to None.
        let mut ann = base(10, 20).to_announcement();
        *ann.message.last_mut().unwrap() = BFieldElement::new(u64::MAX);
        assert!(AggregatedAnnouncementData::from_announcement(&ann).is_none());

        let mut ann2 = base(10, 20).to_announcement();
        let burns_idx = FIXED_HEADER_LEN;
        ann2.message[burns_idx] = BFieldElement::new(u64::MAX);
        assert!(AggregatedAnnouncementData::from_announcement(&ann2).is_none());
        ann2.message[burns_idx] = BFieldElement::new(MAX_BURNS_PER_SETTLEMENT as u64);
        assert!(AggregatedAnnouncementData::from_announcement(&ann2).is_none());
    }

    #[test]
    fn burn_cap_is_inclusive() {
        let mut data = base(10, 20);
        data.burns = (0..MAX_BURNS_PER_SETTLEMENT as u64).map(burn).collect();
        let parsed = AggregatedAnnouncementData::from_announcement(&data.to_announcement());
        assert_eq!(parsed, Some(data.clone()));

        data.burns.push(burn(0));
        assert!(AggregatedAnnouncementData::from_announcement(&data.to_announcement()).is_none());
    }

    /// R13: a settlement at `max_relayed_burns` fits the peers' relay limit; one more burn does not.
    #[test]
    fn settlement_at_relay_limit_relays_and_one_more_burn_is_refused() {
        for num_signatures in [0, 1, 3] {
            let mut data = base(10, 20);
            data.change_sender_randomness = Some(Digest::default());
            data.authority_signatures = vec![[7; AUTHORITY_SIGNATURE_BYTES]; num_signatures];
            data.burns = (0..max_relayed_burns(num_signatures) as u64)
                .map(burn)
                .collect();
            assert!(data.to_announcement().message.len() <= MAX_ANNOUNCEMENT_MESSAGE_SIZE);

            data.burns.push(burn(0));
            assert!(data.to_announcement().message.len() > MAX_ANNOUNCEMENT_MESSAGE_SIZE);
        }
    }

    #[test]
    fn faucet_id_sits_after_exit_root() {
        let ann = base(10, 20).to_announcement();
        assert_eq!(ann.message[16], test_faucet().suffix);
        assert_eq!(ann.message[17], test_faucet().prefix);
    }

    #[test]
    fn trailing_felts_return_none() {
        let mut ann = base(10, 20).to_announcement();
        ann.message.push(BFieldElement::new(0));
        assert!(AggregatedAnnouncementData::from_announcement(&ann).is_none());
    }

    #[test]
    fn settlement_digest_covers_payout_fields_and_ignores_proof() {
        let mut data = base(10, 20);
        data.burns = vec![BurnRecord {
            receiver_identifier: BFieldElement::new(1),
            privacy_digest: test_digest(1),
            lock_script_hash: test_digest(2),
            amount: 5,
            serial: serial(3),
        }];
        let d0 = data.settlement_digest(Network::RegTest);

        let mut noise = data.clone();
        noise.authority_signatures = vec![sample_sig(9)];
        assert_eq!(d0, noise.settlement_digest(Network::RegTest));

        // A changed payout field changes the digest.
        let mut tampered = data.clone();
        tampered.burns[0].amount = 6;
        assert_ne!(d0, tampered.settlement_digest(Network::RegTest));

        let mut other_faucet = data.clone();
        other_faucet.faucet_id.suffix = BFieldElement::new(0);
        assert_ne!(d0, other_faucet.settlement_digest(Network::RegTest));

        // change_sender_randomness must not affect the digest (see fn doc).
        let mut with_change = data.clone();
        with_change.change_sender_randomness = Some(test_digest(9));
        assert_eq!(d0, with_change.settlement_digest(Network::RegTest));

        assert_ne!(d0, data.settlement_digest(Network::Main));
        assert_ne!(d0, data.settlement_digest(Network::Testnet(0)));
    }
}
