//! The pool list is node-local, so the authority vouches for a consolidation's pool inputs off-chain
//! and block acceptance checks the block spends exactly those pool entries.

use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;

use super::faucet_registration::FaucetId;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

/// Wire tag: "LEVBR_PC".
pub const POOL_CONSOLIDATION_TAG: u64 = 0x4C45_5642_525F_5043;
/// Domain separator of the signed digest: "XNTBRCON".
const POOL_CONSOLIDATION_SIG_DOMAIN: u64 = 0x584E_5442_5243_4F4E;
/// TAG, change_commitment(5), num_inputs.
const FIXED_LEN: usize = 1 + Digest::LEN + 1;

/// The settlement's `authority_signatures` sign [`pool_consolidation_digest`] over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolConsolidationAuthorization {
    pub change_commitment: Digest,
    /// [`input_digest`]s, strictly ascending.
    pub input_digests: Vec<Digest>,
}

/// Identifies an input by its absolute index set, which mutator-set updates leave unchanged.
pub fn input_digest(removal_record: &RemovalRecord) -> Digest {
    Tip5::hash(&removal_record.absolute_indices)
}

/// [`input_digest`] from a UTXO's mutator-set data, as the signer computes it.
pub fn utxo_input_digest(
    utxo: &Utxo,
    sender_randomness: Digest,
    receiver_preimage: Digest,
    aocl_leaf_index: u64,
) -> Digest {
    Tip5::hash(&AbsoluteIndexSet::compute(
        Tip5::hash(utxo),
        sender_randomness,
        receiver_preimage,
        aocl_leaf_index,
    ))
}

/// What the authority signs, like a settlement digest.
pub fn pool_consolidation_digest(
    network: Network,
    faucet_id: FaucetId,
    prev_state_commitment: Digest,
    change_commitment: Digest,
    input_digests: &[Digest],
) -> Digest {
    let mut sorted = input_digests.to_vec();
    sorted.sort();
    let mut elements = vec![
        BFieldElement::new(POOL_CONSOLIDATION_SIG_DOMAIN),
        BFieldElement::new(u64::from(network.id())),
        faucet_id.suffix,
        faucet_id.prefix,
    ];
    elements.extend(prev_state_commitment.values());
    elements.extend(change_commitment.values());
    elements.push(BFieldElement::new(sorted.len() as u64));
    elements.extend(sorted.iter().flat_map(|d| d.values()));
    Tip5::hash_varlen(&elements)
}

impl PoolConsolidationAuthorization {
    /// Sorts and dedups `input_digests` into the canonical order.
    pub fn new(change_commitment: Digest, mut input_digests: Vec<Digest>) -> Self {
        input_digests.sort();
        input_digests.dedup();
        Self {
            change_commitment,
            input_digests,
        }
    }

    pub fn to_announcement(&self) -> Announcement {
        let mut msg = vec![BFieldElement::new(POOL_CONSOLIDATION_TAG)];
        msg.extend(self.change_commitment.values());
        msg.push(BFieldElement::new(self.input_digests.len() as u64));
        msg.extend(self.input_digests.iter().flat_map(|d| d.values()));
        Announcement::new(msg)
    }

    /// Parse; the message must be consumed exactly and the inputs strictly ascending.
    pub fn from_announcement(announcement: &Announcement) -> Option<Self> {
        let msg = &announcement.message;
        if msg.len() < FIXED_LEN || !Self::is_tagged(announcement) {
            return None;
        }
        let change_commitment = Digest::new(msg[1..1 + Digest::LEN].try_into().ok()?);
        let num_inputs = usize::try_from(msg[FIXED_LEN - 1].value()).ok()?;
        let input_felts = &msg[FIXED_LEN..];
        if num_inputs.checked_mul(Digest::LEN)? != input_felts.len() {
            return None;
        }
        let input_digests = input_felts
            .chunks_exact(Digest::LEN)
            .map(|felts| Some(Digest::new(felts.try_into().ok()?)))
            .collect::<Option<Vec<_>>>()?;
        if !input_digests.windows(2).all(|w| w[0] < w[1]) {
            return None;
        }
        Some(Self {
            change_commitment,
            input_digests,
        })
    }

    pub fn is_tagged(announcement: &Announcement) -> bool {
        announcement.message.first() == Some(&BFieldElement::new(POOL_CONSOLIDATION_TAG))
    }

    pub fn find_in_announcements(announcements: &[Announcement]) -> Option<Self> {
        announcements.iter().find_map(Self::from_announcement)
    }

    pub fn digest(
        &self,
        network: Network,
        faucet_id: FaucetId,
        prev_state_commitment: Digest,
    ) -> Digest {
        pool_consolidation_digest(
            network,
            faucet_id,
            prev_state_commitment,
            self.change_commitment,
            &self.input_digests,
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn digest(seed: u64) -> Digest {
        Digest::new([BFieldElement::new(seed); Digest::LEN])
    }

    #[test]
    fn announcement_round_trips_in_canonical_order() {
        let auth =
            PoolConsolidationAuthorization::new(digest(9), vec![digest(3), digest(1), digest(3)]);
        assert_eq!(auth.input_digests, vec![digest(1), digest(3)]);
        assert_eq!(
            PoolConsolidationAuthorization::from_announcement(&auth.to_announcement()),
            Some(auth)
        );
    }

    #[test]
    fn rejects_unsorted_duplicate_or_truncated_inputs() {
        let unsorted = PoolConsolidationAuthorization {
            change_commitment: digest(9),
            input_digests: vec![digest(3), digest(1)],
        };
        assert!(
            PoolConsolidationAuthorization::from_announcement(&unsorted.to_announcement())
                .is_none()
        );
        let duplicate = PoolConsolidationAuthorization {
            change_commitment: digest(9),
            input_digests: vec![digest(1), digest(1)],
        };
        assert!(
            PoolConsolidationAuthorization::from_announcement(&duplicate.to_announcement())
                .is_none()
        );
        let mut truncated =
            PoolConsolidationAuthorization::new(digest(9), vec![digest(1)]).to_announcement();
        truncated.message.pop();
        assert!(PoolConsolidationAuthorization::from_announcement(&truncated).is_none());
    }

    #[test]
    fn digest_binds_every_field_but_not_input_order() {
        let faucet = FaucetId {
            suffix: BFieldElement::new(1),
            prefix: BFieldElement::new(2),
        };
        let base = pool_consolidation_digest(
            Network::RegTest,
            faucet,
            digest(5),
            digest(9),
            &[digest(1), digest(3)],
        );
        assert_eq!(
            base,
            pool_consolidation_digest(
                Network::RegTest,
                faucet,
                digest(5),
                digest(9),
                &[digest(3), digest(1)]
            )
        );
        assert_ne!(
            base,
            pool_consolidation_digest(
                Network::RegTest,
                faucet,
                digest(6),
                digest(9),
                &[digest(1), digest(3)]
            )
        );
        assert_ne!(
            base,
            pool_consolidation_digest(
                Network::RegTest,
                faucet,
                digest(5),
                digest(8),
                &[digest(1), digest(3)]
            )
        );
        assert_ne!(
            base,
            pool_consolidation_digest(Network::RegTest, faucet, digest(5), digest(9), &[digest(1)])
        );
    }
}
