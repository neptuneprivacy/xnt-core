pub mod aggregated_announcement;
pub mod authority;
pub mod authority_rotation;
pub mod deposit_announcement;
pub mod faucet_registration;
pub mod lock_script;
pub mod pool_consolidation;

use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::protocol::consensus::transaction::announcement::Announcement;

/// Tags of announcements that may only enter a `SingleProof` through the ProofCollection branch.
/// BDAV binds deposits and BAAV settlements; a consolidation is bound by block rule 2.r (it must
/// ride a no-op settlement) and its authority signature, not by any proof.
pub const PROOF_BOUND_TAGS: [u64; 3] = [
    deposit_announcement::BRIDGE_DEPOSIT_TAG,
    aggregated_announcement::AGGREGATED_ANNOUNCEMENT_TAG,
    pool_consolidation::POOL_CONSOLIDATION_TAG,
];

/// Whether the announcement carries one of the [`PROOF_BOUND_TAGS`].
pub fn has_proof_bound_tag(announcement: &Announcement) -> bool {
    announcement.message.first().is_some_and(|first| {
        PROOF_BOUND_TAGS
            .iter()
            .any(|tag| *first == BFieldElement::new(*tag))
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;

    use super::*;
    use crate::state::wallet::address::dctidh_address::CTIDH_FLAG;
    use crate::state::wallet::address::dctidh_address::CTIDH_SUBADDR_FLAG;
    use crate::state::wallet::address::generation_address::GENERATION_FLAG;
    use crate::state::wallet::address::generation_address::GENERATION_SUBADDR_FLAG;
    use crate::state::wallet::address::symmetric_key::SYMMETRIC_KEY_FLAG;

    #[test]
    fn bridge_tags_are_distinct_and_collide_with_no_upstream_announcement() {
        let bridge_tags = [
            deposit_announcement::BRIDGE_DEPOSIT_TAG,
            aggregated_announcement::AGGREGATED_ANNOUNCEMENT_TAG,
            faucet_registration::FAUCET_REGISTRATION_TAG,
            authority_rotation::AUTHORITY_ROTATION_TAG,
            pool_consolidation::POOL_CONSOLIDATION_TAG,
        ];
        assert!(bridge_tags.iter().all_unique());
        let upstream_flags = [
            GENERATION_FLAG,
            GENERATION_SUBADDR_FLAG,
            SYMMETRIC_KEY_FLAG,
            CTIDH_FLAG,
            CTIDH_SUBADDR_FLAG,
        ];
        for tag in bridge_tags {
            assert!(tag < BFieldElement::P, "{tag:#x} is not a field element");
            assert!(!upstream_flags.contains(&BFieldElement::new(tag)));
            assert!(tag.to_be_bytes().starts_with(b"LEVBR_"), "{tag:#x}");
        }
    }
}
