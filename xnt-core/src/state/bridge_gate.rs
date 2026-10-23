//! The bridge rules a block must pass against its parent's chain state.

use tasm_lib::prelude::Digest;

use super::archival_state::ArchivalState;
use super::bridge_pool::bridge_unlock_effects;
use super::bridge_pool::PoolView;
use super::transaction::transaction_kernel_id::TransactionKernelId;
use super::GlobalState;
use super::InvalidBridgeChange;
use super::InvalidBridgeRegistration;
use super::StaleBridgeSettlement;
use super::UnauthorizedBridgeRotation;
use super::UnauthorizedBridgeSettlement;
use super::UnregisteredBridgeSettlement;
use crate::application::config::network::Network;
use crate::protocol::consensus::block::pool_consolidation_authorization;
use crate::protocol::consensus::block::validate_bridge_deposits_against_settlement_change;
use crate::protocol::consensus::block::validate_bridge_registrations;
use crate::protocol::consensus::block::validate_bridge_settlements;
use crate::protocol::consensus::block::validate_unique_bridge_deposits;
use crate::protocol::consensus::bridge::aggregated_announcement::AggregatedAnnouncementData;
use crate::protocol::consensus::bridge::authority::BridgeAuthoritySet;
use crate::protocol::consensus::bridge::authority_rotation::AuthorityRotationAnnouncement;
use crate::protocol::consensus::bridge::authority_rotation::AUTHORITY_ROTATION_TAG;
use crate::protocol::consensus::bridge::deposit_announcement::is_deposit_tagged;
use crate::protocol::consensus::bridge::faucet_registration::BridgeRegistration;
use crate::protocol::consensus::bridge::faucet_registration::FaucetRegistrationAnnouncement;
use crate::protocol::consensus::bridge::pool_consolidation::PoolConsolidationAuthorization;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;

/// Bridge state as of a parent block; every rule in a block is checked against it.
#[derive(Debug)]
pub(crate) struct BridgeGate {
    network: Network,
    registration: Option<BridgeRegistration>,
    commitment: Option<Digest>,
    authority: Option<BridgeAuthoritySet>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BridgeEffects {
    /// A settlement's new state commitment.
    pub(crate) settled_to: Option<Digest>,
    pub(crate) registration: Option<BridgeRegistration>,
    pub(crate) new_authority: Option<BridgeAuthoritySet>,
}

pub(crate) fn settlement_kind(announcements: &[Announcement]) -> Option<SettlementKind> {
    AggregatedAnnouncementData::find_in_announcements(announcements).map(|_| {
        if announcements
            .iter()
            .any(PoolConsolidationAuthorization::is_tagged)
        {
            SettlementKind::PoolConsolidation
        } else {
            SettlementKind::Real
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettlementKind {
    Real,
    PoolConsolidation,
}

pub(crate) fn has_bridge_announcements(announcements: &[Announcement]) -> bool {
    announcements.iter().any(|a| {
        AggregatedAnnouncementData::is_settlement_tagged(a)
            || FaucetRegistrationAnnouncement::is_registration_tagged(a)
            || PoolConsolidationAuthorization::is_tagged(a)
            || a.message.first() == Some(&AUTHORITY_ROTATION_TAG.into())
    })
}

impl BridgeGate {
    pub(crate) async fn as_of(archival: &ArchivalState, parent: Digest) -> Self {
        Self {
            network: archival.network(),
            registration: archival.bridge_registration_as_of(parent).await,
            commitment: archival.bridge_commitment_as_of(parent).await,
            authority: archival.bridge_authority_set_as_of(parent).await,
        }
    }

    /// Errors are the typed `state` errors, so callers can tell an invalid block from a fatal one.
    pub(crate) fn check(&self, announcements: &[Announcement]) -> anyhow::Result<BridgeEffects> {
        let mut effects = BridgeEffects::default();

        if let Some(ann) = AggregatedAnnouncementData::find_in_announcements(announcements) {
            let registered = self.registration.map(|r| r.faucet_id);
            if registered != Some(ann.faucet_id) {
                return Err(UnregisteredBridgeSettlement {
                    announced: ann.faucet_id,
                    registered,
                }
                .into());
            }
            let Some(expected) = self.commitment else {
                return Err(UnregisteredBridgeSettlement {
                    announced: ann.faucet_id,
                    registered,
                }
                .into());
            };
            if ann.prev_state_commitment != expected {
                return Err(StaleBridgeSettlement {
                    expected,
                    claimed: ann.prev_state_commitment,
                }
                .into());
            }
            let signed_digest =
                match PoolConsolidationAuthorization::find_in_announcements(announcements) {
                    Some(auth) => {
                        auth.digest(self.network, ann.faucet_id, ann.prev_state_commitment)
                    }
                    None => ann.settlement_digest(self.network),
                };
            let authorized = self
                .authority
                .as_ref()
                .is_some_and(|set| set.verify_settlement(signed_digest, &ann.authority_signatures));
            if !authorized {
                return Err(UnauthorizedBridgeSettlement.into());
            }
            effects.settled_to = Some(ann.new_state_commitment);
        }

        if let Some(rot) = AuthorityRotationAnnouncement::find_in_announcements(announcements) {
            let new_set = self
                .authority
                .as_ref()
                .and_then(|set| rot.verify_and_build(set, self.network).ok())
                .ok_or(UnauthorizedBridgeRotation)?;
            effects.new_authority = Some(new_set);
        }

        if let Some(reg) = FaucetRegistrationAnnouncement::find_in_announcements(announcements) {
            let registration = self
                .authority
                .as_ref()
                .filter(|_| self.registration.is_none())
                .and_then(|set| reg.verify(set, self.network).ok())
                .ok_or(InvalidBridgeRegistration)?;
            effects.registration = Some(registration);
        }

        Ok(effects)
    }

    /// [`Self::check`] plus the announcement-only parts of 2.m-2.p.
    pub(crate) fn admit(&self, announcements: &[Announcement]) -> anyhow::Result<BridgeEffects> {
        validate_bridge_settlements(announcements)?;
        validate_bridge_registrations(announcements)?;
        validate_bridge_deposits_against_settlement_change(announcements)?;
        let authorization = pool_consolidation_authorization(announcements)?;
        // Policy: an unauthorized no-op settlement's signature never goes stale (its state stays).
        if authorization.is_none()
            && AggregatedAnnouncementData::find_in_announcements(announcements)
                .is_some_and(|settlement| settlement.is_pool_consolidation())
        {
            return Err(UnauthorizedBridgeSettlement.into());
        }
        self.check(announcements)
    }

    pub(crate) fn advance(&mut self, effects: BridgeEffects) {
        if let Some(commitment) = effects.settled_to {
            self.commitment = Some(commitment);
        }
        if let Some(registration) = effects.registration {
            self.commitment = Some(registration.genesis_state_commitment);
            self.registration = Some(registration);
        }
        if let Some(authority) = effects.new_authority {
            self.authority = Some(authority);
        }
    }
}

fn admit_tx(
    gate: &BridgeGate,
    pool: Option<&PoolView>,
    kernel: &TransactionKernel,
) -> anyhow::Result<()> {
    gate.admit(&kernel.announcements)?;
    if let Some(pool) = pool {
        bridge_unlock_effects(kernel, pool)?;
    }
    Ok(())
}

impl GlobalState {
    pub(crate) async fn bridge_admission_check(
        &self,
        kernel: &TransactionKernel,
    ) -> anyhow::Result<()> {
        if !self.bridge_rules_apply_to_next_block() {
            return Ok(());
        }
        validate_unique_bridge_deposits(&kernel.announcements)?;
        if !has_bridge_announcements(&kernel.announcements) {
            return Ok(());
        }
        let tip = self.chain.light_state().hash();
        let gate = BridgeGate::as_of(self.chain.archival_state(), tip).await;
        let pool = self.bridge_pool_for(&[kernel], tip).await?;
        admit_tx(&gate, pool.as_ref(), kernel)
    }

    /// The pool as of `tip`, if any of `kernels` settles.
    async fn bridge_pool_for(
        &self,
        kernels: &[&TransactionKernel],
        tip: Digest,
    ) -> Result<Option<PoolView>, InvalidBridgeChange> {
        if !kernels
            .iter()
            .any(|kernel| settlement_kind(&kernel.announcements).is_some())
        {
            return Ok(None);
        }
        self.chain
            .archival_state()
            .bridge_pool_as_of(tip)
            .await
            .map(Some)
    }

    /// Evicts mempool txs failing the gate against the tip, e.g. settlements another one made stale.
    pub(crate) async fn evict_bridge_inadmissible(&mut self) -> Vec<TransactionKernelId> {
        if !self.bridge_rules_apply_to_next_block() {
            return vec![];
        }
        let candidates = self
            .mempool
            .fee_density_iter()
            .filter_map(|(txid, _)| {
                self.mempool
                    .get(txid)
                    .map(|tx| &tx.kernel)
                    .or_else(|| self.mempool.get_link(txid).map(|link| &link.kernel.kernel))
                    .filter(|kernel| has_bridge_announcements(&kernel.announcements))
                    .map(|kernel| (txid, kernel.clone()))
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return vec![];
        }

        let tip = self.chain.light_state().hash();
        let gate = BridgeGate::as_of(self.chain.archival_state(), tip).await;
        let kernels = candidates
            .iter()
            .map(|(_, kernel)| kernel)
            .collect::<Vec<_>>();
        let pool = match self.bridge_pool_for(&kernels, tip).await {
            Ok(pool) => pool,
            Err(e) => {
                tracing::error!(
                    "cannot rebuild the bridge pool as of the tip, evicting nothing: {e}"
                );
                return vec![];
            }
        };
        let evicted = candidates
            .into_iter()
            .filter_map(|(txid, kernel)| {
                let e = admit_tx(&gate, pool.as_ref(), &kernel).err()?;
                tracing::info!("evicting tx {txid} from mempool: {e}");
                Some(txid)
            })
            .collect::<Vec<_>>();
        for txid in &evicted {
            self.mempool_remove(*txid).await;
        }
        evicted
    }

    pub(crate) fn bridge_rules_apply_to_next_block(&self) -> bool {
        let next_height = self.chain.light_state().header().height.next();
        ConsensusRuleSet::infer_from(self.cli().network, next_height).bav_active()
    }
}

/// At most one settlement, registration and rotation per composed block (one rotation is stricter
/// than consensus, which ignores all but the first).
#[derive(Debug)]
pub(crate) struct BlockBridgeSelection {
    gate: BridgeGate,
    settlement: bool,
    registration: bool,
    rotation: bool,
    defer_pool_consolidations: bool,
    /// Deposit and settlement announcements of admitted txs, for 2.q and 2.t across txs.
    change_claims: Vec<Announcement>,
    /// The pool as of the parent, which a settlement's change must be rebuildable from, as block
    /// apply rebuilds it; `Err` refuses every settlement. Unset only in tests of the rest.
    pool: Option<Result<PoolView, InvalidBridgeChange>>,
}

impl BlockBridgeSelection {
    pub(crate) fn new(gate: BridgeGate) -> Self {
        Self {
            gate,
            settlement: false,
            registration: false,
            rotation: false,
            defer_pool_consolidations: false,
            change_claims: vec![],
            pool: None,
        }
    }

    pub(crate) fn checking_pool(mut self, pool: Result<PoolView, InvalidBridgeChange>) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Keeps the settlement slot free while any real settlement in `candidates` is admissible.
    pub(crate) fn prefer_real_settlements<'a>(
        &mut self,
        candidates: impl IntoIterator<Item = &'a TransactionKernel>,
    ) {
        self.defer_pool_consolidations = candidates.into_iter().any(|kernel| {
            settlement_kind(&kernel.announcements) == Some(SettlementKind::Real)
                && self.gate.admit(&kernel.announcements).is_ok()
        });
    }

    pub(crate) fn admit(&mut self, kernel: &TransactionKernel) -> bool {
        let claims = kernel
            .announcements
            .iter()
            .filter(|a| {
                is_deposit_tagged(a)
                    || AggregatedAnnouncementData::is_settlement_tagged(a)
                    || PoolConsolidationAuthorization::is_tagged(a)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !claims.is_empty() {
            let merged = [self.change_claims.clone(), claims.clone()].concat();
            let checked = validate_bridge_deposits_against_settlement_change(&merged)
                .and_then(|()| validate_unique_bridge_deposits(&merged));
            if let Err(e) = checked {
                tracing::info!("composer skips tx {}: {e}", kernel.txid());
                return false;
            }
        }
        if !has_bridge_announcements(&kernel.announcements) {
            self.change_claims.extend(claims);
            return true;
        }
        let effects = match self.gate.admit(&kernel.announcements) {
            Ok(effects) => effects,
            Err(e) => {
                tracing::info!("composer skips tx {}: {e}", kernel.txid());
                return false;
            }
        };
        if settlement_kind(&kernel.announcements).is_some() {
            let pool_change = match &self.pool {
                None => Ok(()),
                Some(Ok(pool)) => bridge_unlock_effects(kernel, pool).map(|_| ()),
                Some(Err(e)) => Err(*e),
            };
            if let Err(e) = pool_change {
                tracing::info!("composer skips settlement {}: {e}", kernel.txid());
                return false;
            }
        }
        if self.defer_pool_consolidations
            && settlement_kind(&kernel.announcements) == Some(SettlementKind::PoolConsolidation)
        {
            tracing::info!(
                "composer skips pool consolidation {}: a real settlement is pending",
                kernel.txid()
            );
            return false;
        }
        let settlement = effects.settled_to.is_some();
        let registration = effects.registration.is_some();
        let rotation = effects.new_authority.is_some();
        if (settlement && self.settlement)
            || (registration && self.registration)
            || (rotation && self.rotation)
        {
            tracing::info!(
                "composer skips tx {}: block already carries its bridge action",
                kernel.txid()
            );
            return false;
        }
        self.settlement |= settlement;
        self.registration |= registration;
        self.rotation |= rotation;
        self.change_claims.extend(claims);
        true
    }

    /// Forget admitted transactions that did not make it into the block.
    pub(crate) fn reset(&mut self) {
        self.settlement = false;
        self.registration = false;
        self.rotation = false;
        self.change_claims.clear();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::Signature;
    use k256::ecdsa::SigningKey;
    use num_traits::Zero;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use super::*;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::Timestamp;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::bridge::aggregated_announcement::StatePreimage;
    use crate::protocol::consensus::bridge::aggregated_announcement::STATE_PREIMAGE_LEN;
    use crate::protocol::consensus::bridge::authority::settlement_signing_prehash;
    use crate::protocol::consensus::bridge::faucet_registration::FaucetId;
    use crate::protocol::consensus::bridge::pool_consolidation::input_digest;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;
    use crate::util_types::test_shared::mutator_set::mock_item_mp_rr_for_init_msa;

    fn key(scalar: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        SigningKey::from_bytes(&bytes.into()).unwrap()
    }

    fn sign_with(key: &SigningKey, digest: Digest) -> [u8; 64] {
        let sig: Signature = key
            .sign_prehash(&settlement_signing_prehash(digest))
            .unwrap();
        sig.to_bytes().into()
    }

    /// RegTest's dev authority key (scalar 1).
    fn sign(digest: Digest) -> [u8; 64] {
        sign_with(&key(1), digest)
    }

    fn authority() -> BridgeAuthoritySet {
        Network::RegTest.bridge_genesis_authority_set().unwrap()
    }

    fn registration() -> BridgeRegistration {
        BridgeRegistration {
            faucet_id: FaucetId {
                suffix: BFieldElement::new(1 << 8),
                prefix: BFieldElement::new(1),
            },
            genesis_state_commitment: Tip5::hash_varlen(&[BFieldElement::new(1)]),
        }
    }

    fn registration_announcement(signed: bool) -> Announcement {
        let mut ann = FaucetRegistrationAnnouncement {
            registration: registration(),
            signatures: vec![],
        };
        if signed {
            ann.signatures = vec![sign(
                ann.registration_digest(Network::RegTest, authority().commitment()),
            )];
        }
        ann.to_announcement()
    }

    fn settlement(prev: Digest, signed: bool) -> Announcement {
        let mut data = AggregatedAnnouncementData {
            prev_state_commitment: prev,
            new_state_commitment: next_state(),
            exit_root: Digest::default(),
            faucet_id: registration().faucet_id,
            prev_state_preimage: StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
            burns: vec![],
            change_sender_randomness: None,
            authority_signatures: vec![],
        };
        if signed {
            data.authority_signatures = vec![sign(data.settlement_digest(Network::RegTest))];
        }
        data.to_announcement()
    }

    #[test]
    fn rejects_bridge_signatures_made_for_another_network() {
        let prev = registration().genesis_state_commitment;
        let mut main_settlement =
            AggregatedAnnouncementData::from_announcement(&settlement(prev, false)).unwrap();
        main_settlement.authority_signatures =
            vec![sign(main_settlement.settlement_digest(Network::Main))];
        assert!(rejects_with::<UnauthorizedBridgeSettlement>(
            registered().admit(&[main_settlement.to_announcement()])
        ));

        let mut main_registration = FaucetRegistrationAnnouncement {
            registration: registration(),
            signatures: vec![],
        };
        main_registration.signatures = vec![sign(
            main_registration.registration_digest(Network::Main, authority().commitment()),
        )];
        assert!(rejects_with::<InvalidBridgeRegistration>(
            unregistered().admit(&[main_registration.to_announcement()])
        ));

        let new_key = key(2);
        let mut rotation = AuthorityRotationAnnouncement {
            new_keys: vec![new_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()],
            new_threshold: 1,
            signatures: vec![],
        };
        let digest = rotation.rotation_digest(Network::Main, authority().commitment());
        rotation.signatures = vec![sign_with(&key(1), digest), sign_with(&new_key, digest)];
        assert!(rejects_with::<UnauthorizedBridgeRotation>(
            registered().admit(&[rotation.to_announcement()])
        ));

        let inputs = pool_inputs(2);
        let [no_op_announcement, authorization_announcement] =
            <[Announcement; 2]>::try_from(consolidation(prev, &inputs, None)).unwrap();
        let mut no_op = AggregatedAnnouncementData::from_announcement(&no_op_announcement).unwrap();
        no_op.authority_signatures = vec![sign(authorization(&inputs).digest(
            Network::Main,
            no_op.faucet_id,
            prev,
        ))];
        assert!(rejects_with::<UnauthorizedBridgeSettlement>(
            registered().admit(&[no_op.to_announcement(), authorization_announcement])
        ));
    }

    fn tx(announcements: &[Announcement]) -> TransactionKernel {
        TransactionKernelProxy {
            inputs: vec![],
            outputs: vec![],
            announcements: announcements.to_vec(),
            fee: NativeCurrencyAmount::zero(),
            coinbase: None,
            timestamp: Timestamp::now(),
            mutator_set_hash: Digest::default(),
            merge_bit: false,
        }
        .into_kernel()
    }

    /// A rotation to a set holding only `new_key`, signed by the dev key and `new_key`.
    fn signed_rotation(new_key: &SigningKey) -> Announcement {
        let mut rotation = AuthorityRotationAnnouncement {
            new_keys: vec![new_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()],
            new_threshold: 1,
            signatures: vec![],
        };
        let digest = rotation.rotation_digest(Network::RegTest, authority().commitment());
        rotation.signatures = vec![sign_with(&key(1), digest), sign_with(new_key, digest)];
        rotation.to_announcement()
    }

    fn next_state() -> Digest {
        Digest::new([BFieldElement::new(9); 5])
    }

    fn unregistered() -> BridgeGate {
        BridgeGate {
            network: Network::RegTest,
            registration: None,
            commitment: None,
            authority: Some(authority()),
        }
    }

    fn registered() -> BridgeGate {
        BridgeGate {
            network: Network::RegTest,
            registration: Some(registration()),
            commitment: Some(registration().genesis_state_commitment),
            authority: Some(authority()),
        }
    }

    fn rejects_with<E: std::error::Error + Send + Sync + 'static>(
        result: anyhow::Result<BridgeEffects>,
    ) -> bool {
        result.is_err_and(|e| e.downcast_ref::<E>().is_some())
    }

    #[test]
    fn no_bridge_announcements_pass_with_no_effects() {
        let effects = unregistered().admit(&[Announcement::new(vec![])]).unwrap();
        assert!(effects.settled_to.is_none());
        assert!(effects.registration.is_none());
        assert!(effects.new_authority.is_none());
    }

    #[test]
    fn settlement_continuing_the_state_is_admitted_and_advances_it() {
        let mut gate = registered();
        let effects = gate
            .admit(&[settlement(registration().genesis_state_commitment, true)])
            .unwrap();
        assert_eq!(effects.settled_to, Some(next_state()));

        gate.advance(effects);
        assert!(rejects_with::<StaleBridgeSettlement>(gate.admit(&[
            settlement(registration().genesis_state_commitment, true)
        ])));
        assert!(gate.admit(&[settlement(next_state(), true)]).is_ok());
    }

    #[test]
    fn rejects_stale_unsigned_and_unregistered_settlements() {
        let stale = settlement(Digest::new([BFieldElement::new(5); 5]), true);
        assert!(rejects_with::<StaleBridgeSettlement>(
            registered().admit(&[stale])
        ));

        let unsigned = settlement(registration().genesis_state_commitment, false);
        assert!(rejects_with::<UnauthorizedBridgeSettlement>(
            registered().admit(&[unsigned])
        ));

        let ok = settlement(registration().genesis_state_commitment, true);
        assert!(rejects_with::<UnregisteredBridgeSettlement>(
            unregistered().admit(std::slice::from_ref(&ok))
        ));

        let no_authority = BridgeGate {
            authority: None,
            ..registered()
        };
        assert!(rejects_with::<UnauthorizedBridgeSettlement>(
            no_authority.admit(&[ok])
        ));
    }

    #[test]
    fn admit_applies_the_stateless_block_rules_and_check_does_not() {
        let ok = settlement(registration().genesis_state_commitment, true);
        let two = [ok.clone(), ok];
        let err = registered().admit(&two).unwrap_err();
        assert_eq!(
            err.to_string(),
            "block carries more than one settlement announcement"
        );
        assert!(registered().check(&two).is_ok());

        let mut tagged_garbage = settlement(registration().genesis_state_commitment, true);
        tagged_garbage.message.truncate(3);
        let malformed = registered().admit(&[tagged_garbage]).unwrap_err();
        assert_eq!(
            malformed.to_string(),
            "block carries a malformed settlement announcement"
        );
    }

    #[test]
    fn registration_only_once_and_only_signed() {
        let mut gate = unregistered();
        let effects = gate.admit(&[registration_announcement(true)]).unwrap();
        assert_eq!(effects.registration, Some(registration()));
        assert_eq!(effects.settled_to, None);

        gate.advance(effects);
        assert!(gate
            .admit(&[settlement(registration().genesis_state_commitment, true)])
            .is_ok());

        assert!(rejects_with::<InvalidBridgeRegistration>(
            unregistered().admit(&[registration_announcement(false)])
        ));
        assert!(rejects_with::<InvalidBridgeRegistration>(
            registered().admit(&[registration_announcement(true)])
        ));
    }

    #[test]
    fn settlement_in_the_registration_block_is_unregistered() {
        let both = [
            registration_announcement(true),
            settlement(registration().genesis_state_commitment, true),
        ];
        assert!(rejects_with::<UnregisteredBridgeSettlement>(
            unregistered().admit(&both)
        ));
    }

    #[test]
    fn unsigned_rotation_is_rejected() {
        let rotation = AuthorityRotationAnnouncement {
            new_keys: vec![],
            new_threshold: 1,
            signatures: vec![],
        };
        assert!(rejects_with::<UnauthorizedBridgeRotation>(
            registered().admit(&[rotation.to_announcement()])
        ));
    }

    #[test]
    fn rejects_settlement_for_another_faucet_or_without_commitment() {
        let ok = settlement(registration().genesis_state_commitment, true);
        let other_faucet = BridgeGate {
            registration: Some(BridgeRegistration {
                faucet_id: FaucetId {
                    suffix: BFieldElement::new(2 << 8),
                    prefix: BFieldElement::new(2),
                },
                ..registration()
            }),
            ..registered()
        };
        assert!(rejects_with::<UnregisteredBridgeSettlement>(
            other_faucet.admit(std::slice::from_ref(&ok))
        ));

        let no_commitment = BridgeGate {
            commitment: None,
            ..registered()
        };
        assert!(rejects_with::<UnregisteredBridgeSettlement>(
            no_commitment.admit(&[ok])
        ));
    }

    #[test]
    fn rejects_registration_signed_by_another_key_and_two_registrations() {
        let mut ann = FaucetRegistrationAnnouncement {
            registration: registration(),
            signatures: vec![],
        };
        ann.signatures = vec![sign_with(
            &key(7),
            ann.registration_digest(Network::RegTest, authority().commitment()),
        )];
        assert!(rejects_with::<InvalidBridgeRegistration>(
            unregistered().admit(&[ann.to_announcement()])
        ));

        let two = [
            registration_announcement(true),
            registration_announcement(true),
        ];
        let err = unregistered().admit(&two).unwrap_err();
        assert_eq!(
            err.to_string(),
            "block carries more than one bridge registration announcement"
        );
    }

    #[test]
    fn signed_rotation_replaces_the_authority_for_the_next_block() {
        let new_key = key(2);
        let mut gate = registered();
        let effects = gate.admit(&[signed_rotation(&new_key)]).unwrap();
        assert!(effects.new_authority.is_some());
        gate.advance(effects);

        // The old key no longer authorizes a settlement; the new one does.
        let prev = registration().genesis_state_commitment;
        assert!(rejects_with::<UnauthorizedBridgeSettlement>(
            gate.admit(&[settlement(prev, true)])
        ));
        let mut data =
            AggregatedAnnouncementData::from_announcement(&settlement(prev, false)).unwrap();
        data.authority_signatures = vec![sign_with(
            &new_key,
            data.settlement_digest(Network::RegTest),
        )];
        assert!(gate.admit(&[data.to_announcement()]).is_ok());
    }

    #[test]
    fn block_selection_takes_one_valid_settlement_and_skips_the_rest() {
        let genesis = registration().genesis_state_commitment;
        let mut selection = BlockBridgeSelection::new(registered());

        assert!(selection.admit(&tx(&[Announcement::new(
            vec![1, 2, 3].into_iter().map(BFieldElement::new).collect()
        )])));
        assert!(!selection.admit(&tx(&[settlement(
            Digest::new([BFieldElement::new(5); 5]),
            true
        )])));
        assert!(!selection.admit(&tx(&[settlement(genesis, false)])));
        assert!(selection.admit(&tx(&[settlement(genesis, true)])));
        assert!(
            !selection.admit(&tx(&[settlement(genesis, true)])),
            "second settlement in one block"
        );
        // checked against the parent, not the state after the first settlement
        assert!(!selection.admit(&tx(&[settlement(next_state(), true)])));
        assert!(selection.admit(&tx(&[])));
    }

    #[test]
    fn block_selection_allows_one_registration() {
        let mut selection = BlockBridgeSelection::new(unregistered());
        assert!(selection.admit(&tx(&[registration_announcement(true)])));
        assert!(!selection.admit(&tx(&[registration_announcement(true)])));
        assert!(!selection.admit(&tx(&[settlement(
            registration().genesis_state_commitment,
            true
        )])));
    }

    #[test]
    fn block_selection_allows_one_rotation_and_reset_forgets_admissions() {
        let genesis = registration().genesis_state_commitment;
        let mut selection = BlockBridgeSelection::new(registered());
        assert!(selection.admit(&tx(&[signed_rotation(&key(2))])));
        assert!(!selection.admit(&tx(&[signed_rotation(&key(3))])));
        assert!(selection.admit(&tx(&[settlement(genesis, true)])));

        selection.reset();
        assert!(selection.admit(&tx(&[settlement(genesis, true)])));
        assert!(selection.admit(&tx(&[signed_rotation(&key(3))])));
    }

    fn change_commitment() -> Digest {
        Digest::new([BFieldElement::new(6); 5])
    }

    fn pool_inputs(n: usize) -> Vec<RemovalRecord> {
        (0..n).map(|_| mock_item_mp_rr_for_init_msa().2).collect()
    }

    fn authorization(inputs: &[RemovalRecord]) -> PoolConsolidationAuthorization {
        PoolConsolidationAuthorization::new(
            change_commitment(),
            inputs.iter().map(input_digest).collect(),
        )
    }

    fn consolidation(
        prev: Digest,
        inputs: &[RemovalRecord],
        signed_over: Option<&[RemovalRecord]>,
    ) -> Vec<Announcement> {
        let mut data = AggregatedAnnouncementData {
            prev_state_commitment: prev,
            new_state_commitment: prev,
            exit_root: Digest::default(),
            faucet_id: registration().faucet_id,
            prev_state_preimage: StatePreimage([BFieldElement::new(0); STATE_PREIMAGE_LEN]),
            burns: vec![],
            change_sender_randomness: Some(Digest::new([BFieldElement::new(4); 5])),
            authority_signatures: vec![],
        };
        if let Some(signed_over) = signed_over {
            data.authority_signatures = vec![sign(authorization(signed_over).digest(
                Network::RegTest,
                data.faucet_id,
                prev,
            ))];
        }
        vec![
            data.to_announcement(),
            authorization(inputs).to_announcement(),
        ]
    }

    fn tx_spending(
        announcements: &[Announcement],
        inputs: Vec<RemovalRecord>,
    ) -> TransactionKernel {
        TransactionKernelModifier::default()
            .inputs(inputs)
            .modify(tx(announcements))
    }

    #[test]
    fn pool_consolidation_must_be_signed_over_its_listed_inputs() {
        let genesis = registration().genesis_state_commitment;
        let inputs = pool_inputs(3);
        let effects = registered()
            .admit(&consolidation(genesis, &inputs, Some(&inputs)))
            .unwrap();
        assert_eq!(effects.settled_to, Some(genesis));

        for announcements in [
            consolidation(genesis, &inputs, None),
            consolidation(genesis, &inputs, Some(&inputs[..2])),
            consolidation(genesis, &inputs, Some(&pool_inputs(3))),
        ] {
            assert!(rejects_with::<UnauthorizedBridgeSettlement>(
                registered().admit(&announcements)
            ));
        }
        // a settlement-digest signature does not authorize a consolidation
        let mut announcements = consolidation(genesis, &inputs, None);
        let mut data = AggregatedAnnouncementData::from_announcement(&announcements[0]).unwrap();
        data.authority_signatures = vec![sign(data.settlement_digest(Network::RegTest))];
        announcements[0] = data.to_announcement();
        assert!(rejects_with::<UnauthorizedBridgeSettlement>(
            registered().admit(&announcements)
        ));

        let stale = next_state();
        assert!(rejects_with::<StaleBridgeSettlement>(
            registered().admit(&consolidation(stale, &inputs, Some(&inputs)))
        ));
    }

    #[test]
    fn admit_refuses_a_no_op_settlement_without_authorization() {
        let genesis = registration().genesis_state_commitment;
        let inputs = pool_inputs(2);
        let mut data = AggregatedAnnouncementData::from_announcement(
            &consolidation(genesis, &inputs, None)[0],
        )
        .unwrap();
        data.authority_signatures = vec![sign(data.settlement_digest(Network::RegTest))];
        assert!(registered().check(&[data.to_announcement()]).is_ok());
        assert!(rejects_with::<UnauthorizedBridgeSettlement>(
            registered().admit(&[data.to_announcement()])
        ));
    }

    #[test]
    fn admit_refuses_a_deposit_claiming_the_consolidation_change() {
        use crate::protocol::consensus::bridge::deposit_announcement::BridgeDepositData;

        let genesis = registration().genesis_state_commitment;
        let inputs = pool_inputs(2);
        let deposit = |sender_randomness: Digest, utxo_commitment: Digest| {
            BridgeDepositData {
                account_id: [BFieldElement::new(3), BFieldElement::new(4)],
                amount: NativeCurrencyAmount::coins(2),
                utxo_commitment: utxo_commitment.values(),
                sender_randomness: sender_randomness.values(),
                receiver_preimage: [BFieldElement::new(0); 5],
            }
            .to_announcement()
        };
        let change_sr = Digest::new([BFieldElement::new(4); 5]);
        let unrelated = Digest::new([BFieldElement::new(9); 5]);
        for claim in [
            deposit(change_sr, unrelated),
            deposit(unrelated, change_commitment()),
        ] {
            let mut announcements = consolidation(genesis, &inputs, Some(&inputs));
            announcements.push(claim);
            let err = registered().admit(&announcements).unwrap_err();
            assert_eq!(
                err.to_string(),
                "block carries a deposit claiming a settlement's change output"
            );
        }
    }

    #[test]
    fn block_selection_keeps_the_slot_for_a_pending_real_settlement() {
        let genesis = registration().genesis_state_commitment;
        let inputs = pool_inputs(2);
        let real = tx(&[settlement(genesis, true)]);
        let pool_consolidation = tx_spending(
            &consolidation(genesis, &inputs, Some(&inputs)),
            inputs.clone(),
        );

        let mut selection = BlockBridgeSelection::new(registered());
        selection.prefer_real_settlements([&real, &pool_consolidation]);
        assert!(!selection.admit(&pool_consolidation));
        assert!(selection.admit(&real));

        // a stale or unsigned real settlement does not hold the block
        let mut without_real = BlockBridgeSelection::new(registered());
        let stale = tx(&[settlement(next_state(), true)]);
        let unsigned = tx(&[settlement(genesis, false)]);
        without_real.prefer_real_settlements([&stale, &unsigned, &pool_consolidation]);
        assert!(without_real.admit(&pool_consolidation));
    }

    /// A settlement is selected only if apply can rebuild its change from the parent's pool.
    #[test]
    fn block_selection_checks_settlements_against_the_parent_pool() {
        let genesis = registration().genesis_state_commitment;
        let inputs = pool_inputs(2);
        let pool_consolidation = tx_spending(
            &consolidation(genesis, &inputs, Some(&inputs)),
            inputs.clone(),
        );
        assert!(BlockBridgeSelection::new(registered()).admit(&pool_consolidation));

        // its inputs are not in the pool
        let mut against_empty_pool =
            BlockBridgeSelection::new(registered()).checking_pool(Ok(PoolView::default()));
        assert!(!against_empty_pool.admit(&pool_consolidation));
        assert!(against_empty_pool.admit(&tx(&[settlement(genesis, true)])));

        let mut without_pool = BlockBridgeSelection::new(registered())
            .checking_pool(Err(InvalidBridgeChange::AmountOverflow));
        assert!(!without_pool.admit(&tx(&[settlement(genesis, true)])));
        assert!(without_pool.admit(&tx(&[])));
    }

    #[test]
    fn block_selection_skips_a_repeated_deposit_commitment() {
        use crate::protocol::consensus::bridge::deposit_announcement::BridgeDepositData;

        let deposit = BridgeDepositData {
            account_id: [BFieldElement::new(3), BFieldElement::new(4)],
            amount: NativeCurrencyAmount::coins(2),
            utxo_commitment: [BFieldElement::new(5); 5],
            sender_randomness: [BFieldElement::new(4); 5],
            receiver_preimage: [BFieldElement::new(0); 5],
        }
        .to_announcement();

        let mut selection = BlockBridgeSelection::new(registered());
        assert!(selection.admit(&tx(std::slice::from_ref(&deposit))));
        assert!(
            !selection.admit(&tx(&[deposit])),
            "the same commitment in a second tx"
        );
    }

    #[test]
    fn block_selection_refuses_a_deposit_claiming_an_admitted_change() {
        use crate::protocol::consensus::bridge::deposit_announcement::BridgeDepositData;

        let genesis = registration().genesis_state_commitment;
        let inputs = pool_inputs(2);
        let pool_consolidation = tx_spending(
            &consolidation(genesis, &inputs, Some(&inputs)),
            inputs.clone(),
        );
        let claiming = tx(&[BridgeDepositData {
            account_id: [BFieldElement::new(3), BFieldElement::new(4)],
            amount: NativeCurrencyAmount::coins(2),
            utxo_commitment: [BFieldElement::new(5); 5],
            sender_randomness: [BFieldElement::new(4); 5],
            receiver_preimage: [BFieldElement::new(0); 5],
        }
        .to_announcement()]);

        let mut selection = BlockBridgeSelection::new(registered());
        assert!(selection.admit(&pool_consolidation));
        assert!(!selection.admit(&claiming));
        selection.reset();
        assert!(selection.admit(&claiming));
        assert!(!selection.admit(&pool_consolidation));
    }
}
