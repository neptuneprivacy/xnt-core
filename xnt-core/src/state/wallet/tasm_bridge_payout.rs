//! TASM bridge payouts carry no UTXO notification: a wallet finds them in the burn records of
//! settle announcements. `leviathan-xnt-bridge` reuses these settle layout constants.

use num_traits::ConstZero;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;

use super::address::SpendingKey;
use super::incoming_utxo::IncomingUtxo;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::util_types::mutator_set::addition_record::AdditionRecord;

pub const SETTLE_TAG: u64 = 0x4C45_5642_325F_5354;
pub const STATE_PREIMAGE_LEN: usize = 19;
pub const SETTLE_HEADER_LEN: usize = 1 + 3 * Digest::LEN + 2 + STATE_PREIMAGE_LEN + 1;
pub const BURN_RECORD_LEN: usize = 16;
pub const MAX_BURNS_PER_SETTLEMENT: u64 = 4096;
pub const LEVIATHAN_UNIT_TO_NAU: u128 = 4_000_000_000_000_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BurnRecord {
    receiver_identifier: BFieldElement,
    privacy_digest: Digest,
    lock_script_hash: Digest,
    amount: u64,
    serial: [BFieldElement; 4],
}

impl BurnRecord {
    fn from_elements(e: &[BFieldElement]) -> Self {
        Self {
            receiver_identifier: e[0],
            privacy_digest: Digest::new(e[1..6].try_into().unwrap()),
            lock_script_hash: Digest::new(e[6..11].try_into().unwrap()),
            amount: e[11].value(),
            serial: e[12..16].try_into().unwrap(),
        }
    }

    fn payout(&self) -> Option<NativeCurrencyAmount> {
        let nau = u128::from(self.amount).checked_mul(LEVIATHAN_UNIT_TO_NAU)?;
        Some(NativeCurrencyAmount::from_nau(i128::try_from(nau).ok()?))
    }
}

/// The burns of a settle announcement, `None` if it is not a well-formed one.
fn settlement_burns(announcement: &Announcement) -> Option<Vec<BurnRecord>> {
    let m = &announcement.message;
    if m.len() < SETTLE_HEADER_LEN || m[0] != BFieldElement::new(SETTLE_TAG) {
        return None;
    }
    let num_burns = m[SETTLE_HEADER_LEN - 1].value();
    if num_burns > MAX_BURNS_PER_SETTLEMENT
        || m.len() != SETTLE_HEADER_LEN + BURN_RECORD_LEN * num_burns as usize
    {
        return None;
    }
    Some(
        m[SETTLE_HEADER_LEN..]
            .chunks_exact(BURN_RECORD_LEN)
            .map(BurnRecord::from_elements)
            .collect(),
    )
}

/// A bridge payout UTXO with what its key needs to claim and spend it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgePayout {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
}

impl BridgePayout {
    pub fn addition_record(&self) -> AdditionRecord {
        UtxoTriple {
            utxo: self.utxo.clone(),
            sender_randomness: self.sender_randomness,
            receiver_digest: self.receiver_preimage.hash(),
        }
        .addition_record()
    }
}

impl From<BridgePayout> for IncomingUtxo {
    fn from(payout: BridgePayout) -> Self {
        Self {
            utxo: payout.utxo,
            sender_randomness: payout.sender_randomness,
            receiver_preimage: payout.receiver_preimage,
            is_guesser_fee: false,
            payment_id: BFieldElement::ZERO,
        }
    }
}

/// Whether `kernel` has a settle announcement with burns, so it may hold payouts.
pub(crate) fn has_burns(kernel: &TransactionKernel) -> bool {
    kernel
        .announcements
        .iter()
        .filter_map(settlement_burns)
        .any(|burns| !burns.is_empty())
}

/// The payouts in `kernel` to `key`, see [`payouts_to_keys`].
pub fn payouts_to(kernel: &TransactionKernel, key: &SpendingKey) -> Vec<BridgePayout> {
    payouts_to_keys(kernel, std::slice::from_ref(key))
        .into_iter()
        .map(|(_, payout)| payout)
        .collect()
}

/// The payouts in `kernel` to any of `keys`, each with the position in `keys` of the key it pays:
/// burns in any settle announcement naming the key's receiver identifier, privacy digest and lock
/// whose payout record is a kernel output, whoever announced them.
pub fn payouts_to_keys(
    kernel: &TransactionKernel,
    keys: &[SpendingKey],
) -> Vec<(usize, BridgePayout)> {
    let burns = kernel
        .announcements
        .iter()
        .filter_map(settlement_burns)
        .flatten()
        .collect::<Vec<_>>();
    if burns.is_empty() {
        return vec![];
    }
    let keys = keys
        .iter()
        .map(|key| {
            let preimage = key.privacy_preimage();
            (
                key.receiver_identifier(),
                preimage,
                preimage.hash(),
                key.lock_script_hash(),
            )
        })
        .collect::<Vec<_>>();
    let mut payouts: Vec<(usize, BridgePayout)> = vec![];
    for burn in burns {
        let Some(position) = keys.iter().position(|(id, _, digest, lock)| {
            burn.receiver_identifier == *id
                && burn.privacy_digest == *digest
                && burn.lock_script_hash == *lock
        }) else {
            continue;
        };
        let Some(amount) = burn.payout() else {
            continue;
        };
        let payout = BridgePayout {
            utxo: Utxo::new_native_currency(burn.lock_script_hash, amount),
            sender_randomness: Tip5::hash_varlen(&burn.serial),
            receiver_preimage: keys[position].1,
        };
        let is_output = kernel.outputs.contains(&payout.addition_record());
        let is_new = !payouts
            .iter()
            .any(|(_, seen)| seen.addition_record() == payout.addition_record());
        if is_output && is_new {
            payouts.push((position, payout));
        }
    }
    payouts
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use super::*;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::state::wallet::address::generation_address::GenerationSpendingKey;
    use crate::tests::shared::strategies::txkernel;
    use crate::util_types::mutator_set::commit;

    pub(crate) fn burn_to(key: &SpendingKey, amount: u64, serial: u64) -> Vec<BFieldElement> {
        let mut e = vec![key.receiver_identifier()];
        e.extend(key.privacy_preimage().hash().values());
        e.extend(key.lock_script_hash().values());
        e.push(BFieldElement::new(amount));
        e.extend([BFieldElement::new(serial); 4]);
        e
    }

    pub(crate) fn settle_announcement(burns: &[Vec<BFieldElement>]) -> Announcement {
        let mut m = vec![BFieldElement::new(SETTLE_TAG)];
        m.extend([BFieldElement::ZERO; SETTLE_HEADER_LEN - 2]);
        m.push(BFieldElement::new(burns.len() as u64));
        m.extend(burns.iter().flatten());
        Announcement::new(m)
    }

    pub(crate) fn payout_output(burn: &[BFieldElement]) -> AdditionRecord {
        let burn = BurnRecord::from_elements(burn);
        let utxo = Utxo::new_native_currency(burn.lock_script_hash, burn.payout().unwrap());
        commit(
            Tip5::hash(&utxo),
            Tip5::hash_varlen(&burn.serial),
            burn.privacy_digest,
        )
    }

    pub(crate) fn kernel_with(
        announcements: Vec<Announcement>,
        outputs: Vec<AdditionRecord>,
    ) -> TransactionKernel {
        let kernel = txkernel::with_lengths(0usize, 0usize, 0usize, false)
            .new_tree(&mut TestRunner::deterministic())
            .unwrap()
            .current();
        TransactionKernelModifier::default()
            .announcements(announcements)
            .outputs(outputs)
            .fee(NativeCurrencyAmount::coins(0))
            .coinbase(None)
            .modify(kernel)
    }

    fn key(seed: u8) -> SpendingKey {
        GenerationSpendingKey::derive_from_seed(Digest::new([BFieldElement::new(seed.into()); 5]))
            .into()
    }

    #[test]
    fn matching_payout_is_found() {
        let burn = burn_to(&key(1), 3, 7);
        let kernel = kernel_with(
            vec![settle_announcement(std::slice::from_ref(&burn))],
            vec![payout_output(&burn)],
        );

        let payouts = payouts_to_keys(&kernel, &[key(1)]);

        assert_eq!(1, payouts.len());
        let (position, payout) = &payouts[0];
        assert_eq!(0, *position);
        assert_eq!(
            NativeCurrencyAmount::from_nau(3 * LEVIATHAN_UNIT_TO_NAU as i128),
            payout.utxo.get_native_currency_amount()
        );
        assert_eq!(key(1).privacy_preimage(), payout.receiver_preimage);
    }

    #[test]
    fn second_key_reports_its_position() {
        let burn = burn_to(&key(2), 1, 1);
        let kernel = kernel_with(
            vec![settle_announcement(std::slice::from_ref(&burn))],
            vec![payout_output(&burn)],
        );

        let positions = payouts_to_keys(&kernel, &[key(1), key(2)])
            .into_iter()
            .map(|(position, _)| position)
            .collect::<Vec<_>>();

        assert_eq!(vec![1], positions);
    }

    #[test]
    fn foreign_id_lock_or_digest_is_ignored() {
        let mut foreign_id = burn_to(&key(1), 1, 3);
        foreign_id[0] = key(2).receiver_identifier();
        let mut foreign_lock = burn_to(&key(1), 1, 1);
        foreign_lock[6..11].copy_from_slice(&key(2).lock_script_hash().values());
        let mut foreign_digest = burn_to(&key(1), 1, 2);
        foreign_digest[1..6].copy_from_slice(&key(2).privacy_preimage().hash().values());
        let burns = [foreign_id, foreign_lock, foreign_digest];
        let kernel = kernel_with(
            vec![settle_announcement(&burns)],
            burns.iter().map(|burn| payout_output(burn)).collect(),
        );

        assert!(payouts_to_keys(&kernel, &[key(1)]).is_empty());
    }

    #[test]
    fn unpaid_burn_is_ignored() {
        let burn = burn_to(&key(1), 1, 1);
        let kernel = kernel_with(vec![settle_announcement(&[burn])], vec![]);

        assert!(payouts_to_keys(&kernel, &[key(1)]).is_empty());
    }

    #[test]
    fn malformed_settlement_is_ignored() {
        let burn = burn_to(&key(1), 1, 1);
        let output = payout_output(&burn);
        let mut truncated = settle_announcement(std::slice::from_ref(&burn));
        truncated.message.pop();
        let mut wrong_count = settle_announcement(std::slice::from_ref(&burn));
        wrong_count.message[SETTLE_HEADER_LEN - 1] = BFieldElement::new(2);
        let too_many =
            settle_announcement(&vec![burn.clone(); MAX_BURNS_PER_SETTLEMENT as usize + 1]);
        let short = Announcement::new(vec![BFieldElement::new(SETTLE_TAG); 3]);
        let mut wrong_tag = settle_announcement(&[burn]);
        wrong_tag.message[0] = BFieldElement::new(SETTLE_TAG + 1);

        for announcement in [truncated, wrong_count, too_many, short, wrong_tag] {
            let kernel = kernel_with(vec![announcement], vec![output]);
            assert!(payouts_to_keys(&kernel, &[key(1)]).is_empty());
        }
    }

    #[test]
    fn overflowing_payout_does_not_panic() {
        let mut burn = burn_to(&key(1), 1, 1);
        burn[11] = BFieldElement::new(1 << 63);
        let kernel = kernel_with(vec![settle_announcement(&[burn])], vec![]);

        assert!(payouts_to_keys(&kernel, &[key(1)]).is_empty());
    }

    #[test]
    fn duplicate_burns_dedup() {
        let burn = burn_to(&key(1), 1, 1);
        let kernel = kernel_with(
            vec![
                settle_announcement(&[burn.clone(), burn.clone()]),
                settle_announcement(std::slice::from_ref(&burn)),
            ],
            vec![payout_output(&burn)],
        );

        assert_eq!(1, payouts_to_keys(&kernel, &[key(1)]).len());
    }
}
