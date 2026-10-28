//! Bridge lock announcement format.
//!
//! When a user locks XNT into the bridge pool (XNT → Leviathan direction),
//! a lock announcement is included in the transaction kernel. Relayers
//! pick up these announcements and submit mint claims on the Leviathan side.
//!
//! ## Announcement Format
//!
//! ```text
//! [TAG, account_id0..1, amount_lo, amount_hi,
//!  utxo_commitment0..4, sender_randomness0..4, receiver_preimage0..4]
//! ```
//!
//! - TAG: well-known identifier
//! - account_id0..1: Leviathan account to receive minted WXNT (2 elements)
//! - amount_lo, amount_hi: XNT amount locked into pool (= WXNT to mint) (2 elements)
//! - utxo_commitment0..4: canonical commitment of the pool UTXO (5 elements)
//! - sender_randomness0..4: sender randomness for the pool UTXO (5 elements)
//! - receiver_preimage0..4: receiver preimage for the pool UTXO (5 elements)
//!
//! `sender_randomness` and `receiver_preimage` are published so that all nodes
//! can later create removal records for pool UTXOs during withdrawals. Pool
//! UTXOs have no privacy requirements (protocol-owned, unspendable).
//!
//! `receiver_preimage` must be [`deposit_receiver_preimage`] of the announced account.

use bech32::FromBase32;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// Well-known tag identifying a Leviathan bridge lock announcement.
/// "LEVBR_LK" as u64.
pub const BRIDGE_DEPOSIT_TAG: u64 = 0x4C45_5642_525F_4C4B;

/// Whether an announcement is a deposit (lock): non-empty with `message[0] == BRIDGE_DEPOSIT_TAG`.
/// Consensus requires a BDAV proof for any transaction carrying one. The Leviathan faucet relies on
/// this: it must only mint announcements this function classifies as deposits.
pub fn is_deposit_tagged(announcement: &Announcement) -> bool {
    announcement.message.first() == Some(&BFieldElement::new(BRIDGE_DEPOSIT_TAG))
}

/// Domain of [`deposit_receiver_preimage`]. "LEVBR_RP" as u64.
pub const DEPOSIT_RECEIVER_DOMAIN: u64 = 0x4C45_5642_525F_5250;

/// The receiver preimage of a deposit's pool UTXO, salted with the deposit's own sender randomness.
pub fn deposit_receiver_preimage(
    account_id: [BFieldElement; 2],
    sender_randomness: Digest,
) -> Digest {
    let mut elements = vec![BFieldElement::new(DEPOSIT_RECEIVER_DOMAIN)];
    elements.extend(account_id);
    elements.extend(sender_randomness.values());
    Tip5::hash_varlen(&elements)
}

/// Minimum XNT amount for a bridge deposit (1 coin), checked by BDAV and by the parser below.
/// Must stay above the faucet's per-lock WXNT mint fee (default 0.0005 WXNT), or the lock can
/// never be minted. It cannot follow later fee changes on Leviathan.
pub const MIN_BRIDGE_AMOUNT: NativeCurrencyAmount = NativeCurrencyAmount::coins(1);

/// Total number of BFieldElements in a bridge lock announcement.
/// 1 tag + 2 account + 2 amount + 5 utxo_commitment + 5 sender_randomness + 5 receiver_preimage
pub const BRIDGE_DEPOSIT_ANNOUNCEMENT_LEN: usize = 20;

/// Parsed bridge lock announcement data.
///
/// Describes XNT locked into the bridge pool, destined for WXNT minting on Leviathan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeDepositData {
    /// Leviathan account that should receive minted WXNT.
    /// Stored as [suffix, prefix] to match Leviathan's `AccountId::try_from_elements(suffix, prefix)`.
    pub account_id: [BFieldElement; 2],
    /// XNT amount locked into pool (= WXNT to mint).
    pub amount: NativeCurrencyAmount,
    /// Canonical commitment of the pool UTXO (5 BFieldElements).
    /// Not unique: identical outputs share it.
    pub utxo_commitment: [BFieldElement; 5],
    /// Sender randomness used to create the pool UTXO's addition record.
    /// Published so nodes can create removal records during withdrawals.
    pub sender_randomness: [BFieldElement; 5],
    /// Receiver preimage used to create the pool UTXO's addition record.
    /// Published so nodes can create removal records during withdrawals.
    pub receiver_preimage: [BFieldElement; 5],
}

impl BridgeDepositData {
    pub fn binds_account(&self) -> bool {
        self.receiver_preimage
            == deposit_receiver_preimage(self.account_id, Digest::new(self.sender_randomness))
                .values()
    }

    /// Encode as an XNT transaction announcement.
    pub fn to_announcement(&self) -> Announcement {
        let mut message = Vec::with_capacity(BRIDGE_DEPOSIT_ANNOUNCEMENT_LEN);
        message.push(BFieldElement::new(BRIDGE_DEPOSIT_TAG));
        message.extend_from_slice(&self.account_id);
        let nau = self.amount.to_nau() as u128;
        message.push(BFieldElement::new(nau as u64));
        message.push(BFieldElement::new((nau >> 64) as u64));
        message.extend_from_slice(&self.utxo_commitment);
        message.extend_from_slice(&self.sender_randomness);
        message.extend_from_slice(&self.receiver_preimage);
        Announcement::new(message)
    }

    /// Try to parse from an announcement.
    pub fn from_announcement(announcement: &Announcement) -> Option<Self> {
        let msg = &announcement.message;
        if msg.len() != BRIDGE_DEPOSIT_ANNOUNCEMENT_LEN {
            return None;
        }
        if msg[0] != BFieldElement::new(BRIDGE_DEPOSIT_TAG) {
            return None;
        }
        let amount_lo = u128::from(msg[3].value());
        let amount_hi = u128::from(msg[4].value());
        let amount = NativeCurrencyAmount::from_nau((amount_lo | (amount_hi << 64)) as i128);
        if amount < MIN_BRIDGE_AMOUNT {
            return None;
        }

        Some(Self {
            account_id: [msg[1], msg[2]],
            amount,
            utxo_commitment: [msg[5], msg[6], msg[7], msg[8], msg[9]],
            sender_randomness: [msg[10], msg[11], msg[12], msg[13], msg[14]],
            receiver_preimage: [msg[15], msg[16], msg[17], msg[18], msg[19]],
        })
    }

    /// Find all bridge lock announcements in a list.
    pub fn find_all_in_announcements(announcements: &[Announcement]) -> Vec<Self> {
        announcements
            .iter()
            .filter_map(Self::from_announcement)
            .collect()
    }
}

/// Leviathan v1 account id (30 hex, optional `0x`) as `[suffix, prefix]`, validated like `AccountIdV1`.
pub fn parse_leviathan_account_id(hex: &str) -> anyhow::Result<[u64; 2]> {
    let hex = hex.trim().trim_start_matches("0x");
    anyhow::ensure!(
        hex.len() == 30 && hex.chars().all(|c| c.is_ascii_hexdigit()),
        "Leviathan account id must be 30 hex chars, got {hex:?}"
    );
    let prefix = u64::from_str_radix(&hex[..16], 16)?;
    let suffix = u64::from_str_radix(&hex[16..], 16)? << 8;
    anyhow::ensure!(
        prefix < BFieldElement::P,
        "account id prefix is not a field element"
    );
    anyhow::ensure!(
        prefix & 0xf == 1,
        "account id version (prefix low nibble) must be 1"
    );
    anyhow::ensure!(
        suffix >> 63 == 0,
        "account id suffix most significant bit must be 0"
    );
    Ok([suffix, prefix])
}

/// `AddressType::AccountId` in a Leviathan `Address`, bech32m over `[232, id(15)]`.
const LEVIATHAN_ADDRESS_ACCOUNT_ID_TYPE: u8 = 232;

/// The Leviathan address prefixes (HRPs) bridging from each XNT network may pay to.
fn leviathan_address_hrps(network: Network) -> &'static [&'static str] {
    match network {
        Network::Main => &["mm"],
        Network::Testnet(_) | Network::TestnetMock => &["mtst"],
        Network::RegTest => &["mdev", "mtst"],
    }
}

/// A Leviathan account id, `[suffix, prefix]`, from an address of `network`'s Leviathan network or 30 hex
/// chars (any network); a `miden:` prefix and `_` routing parameters are allowed.
pub fn parse_leviathan_address(address: &str, network: Network) -> anyhow::Result<[u64; 2]> {
    let address = address.trim();
    let address = address.strip_prefix("miden:").unwrap_or(address);
    let hex = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address);
    if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return parse_leviathan_account_id(hex);
    }

    anyhow::ensure!(
        !address.ends_with('_'),
        "Leviathan address ends with a routing separator"
    );
    let id = address.split_once('_').map_or(address, |(id, _)| id);
    let (hrp, data, variant) = bech32::decode(id)?;
    anyhow::ensure!(
        leviathan_address_hrps(network).contains(&hrp.as_str()),
        "a {hrp} Leviathan address cannot receive a bridge deposit from XNT {network}"
    );
    anyhow::ensure!(
        variant == bech32::Variant::Bech32m,
        "Leviathan addresses are bech32m"
    );
    let bytes = Vec::<u8>::from_base32(&data)?;
    let Some((&LEVIATHAN_ADDRESS_ACCOUNT_ID_TYPE, id_bytes)) = bytes.split_first() else {
        anyhow::bail!("not a Leviathan account id address");
    };
    anyhow::ensure!(
        id_bytes.len() == 15,
        "Leviathan account id must be 15 bytes, got {}",
        id_bytes.len()
    );
    parse_leviathan_account_id(&hex::encode(id_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

    fn nau(v: i128) -> NativeCurrencyAmount {
        NativeCurrencyAmount::from_nau(v)
    }

    /// A large base amount above MIN_BRIDGE_AMOUNT with non-zero hi word
    /// to exercise lo/hi encoding.  coins(1) = 10^30 nau; we use 10^31.
    const BIG: i128 = 10_000_000_000_000_000_000_000_000_000_000i128;

    #[test]
    fn bridge_deposit_announcement_roundtrip() {
        let data = BridgeDepositData {
            account_id: [BFieldElement::new(10), BFieldElement::new(20)],
            amount: nau(BIG),

            utxo_commitment: [
                BFieldElement::new(100),
                BFieldElement::new(200),
                BFieldElement::new(300),
                BFieldElement::new(400),
                BFieldElement::new(500),
            ],
            sender_randomness: [BFieldElement::new(0); 5],
            receiver_preimage: [BFieldElement::new(0); 5],
        };

        let announcement = data.to_announcement();
        let parsed = BridgeDepositData::from_announcement(&announcement).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn receiver_preimage_binds_the_account_and_the_randomness() {
        let account = [BFieldElement::new(10), BFieldElement::new(20)];
        let sender_randomness = Digest::new([BFieldElement::new(7); 5]);
        let honest = BridgeDepositData {
            account_id: account,
            amount: MIN_BRIDGE_AMOUNT,
            utxo_commitment: [BFieldElement::new(1); 5],
            sender_randomness: sender_randomness.values(),
            receiver_preimage: deposit_receiver_preimage(account, sender_randomness).values(),
        };
        assert!(honest.binds_account());

        let copy_for_another_account = BridgeDepositData {
            account_id: [BFieldElement::new(11), BFieldElement::new(20)],
            ..honest
        };
        assert!(!copy_for_another_account.binds_account());

        let unbound = BridgeDepositData {
            receiver_preimage: [BFieldElement::new(0); 5],
            ..honest
        };
        assert!(!unbound.binds_account());

        assert_ne!(
            deposit_receiver_preimage(account, sender_randomness),
            deposit_receiver_preimage(account, Digest::new([BFieldElement::new(8); 5]))
        );
    }

    /// Wallets outside this repo must derive the same preimage.
    #[test]
    fn receiver_preimage_derivation_is_pinned() {
        let preimage = deposit_receiver_preimage(
            [BFieldElement::new(10), BFieldElement::new(20)],
            Digest::new([BFieldElement::new(7); 5]),
        );
        assert_eq!(
            "4db6bac78b8882d7854bf9b4857a34adc6839e3fd4b95dd7fab703c27de1b3734f68e32f7e428624",
            preimage.to_hex()
        );
    }

    #[test]
    fn bridge_deposit_announcement_rejects_wrong_tag() {
        let announcement = Announcement::new(vec![
            BFieldElement::new(999);
            BRIDGE_DEPOSIT_ANNOUNCEMENT_LEN
        ]);
        assert!(BridgeDepositData::from_announcement(&announcement).is_none());
    }

    #[test]
    fn bridge_deposit_announcement_rejects_wrong_length() {
        let mut msg = vec![BFieldElement::new(BRIDGE_DEPOSIT_TAG)];
        msg.extend(vec![BFieldElement::new(1); 2]); // account
        msg.push(BFieldElement::new(100)); // amount lo
        msg.push(BFieldElement::new(0)); // amount hi
        msg.extend(vec![BFieldElement::new(99); 5]); // utxo_commitment
        msg.extend(vec![BFieldElement::new(0); 5]); // sender_randomness
                                                    // missing receiver_preimage - only 15 elements instead of 20
        let announcement = Announcement::new(msg);
        assert!(BridgeDepositData::from_announcement(&announcement).is_none());
    }

    #[test]
    fn bridge_deposit_announcement_rejects_zero_amount() {
        let mut msg = vec![BFieldElement::new(BRIDGE_DEPOSIT_TAG)];
        msg.extend(vec![BFieldElement::new(1); 2]); // account
        msg.push(BFieldElement::new(0)); // zero amount lo
        msg.push(BFieldElement::new(0)); // zero amount hi
        msg.extend(vec![BFieldElement::new(99); 5]); // utxo_commitment
        msg.extend(vec![BFieldElement::new(0); 5]); // sender_randomness
        msg.extend(vec![BFieldElement::new(0); 5]); // receiver_preimage
        let announcement = Announcement::new(msg);
        assert!(BridgeDepositData::from_announcement(&announcement).is_none());
    }

    #[test]
    fn find_all_locks() {
        let lock1 = BridgeDepositData {
            account_id: [BFieldElement::new(1); 2],
            amount: nau(BIG + 100),
            utxo_commitment: [BFieldElement::new(11); 5],
            sender_randomness: [BFieldElement::new(0); 5],
            receiver_preimage: [BFieldElement::new(0); 5],
        };
        let lock2 = BridgeDepositData {
            account_id: [BFieldElement::new(3); 2],
            amount: nau(BIG + 200),
            utxo_commitment: [BFieldElement::new(22); 5],
            sender_randomness: [BFieldElement::new(0); 5],
            receiver_preimage: [BFieldElement::new(0); 5],
        };
        let unrelated = Announcement::new(vec![BFieldElement::new(42); 5]);

        let announcements = vec![lock1.to_announcement(), unrelated, lock2.to_announcement()];

        let locks = BridgeDepositData::find_all_in_announcements(&announcements);
        assert_eq!(locks.len(), 2);
        assert_eq!(locks[0], lock1);
        assert_eq!(locks[1], lock2);
    }

    /// Verify that a correctly constructed lock announcement has a
    /// utxo_commitment that matches the recomputed commitment using
    /// `bridge_lock_script()`.
    #[test]
    fn commitment_matches_recomputed_pool_utxo() {
        use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::util_types::mutator_set::commit;
        use tasm_lib::prelude::Digest;
        use tasm_lib::prelude::Tip5;

        let lock_script_hash = bridge_lock_script().hash();
        let sender_randomness = Digest::new([
            BFieldElement::new(111),
            BFieldElement::new(222),
            BFieldElement::new(333),
            BFieldElement::new(444),
            BFieldElement::new(555),
        ]);
        let receiver_preimage = Digest::default();
        let receiver_digest = receiver_preimage.hash();

        let amount = nau(BIG);
        let native_coins = amount.to_native_coins();
        let utxo = Utxo::new(lock_script_hash, native_coins);
        let item = Tip5::hash(&utxo);
        let expected = commit(item, sender_randomness, receiver_digest);

        // Build a lock announcement with the correct utxo_commitment.
        let lock = BridgeDepositData {
            account_id: [BFieldElement::new(1); 2],
            amount,
            utxo_commitment: expected.canonical_commitment.values(),
            sender_randomness: sender_randomness.values(),
            receiver_preimage: receiver_preimage.values(),
        };

        // Recompute - must match.
        let recomputed_coins = lock.amount.to_native_coins();
        let recomputed_utxo = Utxo::new(lock_script_hash, recomputed_coins);
        let recomputed_item = Tip5::hash(&recomputed_utxo);
        let recomputed_rd = Digest::new(lock.receiver_preimage).hash();
        let recomputed_commitment = commit(
            recomputed_item,
            Digest::new(lock.sender_randomness),
            recomputed_rd,
        );

        assert_eq!(
            Digest::new(lock.utxo_commitment),
            recomputed_commitment.canonical_commitment,
            "Honest lock announcement must match recomputed commitment"
        );
    }

    /// A lock announcement with a utxo_commitment computed from a
    /// different lock script must NOT match the recomputed commitment.
    #[test]
    fn fake_lock_script_commitment_rejected() {
        use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::util_types::mutator_set::commit;
        use tasm_lib::prelude::Digest;
        use tasm_lib::prelude::Tip5;

        let sender_randomness = Digest::new([BFieldElement::new(42); 5]);
        let receiver_preimage = Digest::default();
        let receiver_digest = receiver_preimage.hash();

        let amount = nau(BIG + 500);

        // Attacker uses a different lock script (their own address).
        let fake_lock_script_hash = Digest::new([BFieldElement::new(999); 5]);
        let fake_utxo = Utxo::new(fake_lock_script_hash, amount.to_native_coins());
        let fake_item = Tip5::hash(&fake_utxo);
        let fake_commitment = commit(fake_item, sender_randomness, receiver_digest);

        // Build announcement with fake commitment.
        let lock = BridgeDepositData {
            account_id: [BFieldElement::new(1); 2],
            amount,
            utxo_commitment: fake_commitment.canonical_commitment.values(),
            sender_randomness: sender_randomness.values(),
            receiver_preimage: receiver_preimage.values(),
        };

        // Recompute using the REAL bridge lock script.
        let real_lock_script_hash = bridge_lock_script().hash();
        let recomputed_utxo = Utxo::new(real_lock_script_hash, lock.amount.to_native_coins());
        let recomputed_item = Tip5::hash(&recomputed_utxo);
        let recomputed_rd = Digest::new(lock.receiver_preimage).hash();
        let recomputed_commitment = commit(
            recomputed_item,
            Digest::new(lock.sender_randomness),
            recomputed_rd,
        );

        assert_ne!(
            Digest::new(lock.utxo_commitment),
            recomputed_commitment.canonical_commitment,
            "Fake lock script must produce a different commitment"
        );
    }

    /// Attacker announces amount=5 but creates pool UTXO with amount=3.
    /// The recomputed commitment (using announced amount) won't match the
    /// real UTXO, so validation rejects it.
    #[test]
    fn mismatched_amount_commitment_rejected() {
        use crate::protocol::consensus::bridge::lock_script::bridge_lock_script;
        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::util_types::mutator_set::commit;
        use tasm_lib::prelude::Digest;
        use tasm_lib::prelude::Tip5;

        let lock_script_hash = bridge_lock_script().hash();
        let sender_randomness = Digest::new([BFieldElement::new(77); 5]);
        let receiver_preimage = Digest::default();
        let receiver_digest = receiver_preimage.hash();

        // Real UTXO has amount=BIG+3.
        let real_amount = nau(BIG + 3);
        let real_utxo = Utxo::new(lock_script_hash, real_amount.to_native_coins());
        let real_item = Tip5::hash(&real_utxo);
        let real_commitment = commit(real_item, sender_randomness, receiver_digest);

        // Attacker announces amount=BIG+5 but uses the UTXO commitment from
        // the real UTXO (amount=BIG+3).
        let lock = BridgeDepositData {
            account_id: [BFieldElement::new(1); 2],
            amount: nau(BIG + 5), // LIES about amount
            utxo_commitment: real_commitment.canonical_commitment.values(),
            sender_randomness: sender_randomness.values(),
            receiver_preimage: receiver_preimage.values(),
        };

        // Validator recomputes using announced amount (BIG+5).
        let recomputed_utxo = Utxo::new(lock_script_hash, lock.amount.to_native_coins());
        let recomputed_item = Tip5::hash(&recomputed_utxo);
        let recomputed_rd = Digest::new(lock.receiver_preimage).hash();
        let recomputed_commitment = commit(
            recomputed_item,
            Digest::new(lock.sender_randomness),
            recomputed_rd,
        );

        // Announced commitment (from amount=3 UTXO) != recomputed (amount=5).
        assert_ne!(
            Digest::new(lock.utxo_commitment),
            recomputed_commitment.canonical_commitment,
            "Mismatched amount must produce different commitment"
        );
    }

    #[test]
    fn parses_leviathan_v1_account_id_as_suffix_prefix() {
        let [suffix, prefix] =
            parse_leviathan_account_id("0x1872a5b34229040164a19591e372ed").unwrap();
        assert_eq!(prefix, 0x1872_a5b3_4229_0401);
        assert_eq!(suffix, 0x64a1_9591_e372_ed00);
    }

    #[test]
    fn rejects_invalid_leviathan_account_ids() {
        for bad in [
            "1872a5b34229040164a19591e372",     // too short
            "1872a5b34229040164a19591e372ed00", // 32 chars
            "1872a5b34229040064a19591e372ed",   // version 0
            "1872a5b34229040184a19591e372ed",   // suffix msb set
            "ffffffffffffffff64a19591e372ed",   // prefix not a field element
            "1872a5b3422904016za19591e372ed",   // not hex
        ] {
            assert!(
                parse_leviathan_account_id(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn leviathan_addresses_and_hex_ids_parse_to_the_same_account() {
        let id = [0x7db0_664f_500c_4c00, 0x6942_9324_3acf_dec1];
        let testnet = Network::Testnet(0);
        for address in [
            "694293243acfdec17db0664f500c4c",
            "0x694293243ACFDEC17DB0664F500C4C",
            "mtst1ap559yey8t8aastakpny75qvfs9t28tl",
            "miden:mtst1ap559yey8t8aastakpny75qvfs9t28tl",
            "miden:0x694293243acfdec17db0664f500c4c",
            " MTST1AP559YEY8T8AASTAKPNY75QVFS9T28TL ",
            "mtst1ap559yey8t8aastakpny75qvfs9t28tl_qruqqypuyph",
        ] {
            assert_eq!(
                parse_leviathan_address(address, testnet).unwrap(),
                id,
                "{address}"
            );
        }
        assert_eq!(
            parse_leviathan_address("mtst1armmy3cjrhzahygtmg9hu0zgcyfpau5k", testnet).unwrap(),
            [0x0bda_0b7e_3c48_c100, 0xf7b2_4712_1dc5_db91]
        );
    }

    #[test]
    fn each_network_accepts_only_its_leviathan_addresses_but_any_hex() {
        let id = [0x7db0_664f_500c_4c00, 0x6942_9324_3acf_dec1];
        let mainnet = "mm1ap559yey8t8aastakpny75qvfsjd3ezw";
        let testnet = "mtst1ap559yey8t8aastakpny75qvfs9t28tl";
        let devnet = "mdev1ap559yey8t8aastakpny75qvfsapehjn";
        let hex = "694293243acfdec17db0664f500c4c";
        for (network, accepted, refused) in [
            (Network::Main, vec![mainnet, hex], vec![testnet, devnet]),
            (
                Network::Testnet(0),
                vec![testnet, hex],
                vec![mainnet, devnet],
            ),
            (
                Network::TestnetMock,
                vec![testnet, hex],
                vec![mainnet, devnet],
            ),
            (Network::RegTest, vec![devnet, testnet, hex], vec![mainnet]),
        ] {
            for address in accepted {
                assert_eq!(
                    parse_leviathan_address(address, network).unwrap(),
                    id,
                    "{network} {address}"
                );
            }
            for address in refused {
                assert!(
                    parse_leviathan_address(address, network).is_err(),
                    "{network} {address}"
                );
            }
        }
    }

    #[test]
    fn malformed_or_pre_v1_leviathan_addresses_are_refused() {
        for address in [
            // a pre-0.17 (version 0) id, from leviathan-protocol's agglayer spec
            "mtst1azcw08rget79fqp8ymr0zqkv5v5lj466",
            // bech32, not bech32m
            "mtst1ap559yey8t8aastakpny75qvfssh6twa",
            // address type 0
            "mtst1qp559yey8t8aastakpny75qvfst9rs30",
            // 14 id bytes
            "mtst1ap559yey8t8aastakpny75qvn2mtmk",
            // bad checksum
            "mtst1ap559yey8t8aastakpny75qvfs9t28tm",
            "mtst1ap559yey8t8aastakpny75qvfs9t28tl_",
            "mtst1AP559yey8t8aastakpny75qvfs9t28tl",
        ] {
            assert!(
                parse_leviathan_address(address, Network::Testnet(0)).is_err(),
                "{address}"
            );
        }
        let short_hex =
            parse_leviathan_address("0x694293243acfdec17db0664f500c4", Network::Testnet(0))
                .unwrap_err();
        assert!(short_hex.to_string().contains("30 hex"), "{short_hex}");
    }
}
