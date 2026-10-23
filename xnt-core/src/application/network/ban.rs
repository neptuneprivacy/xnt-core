use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;

use super::save_json_atomically;
use crate::protocol::peer::STANDING_HALF_LIFE;

/// How long a ban applies for.
const BAN_DURATION: Duration = STANDING_HALF_LIFE;

/// Manages a persistent blacklist of IP addresses to enforce network-level
/// bans.
///
/// The [`BlackList`] serves as a gatekeeper for the
/// [`NetworkActor`](super::actor::NetworkActor), storing the [`IpAddr`] of
/// peers that have exceeded negative reputation thresholds.
///
/// Unlike a [`PeerId`](libp2p::PeerId) ban, an IP ban prevents malicious actors
/// from simply generating a new identity to bypass restrictions.
///
/// IP addresses are kept in their canonical form, so that a ban of an IPv4
/// address also applies to its IPv4-mapped IPv6 form, and the other way
/// around.
///
/// # Persistence
///
/// To ensure bans survive node restarts, the list is serialized to a JSON file
/// specified by the `filename` field. The network actor writes this file
/// whenever a ban is imposed or lifted, and the list is reloaded during the
/// initialization of the network stack.
///
/// # Example
///
/// ```ignore
/// let mut blacklist = BlackList::load_from_disk_or_new("bans.json")?;
/// if blacklist.is_banned(&remote_ip) {
///     return Err(ConnectionDenied::new("Blacklisted"));
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct BlackList {
    pub(crate) filename: PathBuf,
    pub(crate) list: HashMap<IpAddr, SystemTime>,

    /// Ephemeral bans are not persisted. They may correspond to bans specified
    /// as CLI arguments.
    pub(crate) ephemeral_bans: HashSet<IpAddr>,
}

impl BlackList {
    pub(crate) fn new(filename: PathBuf) -> Self {
        BlackList {
            filename,
            list: HashMap::new(),
            ephemeral_bans: HashSet::new(),
        }
    }

    pub(crate) fn with_ephemeral_bans(mut self, ephemeral_bans: Vec<IpAddr>) -> Self {
        self.ephemeral_bans = ephemeral_bans
            .into_iter()
            .map(|ip| ip.to_canonical())
            .collect();
        self
    }

    /// Insert the IP into the black list.
    pub(crate) fn ban(&mut self, ip_address: IpAddr) {
        let now = SystemTime::now();
        self.list.insert(ip_address.to_canonical(), now);
    }

    /// Remove the IP from the black list.
    ///
    /// # Return Value
    ///
    ///  - `true` if the IP address was on the black list.
    ///  - `false` otherwise.
    pub(crate) fn unban(&mut self, ip_address: &IpAddr) -> bool {
        self.list.remove(&ip_address.to_canonical()).is_some()
    }

    /// Determine whether the given IP is on the black list.
    ///
    /// A ban expires after [`BAN_DURATION`], so that a node sanctioned once, or
    /// sanctioned for behaviour it has since stopped, is not shut out of the
    /// network for the lifetime of the blacklist file. Bans given on the
    /// command line never expire.
    pub(crate) fn is_banned(&self, ip_address: &IpAddr) -> bool {
        let ip_address = ip_address.to_canonical();
        if self.ephemeral_bans.contains(&ip_address) {
            return true;
        }

        self.list
            .get(&ip_address)
            .is_some_and(|banned_at| !Self::is_expired(*banned_at))
    }

    /// Whether a ban imposed at the given time no longer applies.
    fn is_expired(banned_at: SystemTime) -> bool {
        banned_at.elapsed().is_ok_and(|age| age >= BAN_DURATION)
    }

    /// Drop bans that have expired.
    ///
    /// Keeps the persisted file from growing without bound.
    fn forget_expired_bans(&mut self) {
        self.list
            .retain(|_ip, banned_at| !Self::is_expired(*banned_at));
    }

    /// Write the current blacklist to disk.
    ///
    /// Uses JSON encoding. The file is replaced atomically; see
    /// [`save_json_atomically`].
    ///
    /// # Return Value
    ///
    ///  - `Ok(())` in case of success.
    ///  - `Err(_)` if JSON encoding failed or it file operations failed.
    pub(crate) fn save_to_disk(&self) -> anyhow::Result<()> {
        save_json_atomically(&self.filename, &self.list)
    }

    /// Read the blacklist from a file or returns a new one.
    ///
    /// The file is decoded using JSON.
    ///
    /// # Return Value
    ///
    ///  - `Ok(BlackList::new())` if the file does not exist.
    ///  - `Ok(black_list)` if the file does exist and reading and decoding
    ///    succeeded.
    ///  - `Err(_)` if the file does exist and either reading or decoding
    ///    failed.
    pub(crate) fn load_or_new<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::new(path.as_ref().to_path_buf()));
        }

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let stored_list: HashMap<IpAddr, SystemTime> = serde_json::from_reader(reader)?;

        // Keep the later of two bans of one address in different forms.
        let mut list = HashMap::new();
        for (ip, banned_at) in stored_list {
            list.entry(ip.to_canonical())
                .and_modify(|latest: &mut SystemTime| *latest = (*latest).max(banned_at))
                .or_insert(banned_at);
        }
        let mut black_list = BlackList {
            filename: path.as_ref().to_path_buf(),
            list,
            ephemeral_bans: HashSet::new(),
        };
        black_list.forget_expired_bans();

        Ok(black_list)
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::prelude::Strategy;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::application::network::arbitrary::arb_ip_addr;
    use crate::application::network::arbitrary::tests::arb_system_time;
    use crate::protocol::peer::NegativePeerSanction;
    use crate::protocol::peer::PeerStanding;

    fn black_list_strategy() -> impl Strategy<Value = BlackList> {
        let path_strategy = any::<String>().prop_map(|s| PathBuf::from(format!("{}.json", s)));
        let list_strategy =
            proptest::collection::hash_map(arb_ip_addr(), arb_system_time(), 0..100);
        let set_strategy = vec(arb_ip_addr(), 0..20);

        (path_strategy, list_strategy, set_strategy).prop_map(|(filename, list, set)| BlackList {
            filename,
            list,
            ephemeral_bans: set.into_iter().collect(),
        })
    }

    #[proptest]
    fn test_blacklist_round_trip(
        #[strategy(black_list_strategy())] mut original: BlackList,
        #[strategy(arb::<u64>())] file_id: u64,
    ) {
        // cross-platform temp directory
        let mut temp_path = std::env::temp_dir();

        // unique filename for this specific test run to avoid collisions
        let unique_name = format!("blacklist_test_{}.json", file_id);
        temp_path.push(unique_name);
        original.filename = temp_path.clone();

        original.forget_expired_bans();

        original.save_to_disk().expect("Failed to save to disk");

        let loaded = BlackList::load_or_new(&temp_path).expect("Failed to load from disk");

        // aAssert equality
        // Note: SystemTime precision can sometimes vary by a few nanoseconds on
        // certain filesystems/platforms after serialization. For most
        // use cases, comparing the debug string or checking seconds is safer,
        // but standard equality usually holds for JSON.
        assert_eq!(original.filename, loaded.filename);
        assert_eq!(original.list.len(), loaded.list.len());

        for (ip, time) in &original.list {
            prop_assert!(loaded.list.contains_key(ip));

            // Compare seconds since epoch to avoid minor precision issues
            let original_dur = time
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let loaded_dur = loaded
                .list
                .get(ip)
                .unwrap()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            prop_assert_eq!(original_dur, loaded_dur);

            prop_assert!(loaded.ephemeral_bans.is_empty());
        }

        // clean up
        let _ = std::fs::remove_file(temp_path);
    }

    /// A standing that was sanctioned to exactly the ban threshold, `ago` in
    /// the past.
    fn standing_at_threshold(tolerance: u16, ago: Duration) -> PeerStanding {
        let mut standing = PeerStanding::new(tolerance);
        standing.standing = -i32::from(tolerance);
        standing.latest_punishment = Some((
            NegativePeerSanction::DifferentGenesis,
            SystemTime::now() - ago,
        ));
        standing
    }

    // A tolerance of 1 is left out: halving a standing of -1 rounds toward
    // negative infinity and keeps it at -1, so that standing stays bad for
    // longer than one half-life.
    #[proptest]
    fn the_two_peer_admission_gates_expire_together(
        #[strategy(2u16..=u16::MAX)] tolerance: u16,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        // Ensure that the ban list of the libp2p protocol expires at the same
        // time as the negative sanction half life is applied.

        let margin = Duration::from_secs(60);
        let just_short = BAN_DURATION.checked_sub(margin).unwrap();
        let just_over = BAN_DURATION + margin;

        // Just before the deadline: both gates refuse.
        let mut before = BlackList::new(PathBuf::from("does-not-exist.json"));
        before.list.insert(ip, SystemTime::now() - just_short);
        let standing_before = standing_at_threshold(tolerance, just_short);

        prop_assert!(before.is_banned(&ip), "blacklist must still refuse");
        prop_assert!(standing_before.is_bad(), "standing must still be bad");

        // Just after: both gates admit.
        let mut after = BlackList::new(PathBuf::from("does-not-exist.json"));
        after.list.insert(ip, SystemTime::now() - just_over);
        let standing_after = standing_at_threshold(tolerance, just_over);

        prop_assert!(!after.is_banned(&ip), "blacklist must have expired");
        prop_assert!(!standing_after.is_bad(), "standing must no longer be bad");
    }

    #[proptest]
    fn ban_expires_after_the_ban_duration(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ban(ip);
        prop_assert!(black_list.is_banned(&ip));

        // Just short of the duration: still banned.
        let almost = SystemTime::now() - BAN_DURATION + Duration::from_secs(60);
        black_list.list.insert(ip, almost);
        prop_assert!(black_list.is_banned(&ip));

        // Past the duration: no longer banned.
        let expired = SystemTime::now() - BAN_DURATION - Duration::from_secs(60);
        black_list.list.insert(ip, expired);
        prop_assert!(!black_list.is_banned(&ip));
    }

    #[proptest]
    fn cli_bans_do_not_expire(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ephemeral_bans.insert(ip);
        black_list.list.insert(
            ip,
            SystemTime::now() - BAN_DURATION - Duration::from_secs(60),
        );

        prop_assert!(black_list.is_banned(&ip));
    }

    #[proptest]
    fn forgetting_expired_bans_keeps_the_live_ones(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] live: IpAddr,
        #[strategy(arb_ip_addr())] expired: IpAddr,
    ) {
        black_list.list.insert(live, SystemTime::now());
        black_list.list.insert(
            expired,
            SystemTime::now() - BAN_DURATION - Duration::from_secs(60),
        );

        black_list.forget_expired_bans();

        prop_assert!(black_list.list.contains_key(&live));
        prop_assert!(!black_list.list.contains_key(&expired));
    }

    #[proptest]
    fn banned_peer_is_banned(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ban(ip);

        prop_assert!(black_list.is_banned(&ip));
    }

    #[proptest]
    fn cli_peer_is_banned(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ephemeral_bans.insert(ip);

        prop_assert!(black_list.is_banned(&ip));
    }

    #[proptest]
    fn new_peer_is_not_banned(
        #[strategy(black_list_strategy())] black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        prop_assert!(!black_list.is_banned(&ip));
    }

    /// An IPv4 address, and its IPv4-mapped IPv6 form.
    fn ipv4_in_both_forms() -> (IpAddr, IpAddr) {
        let ipv4 = std::net::Ipv4Addr::new(198, 51, 100, 7);
        (IpAddr::V4(ipv4), IpAddr::V6(ipv4.to_ipv6_mapped()))
    }

    #[test]
    fn a_ban_applies_to_both_forms_of_an_ipv4_address() {
        let (ipv4, mapped) = ipv4_in_both_forms();
        for (banned, other_form) in [(ipv4, mapped), (mapped, ipv4)] {
            let mut black_list = BlackList::new(PathBuf::from("does-not-exist.json"));
            black_list.ban(banned);
            assert!(black_list.is_banned(&other_form));
            assert!(black_list.unban(&other_form));
            assert!(!black_list.is_banned(&banned));

            let cli_bans = BlackList::new(PathBuf::from("does-not-exist.json"))
                .with_ephemeral_bans(vec![banned]);
            assert!(cli_bans.is_banned(&other_form));
        }
    }

    #[test]
    fn bans_stored_in_the_ipv4_mapped_form_are_loaded_in_canonical_form() {
        let (ipv4, mapped) = ipv4_in_both_forms();
        let path = std::env::temp_dir().join(format!(
            "blacklist_mapped_{}_{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let stored = HashMap::from([(mapped, SystemTime::now())]);
        std::fs::write(&path, serde_json::to_string(&stored).unwrap()).unwrap();

        let black_list = BlackList::load_or_new(&path).unwrap();
        assert!(black_list.list.contains_key(&ipv4));
        assert!(black_list.is_banned(&ipv4));
        assert!(black_list.is_banned(&mapped));

        let _ = std::fs::remove_file(&path);
    }

    #[proptest]
    fn unbanned_peer_is_not_banned(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ban(ip);

        black_list.unban(&ip);

        prop_assert!(!black_list.is_banned(&ip));
    }
}
