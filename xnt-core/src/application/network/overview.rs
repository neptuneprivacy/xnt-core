use std::fmt::Display;

use libp2p::autonat::NatStatus;
use libp2p::Multiaddr;
use libp2p::PeerId;
use serde::Deserialize;
use serde::Serialize;

use crate::application::network::reachability::ReachabilityState;
use crate::application::rpc::server::network_overview_data::NetworkOverviewData;

/// Shadow enum to avoid Serialize / Deserialize problems for [`NatStatus`].
#[derive(Serialize, Deserialize)]
#[serde(remote = "NatStatus")]
enum NatStatusDef {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "public")]
    Public(Multiaddr),
    #[serde(rename = "private")]
    Private,
}

/// Overview data for the libp2p network stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOverview {
    // Reachability
    #[serde(with = "NatStatusDef")]
    pub nat_status: NatStatus,
    pub reachability_state: ReachabilityState,
    pub external_addresses: Vec<Multiaddr>,

    // Connection Capacity
    pub connection_count: usize,
    pub connection_limit: usize,

    // Relay State
    pub num_active_relays: usize,

    // Persistent State
    pub peer_id: PeerId,
    pub address_book_size: usize,
    pub num_banned_peers: usize,
}

impl From<NetworkOverview> for NetworkOverviewData {
    fn from(o: NetworkOverview) -> Self {
        let nat_status = match &o.nat_status {
            NatStatus::Public(addr) => format!("public({addr})"),
            NatStatus::Private => "private".to_string(),
            NatStatus::Unknown => "unknown".to_string(),
        };
        NetworkOverviewData {
            nat_status,
            reachability_state: o.reachability_state.to_string(),
            external_addresses: o
                .external_addresses
                .iter()
                .map(ToString::to_string)
                .collect(),
            connection_count: o.connection_count,
            connection_limit: o.connection_limit,
            num_active_relays: o.num_active_relays,
            peer_id: o.peer_id.to_string(),
            address_book_size: o.address_book_size,
            num_banned_peers: o.num_banned_peers,
        }
    }
}

impl Display for NetworkOverview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        NetworkOverviewData::from(self.clone()).fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
mod arbitrary {
    use ::arbitrary::Arbitrary;
    use ::arbitrary::Result;
    use ::arbitrary::Unstructured;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use super::*;
    use crate::application::network::arbitrary::arb_multiaddr;
    use crate::application::network::arbitrary::arb_peer_id;

    impl<'a> Arbitrary<'a> for NetworkOverview {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
            let mut runner = TestRunner::deterministic();
            let peer_id = arb_peer_id().new_tree(&mut runner).unwrap().current();
            let reachability_state = ReachabilityState::arbitrary()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            let mut get_multiaddr = || arb_multiaddr().new_tree(&mut runner).unwrap().current();

            let connection_limit = u.int_in_range(10..=1000)?;
            let num_active_relays = u.int_in_range(0..=5)?;

            let address_book_size = u.int_in_range(0..=100)?;
            let num_banned_peers = u.int_in_range(0..=50)?;

            Ok(NetworkOverview {
                peer_id,
                nat_status: match u.int_in_range(0..=2)? {
                    0 => NatStatus::Public(get_multiaddr()),
                    1 => NatStatus::Private,
                    _ => NatStatus::Unknown,
                },
                external_addresses: (0..u.int_in_range(0..=4)?)
                    .map(|_| Ok(get_multiaddr()))
                    .collect::<Result<Vec<_>>>()?,

                connection_count: u.int_in_range(0..=connection_limit)?,
                connection_limit,
                num_active_relays,
                address_book_size,
                num_banned_peers,
                reachability_state,
            })
        }
    }
}

#[cfg(any(test, feature = "mock-rpc"))]
impl rand::distr::Distribution<NetworkOverview> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> NetworkOverview {
        use rand::RngExt;

        const SHA256_CODE: u64 = 0x12;
        let raw_hash = rng.random::<[u8; 32]>();
        let multihash = libp2p::multihash::Multihash::wrap(SHA256_CODE, &raw_hash)
            .expect("32 bytes is valid for SHA2-256");
        let peer_id = PeerId::from_multihash(multihash).expect("Valid multihash");
        let num_public_addresses = rng.random_range(0..5);
        let external_addresses: Vec<_> = (0..num_public_addresses)
            .map(|_| rng.random::<[u8; 4]>())
            .map(std::net::Ipv4Addr::from)
            .map(std::net::IpAddr::V4)
            .map(Multiaddr::from)
            .collect();
        let nat_status = match rng.random_range(0usize..3) {
            0 => NatStatus::Unknown,
            1 => NatStatus::Private,
            2 => {
                if !external_addresses.is_empty() {
                    NatStatus::Public(external_addresses[0].clone())
                } else {
                    NatStatus::Private
                }
            }
            _ => unreachable!(),
        };
        let reachability_state = rng.random::<ReachabilityState>();
        let connection_limit = rng.random_range(0usize..=10);
        let connection_count = rng.random_range(0..=connection_limit);

        let num_active_relays = rng.random_range(0usize..5);

        let address_book_size = rng.random_range(0usize..100);
        let num_banned_peers = rng.random_range(0usize..50);

        NetworkOverview {
            peer_id,
            nat_status,
            external_addresses,
            connection_count,
            connection_limit,
            num_active_relays,
            address_book_size,
            num_banned_peers,
            reachability_state,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::hint::black_box;

    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use rand::rng;
    use rand::RngExt;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn can_format_arbitrary_network_overview(
        #[strategy(arb::<NetworkOverview>())] overview: NetworkOverview,
    ) {
        let s = format!("{overview}"); // no crash
        black_box(s);
    }

    #[test]
    fn can_format_random_network_overview() {
        let mut rng = rng();
        let overview = rng.random::<NetworkOverview>();
        let s = format!("{overview}"); // no crash
        black_box(s);
    }

    #[proptest]
    fn rpc_data_carries_the_overview(
        #[strategy(arb::<NetworkOverview>())] overview: NetworkOverview,
    ) {
        let data = NetworkOverviewData::from(overview.clone());
        prop_assert_eq!(overview.peer_id.to_string(), data.peer_id.clone());
        prop_assert_eq!(
            overview.reachability_state.to_string(),
            data.reachability_state.clone()
        );
        prop_assert_eq!(
            overview
                .external_addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            data.external_addresses.clone()
        );
        prop_assert_eq!(overview.connection_count, data.connection_count);
        prop_assert_eq!(overview.connection_limit, data.connection_limit);
        prop_assert_eq!(overview.num_active_relays, data.num_active_relays);
        prop_assert_eq!(overview.address_book_size, data.address_book_size);
        prop_assert_eq!(overview.num_banned_peers, data.num_banned_peers);
        prop_assert_eq!(format!("{overview}"), format!("{data}"));
    }

    #[test]
    fn nat_status_is_rendered_without_libp2p_types() {
        let mut overview = rng().random::<NetworkOverview>();
        overview.nat_status = NatStatus::Private;
        assert_eq!(
            "private",
            NetworkOverviewData::from(overview.clone()).nat_status
        );

        overview.nat_status = NatStatus::Unknown;
        assert_eq!(
            "unknown",
            NetworkOverviewData::from(overview.clone()).nat_status
        );

        overview.nat_status =
            NatStatus::Public("/ip4/203.0.113.1/udp/9901/quic-v1".parse().unwrap());
        assert_eq!(
            "public(/ip4/203.0.113.1/udp/9901/quic-v1)",
            NetworkOverviewData::from(overview).nat_status
        );
    }

    #[test]
    fn network_overview_serde_round_trip() {
        let overview = rng().random::<NetworkOverview>();
        let json = serde_json::to_string(&overview).unwrap();
        let decoded: NetworkOverview = serde_json::from_str(&json).unwrap();
        assert_eq!(
            NetworkOverviewData::from(overview),
            NetworkOverviewData::from(decoded)
        );
    }
}
