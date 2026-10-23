use std::net::IpAddr;
use std::path::PathBuf;

use libp2p::Multiaddr;

use super::source_limits::SourceLimitsConfig;
use crate::application::config::network::Network;

pub(crate) const DEFAULT_SUBDIRECTORY: &str = "network/";
pub(crate) const DEFAULT_IDENTITY_FILENAME: &str = "identity.key";
pub(crate) const DEFAULT_ADDRESS_BOOK_FILENAME: &str = "address-book.json";
pub(crate) const DEFAULT_BLACKLIST_FILENAME: &str = "blacklist.json";

#[derive(Debug, Clone)]
pub(crate) struct NetworkConfig {
    /// Which network we are on: Main / Testnet / Regtest / ...
    pub(super) network: Network,

    /// Subdirectory of the data directory where the network-specific data is
    /// stored.
    pub(super) subdirectory: Option<PathBuf>,

    identify_file: Option<PathBuf>,
    address_book_file: Option<PathBuf>,
    blacklist_file: Option<PathBuf>,

    /// IPs banned on the command line.
    banned_ips: Vec<IpAddr>,
    pub(super) sticky_peers: Vec<Multiaddr>,

    /// If set, the only IPs to connect with, in either direction
    /// (`--restrict-peers-to-list`). Peer discovery is then off.
    pub(super) peer_allow_list: Option<Vec<IpAddr>>,

    /// The max. number of peers to connect to.
    pub(super) max_num_peers: usize,

    /// Limits on inbound connections for related IPs.
    pub(super) source_limits: SourceLimitsConfig,

    external_addresses: Vec<Multiaddr>,

    /// Whether to offer relay reservations to peers behind NATs.
    pub(super) relay_server: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network: Network::default(),
            subdirectory: None,
            identify_file: None,
            address_book_file: None,
            blacklist_file: None,
            banned_ips: vec![],
            sticky_peers: vec![],
            peer_allow_list: None,
            max_num_peers: 10,
            source_limits: SourceLimitsConfig::default(),
            external_addresses: vec![],
            relay_server: true,
        }
    }
}

impl NetworkConfig {
    pub(crate) fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub(crate) fn with_subdirectory(mut self, path: PathBuf) -> Self {
        self.subdirectory = Some(path);
        self
    }

    pub(crate) fn with_max_num_peers(mut self, new_max: usize) -> Self {
        self.max_num_peers = new_max;
        self
    }

    pub(crate) fn with_source_limits(mut self, source_limits: SourceLimitsConfig) -> Self {
        self.source_limits = source_limits;
        self
    }

    pub(crate) fn with_cli_bans(mut self, banned_ips: Vec<IpAddr>) -> Self {
        self.banned_ips.extend(banned_ips);
        self
    }

    pub(crate) fn with_cli_peers(mut self, sticky_peers: Vec<Multiaddr>) -> Self {
        self.sticky_peers.extend(sticky_peers);
        self
    }

    /// Restrict connections to the given IPs, if any, and turn off peer
    /// discovery. `None` allows any IP.
    pub(crate) fn with_peer_allow_list(mut self, peer_allow_list: Option<Vec<IpAddr>>) -> Self {
        self.peer_allow_list = peer_allow_list;
        self
    }

    pub(crate) fn with_relay_server(mut self, enabled: bool) -> Self {
        self.relay_server = enabled;
        self
    }

    /// Overwrite the `external_addresses` field.
    pub(crate) fn with_external_addresses(mut self, external_addresses: Vec<Multiaddr>) -> Self {
        self.external_addresses = external_addresses;
        self
    }

    pub(crate) fn subdirectory(&self) -> PathBuf {
        self.subdirectory
            .clone()
            .unwrap_or_else(|| DEFAULT_SUBDIRECTORY.into())
    }

    pub(crate) fn identity_file(&self) -> PathBuf {
        self.subdirectory().join(
            self.identify_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_FILENAME)),
        )
    }

    pub(crate) fn address_book_file(&self) -> PathBuf {
        self.subdirectory().join(
            self.address_book_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_ADDRESS_BOOK_FILENAME)),
        )
    }

    pub(crate) fn blacklist_file(&self) -> PathBuf {
        self.subdirectory().join(
            self.blacklist_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_BLACKLIST_FILENAME)),
        )
    }

    pub(crate) fn banned_ips(&self) -> Vec<IpAddr> {
        self.banned_ips.clone()
    }

    pub(crate) fn external_addresses(&self) -> Vec<Multiaddr> {
        self.external_addresses.clone()
    }
}
