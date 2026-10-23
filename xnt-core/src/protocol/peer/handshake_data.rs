use std::time::SystemTime;

use arraystring::typenum::U255;
use arraystring::typenum::U30;
use arraystring::ArrayString;
use serde::Deserialize;
use serde::Serialize;

use crate::application::config::network::Network;
use crate::protocol::consensus::block::block_header::BlockHeader;

pub(crate) type VersionString = ArrayString<U30>;
pub(crate) type ExtraDataString = ArrayString<U255>;

/// Datastruct defining the handshake peers exchange when establishing a new
/// connection.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct HandshakeData {
    pub tip_header: BlockHeader,
    pub listen_port: Option<u16>,
    pub network: Network,
    pub instance_id: u128,
    pub version: VersionString,
    pub is_archival_node: bool,

    /// Indicates whether node acts as a bootstrapping node in a network
    /// context.
    pub is_bootstrapper_node: bool,

    /// Client's timestamp when the handshake was generated. Can be used to
    /// compare own timestamp to peer's or to a list of peers.
    pub timestamp: SystemTime,

    /// Use this field to add extra data in a backwards compatible manner. An
    /// encoding should be selected for this. Currently unused.
    pub extra_data: ExtraDataString,
}

impl HandshakeData {
    /// The first version that knows the link-transaction peer messages. Since
    /// a peer cannot decode a message it does not know, and is entitled to
    /// sanction one it cannot decode, earlier versions must not be sent any.
    const FIRST_VERSION_WITH_LINK_TRANSACTIONS: semver::Version = semver::Version::new(0, 3, 0);

    /// Whether the peer that sent this handshake knows the link-transaction
    /// peer messages.
    pub(crate) fn supports_link_transactions(&self) -> bool {
        semver::Version::parse(self.version.as_str())
            .is_ok_and(|version| version >= Self::FIRST_VERSION_WITH_LINK_TRANSACTIONS)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::tests::shared::globalstate::get_dummy_handshake_data_for_genesis;

    #[test]
    fn link_transactions_are_known_from_version_0_3_0() {
        let mut handshake_data = get_dummy_handshake_data_for_genesis(Network::Main);
        for (version, supported) in [
            ("0.2.7", false),
            ("0.3.0-rc.1", false),
            ("0.3.0", true),
            ("0.3.1", true),
            ("1.0.0", true),
            ("not a version", false),
        ] {
            handshake_data.version = VersionString::try_from_str(version).unwrap();
            assert_eq!(
                supported,
                handshake_data.supports_link_transactions(),
                "version {version}"
            );
        }
    }
}
