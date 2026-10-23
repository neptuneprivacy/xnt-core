use std::fmt;
use std::str::FromStr;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::protocol::consensus::block::difficulty_control::Difficulty;
use crate::protocol::consensus::bridge::authority::BridgeAuthoritySet;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

/// Dev bridge authority key for test networks: the SEC1-compressed secp256k1
/// public key for secret scalar 1 (i.e. the generator point). The signer holds
/// scalar 1; the guard test `dev_authority_pubkey_is_generator` pins this.
/// Hex: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
const DEV_BRIDGE_AUTHORITY_PUBKEY: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

/// Main net bridge authority key (SEC1-compressed secp256k1).
/// Hex: 03e3e2534597374254bc9ba0f4bce775b1e354e7fe61b3222c4df0ef1baf9156a6
const MAIN_BRIDGE_AUTHORITY_PUBKEY: [u8; 33] = [
    0x03, 0xE3, 0xE2, 0x53, 0x45, 0x97, 0x37, 0x42, 0x54, 0xBC, 0x9B, 0xA0, 0xF4, 0xBC, 0xE7, 0x75,
    0xB1, 0xE3, 0x54, 0xE7, 0xFE, 0x61, 0xB3, 0x22, 0x2C, 0x4D, 0xF0, 0xEF, 0x1B, 0xAF, 0x91, 0x56,
    0xA6,
];

#[derive(
    Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default, strum::EnumIs, GetSize,
)]
#[non_exhaustive]
pub enum Network {
    /// Main net. Feature-complete. Fixed launch date.
    #[default]
    Main,

    /// Public test network that utilizes mock proofs and difficulty resets so
    /// that mining is possible without high-end hardware.  Intended for staging
    /// of release candidates prior to release and for the community to try out
    /// release candidates and report issues.
    TestnetMock,

    /// Network for individual unit and integration tests. The timestamp for the
    /// RegTest genesis block is set to now, rounded down to the first block of
    /// seven days. As a result, there is a small probability that tests fail
    /// because they generate the genesis block twice on two opposite sides of a
    /// round timestamp. You probably shouldn't use `RegTest` for unit tests, as
    /// this will invalidate the stored proofs when the rounded timestamp
    /// changes.
    RegTest,

    /// Feature-complete (or as feature-complete as possible) test network separate
    /// from whichever network is currently running. For integration tests involving
    /// multiple nodes over a network.
    Testnet(u8),
}

impl Network {
    pub fn id(&self) -> u32 {
        match self {
            Network::Main => 0u32,
            Network::TestnetMock => 1u32,
            Network::RegTest => 2u32,
            Network::Testnet(i) => 3u32 + u32::from(*i),
        }
    }

    pub fn launch_date(&self) -> Timestamp {
        // 28 November 2025 00:00:00 UTC
        Timestamp(BFieldElement::new(1764288000000))
    }

    /// indicates if the network uses mock proofs
    ///
    /// mock proofs enable transactions and blocks to be created quickly but
    /// must only be used for testing purposes.
    pub fn use_mock_proof(&self) -> bool {
        matches!(self, Self::RegTest | Self::TestnetMock)
    }

    /// Indicates if network allows for mocked PoW
    pub(crate) fn allows_mock_pow(self) -> bool {
        matches!(self, Network::RegTest)
    }

    /// indicates max duration between blocks before difficulty reset, if any.
    ///
    /// The difficulty is reset to genesis difficulty on testnet network(s) any
    /// time the duration between a block and the previous block is >= twice the
    /// target interval ie 19.6 minutes.
    ///
    /// - testnet, testnet-mock: Some(19.6 minutes)
    /// - mainnet, others: None
    pub fn difficulty_reset_interval(&self) -> Option<Timestamp> {
        match *self {
            Self::TestnetMock => Some(self.target_block_interval() * 2),
            _ => None,
        }
    }

    /// indicates if peer discovery should be performed by nodes on this network
    ///
    /// - regtest: false
    /// - mainnet and others: true
    pub fn performs_peer_discovery(&self) -> bool {
        // disable peer-discovery for regtest only (so far)
        !self.is_reg_test()
    }

    /// difficulty setting for the Genesis block
    pub fn genesis_difficulty(&self) -> Difficulty {
        match *self {
            Self::RegTest => Difficulty::MINIMUM,
            Self::Testnet(_) => Difficulty::MINIMUM,
            Self::TestnetMock => Difficulty::new([100_000, 0, 0, 0, 0]),
            Self::Main => Difficulty::new([100_000_000, 0, 0, 0, 0]),
        }
    }

    /// Genesis seed for the bridge authority set; the live value is read from
    /// chain state (rotatable without re-genesis).
    pub fn bridge_genesis_authority_set(&self) -> Option<BridgeAuthoritySet> {
        match *self {
            Self::RegTest | Self::TestnetMock | Self::Testnet(_) => Some(
                BridgeAuthoritySet::from_compressed(&[&DEV_BRIDGE_AUTHORITY_PUBKEY], 1)
                    .expect("pinned dev bridge authority key must be valid"),
            ),
            Self::Main => Some(
                BridgeAuthoritySet::from_compressed(&[&MAIN_BRIDGE_AUTHORITY_PUBKEY], 1)
                    .expect("pinned main bridge authority key must be valid"),
            ),
        }
    }

    /// minimum time between blocks.
    ///
    /// Blocks spaced apart by less than this amount of time are not valid.
    ///
    /// - for regtest: 1 milli
    /// - for testnet-mock: 100 milli
    /// - for mainnet and others: 60 seconds
    pub fn minimum_block_time(&self) -> Timestamp {
        match *self {
            Self::RegTest => Timestamp::millis(1),
            Self::TestnetMock => Timestamp::millis(100),
            Self::Testnet(_) => Timestamp::seconds(5),
            Self::Main => Timestamp::seconds(60),
        }
    }

    /// desired/average time between blocks.
    ///
    /// - for regtest: 100 milliseconds.
    /// - for mainnet and others: 300000 milliseconds equals 5 minutes.
    pub fn target_block_interval(&self) -> Timestamp {
        match *self {
            Self::RegTest => Timestamp::millis(100),
            Self::Testnet(_) => Timestamp::millis(30000),
            Self::Main | Self::TestnetMock => Timestamp::millis(300000),
        }
    }

    /// indicates if automated mining should be performed by this network
    ///
    /// note: we disable auto-mining in regtest mode because it generates blocks
    /// very quickly and that is not a good fit when mining is enabled for
    /// duration of the xnt-core process as blockchain grows very quickly.
    ///
    /// instead developers are encouraged to use [crate::api::regtest] module to
    /// generate any number of blocks in a controlled, deterministic fashion.
    //
    // bitcoin-core does not use cli flags, but rather RPC commands to
    // enable/disable mining in controlled fashion. We might consider moving to
    // that model before enabling automated mining for RegTest.
    pub fn performs_automated_mining(&self) -> bool {
        !self.is_reg_test()
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            Network::TestnetMock => "testnet-mock".to_string(),
            Network::Testnet(i) => format!("testnet-{i}"),
            Network::RegTest => "regtest".to_string(),
            Network::Main => "main".to_string(),
        };
        write!(f, "{}", string)
    }
}

impl FromStr for Network {
    type Err = String;
    fn from_str(input: &str) -> Result<Network, String> {
        match input {
            "testnet-mock" => Ok(Network::TestnetMock),
            "testnet" => Ok(Network::Testnet(0)), // default to 0
            "regtest" => Ok(Network::RegTest),
            "main" => Ok(Network::Main),
            _ => {
                if let Some(stripped) = input.strip_prefix("testnet-") {
                    match stripped.parse::<u8>() {
                        Ok(id) => Ok(Network::Testnet(id)),
                        Err(_) => Err(format!("Invalid testnet ID in '{}'", input)),
                    }
                } else {
                    Err(format!("Failed to parse '{}' as network", input))
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashSet;

    use super::*;

    impl Network {
        pub(crate) fn all_networks() -> impl Iterator<Item = Self> {
            [Self::Main, Self::TestnetMock, Self::RegTest]
                .into_iter()
                .chain((0..=u8::MAX).map(Self::Testnet))
        }
    }

    #[test]
    fn main_id() {
        assert_eq!(0, Network::Main.id());
    }

    #[test]
    fn expected_num_networks() {
        assert_eq!(259usize, Network::all_networks().count());
    }

    #[test]
    fn can_parse() {
        assert_eq!(Network::Main, Network::from_str("main").unwrap());
        assert_eq!(Network::Testnet(0), Network::from_str("testnet-0").unwrap());
        assert_eq!(
            Network::Testnet(42),
            Network::from_str("testnet-42").unwrap()
        );
        assert_eq!(
            Network::Testnet(255),
            Network::from_str("testnet-255").unwrap()
        );
    }

    #[test]
    fn no_parse_garbage() {
        assert!(Network::from_str("mainnn").is_err());
        assert!(Network::from_str("man").is_err());
        assert!(Network::from_str("testnet-777777777777777777777").is_err());
        assert!(Network::from_str("testnet-256").is_err());
        assert!(Network::from_str("Main").is_err());
        assert!(Network::from_str("").is_err());
        assert!(Network::from_str("testnet42").is_err());
        assert!(Network::from_str("testnet0").is_err());
        assert!(Network::from_str("0").is_err());
    }

    #[test]
    fn all_ids_unique() {
        let mut seen: HashSet<u32, _> = HashSet::new();
        for network in Network::all_networks() {
            assert!(
                seen.insert(network.id()),
                "All IDs must be unique. network {network} has non-unique ID."
            );
        }
    }

    #[test]
    fn dev_authority_pubkey_is_generator() {
        let mut scalar_one = [0u8; 32];
        scalar_one[31] = 1;
        let signing_key = k256::ecdsa::SigningKey::from_bytes(&scalar_one.into()).unwrap();
        let compressed = signing_key.verifying_key().to_encoded_point(true);
        assert_eq!(compressed.as_bytes(), DEV_BRIDGE_AUTHORITY_PUBKEY);
    }

    #[test]
    fn test_networks_seed_the_dev_authority() {
        for network in [Network::RegTest, Network::TestnetMock, Network::Testnet(0)] {
            let stored = network.bridge_genesis_authority_set().unwrap().to_stored();
            assert_eq!(stored.keys, vec![DEV_BRIDGE_AUTHORITY_PUBKEY.to_vec()]);
            assert_eq!(stored.threshold, 1);
        }
    }

    #[test]
    fn main_seeds_the_main_authority() {
        let stored = Network::Main
            .bridge_genesis_authority_set()
            .unwrap()
            .to_stored();
        let main_key =
            hex::decode("03e3e2534597374254bc9ba0f4bce775b1e354e7fe61b3222c4df0ef1baf9156a6")
                .unwrap();
        assert_eq!(stored.keys, vec![main_key]);
        assert_eq!(stored.threshold, 1);
        assert_eq!(stored.generation, 0);
    }
}
