//! Core types shared between FFI and NAPI

use neptune_privacy::application::config::network::Network as CoreNetwork;
use neptune_privacy::prelude::twenty_first::prelude::Digest as CoreDigest;
use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
use num_traits::ConstZero;

/// Network type for address encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Main,
    TestnetMock,
    RegTest,
    Testnet,
}

impl From<Network> for CoreNetwork {
    fn from(n: Network) -> Self {
        match n {
            Network::Main => CoreNetwork::Main,
            Network::TestnetMock => CoreNetwork::TestnetMock,
            Network::RegTest => CoreNetwork::RegTest,
            Network::Testnet => CoreNetwork::Testnet(0),
        }
    }
}

impl From<CoreNetwork> for Network {
    fn from(n: CoreNetwork) -> Self {
        match n {
            CoreNetwork::Main => Network::Main,
            CoreNetwork::TestnetMock => Network::TestnetMock,
            CoreNetwork::RegTest => Network::RegTest,
            CoreNetwork::Testnet(_) => Network::Testnet,
            _ => Network::Main, // fallback for non-exhaustive
        }
    }
}

/// 40-byte digest (TIP5 output)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Digest {
    pub bytes: [u8; 40],
}

impl Default for Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Digest {
    pub const fn new() -> Self {
        Self { bytes: [0u8; 40] }
    }

    pub fn from_bytes(bytes: [u8; 40]) -> Self {
        Self { bytes }
    }

    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 40 {
            return None;
        }
        let mut digest = Self::new();
        digest.bytes.copy_from_slice(&bytes);
        Some(digest)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub(crate) fn to_core(&self) -> CoreDigest {
        let mut bfes = [BFieldElement::ZERO; 5];
        for (i, chunk) in self.bytes.chunks(8).enumerate() {
            let arr: [u8; 8] = chunk.try_into().unwrap();
            bfes[i] = BFieldElement::new(u64::from_le_bytes(arr));
        }
        CoreDigest::new(bfes)
    }

    pub(crate) fn from_core(d: CoreDigest) -> Self {
        Self {
            bytes: d.into(),
        }
    }
}

impl From<[u8; 40]> for Digest {
    fn from(bytes: [u8; 40]) -> Self {
        Self { bytes }
    }
}

impl From<Digest> for [u8; 40] {
    fn from(d: Digest) -> [u8; 40] {
        d.bytes
    }
}

impl From<CoreDigest> for Digest {
    fn from(d: CoreDigest) -> Self {
        Self::from_core(d)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Amount in native currency (NepCoin)
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Amount {
    pub nau: u128,
}

impl Amount {
    pub const fn zero() -> Self {
        Self { nau: 0 }
    }

    pub const fn from_nau(nau: u128) -> Self {
        Self { nau }
    }

    /// Create from NepCoin (1 NepCoin = 10^18 NAU)
    pub fn from_coins(coins: f64) -> Self {
        Self {
            nau: (coins * 1e18) as u128,
        }
    }

    /// Convert to NepCoin
    pub fn to_coins(&self) -> f64 {
        self.nau as f64 / 1e18
    }
}
