//! Address types and operations

use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
use neptune_privacy::state::wallet::address::generation_address::{
    GenerationReceivingAddress, GenerationSubAddress,
};
use neptune_privacy::state::wallet::address::{
    ReceivingAddress as CoreReceivingAddress, SubAddress as CoreSubAddress,
};

use super::error::{Result, XntError};
use super::types::{Digest, Network};

/// Receiving address for receiving funds
#[derive(Clone)]
pub struct Address {
    pub(crate) inner: CoreReceivingAddress,
}

impl Address {
    /// Decode address from bech32m string
    pub fn from_bech32(bech32: &str, network: Network) -> Result<Self> {
        let inner = CoreReceivingAddress::from_bech32m(bech32, network.into())
            .map_err(|e| XntError::InvalidAddress(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Encode address to bech32m string
    pub fn to_bech32(&self, network: Network) -> Result<String> {
        self.inner
            .to_bech32m(network.into())
            .map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Get lock_script_hash (40 bytes = Digest)
    pub fn lock_script_hash(&self) -> Digest {
        Digest::from_core(self.inner.lock_script_hash())
    }

    /// Get receiver_identifier (8 bytes)
    pub fn receiver_id(&self) -> u64 {
        self.inner.receiver_identifier().value()
    }

    /// Get receiver_identifier as hex string
    pub fn receiver_id_hex(&self) -> String {
        format!("{:016x}", self.receiver_id())
    }

    /// Get privacy_digest (receiver_postimage) for output commitments
    pub fn privacy_digest(&self) -> Digest {
        Digest::from_core(self.inner.privacy_digest())
    }

    /// Create subaddress with payment_id (only for Generation addresses)
    pub fn with_payment_id(&self, payment_id: u64) -> Result<SubAddress> {
        if payment_id == 0 {
            return Err(XntError::InvalidInput(
                "payment_id must be non-zero".to_string(),
            ));
        }

        match &self.inner {
            CoreReceivingAddress::Generation(gen_addr) => {
                let subaddr = gen_addr
                    .with_payment_id(BFieldElement::new(payment_id))
                    .map_err(|e| XntError::Other(e.to_string()))?;
                Ok(SubAddress { inner: subaddr })
            }
            _ => Err(XntError::InvalidInput(
                "subaddress only supported for Generation addresses".to_string(),
            )),
        }
    }

    /// Check if this is a Generation address
    pub fn is_generation(&self) -> bool {
        matches!(self.inner, CoreReceivingAddress::Generation(_))
    }

    /// Get the underlying Generation address if this is one
    pub fn as_generation(&self) -> Option<&GenerationReceivingAddress> {
        match &self.inner {
            CoreReceivingAddress::Generation(gen) => Some(gen),
            _ => None,
        }
    }

    pub(crate) fn from_core(inner: CoreReceivingAddress) -> Self {
        Self { inner }
    }
}

/// Subaddress with payment_id for tracking payments
#[derive(Clone)]
pub struct SubAddress {
    pub(crate) inner: GenerationSubAddress,
}

impl SubAddress {
    /// Encode subaddress to bech32m string
    pub fn to_bech32(&self, network: Network) -> Result<String> {
        self.inner
            .to_bech32m(network.into())
            .map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Get payment_id
    pub fn payment_id(&self) -> u64 {
        self.inner.payment_id().value()
    }

    /// Get the base address (without payment_id)
    pub fn base_address(&self) -> Address {
        // Use the SubAddress trait to get base
        use neptune_privacy::state::wallet::address::SubAddress as SubAddressTrait;
        Address {
            inner: CoreReceivingAddress::Generation(Box::new(self.inner.base().clone())),
        }
    }

    /// Get privacy_digest for output commitments (same as base address)
    pub fn privacy_digest(&self) -> Digest {
        use neptune_privacy::state::wallet::address::SubAddress as SubAddressTrait;
        Digest::from_core(self.inner.base().receiver_postimage())
    }

    /// Convert to ReceivingAddress for transaction outputs
    pub fn to_receiving_address(&self) -> ReceivingAddress {
        ReceivingAddress {
            inner: CoreReceivingAddress::GenerationSubAddr(self.inner),
        }
    }
}

/// Unified receiving address for transaction outputs
/// Wraps Neptune's ReceivingAddress enum - can be main address or subaddress
#[derive(Clone)]
pub struct ReceivingAddress {
    pub(crate) inner: CoreReceivingAddress,
}

impl ReceivingAddress {
    /// Get payment_id if this is a subaddress, None for main address
    pub fn payment_id(&self) -> Option<u64> {
        use neptune_privacy::state::wallet::address::SubAddress as SubAddressTrait;
        match &self.inner {
            CoreReceivingAddress::GenerationSubAddr(sub) => Some(sub.payment_id().value()),
            _ => None,
        }
    }

    /// Check if this is a subaddress
    pub fn is_subaddress(&self) -> bool {
        matches!(self.inner, CoreReceivingAddress::GenerationSubAddr(_))
    }

    /// Get the inner CoreReceivingAddress
    pub(crate) fn into_inner(self) -> CoreReceivingAddress {
        self.inner
    }
}

impl Address {
    /// Convert to ReceivingAddress for transaction outputs
    pub fn to_receiving_address(&self) -> ReceivingAddress {
        ReceivingAddress {
            inner: self.inner.clone(),
        }
    }
}
