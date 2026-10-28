//! Indexed UTXO data structure.

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::BlockHeight;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum IndexedUtxo {
    /// Normal encrypted UTXO from an onchain announcement.
    EncryptedUtxo {
        block_height: BlockHeight,
        block_digest: Digest,
        ciphertext: Vec<BFieldElement>,
    },
    /// Bridge unlock UTXO — plaintext, constructed from burn data.
    PublicUtxo {
        block_height: BlockHeight,
        block_digest: Digest,
        receiver_digest: Digest,
        lock_script_hash: Digest,
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
    },
}

impl IndexedUtxo {
    pub fn new_encrypted(
        block_height: BlockHeight,
        block_digest: Digest,
        ciphertext: Vec<BFieldElement>,
    ) -> Self {
        Self::EncryptedUtxo {
            block_height,
            block_digest,
            ciphertext,
        }
    }

    pub fn new_public(
        block_height: BlockHeight,
        block_digest: Digest,
        receiver_digest: Digest,
        lock_script_hash: Digest,
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
    ) -> Self {
        Self::PublicUtxo {
            block_height,
            block_digest,
            receiver_digest,
            lock_script_hash,
            amount,
            sender_randomness,
        }
    }

    pub fn block_height(&self) -> BlockHeight {
        match self {
            Self::EncryptedUtxo { block_height, .. } | Self::PublicUtxo { block_height, .. } => {
                *block_height
            }
        }
    }

    pub fn block_digest(&self) -> Digest {
        match self {
            Self::EncryptedUtxo { block_digest, .. } | Self::PublicUtxo { block_digest, .. } => {
                *block_digest
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_utxo_serialization() {
        let utxo = IndexedUtxo::new_encrypted(
            BlockHeight::from(1000u64),
            Digest::default(),
            vec![BFieldElement::new(1), BFieldElement::new(2)],
        );

        let serialized = bincode::serialize(&utxo).unwrap();
        let deserialized: IndexedUtxo = bincode::deserialize(&serialized).unwrap();
        assert_eq!(utxo, deserialized);
    }

    #[test]
    fn test_public_utxo_serialization() {
        let utxo = IndexedUtxo::new_public(
            BlockHeight::from(2000u64),
            Digest::default(),
            Digest::new([BFieldElement::new(1); 5]),
            Digest::new([BFieldElement::new(2); 5]),
            NativeCurrencyAmount::from_nau(1_000_000),
            Digest::new([BFieldElement::new(3); 5]),
        );

        let serialized = bincode::serialize(&utxo).unwrap();
        let deserialized: IndexedUtxo = bincode::deserialize(&serialized).unwrap();
        assert_eq!(utxo, deserialized);
    }
}
