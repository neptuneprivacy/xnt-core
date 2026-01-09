//! Indexed UTXO data structure.

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::BlockHeight;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexedUtxo {
    pub block_height: BlockHeight,
    pub block_digest: Digest,
    pub ciphertext: Vec<BFieldElement>,
}

impl IndexedUtxo {
    pub fn new(block_height: BlockHeight, block_digest: Digest, ciphertext: Vec<BFieldElement>) -> Self {
        Self {
            block_height,
            block_digest,
            ciphertext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indexed_utxo_serialization() {
        let utxo = IndexedUtxo::new(
            BlockHeight::from(1000u64),
            Digest::default(),
            vec![BFieldElement::new(1), BFieldElement::new(2)],
        );

        // Test bincode serialization (used by LevelDB storage)
        let serialized = bincode::serialize(&utxo).unwrap();
        let deserialized: IndexedUtxo = bincode::deserialize(&serialized).unwrap();

        assert_eq!(utxo.block_height, deserialized.block_height);
        assert_eq!(utxo.block_digest, deserialized.block_digest);
        assert_eq!(utxo.ciphertext, deserialized.ciphertext);
    }
}
