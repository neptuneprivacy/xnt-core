//! Where a commitment sits in the AOCL.

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::api::export::BlockHeight;

/// One AOCL leaf of a commitment. A commitment can have several: two identical outputs share it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AoclLeaf {
    pub aocl_leaf_index: u64,
    pub block_height: BlockHeight,
    pub block_digest: Digest,
}

impl AoclLeaf {
    /// The leaf index the index reported when it kept one leaf per commitment: the latest.
    pub fn latest_index(leaves: &[Self]) -> Option<u64> {
        leaves.iter().map(|leaf| leaf.aocl_leaf_index).max()
    }
}
