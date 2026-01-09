//! UTXO indexer database schema.

use std::collections::HashSet;

use tasm_lib::prelude::Digest;

use super::indexed_utxo::IndexedUtxo;
use crate::api::export::BlockHeight;
use crate::application::database::storage::storage_schema::DbtMap;
use crate::application::database::storage::storage_schema::DbtSingleton;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;

pub(super) const UTXO_INDEXER_SCHEMA_VERSION: u16 = 1;

pub const BUCKET_SIZE: u64 = 1000;

pub fn height_to_bucket(height: BlockHeight) -> u64 {
    u64::from(height) / BUCKET_SIZE
}

/// Tables must be loaded in same order (DbtSchema uses table order as prefix).
#[derive(Debug)]
pub(super) struct UtxoIndexerTables {
    /// (receiver_hash, bucket) -> Vec<IndexedUtxo>
    pub(super) utxos: DbtMap<(Digest, u64), Vec<IndexedUtxo>>,
    /// Orphaned block digests for reorg filtering
    pub(super) orphaned_blocks: DbtMap<Digest, ()>,
    /// commitment -> aocl_leaf_index
    pub(super) commitment_index: DbtMap<Digest, u64>,
    /// hash(AbsoluteIndexSet) -> (block_height, block_digest) where spent
    pub(super) removal_index: DbtMap<Digest, (BlockHeight, Digest)>,
    pub(super) sync_height: DbtSingleton<BlockHeight>,
    pub(super) schema_version: DbtSingleton<u16>,
}

impl UtxoIndexerTables {
    pub(super) async fn load_schema_in_order(storage: &mut SimpleRustyStorage) -> Self {
        let utxos = storage.schema.new_map("utxos").await;
        let orphaned_blocks = storage.schema.new_map("orphaned_blocks").await;
        let commitment_index = storage.schema.new_map("commitment_index").await;
        let removal_index = storage.schema.new_map("removal_index").await;
        let sync_height = storage.schema.new_singleton::<BlockHeight>("sync_height").await;
        let schema_version = storage.schema.new_singleton::<u16>("schema_version").await;

        Self { utxos, orphaned_blocks, commitment_index, removal_index, sync_height, schema_version }
    }

    pub(super) async fn get_orphaned_blocks_set(&self) -> HashSet<Digest> {
        self.orphaned_blocks
            .all_keys()
            .await
            .into_iter()
            .collect()
    }
}
