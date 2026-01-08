//! UTXO indexer database operations.

use std::cmp::Ordering;

use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;

use super::indexed_utxo::IndexedUtxo;
use super::utxo_indexer_tables::height_to_bucket;
use super::utxo_indexer_tables::UtxoIndexerTables;
use super::utxo_indexer_tables::UTXO_INDEXER_SCHEMA_VERSION;
use crate::api::export::BlockHeight;
use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::NeptuneLevelDb;
use crate::protocol::consensus::block::Block;
use crate::state::wallet::address::ciphertext_from_announcement;
use crate::state::wallet::address::receiver_identifier_from_announcement;

#[derive(Debug)]
pub struct UtxoIndexerDatabase {
    storage: SimpleRustyStorage,
    tables: UtxoIndexerTables,
}

impl UtxoIndexerDatabase {
    pub async fn try_connect(
        db: NeptuneLevelDb<RustyKey, RustyValue>,
    ) -> Result<Self, UtxoIndexerDbConnectError> {
        Self::try_connect_internal(db, false).await
    }

    pub async fn try_connect_and_migrate(
        db: NeptuneLevelDb<RustyKey, RustyValue>,
    ) -> Result<Self, UtxoIndexerDbConnectError> {
        Self::try_connect_internal(db, true).await
    }

    async fn try_connect_internal(
        db: NeptuneLevelDb<RustyKey, RustyValue>,
        migrate: bool,
    ) -> Result<Self, UtxoIndexerDbConnectError> {
        let mut storage = SimpleRustyStorage::new_with_callback(
            db,
            "UtxoIndexerDatabase-Schema",
            crate::LOG_TOKIO_LOCK_EVENT_CB,
        );
        let mut tables = UtxoIndexerTables::load_schema_in_order(&mut storage).await;
        let schema_version = tables.schema_version.get();
        let sync_height = tables.sync_height.get();

        tracing::trace!("Read UTXO indexer schema version: {schema_version}");
        tracing::trace!("Read sync_height: {sync_height}");

        // If DB is brand-new, set schema version to current
        let is_new_db = schema_version == 0 && sync_height == BlockHeight::genesis();
        if is_new_db {
            tables.schema_version.set(UTXO_INDEXER_SCHEMA_VERSION).await;
            storage.persist().await;
            tracing::info!(
                "Set new UTXO indexer database to schema version: v{}",
                UTXO_INDEXER_SCHEMA_VERSION
            );
        } else {
            tracing::debug!("UTXO indexer DB schema version is {}", schema_version);

            match schema_version.cmp(&UTXO_INDEXER_SCHEMA_VERSION) {
                Ordering::Equal => {
                    tracing::info!(
                        "UTXO indexer DB schema version {} is correct. Proceeding.",
                        schema_version
                    );
                }
                Ordering::Less => {
                    if migrate {
                        // Future: implement migrations here
                        // For now, just update version since no migration logic needed yet
                        tables.schema_version.set(UTXO_INDEXER_SCHEMA_VERSION).await;
                        storage.persist().await;
                        tracing::info!(
                            "Updated UTXO indexer schema version to v{}",
                            UTXO_INDEXER_SCHEMA_VERSION
                        );
                    } else {
                        return Err(UtxoIndexerDbConnectError::SchemaVersionTooLow {
                            found: schema_version,
                            expected: UTXO_INDEXER_SCHEMA_VERSION,
                        });
                    }
                }
                Ordering::Greater => {
                    return Err(UtxoIndexerDbConnectError::SchemaVersionTooHigh {
                        found: schema_version,
                        expected: UTXO_INDEXER_SCHEMA_VERSION,
                    });
                }
            }
        }

        Ok(UtxoIndexerDatabase { storage, tables })
    }

    pub async fn get_utxos_in_range(
        &self,
        receiver_id_hash: &Digest,
        from_height: BlockHeight,
        to_height: BlockHeight,
    ) -> Vec<IndexedUtxo> {
        let from_bucket = height_to_bucket(from_height);
        let to_bucket = height_to_bucket(to_height);

        // Load orphaned blocks set once for filtering
        let orphaned = self.tables.get_orphaned_blocks_set().await;

        let mut result = Vec::new();
        for bucket in from_bucket..=to_bucket {
            if let Some(utxos) = self.tables.utxos.get(&(*receiver_id_hash, bucket)).await {
                for utxo in utxos {
                    // Filter by exact height range AND not orphaned
                    if utxo.block_height >= from_height
                        && utxo.block_height <= to_height
                        && !orphaned.contains(&utxo.block_digest)
                    {
                        result.push(utxo);
                    }
                }
            }
        }
        result
    }

    pub async fn get_all_utxos(&self, receiver_id_hash: &Digest) -> Vec<IndexedUtxo> {
        let orphaned = self.tables.get_orphaned_blocks_set().await;
        let sync_height = self.tables.sync_height.get();
        let max_bucket = height_to_bucket(sync_height);

        let mut result = Vec::new();
        for bucket in 0..=max_bucket {
            if let Some(utxos) = self.tables.utxos.get(&(*receiver_id_hash, bucket)).await {
                for utxo in utxos {
                    if !orphaned.contains(&utxo.block_digest) {
                        result.push(utxo);
                    }
                }
            }
        }
        result
    }

    pub async fn add_utxo(&mut self, receiver_id_hash: Digest, utxo: IndexedUtxo) {
        let bucket = height_to_bucket(utxo.block_height);
        let key = (receiver_id_hash, bucket);

        let mut utxos = self.tables.utxos.get(&key).await.unwrap_or_default();
        utxos.push(utxo);
        self.tables.utxos.insert(key, utxos).await;
    }

    pub async fn add_utxos(&mut self, receiver_id_hash: Digest, new_utxos: Vec<IndexedUtxo>) {
        if new_utxos.is_empty() {
            return;
        }

        let mut by_bucket: std::collections::HashMap<u64, Vec<IndexedUtxo>> =
            std::collections::HashMap::new();
        for utxo in new_utxos {
            let bucket = height_to_bucket(utxo.block_height);
            by_bucket.entry(bucket).or_default().push(utxo);
        }

        for (bucket, utxos_for_bucket) in by_bucket {
            let key = (receiver_id_hash, bucket);
            let mut existing = self.tables.utxos.get(&key).await.unwrap_or_default();
            existing.extend(utxos_for_bucket);
            self.tables.utxos.insert(key, existing).await;
        }
    }

    pub async fn handle_reorg(&mut self, orphaned_block_digests: Vec<Digest>) {
        for digest in orphaned_block_digests {
            self.tables.orphaned_blocks.insert(digest, ()).await;
        }
    }

    pub async fn is_block_orphaned(&self, block_digest: &Digest) -> bool {
        self.tables
            .orphaned_blocks
            .get(block_digest)
            .await
            .is_some()
    }

    pub async fn add_commitment(&mut self, commitment: Digest, aocl_leaf_index: u64) {
        self.tables
            .commitment_index
            .insert(commitment, aocl_leaf_index)
            .await;
    }

    pub async fn get_aocl_leaf_index(&self, commitment: &Digest) -> Option<u64> {
        self.tables.commitment_index.get(commitment).await
    }

    pub async fn get_aocl_leaf_indices(&self, commitments: &[Digest]) -> Vec<Option<u64>> {
        let mut results = Vec::with_capacity(commitments.len());
        for commitment in commitments {
            results.push(self.tables.commitment_index.get(commitment).await);
        }
        results
    }

    pub async fn add_removal(&mut self, absolute_index_set_hash: Digest, height: BlockHeight, block_digest: Digest) {
        self.tables.removal_index.insert(absolute_index_set_hash, (height, block_digest)).await;
    }

    /// Returns spent_at_height if UTXO is spent (and not orphaned), None otherwise
    pub async fn get_spent_status(&self, absolute_index_set_hash: &Digest) -> Option<BlockHeight> {
        if let Some((height, block_digest)) = self.tables.removal_index.get(absolute_index_set_hash).await {
            if !self.tables.orphaned_blocks.get(&block_digest).await.is_some() {
                return Some(height);
            }
        }
        None
    }

    /// Batch lookup for spent status
    pub async fn get_spent_statuses(&self, hashes: &[Digest]) -> Vec<Option<BlockHeight>> {
        let orphaned = self.tables.get_orphaned_blocks_set().await;
        let mut results = Vec::with_capacity(hashes.len());
        for hash in hashes {
            if let Some((height, block_digest)) = self.tables.removal_index.get(hash).await {
                if !orphaned.contains(&block_digest) {
                    results.push(Some(height));
                } else {
                    results.push(None);
                }
            } else {
                results.push(None);
            }
        }
        results
    }

    pub fn get_sync_height(&self) -> BlockHeight {
        self.tables.sync_height.get()
    }

    pub async fn set_sync_height(&mut self, height: BlockHeight) {
        self.tables.sync_height.set(height).await;
    }

    pub fn schema_version(&self) -> u16 {
        self.tables.schema_version.get()
    }

    pub async fn index_block(&mut self, block: &Block, prev_aocl_len: u64) -> u64 {
        self.index_block_internal(block, prev_aocl_len, true).await
    }

    pub async fn index_block_batch(&mut self, block: &Block, prev_aocl_len: u64) -> u64 {
        self.index_block_internal(block, prev_aocl_len, false).await
    }

    async fn index_block_internal(&mut self, block: &Block, prev_aocl_len: u64, update_sync: bool) -> u64 {
        let height = block.kernel.header.height;
        let block_digest = block.hash();

        // Index announcements (UTXOs)
        for announcement in block.kernel.body.transaction_kernel.announcements.iter() {
            if let Ok(receiver_id) = receiver_identifier_from_announcement(announcement) {
                if let Ok(ciphertext) = ciphertext_from_announcement(announcement) {
                    let receiver_id_hash = Tip5::hash_varlen(&[receiver_id]);
                    let indexed_utxo = IndexedUtxo::new(height, block_digest, ciphertext);
                    self.add_utxo(receiver_id_hash, indexed_utxo).await;
                }
            }
        }

        // Index outputs (commitments)
        let outputs = &block.kernel.body.transaction_kernel.outputs;
        for (i, output) in outputs.iter().enumerate() {
            let aocl_leaf_index = prev_aocl_len + i as u64;
            self.add_commitment(output.canonical_commitment, aocl_leaf_index).await;
        }

        // Index inputs (removal records)
        for removal_record in block.kernel.body.transaction_kernel.inputs.iter() {
            let abs_index_hash = Tip5::hash(&removal_record.absolute_indices);
            self.add_removal(abs_index_hash, height, block_digest).await;
        }

        if update_sync {
            self.set_sync_height(height).await;
        }

        // Return total AOCL additions: transaction outputs + guesser fee UTXOs
        let guesser_fee_count = block
            .guesser_fee_addition_records()
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        outputs.len() as u64 + guesser_fee_count
    }
}

impl StorageWriter for UtxoIndexerDatabase {
    async fn persist(&mut self) {
        self.storage.persist().await
    }

    async fn drop_unpersisted(&mut self) {
        self.storage.drop_unpersisted().await
    }
}

/// Errors when connecting to the UTXO indexer database.
#[derive(Debug, Clone, thiserror::Error)]
pub enum UtxoIndexerDbConnectError {
    #[error("UTXO indexer database schema version is lower than expected. expected: {expected}, found: {found}")]
    SchemaVersionTooLow { found: u16, expected: u16 },

    #[error("UTXO indexer database schema version is higher than expected. It appears to come from a newer xnt-core. expected: {expected}, found: {found}")]
    SchemaVersionTooHigh { found: u16, expected: u16 },

    #[error("UTXO indexer db connect failed: {0}")]
    Failed(String),
}

impl From<anyhow::Error> for UtxoIndexerDbConnectError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use super::*;
    use crate::application::database::NeptuneLevelDb;

    #[tokio::test]
    async fn test_utxo_indexer_database_crud() {
        let db = NeptuneLevelDb::open_new_test_database(false, None, None, None)
            .await
            .unwrap();
        let mut indexer = UtxoIndexerDatabase::try_connect_and_migrate(db)
            .await
            .unwrap();

        // Create test data
        let receiver_id_hash = Digest::default();
        let utxo1 = IndexedUtxo::new(
            BlockHeight::from(100u64),
            Digest::default(),
            vec![BFieldElement::new(1)],
        );
        let utxo2 = IndexedUtxo::new(
            BlockHeight::from(1500u64), // Different bucket (bucket 1)
            Digest::default(),
            vec![BFieldElement::new(2)],
        );

        // Test add and get
        indexer.add_utxo(receiver_id_hash, utxo1.clone()).await;
        indexer.add_utxo(receiver_id_hash, utxo2.clone()).await;
        indexer.set_sync_height(BlockHeight::from(1500u64)).await;
        indexer.persist().await;

        let all_utxos = indexer.get_all_utxos(&receiver_id_hash).await;
        assert_eq!(all_utxos.len(), 2);

        // Test range query - only bucket 0
        let range_utxos = indexer
            .get_utxos_in_range(
                &receiver_id_hash,
                BlockHeight::from(0u64),
                BlockHeight::from(999u64),
            )
            .await;
        assert_eq!(range_utxos.len(), 1);
        assert_eq!(range_utxos[0].block_height, BlockHeight::from(100u64));

        // Test range query - only bucket 1
        let range_utxos = indexer
            .get_utxos_in_range(
                &receiver_id_hash,
                BlockHeight::from(1000u64),
                BlockHeight::from(1999u64),
            )
            .await;
        assert_eq!(range_utxos.len(), 1);
        assert_eq!(range_utxos[0].block_height, BlockHeight::from(1500u64));

        // Test sync height
        assert_eq!(indexer.get_sync_height(), BlockHeight::from(1500u64));
    }

    #[tokio::test]
    async fn test_handle_reorg() {
        let db = NeptuneLevelDb::open_new_test_database(false, None, None, None)
            .await
            .unwrap();
        let mut indexer = UtxoIndexerDatabase::try_connect_and_migrate(db)
            .await
            .unwrap();

        let receiver_id_hash = Digest::default();
        let orphaned_block_digest = Digest::new([
            BFieldElement::new(999),
            BFieldElement::new(999),
            BFieldElement::new(999),
            BFieldElement::new(999),
            BFieldElement::new(999),
        ]);

        let utxo1 = IndexedUtxo::new(
            BlockHeight::from(100u64),
            Digest::default(), // canonical block
            vec![],
        );
        let utxo2 = IndexedUtxo::new(
            BlockHeight::from(200u64),
            orphaned_block_digest, // will be orphaned
            vec![],
        );

        indexer.add_utxo(receiver_id_hash, utxo1).await;
        indexer.add_utxo(receiver_id_hash, utxo2).await;
        indexer.set_sync_height(BlockHeight::from(200u64)).await;
        indexer.persist().await;

        // Before reorg - both visible
        let all_utxos = indexer.get_all_utxos(&receiver_id_hash).await;
        assert_eq!(all_utxos.len(), 2);

        // Handle reorg - mark block as orphaned
        indexer.handle_reorg(vec![orphaned_block_digest]).await;
        indexer.persist().await;

        // After reorg - only canonical UTXO visible
        let remaining = indexer.get_all_utxos(&receiver_id_hash).await;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].block_height, BlockHeight::from(100u64));

        // Check is_block_orphaned
        assert!(indexer.is_block_orphaned(&orphaned_block_digest).await);
        assert!(!indexer.is_block_orphaned(&Digest::default()).await);
    }

    #[tokio::test]
    async fn test_bucketing() {
        let db = NeptuneLevelDb::open_new_test_database(false, None, None, None)
            .await
            .unwrap();
        let mut indexer = UtxoIndexerDatabase::try_connect_and_migrate(db)
            .await
            .unwrap();

        let receiver_id_hash = Digest::default();

        // Add UTXOs across multiple buckets
        for i in 0..5 {
            let height = i * 500; // 0, 500, 1000, 1500, 2000
            let utxo = IndexedUtxo::new(
                BlockHeight::from(height),
                Digest::default(),
                vec![BFieldElement::new(i)], // Use ciphertext to identify
            );
            indexer.add_utxo(receiver_id_hash, utxo).await;
        }
        indexer.set_sync_height(BlockHeight::from(2000u64)).await;
        indexer.persist().await;

        // Query spanning buckets 0 and 1 (heights 0-1999)
        let range_utxos = indexer
            .get_utxos_in_range(
                &receiver_id_hash,
                BlockHeight::from(400u64),
                BlockHeight::from(1100u64),
            )
            .await;

        // Should get: 500, 1000 (not 0, 1500, 2000)
        assert_eq!(range_utxos.len(), 2);
        let heights: Vec<u64> = range_utxos.iter().map(|u| u64::from(u.block_height)).collect();
        assert!(heights.contains(&500)); // height 500
        assert!(heights.contains(&1000)); // height 1000
    }

    #[tokio::test]
    async fn test_commitment_index() {
        let db = NeptuneLevelDb::open_new_test_database(false, None, None, None)
            .await
            .unwrap();
        let mut indexer = UtxoIndexerDatabase::try_connect_and_migrate(db)
            .await
            .unwrap();

        // Create test commitments
        let commitment1 = Digest::new([
            BFieldElement::new(1),
            BFieldElement::new(2),
            BFieldElement::new(3),
            BFieldElement::new(4),
            BFieldElement::new(5),
        ]);
        let commitment2 = Digest::new([
            BFieldElement::new(10),
            BFieldElement::new(20),
            BFieldElement::new(30),
            BFieldElement::new(40),
            BFieldElement::new(50),
        ]);
        let unknown_commitment = Digest::new([
            BFieldElement::new(99),
            BFieldElement::new(99),
            BFieldElement::new(99),
            BFieldElement::new(99),
            BFieldElement::new(99),
        ]);

        // Add commitments
        indexer.add_commitment(commitment1, 100).await;
        indexer.add_commitment(commitment2, 200).await;
        indexer.persist().await;

        // Test single lookup
        assert_eq!(indexer.get_aocl_leaf_index(&commitment1).await, Some(100));
        assert_eq!(indexer.get_aocl_leaf_index(&commitment2).await, Some(200));
        assert_eq!(
            indexer.get_aocl_leaf_index(&unknown_commitment).await,
            None
        );

        // Test batch lookup
        let results = indexer
            .get_aocl_leaf_indices(&[commitment1, unknown_commitment, commitment2])
            .await;
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], Some(100));
        assert_eq!(results[1], None);
        assert_eq!(results[2], Some(200));
    }
}
