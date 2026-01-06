//! UTXO Index for fast lookups by receiver_identifier
//!
//! This module provides a lightweight index that maps receiver_identifier to UTXO locations.
//! Instead of scanning the entire blockchain, queries can use this index to jump directly
//! to blocks containing UTXOs for a specific receiver.
//!
//! Storage: LevelDB database (same pattern as block index)
//! Index size: ~10 bytes per UTXO (block_height + output_index)
//! At 100M UTXOs: ~1.2-1.3 GB on disk

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::prelude::twenty_first::prelude::Digest;

use crate::application::database::{create_db_if_missing, NeptuneLevelDb};

/// A lightweight reference to a UTXO location in the blockchain
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoLocation {
    /// Block height where this UTXO was created
    pub block_height: u64,

    /// Index of the output within the block's transaction kernel
    pub output_index: u16,
}

/// Database-backed UTXO index
///
/// Maps receiver_identifier (u64) → Vec<UtxoLocation>
/// Uses LevelDB for persistent storage, same pattern as block index
#[derive(Debug, Clone)]
pub struct UtxoIndexDatabase {
    db: NeptuneLevelDb<u64, Vec<UtxoLocation>>,
}

impl UtxoIndexDatabase {
    /// Open or create the UTXO index database
    pub async fn new(path: &Path) -> Result<Self> {
        let options = create_db_if_missing();
        let db = NeptuneLevelDb::new(path, &options)
            .await
            .context("Failed to open UTXO index database")?;

        Ok(Self { db })
    }

    /// Add a UTXO to the index
    pub async fn add_utxo(
        &mut self,
        receiver_identifier: u64,
        location: UtxoLocation,
    ) -> Result<()> {
        // Get existing locations for this receiver
        let mut locations = self.db.get(receiver_identifier).await.unwrap_or_default();

        // Add new location
        locations.push(location);

        // Write back
        self.db.put(receiver_identifier, locations).await;

        Ok(())
    }

    /// Get all UTXO locations for a receiver_identifier
    pub async fn get_utxos(&self, receiver_identifier: u64) -> Result<Option<Vec<UtxoLocation>>> {
        Ok(self.db.get(receiver_identifier).await)
    }
}

/// Database-backed index for fast lookup of UTXO creation block by canonical_commitment
///
/// Maps canonical_commitment (Digest) → UtxoLocation
/// This allows O(1) lookup instead of scanning the blockchain
#[derive(Debug, Clone)]
pub struct UtxoCommitmentIndexDatabase {
    db: NeptuneLevelDb<Digest, UtxoLocation>,
}

impl UtxoCommitmentIndexDatabase {
    /// Open or create the UTXO commitment index database
    pub async fn new(path: &Path) -> Result<Self> {
        let options = create_db_if_missing();
        let db = NeptuneLevelDb::new(path, &options)
            .await
            .context("Failed to open UTXO commitment index database")?;

        Ok(Self { db })
    }

    /// Add a UTXO to the index by its canonical_commitment
    pub async fn add_utxo_by_commitment(
        &mut self,
        canonical_commitment: Digest,
        location: UtxoLocation,
    ) -> Result<()> {
        self.db.put(canonical_commitment, location).await;
        Ok(())
    }

    /// Get UTXO location by canonical_commitment
    pub async fn get_utxo_location(&self, canonical_commitment: Digest) -> Result<Option<UtxoLocation>> {
        Ok(self.db.get(canonical_commitment).await)
    }
}

/// Metadata about the UTXO index
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Default)]
pub struct UtxoIndexMetadata {
    /// Highest block height that has been indexed
    pub indexed_height: u64,

    /// Total number of UTXOs indexed (approximate)
    pub total_utxos: u64,

    /// Number of unique receivers
    pub total_receivers: u64,
}

/// Database for UTXO index metadata
#[derive(Debug, Clone)]
pub struct UtxoIndexMetadataDb {
    db: NeptuneLevelDb<String, UtxoIndexMetadata>,
}

impl UtxoIndexMetadataDb {
    const METADATA_KEY: &'static str = "metadata";

    /// Open or create the metadata database
    pub async fn new(path: &Path) -> Result<Self> {
        let options = create_db_if_missing();
        let db = NeptuneLevelDb::new(path, &options)
            .await
            .context("Failed to open UTXO index metadata database")?;

        Ok(Self { db })
    }

    /// Get the current metadata
    pub async fn get_metadata(&self) -> Result<UtxoIndexMetadata> {
        Ok(self
            .db
            .get(Self::METADATA_KEY.to_string())
            .await
            .unwrap_or_default())
    }

    /// Update the metadata
    pub async fn set_metadata(&mut self, metadata: UtxoIndexMetadata) -> Result<()> {
        self.db.put(Self::METADATA_KEY.to_string(), metadata).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_utxo_index_database() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_utxo_index");

        let index = UtxoIndexDatabase::new(&db_path).unwrap();

        let receiver_id = 0x1234567890abcdef;
        let location = UtxoLocation {
            block_height: 100,
            output_index: 5,
        };

        index.add_utxo(receiver_id, location).await.unwrap();

        let found = index.get_utxos(receiver_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_utxo_index_multiple() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_utxo_index");

        let index = UtxoIndexDatabase::new(&db_path).unwrap();
        let receiver_id = 0x1234567890abcdef;

        index
            .add_utxo(
                receiver_id,
                UtxoLocation {
                    block_height: 100,
                    output_index: 0,
                },
            )
            .await
            .unwrap();
        index
            .add_utxo(
                receiver_id,
                UtxoLocation {
                    block_height: 200,
                    output_index: 3,
                },
            )
            .await
            .unwrap();
        index
            .add_utxo(
                receiver_id,
                UtxoLocation {
                    block_height: 300,
                    output_index: 1,
                },
            )
            .await
            .unwrap();

        let found = index.get_utxos(receiver_id).await.unwrap().unwrap();
        assert_eq!(found.len(), 3);
    }
}
