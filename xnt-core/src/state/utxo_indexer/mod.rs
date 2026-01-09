//! UTXO indexer for offline signing. Indexes by Tip5(receiver_id) with 1000-block buckets.

pub mod indexed_utxo;
mod utxo_indexer_database;
mod utxo_indexer_tables;

pub use indexed_utxo::IndexedUtxo;
pub use utxo_indexer_database::UtxoIndexerDatabase;
pub use utxo_indexer_database::UtxoIndexerDbConnectError;
pub use utxo_indexer_tables::height_to_bucket;
pub use utxo_indexer_tables::BUCKET_SIZE;

pub const UTXO_INDEXER_DB_NAME: &str = "utxo_index";
