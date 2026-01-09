use futures::pin_mut;
use num_traits::ConstZero;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tracing::debug;

use crate::application::database::storage::storage_schema::traits::StorageWriter;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::storage::storage_vec::traits::*;
use crate::state::wallet::wallet_db_tables::WalletDbTables;

/// migrates wallet db with schema-version v2 to v3
///
/// Changes between v2 and v3:
/// - Add `payment_id` field to MonitoredUtxo for subaddress support.
///   Existing UTXOs get payment_id = 0 (base address).
pub(super) async fn migrate(storage: &mut SimpleRustyStorage) -> anyhow::Result<()> {
    // reset the schema, so we start with table_count = 0.
    storage.reset_schema();

    // add a DbtVec<MonitoredUtxoV2> to the schema at the correct position
    // so the correct key-prefix is used. This allows for the reading of
    // v2-monitored UTXOs.
    storage.schema.table_count = WalletDbTables::monitored_utxos_table_count();
    let mutxos_v2 = storage
        .schema
        .new_vec::<migration::schema_v2::MonitoredUtxo>("monitored_utxos")
        .await;

    debug!(
        "Preparing to convert {} monitored UTXOs from v2 to v3.",
        mutxos_v2.len().await
    );

    // reset the schema again, to prepare for loading v3 schema.
    storage.reset_schema();

    // add a DbtVec<MonitoredUtxoV3> to the schema at the correct position
    storage.schema.table_count = WalletDbTables::monitored_utxos_table_count();
    let mut mutxos_v3 = storage
        .schema
        .new_vec::<migration::schema_v3::MonitoredUtxo>("monitored_utxos")
        .await;

    /* Migrate monitored UTXOs - add payment_id field */
    let mutxo_stream = mutxos_v2.stream().await;
    pin_mut!(mutxo_stream); // needed for iteration

    while let Some((list_index, mutxo_v2)) = mutxo_stream.next().await {
        let mutxo_v3 = migration::schema_v3::MonitoredUtxo {
            utxo: mutxo_v2.utxo,
            aocl_leaf_index: mutxo_v2.aocl_leaf_index,
            sender_randomness: mutxo_v2.sender_randomness,
            receiver_preimage: mutxo_v2.receiver_preimage,
            payment_id: BFieldElement::ZERO,
            blockhash_to_membership_proof: mutxo_v2.blockhash_to_membership_proof,
            number_of_mps_per_utxo: mutxo_v2.number_of_mps_per_utxo,
            spent_in_block: mutxo_v2.spent_in_block,
            confirmed_in_block: mutxo_v2.confirmed_in_block,
            abandoned_at: mutxo_v2.abandoned_at,
        };

        // Overwrite the v2 monitored UTXO with a v3.
        debug!("Migrating monitored UTXO number {list_index} to v3");
        mutxos_v3.set(list_index, mutxo_v3).await;
    }

    storage.persist().await;

    // Load tables to set schema version
    storage.reset_schema();
    let mut tables = WalletDbTables::load_schema_in_order(storage).await;
    tables.schema_version.set(3).await;

    // success!
    Ok(())
}

mod migration {
    pub(super) mod schema_v2 {
        use std::collections::VecDeque;

        use serde::Deserialize;
        use serde::Serialize;
        use tasm_lib::prelude::Digest;

        use crate::api::export::BlockHeight;
        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::protocol::proof_abstractions::timestamp::Timestamp;
        use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;

        // This is a copy of MonitoredUtxo as it was in v2 schema (without payment_id).
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub(in super::super) struct MonitoredUtxo {
            pub utxo: Utxo,
            pub aocl_leaf_index: u64,
            pub sender_randomness: Digest,
            pub receiver_preimage: Digest,
            pub blockhash_to_membership_proof: VecDeque<(Digest, MsMembershipProof)>,
            pub number_of_mps_per_utxo: usize,
            pub spent_in_block: Option<(Digest, Timestamp, BlockHeight)>,
            pub confirmed_in_block: (Digest, Timestamp, BlockHeight),
            pub abandoned_at: Option<(Digest, Timestamp, BlockHeight)>,
        }
    }

    pub(super) mod schema_v3 {
        use std::collections::VecDeque;

        use serde::Deserialize;
        use serde::Serialize;
        use tasm_lib::prelude::Digest;
        use tasm_lib::triton_vm::prelude::BFieldElement;

        use crate::api::export::BlockHeight;
        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::protocol::proof_abstractions::timestamp::Timestamp;
        use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;

        // This is MonitoredUtxo as it is in v3/v4 schema (with payment_id).
        // Must match production MonitoredUtxo exactly.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub(in super::super) struct MonitoredUtxo {
            pub utxo: Utxo,
            pub aocl_leaf_index: u64,
            pub sender_randomness: Digest,
            pub receiver_preimage: Digest,
            #[serde(default)]
            pub payment_id: BFieldElement,
            pub blockhash_to_membership_proof: VecDeque<(Digest, MsMembershipProof)>,
            pub number_of_mps_per_utxo: usize,
            pub spent_in_block: Option<(Digest, Timestamp, BlockHeight)>,
            pub confirmed_in_block: (Digest, Timestamp, BlockHeight),
            pub abandoned_at: Option<(Digest, Timestamp, BlockHeight)>,
        }
    }
}
