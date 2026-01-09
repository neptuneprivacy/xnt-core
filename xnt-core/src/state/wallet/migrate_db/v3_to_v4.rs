use futures::pin_mut;
use num_traits::ConstZero;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tracing::debug;

use crate::application::database::storage::storage_schema::traits::StorageWriter;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::storage::storage_vec::traits::*;
use crate::state::wallet::wallet_db_tables::WalletDbTables;

/// migrates wallet db with schema-version v3 to v4
///
/// Changes between v3 and v4:
/// - Add `payment_id` field to ExpectedUtxo for subaddress support.
///   Existing expected UTXOs get payment_id = 0 (base address).
pub(super) async fn migrate(storage: &mut SimpleRustyStorage) -> anyhow::Result<()> {
    // reset the schema, so we start with table_count = 0.
    storage.reset_schema();

    // add a DbtVec<ExpectedUtxoV3> to the schema at the correct position
    // so the correct key-prefix is used. This allows for the reading of
    // v3-expected UTXOs.
    storage.schema.table_count = WalletDbTables::expected_utxo_table_count();
    let eutxos_v3 = storage
        .schema
        .new_vec::<migration::schema_v3::ExpectedUtxo>("expected_utxos")
        .await;

    debug!(
        "Preparing to convert {} expected UTXOs from v3 to v4.",
        eutxos_v3.len().await
    );

    // reset the schema again, to prepare for loading v4 schema.
    storage.reset_schema();

    // add a DbtVec<ExpectedUtxoV4> to the schema at the correct position
    storage.schema.table_count = WalletDbTables::expected_utxo_table_count();
    let mut eutxos_v4 = storage
        .schema
        .new_vec::<migration::schema_v4::ExpectedUtxo>("expected_utxos")
        .await;

    /* Migrate expected UTXOs - add payment_id field */
    let eutxo_stream = eutxos_v3.stream().await;
    pin_mut!(eutxo_stream); // needed for iteration

    while let Some((list_index, eutxo_v3)) = eutxo_stream.next().await {
        let eutxo_v4 = migration::schema_v4::ExpectedUtxo {
            utxo: eutxo_v3.utxo,
            addition_record: eutxo_v3.addition_record,
            sender_randomness: eutxo_v3.sender_randomness,
            receiver_preimage: eutxo_v3.receiver_preimage,
            received_from: eutxo_v3.received_from,
            notification_received: eutxo_v3.notification_received,
            mined_in_block: eutxo_v3.mined_in_block,
            payment_id: BFieldElement::ZERO,
        };

        // Overwrite the v3 expected UTXO with a v4.
        debug!("Migrating expected UTXO number {list_index} to v4");
        eutxos_v4.set(list_index, eutxo_v4).await;
    }

    storage.persist().await;

    // Load tables to set schema version
    storage.reset_schema();
    let mut tables = WalletDbTables::load_schema_in_order(storage).await;
    tables.schema_version.set(4).await;

    // success!
    Ok(())
}

mod migration {
    pub(super) mod schema_v3 {
        use serde::Deserialize;
        use serde::Serialize;
        use tasm_lib::prelude::Digest;

        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::protocol::proof_abstractions::timestamp::Timestamp;
        use crate::state::wallet::expected_utxo::UtxoNotifier;
        use crate::util_types::mutator_set::addition_record::AdditionRecord;

        // This is a copy of ExpectedUtxo as it was in v3 schema (without payment_id).
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub(in super::super) struct ExpectedUtxo {
            pub utxo: Utxo,
            pub addition_record: AdditionRecord,
            pub sender_randomness: Digest,
            pub receiver_preimage: Digest,
            pub received_from: UtxoNotifier,
            pub notification_received: Timestamp,
            pub mined_in_block: Option<(Digest, Timestamp)>,
        }
    }

    pub(super) mod schema_v4 {
        use serde::Deserialize;
        use serde::Serialize;
        use tasm_lib::prelude::Digest;
        use tasm_lib::triton_vm::prelude::BFieldElement;

        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::protocol::proof_abstractions::timestamp::Timestamp;
        use crate::state::wallet::expected_utxo::UtxoNotifier;
        use crate::util_types::mutator_set::addition_record::AdditionRecord;

        // This is ExpectedUtxo as it is in v4 schema (with payment_id).
        // Must match production ExpectedUtxo exactly.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub(in super::super) struct ExpectedUtxo {
            pub utxo: Utxo,
            pub addition_record: AdditionRecord,
            pub sender_randomness: Digest,
            pub receiver_preimage: Digest,
            pub received_from: UtxoNotifier,
            pub notification_received: Timestamp,
            pub mined_in_block: Option<(Digest, Timestamp)>,
            #[serde(default)]
            pub payment_id: BFieldElement,
        }
    }
}
