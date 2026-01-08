//! Transaction building FFI
//!
//! Simple API: inputs + outputs => transaction with auto change

use neptune_privacy::api::export::NativeCurrencyAmount;
use neptune_privacy::api::export::PrimitiveWitness;
use neptune_privacy::api::export::Timestamp;
use neptune_privacy::api::export::TransactionDetails;
use neptune_privacy::api::export::TransactionProof;
use neptune_privacy::api::export::TxInputList;
use neptune_privacy::api::export::TxOutput;
use neptune_privacy::api::export::TxOutputList;
use neptune_privacy::api::export::UnlockedUtxo;
use neptune_privacy::application::json_rpc::core::model::wallet::transaction::RpcTransaction;
use neptune_privacy::protocol::consensus::transaction::Transaction;
use neptune_privacy::state::wallet::address::SpendingKey;

use crate::address::AddressHandle;
use crate::error::{set_last_error, XntErrorCode};
use crate::helpers::read_slice;
use crate::seed::SpendingKeyHandle;
use crate::sync::{MsMembershipProofHandle, MutatorSetHandle};
use crate::types::{ByteBuffer, XntDigest};
use crate::utxo::UtxoHandle;

// ============================================================================
// TransactionBuilder - Simple high-level API
// ============================================================================

/// Transaction builder - collects inputs and outputs, auto-calculates change
pub struct TransactionBuilderHandle {
    inputs: Vec<(UtxoHandle, SpendingKeyHandle, MsMembershipProofHandle)>,
    outputs: Vec<(AddressHandle, i128, XntDigest)>, // (address, amount, sender_randomness)
    change_address: Option<AddressHandle>,
    change_sender_randomness: Option<XntDigest>,
    fee: i128,
}

/// Create new transaction builder
#[no_mangle]
pub extern "C" fn xnt_tx_builder_create() -> *mut TransactionBuilderHandle {
    ffi_begin!();
    Box::into_raw(Box::new(TransactionBuilderHandle {
        inputs: Vec::new(),
        outputs: Vec::new(),
        change_address: None,
        change_sender_randomness: None,
        fee: 0,
    }))
}

/// Add input UTXO to spend (clones the handles, caller keeps ownership)
#[no_mangle]
pub extern "C" fn xnt_tx_builder_add_input(
    builder: *mut TransactionBuilderHandle,
    utxo: *const UtxoHandle,
    spending_key: *const SpendingKeyHandle,
    membership_proof: *const MsMembershipProofHandle,
) -> XntErrorCode {
    ffi_begin!();
    if builder.is_null() || utxo.is_null() || spending_key.is_null() || membership_proof.is_null() {
        set_last_error("null pointer");
        return XntErrorCode::NullPointer;
    }

    let b = ffi_mut!(builder);
    let u = UtxoHandle(ffi_ref!(utxo).0.clone());
    let k = SpendingKeyHandle(ffi_ref!(spending_key).0.clone());
    let m = MsMembershipProofHandle(ffi_ref!(membership_proof).0.clone());
    b.inputs.push((u, k, m));

    XntErrorCode::Ok
}

/// Add output recipient
#[no_mangle]
pub extern "C" fn xnt_tx_builder_add_output(
    builder: *mut TransactionBuilderHandle,
    address: *const AddressHandle,
    amount: i128,
    sender_randomness: *const XntDigest,
) -> XntErrorCode {
    ffi_begin!();
    if builder.is_null() || address.is_null() || sender_randomness.is_null() {
        set_last_error("null pointer");
        return XntErrorCode::NullPointer;
    }

    let b = ffi_mut!(builder);
    let addr = AddressHandle(ffi_ref!(address).0.clone());
    let sr = ffi_ref!(sender_randomness).clone();
    b.outputs.push((addr, amount, sr));

    XntErrorCode::Ok
}

/// Set change address (required if inputs > outputs + fee)
#[no_mangle]
pub extern "C" fn xnt_tx_builder_set_change(
    builder: *mut TransactionBuilderHandle,
    change_address: *const AddressHandle,
    sender_randomness: *const XntDigest,
) -> XntErrorCode {
    ffi_begin!();
    if builder.is_null() || change_address.is_null() || sender_randomness.is_null() {
        set_last_error("null pointer");
        return XntErrorCode::NullPointer;
    }

    let b = ffi_mut!(builder);
    b.change_address = Some(AddressHandle(ffi_ref!(change_address).0.clone()));
    b.change_sender_randomness = Some(ffi_ref!(sender_randomness).clone());

    XntErrorCode::Ok
}

/// Set transaction fee
#[no_mangle]
pub extern "C" fn xnt_tx_builder_set_fee(
    builder: *mut TransactionBuilderHandle,
    fee: i128,
) -> XntErrorCode {
    ffi_begin!();
    if builder.is_null() {
        set_last_error("null pointer");
        return XntErrorCode::NullPointer;
    }

    ffi_mut!(builder).fee = fee;
    XntErrorCode::Ok
}

/// Get total input amount
#[no_mangle]
pub extern "C" fn xnt_tx_builder_input_total(builder: *const TransactionBuilderHandle) -> i128 {
    if builder.is_null() { return 0; }
    ffi_ref!(builder).inputs.iter()
        .map(|(u, _, _)| u.0.get_native_currency_amount().to_nau())
        .sum()
}

/// Get total output amount (excluding change)
#[no_mangle]
pub extern "C" fn xnt_tx_builder_output_total(builder: *const TransactionBuilderHandle) -> i128 {
    if builder.is_null() { return 0; }
    ffi_ref!(builder).outputs.iter().map(|(_, amt, _)| *amt).sum()
}

/// Get calculated change amount (inputs - outputs - fee)
#[no_mangle]
pub extern "C" fn xnt_tx_builder_change_amount(builder: *const TransactionBuilderHandle) -> i128 {
    if builder.is_null() { return 0; }
    let b = ffi_ref!(builder);
    let input_total: i128 = b.inputs.iter()
        .map(|(u, _, _)| u.0.get_native_currency_amount().to_nau())
        .sum();
    let output_total: i128 = b.outputs.iter().map(|(_, amt, _)| *amt).sum();
    input_total - output_total - b.fee
}

ffi_free!(xnt_tx_builder_free, TransactionBuilderHandle);

// ============================================================================
// Build Transaction
// ============================================================================

/// Opaque handle to built transaction data
pub struct BuiltTransactionHandle {
    pub(crate) details: TransactionDetails,
    pub(crate) witness: PrimitiveWitness,
}

/// Build the transaction - creates TransactionDetails and PrimitiveWitness
/// Returns null if validation fails (check xnt_get_last_error)
#[no_mangle]
pub extern "C" fn xnt_tx_builder_build(
    builder: *const TransactionBuilderHandle,
    mutator_set: *const MutatorSetHandle,
    timestamp_ms: u64,
    network: crate::address::XntNetwork,
) -> *mut BuiltTransactionHandle {
    ffi_begin!();
    if builder.is_null() || mutator_set.is_null() {
        set_last_error("null pointer");
        return std::ptr::null_mut();
    }

    let b = ffi_ref!(builder);
    let msa = &ffi_ref!(mutator_set).0;

    // Validate
    if b.inputs.is_empty() {
        set_last_error("no inputs");
        return std::ptr::null_mut();
    }

    let input_total: i128 = b.inputs.iter()
        .map(|(u, _, _)| u.0.get_native_currency_amount().to_nau())
        .sum();
    let output_total: i128 = b.outputs.iter().map(|(_, amt, _)| *amt).sum();
    let change_amount = input_total - output_total - b.fee;

    if change_amount < 0 {
        set_last_error("insufficient funds");
        return std::ptr::null_mut();
    }

    if change_amount > 0 && b.change_address.is_none() {
        set_last_error("change address required");
        return std::ptr::null_mut();
    }

    // Build TxInputList
    let mut tx_inputs = TxInputList::empty();
    for (utxo, key, mp) in &b.inputs {
        // Get lock_script_and_witness from the underlying key type
        // (SpendingKey::lock_script_and_witness is pub(crate), but GenerationSpendingKey's is pub)
        let lock_script_and_witness = match &key.0 {
            SpendingKey::Generation(gen_key) => gen_key.lock_script_and_witness(),
            SpendingKey::Symmetric(_) => {
                set_last_error("symmetric keys not supported in FFI yet");
                return std::ptr::null_mut();
            }
        };
        let unlocked = UnlockedUtxo::unlock(
            utxo.0.clone(),
            lock_script_and_witness,
            mp.0.clone(),
        );
        tx_inputs.push(unlocked.into());
    }

    // Build TxOutputList
    let mut tx_outputs = TxOutputList::default();
    for (addr, amount, sr) in &b.outputs {
        let nca = NativeCurrencyAmount::from_nau(*amount);
        let output = TxOutput::onchain_native_currency(nca, sr.to_digest(), addr.0.clone().into(), false);
        tx_outputs.push(output);
    }

    // Add change output if needed
    if change_amount > 0 {
        if let (Some(addr), Some(sr)) = (&b.change_address, &b.change_sender_randomness) {
            let nca = NativeCurrencyAmount::from_nau(change_amount);
            let change_output = TxOutput::onchain_native_currency_as_change(nca, sr.to_digest(), addr.0.clone().into());
            tx_outputs.push(change_output);
        }
    }

    // Create TransactionDetails
    let details = TransactionDetails::new(
        tx_inputs,
        tx_outputs,
        NativeCurrencyAmount::from_nau(b.fee),
        None,
        Timestamp::millis(timestamp_ms),
        msa.clone(),
        network.into(),
    );

    // Create PrimitiveWitness
    let witness = PrimitiveWitness::from_transaction_details(&details);

    Box::into_raw(Box::new(BuiltTransactionHandle { details, witness }))
}

ffi_free!(xnt_built_transaction_free, BuiltTransactionHandle);

// ============================================================================
// Get data from built transaction
// ============================================================================

/// Get transaction kernel (public data)
#[no_mangle]
pub extern "C" fn xnt_built_transaction_kernel(handle: *const BuiltTransactionHandle) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");
    ffi_serialize!(ffi_ref!(handle).details.transaction_kernel())
}

/// Get primitive witness (secret data for prover)
#[no_mangle]
pub extern "C" fn xnt_built_transaction_witness(handle: *const BuiltTransactionHandle) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");
    ffi_serialize!(ffi_ref!(handle).witness)
}

/// Get full transaction with Witness proof (for sending to prover)
#[no_mangle]
pub extern "C" fn xnt_built_transaction_serialize(handle: *const BuiltTransactionHandle) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");

    let tx = Transaction {
        kernel: ffi_ref!(handle).witness.kernel.clone(),
        proof: TransactionProof::Witness(ffi_ref!(handle).witness.clone()),
    };
    ffi_serialize!(tx)
}

// ============================================================================
// Prove Transaction (creates ProofCollection - requires 16GB RAM)
// ============================================================================

/// Create ProofCollection from built transaction (blocking, ~16GB RAM)
/// Returns Transaction with ProofCollection proof, ready for SingleProof upgrade
#[no_mangle]
pub extern "C" fn xnt_built_transaction_prove(handle: *const BuiltTransactionHandle) -> *mut TransactionHandle {
    ffi_begin!();
    check_null!(handle, "null pointer");

    let witness = &ffi_ref!(handle).witness;

    // Create tokio runtime for async proving
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_last_error(&format!("runtime error: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Get job queue and produce proof collection (must run inside tokio context)
    let proof_collection = match rt.block_on(async {
        let job_queue = neptune_privacy::api::export::TritonVmJobQueue::get_instance();
        let options = neptune_privacy::api::export::TritonVmProofJobOptionsBuilder::new()
            .proving_capability(neptune_privacy::api::export::TxProvingCapability::ProofCollection)
            .build();
        neptune_privacy::api::export::ProofCollection::produce(witness, job_queue, options).await
    }) {
        Ok(pc) => pc,
        Err(e) => {
            set_last_error(&format!("proving failed: {}", e));
            return std::ptr::null_mut();
        }
    };

    let tx = Transaction {
        kernel: witness.kernel.clone(),
        proof: TransactionProof::ProofCollection(proof_collection),
    };

    Box::into_raw(Box::new(TransactionHandle(tx)))
}

// ============================================================================
// Transaction (final, with SingleProof from prover)
// ============================================================================

/// Opaque handle to final Transaction
pub struct TransactionHandle(pub(crate) Transaction);

/// Deserialize Transaction (received from prover with SingleProof)
#[no_mangle]
pub extern "C" fn xnt_transaction_deserialize(data: *const u8, len: usize) -> *mut TransactionHandle {
    ffi_begin!();
    if data.is_null() || len == 0 {
        set_last_error("invalid input");
        return std::ptr::null_mut();
    }
    let bytes = unsafe { read_slice(data, len) };
    ffi_result!(bincode::deserialize::<Transaction>(bytes), TransactionHandle, "deserialize failed")
}

/// Serialize Transaction for broadcast
#[no_mangle]
pub extern "C" fn xnt_transaction_serialize(handle: *const TransactionHandle) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");
    ffi_serialize!(ffi_ref!(handle).0)
}

/// Check if transaction has ProofCollection (locally proven, needs SingleProof for broadcast)
#[no_mangle]
pub extern "C" fn xnt_transaction_has_proof_collection(handle: *const TransactionHandle) -> bool {
    if handle.is_null() { return false; }
    matches!(ffi_ref!(handle).0.proof, TransactionProof::ProofCollection(_))
}

/// Check if transaction has SingleProof (ready for broadcast)
#[no_mangle]
pub extern "C" fn xnt_transaction_has_single_proof(handle: *const TransactionHandle) -> bool {
    if handle.is_null() { return false; }
    matches!(ffi_ref!(handle).0.proof, TransactionProof::SingleProof(_))
}

ffi_free!(xnt_transaction_free, TransactionHandle);

// ============================================================================
// Helper
// ============================================================================

/// Get current timestamp in milliseconds
#[no_mangle]
pub extern "C" fn xnt_timestamp_now() -> u64 {
    Timestamp::now().0.into()
}

// ============================================================================
// Submit Transaction via JSON-RPC
// ============================================================================

/// Submit transaction to node via JSON-RPC (mempool_submitTransaction)
///
/// Parameters:
/// - handle: Transaction to submit (must have ProofCollection or SingleProof)
/// - client: RPC client handle from xnt_rpc_client_create()
///
/// Returns XntErrorCode::Ok on success, error code on failure.
/// Check xnt_get_last_error() for details on failure.
#[no_mangle]
pub extern "C" fn xnt_transaction_submit(
    handle: *const TransactionHandle,
    client: *const crate::json_rpc::RpcClientHandle,
) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(client);

    let tx = &ffi_ref!(handle).0;

    // Check proof type - must be ProofCollection or SingleProof
    match &tx.proof {
        TransactionProof::Witness(_) => {
            set_last_error("cannot submit transaction with PrimitiveWitness proof - must be ProofCollection or SingleProof");
            return XntErrorCode::InvalidInput;
        }
        TransactionProof::ProofCollection(_) | TransactionProof::SingleProof(_) => {}
    }

    // Convert to RpcTransaction
    let rpc_tx: RpcTransaction = tx.clone().into();

    // Call RPC with named params
    let params = serde_json::json!({
        "transaction": rpc_tx
    });

    // Debug: check JSON size
    let json_size = serde_json::to_string(&params).map(|s| s.len()).unwrap_or(0);
    eprintln!("[DEBUG] submit tx JSON size: {} bytes ({:.1} MB)", json_size, json_size as f64 / 1_000_000.0);

    // Use fresh client for large transaction submission
    let client_handle = ffi_ref!(client);
    let fresh_client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))  // 5 min for large tx
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("failed to create client: {e}"));
            return XntErrorCode::NetworkError;
        }
    };

    // Build request manually
    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "mempool_submitTransaction",
        "params": params,
        "id": 1
    });
    let body = match serde_json::to_vec(&rpc_request) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(&format!("JSON serialize failed: {e}"));
            return XntErrorCode::DeserializeFailed;
        }
    };

    eprintln!("[DEBUG] sending {} bytes to {}", body.len(), client_handle.url);

    // Debug: write JSON to file for inspection
    if let Err(e) = std::fs::write("/tmp/submit_tx.json", &body) {
        eprintln!("[DEBUG] failed to write debug file: {e}");
    } else {
        eprintln!("[DEBUG] wrote JSON to /tmp/submit_tx.json");
    }

    let mut req_builder = fresh_client
        .post(&client_handle.url)
        .header("Content-Type", "application/json");

    // Apply auth from original client
    if let Some((ref username, ref password)) = client_handle.auth {
        req_builder = req_builder.basic_auth(username, Some(password));
    }

    req_builder = req_builder.body(body);

    let response = match req_builder.send() {
        Ok(r) => r,
        Err(e) => {
            let mut msg = format!("request failed: {e}");
            if let Some(source) = std::error::Error::source(&e) {
                msg.push_str(&format!(" (cause: {source})"));
            }
            set_last_error(&msg);
            return XntErrorCode::NetworkError;
        }
    };

    if !response.status().is_success() {
        set_last_error(&format!("HTTP error: {}", response.status()));
        return XntErrorCode::RpcError;
    }

    let response_text = match response.text() {
        Ok(t) => t,
        Err(e) => {
            set_last_error(&format!("read response failed: {e}"));
            return XntErrorCode::RpcError;
        }
    };

    eprintln!("[DEBUG] response: {}", &response_text[..response_text.len().min(500)]);

    let json: serde_json::Value = match serde_json::from_str(&response_text) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!("parse failed: {e}"));
            return XntErrorCode::RpcError;
        }
    };

    if let Some(error) = json.get("error") {
        let msg = error.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        set_last_error(&format!("RPC error: {msg}"));
        return XntErrorCode::RpcError;
    }

    match json.get("result") {
        Some(result) => {
            if result.get("success").and_then(|s| s.as_bool()).unwrap_or(false) {
                XntErrorCode::Ok
            } else {
                set_last_error("transaction submission failed");
                XntErrorCode::RpcError
            }
        }
        None => {
            set_last_error("missing result");
            XntErrorCode::RpcError
        }
    }
}
