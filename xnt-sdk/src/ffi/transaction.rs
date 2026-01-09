//! Transaction building FFI
//!
//! Wraps core transaction types for C FFI.

use std::ffi::c_char;

use crate::core::{
    timestamp_now, BuiltTransaction, Transaction, TransactionBuilder,
};

use super::address::{AddressHandle, ReceivingAddressHandle, XntNetwork};
use super::error::{set_last_error, XntErrorCode};
use super::helpers::read_slice;
use super::json_rpc::RpcClientHandle;
use super::seed::SpendingKeyHandle;
use super::sync::{MsMembershipProofHandle, MutatorSetHandle};
use super::types::{ByteBuffer, XntDigest};
use super::utxo::UtxoHandle;

// TransactionBuilder - Simple high-level API

/// Transaction builder handle
pub struct TransactionBuilderHandle(pub(crate) TransactionBuilder);

/// Create new transaction builder
#[no_mangle]
pub extern "C" fn xnt_tx_builder_create() -> *mut TransactionBuilderHandle {
    ffi_begin!();
    Box::into_raw(Box::new(TransactionBuilderHandle(TransactionBuilder::new())))
}

/// Add input UTXO to spend
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
    b.0.add_input(
        ffi_ref!(utxo).0.clone(),
        ffi_ref!(spending_key).0.clone(),
        ffi_ref!(membership_proof).0.clone(),
    );

    XntErrorCode::Ok
}

/// Add output (takes ReceivingAddress - works for both main and subaddresses)
#[no_mangle]
pub extern "C" fn xnt_tx_builder_add_output(
    builder: *mut TransactionBuilderHandle,
    receiving_address: *const ReceivingAddressHandle,
    amount: i128,
    sender_randomness: *const XntDigest,
) -> XntErrorCode {
    ffi_begin!();
    if builder.is_null() || receiving_address.is_null() || sender_randomness.is_null() {
        set_last_error("null pointer");
        return XntErrorCode::NullPointer;
    }

    let b = ffi_mut!(builder);
    let sr = crate::core::Digest::from_bytes(ffi_ref!(sender_randomness).bytes);
    b.0.add_output(ffi_ref!(receiving_address).0.clone(), amount, sr);

    XntErrorCode::Ok
}

/// Set change address
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
    let sr = crate::core::Digest::from_bytes(ffi_ref!(sender_randomness).bytes);
    b.0.set_change(ffi_ref!(change_address).0.clone(), sr);

    XntErrorCode::Ok
}

/// Set transaction fee
#[no_mangle]
pub extern "C" fn xnt_tx_builder_set_fee(builder: *mut TransactionBuilderHandle, fee: i128) -> XntErrorCode {
    ffi_begin!();
    if builder.is_null() {
        set_last_error("null pointer");
        return XntErrorCode::NullPointer;
    }

    ffi_mut!(builder).0.set_fee(fee);
    XntErrorCode::Ok
}

/// Get total input amount
#[no_mangle]
pub extern "C" fn xnt_tx_builder_input_total(builder: *const TransactionBuilderHandle) -> i128 {
    if builder.is_null() { return 0; }
    ffi_ref!(builder).0.input_total()
}

/// Get total output amount
#[no_mangle]
pub extern "C" fn xnt_tx_builder_output_total(builder: *const TransactionBuilderHandle) -> i128 {
    if builder.is_null() { return 0; }
    ffi_ref!(builder).0.output_total()
}

/// Get calculated change amount
#[no_mangle]
pub extern "C" fn xnt_tx_builder_change_amount(builder: *const TransactionBuilderHandle) -> i128 {
    if builder.is_null() { return 0; }
    ffi_ref!(builder).0.change_amount()
}

ffi_free!(xnt_tx_builder_free, TransactionBuilderHandle);

// Build Transaction

/// Opaque handle to built transaction
pub struct BuiltTransactionHandle(pub(crate) BuiltTransaction);

/// Build the transaction
#[no_mangle]
pub extern "C" fn xnt_tx_builder_build(
    builder: *const TransactionBuilderHandle,
    mutator_set: *const MutatorSetHandle,
    timestamp_ms: u64,
    network: XntNetwork,
) -> *mut BuiltTransactionHandle {
    ffi_begin!();
    if builder.is_null() || mutator_set.is_null() {
        set_last_error("null pointer");
        return std::ptr::null_mut();
    }

    let b = ffi_ref!(builder);
    let msa = &ffi_ref!(mutator_set).0;

    match b.0.build(msa, timestamp_ms, network.into()) {
        Ok(built) => Box::into_raw(Box::new(BuiltTransactionHandle(built))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

ffi_free!(xnt_built_transaction_free, BuiltTransactionHandle);

/// Prove the built transaction (creates ProofCollection)
/// This is a blocking operation that can take significant time and memory
#[no_mangle]
pub extern "C" fn xnt_built_transaction_prove(handle: *const BuiltTransactionHandle) -> *mut TransactionHandle {
    ffi_begin!();
    check_null!(handle, "null pointer");

    let built = ffi_ref!(handle);

    // Create a new runtime for async operations
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_last_error(&format!("failed to create runtime: {e}"));
            return std::ptr::null_mut();
        }
    };

    // Block on the async prove function
    match runtime.block_on(built.0.prove()) {
        Ok(tx) => Box::into_raw(Box::new(TransactionHandle(tx))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get transaction kernel bytes
#[no_mangle]
pub extern "C" fn xnt_built_transaction_kernel(handle: *const BuiltTransactionHandle) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");

    match ffi_ref!(handle).0.kernel_bytes() {
        Ok(bytes) => ByteBuffer::from_vec(bytes).into_ptr(),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get primitive witness bytes
#[no_mangle]
pub extern "C" fn xnt_built_transaction_witness(handle: *const BuiltTransactionHandle) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");

    match ffi_ref!(handle).0.witness_bytes() {
        Ok(bytes) => ByteBuffer::from_vec(bytes).into_ptr(),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Serialize full transaction with Witness proof
#[no_mangle]
pub extern "C" fn xnt_built_transaction_serialize(handle: *const BuiltTransactionHandle) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");

    match ffi_ref!(handle).0.to_bytes() {
        Ok(bytes) => ByteBuffer::from_vec(bytes).into_ptr(),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

// Transaction (final)

/// Opaque handle to final Transaction
pub struct TransactionHandle(pub(crate) Transaction);

/// Deserialize Transaction
#[no_mangle]
pub extern "C" fn xnt_transaction_deserialize(data: *const u8, len: usize) -> *mut TransactionHandle {
    ffi_begin!();
    if data.is_null() || len == 0 {
        set_last_error("invalid input");
        return std::ptr::null_mut();
    }
    let bytes = unsafe { read_slice(data, len) };
    match Transaction::from_bytes(bytes) {
        Ok(tx) => Box::into_raw(Box::new(TransactionHandle(tx))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Serialize Transaction for broadcast
#[no_mangle]
pub extern "C" fn xnt_transaction_serialize(handle: *const TransactionHandle) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");

    match ffi_ref!(handle).0.to_bytes() {
        Ok(bytes) => ByteBuffer::from_vec(bytes).into_ptr(),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Check if transaction has ProofCollection
#[no_mangle]
pub extern "C" fn xnt_transaction_has_proof_collection(handle: *const TransactionHandle) -> bool {
    if handle.is_null() { return false; }
    ffi_ref!(handle).0.has_proof_collection()
}

/// Check if transaction has SingleProof
#[no_mangle]
pub extern "C" fn xnt_transaction_has_single_proof(handle: *const TransactionHandle) -> bool {
    if handle.is_null() { return false; }
    ffi_ref!(handle).0.has_single_proof()
}

/// Submit transaction to node via RPC
#[no_mangle]
pub extern "C" fn xnt_transaction_submit(
    handle: *const TransactionHandle,
    client: *const RpcClientHandle,
) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(client);

    let tx = &ffi_ref!(handle).0;
    let client = &ffi_ref!(client).0;

    match tx.submit(client) {
        Ok(_) => XntErrorCode::Ok,
        Err(e) => {
            set_last_error(&format!("{e}"));
            XntErrorCode::RpcError
        }
    }
}

ffi_free!(xnt_transaction_free, TransactionHandle);

/// Get current timestamp in milliseconds
#[no_mangle]
pub extern "C" fn xnt_timestamp_now() -> u64 {
    timestamp_now()
}

/// Select UTXOs to cover target amount (smallest-first)
/// out_indices: buffer to write selected indices, must have capacity >= limit
/// out_capacity: capacity of out_indices buffer (must be >= limit)
/// Returns count of selected indices, writes indices to out_indices
/// Returns -1 on error
#[no_mangle]
pub extern "C" fn xnt_select_inputs(
    amounts: *const i128,
    amounts_len: usize,
    target: i128,
    limit: usize,
    out_indices: *mut usize,
    out_capacity: usize,
) -> i32 {
    ffi_begin!();
    if amounts.is_null() || out_indices.is_null() {
        set_last_error("null pointer");
        return -1;
    }
    if out_capacity < limit {
        set_last_error("out_capacity must be >= limit");
        return -1;
    }

    let amts = unsafe { std::slice::from_raw_parts(amounts, amounts_len) };
    match crate::core::select_inputs(amts, target, limit) {
        Ok(indices) => {
            // Safety: indices.len() <= limit <= out_capacity
            for (i, idx) in indices.iter().enumerate() {
                unsafe { *out_indices.add(i) = *idx };
            }
            indices.len() as i32
        }
        Err(e) => {
            set_last_error(&format!("{e}"));
            -1
        }
    }
}

/// Generate random sender_randomness as XntDigest
#[no_mangle]
pub extern "C" fn xnt_random_sender_randomness() -> XntDigest {
    use rand::Rng;
    let mut bytes = [0u8; 40];
    rand::rng().fill(&mut bytes);
    XntDigest::from_bytes(bytes)
}

/// Generate random sender_randomness as hex string
#[no_mangle]
pub extern "C" fn xnt_random_sender_randomness_hex() -> *mut c_char {
    ffi_begin!();
    use rand::Rng;
    let mut bytes = [0u8; 40];
    rand::rng().fill(&mut bytes);
    ffi_cstring!(hex::encode(bytes))
}

// Transaction Input/Output Info

/// Transaction input info (C-compatible)
#[repr(C)]
pub struct XntTxInputInfo {
    pub utxo: *mut UtxoHandle,
    pub sender_randomness: XntDigest,
    pub commitment: XntDigest,
    pub amount: i128,
}

/// Transaction output info (C-compatible)
#[repr(C)]
pub struct XntTxOutputInfo {
    pub utxo: *mut UtxoHandle,
    pub sender_randomness: XntDigest,
    pub receiver_digest: XntDigest,
    pub commitment: XntDigest,
    pub amount: i128,
    pub is_change: bool,
    pub payment_id: u64,
}

/// Array of input info
#[repr(C)]
pub struct XntTxInputInfoArray {
    pub data: *mut XntTxInputInfo,
    pub len: usize,
}

/// Array of output info
#[repr(C)]
pub struct XntTxOutputInfoArray {
    pub data: *mut XntTxOutputInfo,
    pub len: usize,
}

/// Get all inputs from built transaction
#[no_mangle]
pub extern "C" fn xnt_built_transaction_inputs(handle: *const BuiltTransactionHandle) -> *mut XntTxInputInfoArray {
    ffi_begin!();
    if handle.is_null() {
        set_last_error("null pointer");
        return std::ptr::null_mut();
    }

    let built = ffi_ref!(handle);
    let inputs = built.0.inputs();

    let mut infos: Vec<XntTxInputInfo> = inputs
        .into_iter()
        .map(|i| {
            let amount = i.utxo.amount();
            let sender_randomness = XntDigest::from_bytes(i.sender_randomness.bytes);
            let commitment = XntDigest::from_bytes(i.commitment.bytes);
            XntTxInputInfo {
                utxo: Box::into_raw(Box::new(UtxoHandle(i.utxo))),
                sender_randomness,
                commitment,
                amount,
            }
        })
        .collect();

    let len = infos.len();
    let data = infos.as_mut_ptr();
    std::mem::forget(infos);

    Box::into_raw(Box::new(XntTxInputInfoArray { data, len }))
}

/// Get all outputs from built transaction
#[no_mangle]
pub extern "C" fn xnt_built_transaction_outputs(handle: *const BuiltTransactionHandle) -> *mut XntTxOutputInfoArray {
    ffi_begin!();
    if handle.is_null() {
        set_last_error("null pointer");
        return std::ptr::null_mut();
    }

    let built = ffi_ref!(handle);
    let outputs = built.0.outputs();

    let mut infos: Vec<XntTxOutputInfo> = outputs
        .into_iter()
        .map(|o| {
            let sender_randomness = XntDigest::from_bytes(o.sender_randomness.bytes);
            let receiver_digest = XntDigest::from_bytes(o.receiver_digest.bytes);
            let commitment = XntDigest::from_bytes(o.commitment.bytes);
            let is_change = o.is_change;
            let payment_id = o.payment_id.unwrap_or(0);
            let amount = o.utxo.amount();
            XntTxOutputInfo {
                utxo: Box::into_raw(Box::new(UtxoHandle(o.utxo))),
                sender_randomness,
                receiver_digest,
                commitment,
                amount,
                is_change,
                payment_id,
            }
        })
        .collect();

    let len = infos.len();
    let data = infos.as_mut_ptr();
    std::mem::forget(infos);

    Box::into_raw(Box::new(XntTxOutputInfoArray { data, len }))
}

/// Free input info array
#[no_mangle]
pub extern "C" fn xnt_tx_input_info_array_free(arr: *mut XntTxInputInfoArray) {
    if arr.is_null() { return; }
    let arr = unsafe { Box::from_raw(arr) };
    if !arr.data.is_null() {
        let infos = unsafe { Vec::from_raw_parts(arr.data, arr.len, arr.len) };
        for info in infos {
            if !info.utxo.is_null() {
                unsafe { drop(Box::from_raw(info.utxo)) };
            }
        }
    }
}

/// Free output info array
#[no_mangle]
pub extern "C" fn xnt_tx_output_info_array_free(arr: *mut XntTxOutputInfoArray) {
    if arr.is_null() { return; }
    let arr = unsafe { Box::from_raw(arr) };
    if !arr.data.is_null() {
        let infos = unsafe { Vec::from_raw_parts(arr.data, arr.len, arr.len) };
        for info in infos {
            if !info.utxo.is_null() {
                unsafe { drop(Box::from_raw(info.utxo)) };
            }
        }
    }
}
