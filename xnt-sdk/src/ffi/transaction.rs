//! Transaction building FFI
//!
//! Wraps core transaction types for C FFI.

use std::ffi::c_char;
use std::sync::OnceLock;

use crate::core::{
    timestamp_now, BuiltTransaction, Transaction, TransactionBuilder,
};

/// Persistent tokio runtime shared across all prove() calls.
/// Keeps the TritonVmJobQueue background task alive between calls.
fn global_tokio_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("failed to create global tokio runtime")
    })
}

use super::address::{network_from_raw, AddressHandle, ReceivingAddressHandle};
use super::error::{ffi_guard, set_last_error, XntErrorCode};
use super::helpers::{free_handle, read_amount_le, read_slice};
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
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        Box::into_raw(Box::new(
            TransactionBuilderHandle(TransactionBuilder::new()),
        ))
    })
}

/// Add input UTXO to spend
#[no_mangle]
pub extern "C" fn xnt_tx_builder_add_input(
    builder: *mut TransactionBuilderHandle,
    utxo: *const UtxoHandle,
    spending_key: *const SpendingKeyHandle,
    membership_proof: *const MsMembershipProofHandle,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        if builder.is_null()
            || utxo.is_null()
            || spending_key.is_null()
            || membership_proof.is_null()
        {
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
    })
}

/// Add output (takes ReceivingAddress - works for both main and subaddresses)
///
/// `amount` is passed as a 128-bit integer; see xnt_tx_builder_add_output_le
/// for callers without one.
#[no_mangle]
pub extern "C" fn xnt_tx_builder_add_output(
    builder: *mut TransactionBuilderHandle,
    receiving_address: *const ReceivingAddressHandle,
    amount: i128,
    sender_randomness: *const XntDigest,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        if builder.is_null() || receiving_address.is_null() || sender_randomness.is_null() {
            set_last_error("null pointer");
            return XntErrorCode::NullPointer;
        }

        let b = ffi_mut!(builder);
        let sr = crate::core::Digest::from_bytes(ffi_ref!(sender_randomness).bytes);
        b.0.add_output(ffi_ref!(receiving_address).0.clone(), amount, sr);

        XntErrorCode::Ok
    })
}

/// Add output, with `amount_le` pointing to the amount in nau as 16 bytes,
/// little-endian two's complement
#[no_mangle]
pub extern "C" fn xnt_tx_builder_add_output_le(
    builder: *mut TransactionBuilderHandle,
    receiving_address: *const ReceivingAddressHandle,
    amount_le: *const u8,
    sender_randomness: *const XntDigest,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(amount_le);
        xnt_tx_builder_add_output(
            builder,
            receiving_address,
            unsafe { read_amount_le(amount_le) },
            sender_randomness,
        )
    })
}

/// Set change address
#[no_mangle]
pub extern "C" fn xnt_tx_builder_set_change(
    builder: *mut TransactionBuilderHandle,
    change_address: *const AddressHandle,
    sender_randomness: *const XntDigest,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        if builder.is_null() || change_address.is_null() || sender_randomness.is_null() {
            set_last_error("null pointer");
            return XntErrorCode::NullPointer;
        }

        let b = ffi_mut!(builder);
        let sr = crate::core::Digest::from_bytes(ffi_ref!(sender_randomness).bytes);
        b.0.set_change(ffi_ref!(change_address).0.clone(), sr);

        XntErrorCode::Ok
    })
}

/// Set transaction fee
///
/// Building fails for a fee below 0.0005 coins per input, including a zero
/// fee, unless xnt_tx_builder_set_allow_low_fee is set. See
/// xnt_tx_builder_set_fee_le for callers without a 128-bit integer.
#[no_mangle]
pub extern "C" fn xnt_tx_builder_set_fee(builder: *mut TransactionBuilderHandle, fee: i128) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        if builder.is_null() {
            set_last_error("null pointer");
            return XntErrorCode::NullPointer;
        }

        ffi_mut!(builder).0.set_fee(fee);
        XntErrorCode::Ok
    })
}

/// Set transaction fee, with `fee_le` pointing to the fee in nau as 16 bytes,
/// little-endian two's complement
#[no_mangle]
pub extern "C" fn xnt_tx_builder_set_fee_le(
    builder: *mut TransactionBuilderHandle,
    fee_le: *const u8,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(fee_le);
        xnt_tx_builder_set_fee(builder, unsafe { read_amount_le(fee_le) })
    })
}

/// Allow a fee below the default minimum relay fee (0.0005 coins per input),
/// including a zero fee.
///
/// Nodes with the default --min-relay-pctx-fee-per-input neither keep nor
/// relay such a transaction; use this only with a node configured to accept
/// it.
#[no_mangle]
pub extern "C" fn xnt_tx_builder_set_allow_low_fee(
    builder: *mut TransactionBuilderHandle,
    allow: bool,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(builder);
        ffi_mut!(builder).0.set_allow_low_fee(allow);
        XntErrorCode::Ok
    })
}

/// Get total input amount
#[no_mangle]
pub extern "C" fn xnt_tx_builder_input_total(builder: *const TransactionBuilderHandle) -> i128 {
    ffi_guard(0, || {
        if builder.is_null() {
            return 0;
        }
        ffi_ref!(builder).0.input_total()
    })
}

/// Get total output amount
#[no_mangle]
pub extern "C" fn xnt_tx_builder_output_total(builder: *const TransactionBuilderHandle) -> i128 {
    ffi_guard(0, || {
        if builder.is_null() {
            return 0;
        }
        ffi_ref!(builder).0.output_total()
    })
}

/// Get calculated change amount
#[no_mangle]
pub extern "C" fn xnt_tx_builder_change_amount(builder: *const TransactionBuilderHandle) -> i128 {
    ffi_guard(0, || {
        if builder.is_null() {
            return 0;
        }
        ffi_ref!(builder).0.change_amount()
    })
}

/// Write the total input amount in nau to `out` as 16 bytes, little-endian
/// two's complement
#[no_mangle]
pub extern "C" fn xnt_tx_builder_input_total_le(
    builder: *const TransactionBuilderHandle,
    out: *mut u8,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(builder, out);
        let amount = ffi_ref!(builder).0.input_total();
        copy_bytes_out!(amount.to_le_bytes(), out, 16)
    })
}

/// Write the total output amount in nau to `out` as 16 bytes, little-endian
/// two's complement
#[no_mangle]
pub extern "C" fn xnt_tx_builder_output_total_le(
    builder: *const TransactionBuilderHandle,
    out: *mut u8,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(builder, out);
        let amount = ffi_ref!(builder).0.output_total();
        copy_bytes_out!(amount.to_le_bytes(), out, 16)
    })
}

/// Write the calculated change amount in nau to `out` as 16 bytes,
/// little-endian two's complement
#[no_mangle]
pub extern "C" fn xnt_tx_builder_change_amount_le(
    builder: *const TransactionBuilderHandle,
    out: *mut u8,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(builder, out);
        let amount = ffi_ref!(builder).0.change_amount();
        copy_bytes_out!(amount.to_le_bytes(), out, 16)
    })
}

/// Free a transaction builder handle. NULL is ignored.
#[no_mangle]
pub extern "C" fn xnt_tx_builder_free(handle: *mut TransactionBuilderHandle) {
    ffi_guard((), || free_handle(handle))
}

// Build Transaction

/// Opaque handle to built transaction
pub struct BuiltTransactionHandle(pub(crate) BuiltTransaction);

/// Build the transaction
///
/// `network` is one of the XntNetwork values. Fails for more than 200 inputs,
/// for a fee below the minimum relay fee (see xnt_tx_builder_set_fee), and
/// for a recipient that cannot receive a UTXO notification (legacy-format
/// dCTIDH lock or invalid dCTIDH public key).
#[no_mangle]
pub extern "C" fn xnt_tx_builder_build(
    builder: *const TransactionBuilderHandle,
    mutator_set: *const MutatorSetHandle,
    timestamp_ms: u64,
    network: u32,
) -> *mut BuiltTransactionHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        if builder.is_null() || mutator_set.is_null() {
            set_last_error("null pointer");
            return std::ptr::null_mut();
        }
        let Some(network) = network_from_raw(network) else {
            set_last_error("invalid network");
            return std::ptr::null_mut();
        };

        let b = ffi_ref!(builder);
        let msa = &ffi_ref!(mutator_set).0;

        match b.0.build(msa, timestamp_ms, network) {
            Ok(built) => Box::into_raw(Box::new(BuiltTransactionHandle(built))),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Free a built transaction handle. NULL is ignored.
#[no_mangle]
pub extern "C" fn xnt_built_transaction_free(handle: *mut BuiltTransactionHandle) {
    ffi_guard((), || free_handle(handle))
}

/// Prove the built transaction (creates ProofCollection) for the consensus rule
/// set of the block that follows the tip whose mutator set it was built on, as
/// xnt_built_transaction_prove_for_tip does with that tip's height: before the
/// UpgradeVMv8 hard fork at main-net block 95000, a v7 proof collection.
/// Fails if that height is unknown (see xnt_mutator_set_tip_height); then
/// record it with xnt_mutator_set_set_tip_height before building, or use
/// xnt_built_transaction_prove_for_tip.
/// This is a blocking operation that can take significant time and memory
#[no_mangle]
pub extern "C" fn xnt_built_transaction_prove(handle: *const BuiltTransactionHandle) -> *mut TransactionHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");

        let built = ffi_ref!(handle);

        let runtime = global_tokio_runtime();

        match runtime.block_on(built.0.prove()) {
            Ok(tx) => Box::into_raw(Box::new(TransactionHandle(tx))),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Prove the built transaction (creates ProofCollection) for the consensus rule
/// set of the block that follows a tip at `tip_height`: before the UpgradeVMv8
/// hard fork on main net, a v7 proof collection. Fails if the transaction does
/// not meet the terms of that era, or if the fork is too close.
/// This is a blocking operation that can take significant time and memory
#[no_mangle]
pub extern "C" fn xnt_built_transaction_prove_for_tip(handle: *const BuiltTransactionHandle, tip_height: u64) -> *mut TransactionHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");

        let built = ffi_ref!(handle);

        let runtime = global_tokio_runtime();

        match runtime.block_on(built.0.prove_for_tip(tip_height)) {
            Ok(tx) => Box::into_raw(Box::new(TransactionHandle(tx))),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Get transaction kernel bytes
#[no_mangle]
pub extern "C" fn xnt_built_transaction_kernel(handle: *const BuiltTransactionHandle) -> *mut ByteBuffer {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");

        match ffi_ref!(handle).0.kernel_bytes() {
            Ok(bytes) => ByteBuffer::from_vec(bytes).into_ptr(),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Get primitive witness bytes
///
/// The witness holds the unlock data of every input, which for dCTIDH inputs
/// is the key's spending secret (see xnt_spending_key_receiver_preimage).
/// Keep it on the device that holds the seed.
#[no_mangle]
pub extern "C" fn xnt_built_transaction_witness(handle: *const BuiltTransactionHandle) -> *mut ByteBuffer {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");

        match ffi_ref!(handle).0.witness_bytes() {
            Ok(bytes) => ByteBuffer::from_vec(bytes).into_ptr(),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Serialize full transaction with Witness proof
///
/// Contains the primitive witness, a spending secret for dCTIDH inputs (see
/// xnt_built_transaction_witness). Keep it on the device that holds the seed.
#[no_mangle]
pub extern "C" fn xnt_built_transaction_serialize(handle: *const BuiltTransactionHandle) -> *mut ByteBuffer {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");

        match ffi_ref!(handle).0.to_bytes() {
            Ok(bytes) => ByteBuffer::from_vec(bytes).into_ptr(),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Check the (unproven) transaction is still confirmable against a mutator set.
/// Returns true if it can still be proven & submitted. Call BEFORE prove() with
/// the current tip mutator set (xnt_sync_get_mutator_set) to avoid proving a
/// stale snapshot.
#[no_mangle]
pub extern "C" fn xnt_built_transaction_is_confirmable(
    handle: *const BuiltTransactionHandle,
    mutator_set: *const MutatorSetHandle,
) -> bool {
    ffi_guard(false, || {
        if handle.is_null() || mutator_set.is_null() {
            return false;
        }
        ffi_ref!(handle).0.is_confirmable(&ffi_ref!(mutator_set).0)
    })
}

// Transaction (final)

/// Opaque handle to final Transaction
pub struct TransactionHandle(pub(crate) Transaction);

/// Deserialize Transaction
#[no_mangle]
pub extern "C" fn xnt_transaction_deserialize(data: *const u8, len: usize) -> *mut TransactionHandle {
    ffi_guard(std::ptr::null_mut(), || {
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
    })
}

/// Serialize Transaction for broadcast
#[no_mangle]
pub extern "C" fn xnt_transaction_serialize(handle: *const TransactionHandle) -> *mut ByteBuffer {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");

        match ffi_ref!(handle).0.to_bytes() {
            Ok(bytes) => ByteBuffer::from_vec(bytes).into_ptr(),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Check if transaction has ProofCollection
#[no_mangle]
pub extern "C" fn xnt_transaction_has_proof_collection(handle: *const TransactionHandle) -> bool {
    ffi_guard(false, || {
        if handle.is_null() {
            return false;
        }
        ffi_ref!(handle).0.has_proof_collection()
    })
}

/// Check if transaction has SingleProof
#[no_mangle]
pub extern "C" fn xnt_transaction_has_single_proof(handle: *const TransactionHandle) -> bool {
    ffi_guard(false, || {
        if handle.is_null() {
            return false;
        }
        ffi_ref!(handle).0.has_single_proof()
    })
}

/// Check the transaction is confirmable against a mutator set (mirrors the node
/// submit gate). Call with the current tip mutator set (xnt_sync_get_mutator_set)
/// before submit() to detect a transaction that went stale while proving.
#[no_mangle]
pub extern "C" fn xnt_transaction_is_confirmable(
    handle: *const TransactionHandle,
    mutator_set: *const MutatorSetHandle,
) -> bool {
    ffi_guard(false, || {
        if handle.is_null() || mutator_set.is_null() {
            return false;
        }
        ffi_ref!(handle).0.is_confirmable(&ffi_ref!(mutator_set).0)
    })
}

/// Submit transaction to node via RPC
///
/// Ok only means the node passed its validity and confirmability checks and
/// queued the transaction for its mempool; the node can still drop it, for
/// example if the fee is below its relay minimum. Confirm by looking the
/// transaction up in the mempool or waiting for its outputs on chain.
#[no_mangle]
pub extern "C" fn xnt_transaction_submit(
    handle: *const TransactionHandle,
    client: *const RpcClientHandle,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        check_null!(handle);
        check_null!(client);

        let tx = &ffi_ref!(handle).0;
        let client = &ffi_ref!(client).0;

        match tx.submit(client) {
            Ok(true) => XntErrorCode::Ok,
            Ok(false) => {
                set_last_error("transaction submission rejected by node (success=false)");
                XntErrorCode::RpcError
            }
            Err(e) => {
                set_last_error(&format!("{e}"));
                XntErrorCode::RpcError
            }
        }
    })
}

/// Free a transaction handle. NULL is ignored.
#[no_mangle]
pub extern "C" fn xnt_transaction_free(handle: *mut TransactionHandle) {
    ffi_guard((), || free_handle(handle))
}

/// Get current timestamp in milliseconds
#[no_mangle]
pub extern "C" fn xnt_timestamp_now() -> u64 {
    ffi_guard(0, timestamp_now)
}

/// Select UTXOs to cover target amount (smallest-first)
/// out_indices: buffer to write selected indices, must have capacity >= limit
/// out_capacity: capacity of out_indices buffer (must be >= limit)
/// Returns count of selected indices, writes indices to out_indices
/// Returns -1 on error
/// At most 200 inputs are selected, whatever `limit` is. See
/// xnt_select_inputs_le for callers without a 128-bit integer.
#[no_mangle]
pub extern "C" fn xnt_select_inputs(
    amounts: *const i128,
    amounts_len: usize,
    target: i128,
    limit: usize,
    out_indices: *mut usize,
    out_capacity: usize,
) -> i32 {
    ffi_guard(-1, || {
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
    })
}

/// Generate random sender_randomness as XntDigest
#[no_mangle]
pub extern "C" fn xnt_random_sender_randomness() -> XntDigest {
    ffi_guard(XntDigest::new(), || {
        use rand::RngExt;
        let mut bytes = [0u8; 40];
        rand::rng().fill(&mut bytes);
        XntDigest::from_bytes(bytes)
    })
}

/// Generate random sender_randomness as hex string
#[no_mangle]
pub extern "C" fn xnt_random_sender_randomness_hex() -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        use rand::RngExt;
        let mut bytes = [0u8; 40];
        rand::rng().fill(&mut bytes);
        ffi_cstring!(hex::encode(bytes))
    })
}

/// Select UTXOs to cover target amount (smallest-first), like
/// xnt_select_inputs, with amounts in nau passed as 16 bytes each,
/// little-endian two's complement: `amounts_le` holds `amounts_len` such
/// amounts back to back and `target_le` points to one.
#[no_mangle]
pub extern "C" fn xnt_select_inputs_le(
    amounts_le: *const u8,
    amounts_len: usize,
    target_le: *const u8,
    limit: usize,
    out_indices: *mut usize,
    out_capacity: usize,
) -> i32 {
    ffi_guard(-1, || {
        ffi_begin!();
        if (amounts_le.is_null() && amounts_len > 0) || target_le.is_null() || out_indices.is_null()
        {
            set_last_error("null pointer");
            return -1;
        }
        if out_capacity < limit {
            set_last_error("out_capacity must be >= limit");
            return -1;
        }
        let Some(num_bytes) = amounts_len.checked_mul(16) else {
            set_last_error("too many amounts");
            return -1;
        };

        let bytes = unsafe { read_slice(amounts_le, num_bytes) };
        let amts: Vec<i128> = bytes
            .chunks_exact(16)
            .map(|chunk| unsafe { read_amount_le(chunk.as_ptr()) })
            .collect();
        let target = unsafe { read_amount_le(target_le) };
        match crate::core::select_inputs(&amts, target, limit) {
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
    })
}

// Transaction Input/Output Info

/// Transaction input info (C-compatible)
///
/// `amount` is a 128-bit integer aligned to 16 bytes. Callers without one can
/// read it as two 64-bit halves (low half first on little-endian targets) or
/// call xnt_utxo_get_amount_le on `utxo`.
#[repr(C)]
pub struct XntTxInputInfo {
    pub utxo: *mut UtxoHandle,
    pub sender_randomness: XntDigest,
    pub commitment: XntDigest,
    pub amount: i128,
}

/// Transaction output info (C-compatible)
///
/// `amount` is a 128-bit integer, see XntTxInputInfo.
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
    ffi_guard(std::ptr::null_mut(), || {
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
    })
}

/// Get all outputs from built transaction
#[no_mangle]
pub extern "C" fn xnt_built_transaction_outputs(handle: *const BuiltTransactionHandle) -> *mut XntTxOutputInfoArray {
    ffi_guard(std::ptr::null_mut(), || {
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
    })
}

/// Free input info array
#[no_mangle]
pub extern "C" fn xnt_tx_input_info_array_free(arr: *mut XntTxInputInfoArray) {
    ffi_guard((), || {
        if arr.is_null() {
            return;
        }
        let arr = unsafe { Box::from_raw(arr) };
        if !arr.data.is_null() {
            let infos = unsafe { Vec::from_raw_parts(arr.data, arr.len, arr.len) };
            for info in infos {
                if !info.utxo.is_null() {
                    unsafe { drop(Box::from_raw(info.utxo)) };
                }
            }
        }
    })
}

/// Free output info array
#[no_mangle]
pub extern "C" fn xnt_tx_output_info_array_free(arr: *mut XntTxOutputInfoArray) {
    ffi_guard((), || {
        if arr.is_null() {
            return;
        }
        let arr = unsafe { Box::from_raw(arr) };
        if !arr.data.is_null() {
            let infos = unsafe { Vec::from_raw_parts(arr.data, arr.len, arr.len) };
            for info in infos {
                if !info.utxo.is_null() {
                    unsafe { drop(Box::from_raw(info.utxo)) };
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::address::{xnt_address_free, xnt_address_to_receiving};
    use crate::ffi::address::{xnt_receiving_address_free, xnt_spending_key_to_address};
    use crate::ffi::seed::xnt_wallet_free;
    use crate::ffi::seed::{xnt_spending_key_free, xnt_wallet_derive_key, xnt_wallet_devnet};

    #[test]
    fn builder_amounts_as_little_endian_bytes() {
        let wallet = xnt_wallet_devnet();
        let key = xnt_wallet_derive_key(wallet, 0);
        let addr = xnt_spending_key_to_address(key);
        let recipient = xnt_address_to_receiving(addr);
        let builder = xnt_tx_builder_create();
        let amount: i128 = 3 * 10i128.pow(37);
        let fee: i128 = 5;
        let sender_randomness = XntDigest::new();

        let amount_le = amount.to_le_bytes();
        let code = xnt_tx_builder_add_output_le(
            builder,
            recipient,
            amount_le.as_ptr(),
            &sender_randomness,
        );
        assert_eq!(XntErrorCode::Ok, code);
        let code = xnt_tx_builder_set_fee_le(builder, fee.to_le_bytes().as_ptr());
        assert_eq!(XntErrorCode::Ok, code);

        let mut out = [0u8; 16];
        let code = xnt_tx_builder_output_total_le(builder, out.as_mut_ptr());
        assert_eq!(XntErrorCode::Ok, code);
        assert_eq!(amount, i128::from_le_bytes(out));
        let code = xnt_tx_builder_change_amount_le(builder, out.as_mut_ptr());
        assert_eq!(XntErrorCode::Ok, code);
        assert_eq!(-amount - fee, i128::from_le_bytes(out));
        let code = xnt_tx_builder_input_total_le(builder, out.as_mut_ptr());
        assert_eq!(XntErrorCode::Ok, code);
        assert_eq!(0, i128::from_le_bytes(out));

        xnt_tx_builder_free(builder);
        xnt_receiving_address_free(recipient);
        xnt_address_free(addr);
        xnt_spending_key_free(key);
        xnt_wallet_free(wallet);
    }

    #[test]
    fn select_inputs_le_matches_select_inputs() {
        let amounts: [i128; 4] = [5, 1, 3, 10i128.pow(36)];
        let amounts_le: Vec<u8> = amounts.iter().flat_map(|a| a.to_le_bytes()).collect();
        let target: i128 = 4;
        let mut plain = [usize::MAX; 4];
        let mut le = [usize::MAX; 4];

        let n = xnt_select_inputs(amounts.as_ptr(), 4, target, 4, plain.as_mut_ptr(), 4);
        let target_le = target.to_le_bytes();
        let n_le = xnt_select_inputs_le(
            amounts_le.as_ptr(),
            4,
            target_le.as_ptr(),
            4,
            le.as_mut_ptr(),
            4,
        );
        assert!(n > 0);
        assert_eq!(n, n_le);
        assert_eq!(plain, le);
    }
}
