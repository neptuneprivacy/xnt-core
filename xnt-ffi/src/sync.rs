//! UTXO sync client FFI
//!
//! JSON-RPC client for fetching UTXOs from indexer, checking spent status,
//! and getting data needed for client-side membership proof generation.

use neptune_privacy::prelude::twenty_first::prelude::Tip5;
use neptune_privacy::util_types::mutator_set::commit;
use neptune_privacy::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use neptune_privacy::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_privacy::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_privacy::application::json_rpc::core::model::block::body::RpcMutatorSetAccumulator;
use neptune_privacy::application::json_rpc::core::model::wallet::mutator_set::RpcMsMembershipSnapshot;
use serde_json::{json, Value};

use crate::error::{set_last_error, XntErrorCode};
use crate::helpers::{parse_bfes_le, parse_digests, read_slice, vec_to_ptr};
use crate::json_rpc::{rpc_call, RpcClientHandle};
use crate::seed::SpendingKeyHandle;
use crate::types::XntDigest;
use crate::utxo::{UtxoHandle, XntDecryptedUtxo};

/// Indexed UTXO from sync (FFI-compatible)
#[repr(C)]
pub struct XntIndexedUtxo {
    pub block_height: u64,
    pub block_digest: XntDigest,
    pub ciphertext_data: *mut u8,
    pub ciphertext_len: usize,
}

/// Array of indexed UTXOs
#[repr(C)]
pub struct XntIndexedUtxoArray {
    pub data: *mut XntIndexedUtxo,
    pub len: usize,
}

impl XntIndexedUtxoArray {
    fn null() -> Self {
        Self { data: std::ptr::null_mut(), len: 0 }
    }
}

/// Spent status result
#[repr(C)]
pub struct XntSpentStatus {
    pub heights: *mut i64,
    pub len: usize,
}

impl XntSpentStatus {
    fn null() -> Self {
        Self { heights: std::ptr::null_mut(), len: 0 }
    }
}

/// AOCL indices result
#[repr(C)]
pub struct XntAoclIndices {
    pub indices: *mut i64,
    pub len: usize,
}

impl XntAoclIndices {
    fn null() -> Self {
        Self { indices: std::ptr::null_mut(), len: 0 }
    }
}

// === UTXO Fetching ===

/// Fetch UTXOs by receiver_id_hash from indexer
#[no_mangle]
pub extern "C" fn xnt_sync_fetch_utxos(
    client: *const RpcClientHandle,
    receiver_id_hash: *const XntDigest,
    from_height: u64,
    to_height: u64,
) -> XntIndexedUtxoArray {
    ffi_begin!();
    if client.is_null() || receiver_id_hash.is_null() {
        set_last_error("null pointer");
        return XntIndexedUtxoArray::null();
    }

    let client = ffi_ref!(client);
    let digest = ffi_ref!(receiver_id_hash);

    let params = json!({
        "receiverIdHash": digest.to_digest(),
        "fromBlockHeight": from_height,
        "toBlockHeight": to_height
    });

    let result = rpc_try!(client, "archival_getUtxosByReceiver", params, XntIndexedUtxoArray::null());
    let utxos = rpc_array!(result, "utxos", XntIndexedUtxoArray::null());

    let mut indexed_utxos: Vec<XntIndexedUtxo> = Vec::with_capacity(utxos.len());

    for utxo in utxos.iter() {
        let block_height = utxo.get("blockHeight").and_then(|v| v.as_u64()).unwrap_or(0);
        let block_digest = utxo
            .get("blockDigest")
            .and_then(|v| v.as_str())
            .and_then(XntDigest::from_hex)
            .unwrap_or_default();

        let ciphertext_bfes: Vec<u64> = if let Some(Value::Array(arr)) = utxo.get("ciphertext") {
            arr.iter()
                .filter_map(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .collect()
        } else {
            Vec::new()
        };

        let ciphertext_bytes: Vec<u8> = ciphertext_bfes.iter().flat_map(|&v| v.to_le_bytes()).collect();

        indexed_utxos.push(XntIndexedUtxo {
            block_height,
            block_digest,
            ciphertext_data: vec_to_ptr(ciphertext_bytes),
            ciphertext_len: ciphertext_bfes.len(),
        });
    }

    let len = indexed_utxos.len();
    XntIndexedUtxoArray { data: vec_to_ptr(indexed_utxos), len }
}

/// Free indexed UTXO array
#[no_mangle]
pub extern "C" fn xnt_sync_indexed_utxos_free(arr: *mut XntIndexedUtxoArray) {
    if arr.is_null() {
        return;
    }
    unsafe {
        let arr = &mut *arr;
        if !arr.data.is_null() && arr.len > 0 {
            let slice = std::slice::from_raw_parts_mut(arr.data, arr.len);
            for utxo in slice.iter_mut() {
                if !utxo.ciphertext_data.is_null() && utxo.ciphertext_len > 0 {
                    drop(Vec::from_raw_parts(utxo.ciphertext_data, utxo.ciphertext_len * 8, utxo.ciphertext_len * 8));
                }
            }
            drop(Vec::from_raw_parts(arr.data, arr.len, arr.len));
        }
        arr.data = std::ptr::null_mut();
        arr.len = 0;
    }
}

/// Decrypt indexed UTXO ciphertext with spending key
#[no_mangle]
pub extern "C" fn xnt_sync_decrypt_indexed_utxo(
    spending_key: *const SpendingKeyHandle,
    indexed_utxo: *const XntIndexedUtxo,
) -> XntDecryptedUtxo {
    ffi_begin!();
    if spending_key.is_null() || indexed_utxo.is_null() {
        set_last_error("null pointer");
        return XntDecryptedUtxo::null();
    }

    let key = ffi_ref!(spending_key);
    let utxo = ffi_ref!(indexed_utxo);

    if utxo.ciphertext_data.is_null() || utxo.ciphertext_len == 0 {
        set_last_error("invalid ciphertext");
        return XntDecryptedUtxo::null();
    }

    let bytes = unsafe { read_slice(utxo.ciphertext_data, utxo.ciphertext_len * 8) };
    let ciphertext = parse_bfes_le(bytes);

    // SpendingKey::decrypt handles both Generation and Symmetric keys
    match key.0.decrypt(&ciphertext) {
        Ok((decrypted_utxo, sender_randomness, payment_id)) => XntDecryptedUtxo {
            utxo: Box::into_raw(Box::new(UtxoHandle(decrypted_utxo))),
            sender_randomness: XntDigest::from_digest(sender_randomness),
            payment_id: payment_id.value(),
        },
        Err(e) => {
            set_last_error(&format!("decryption failed: {e}"));
            XntDecryptedUtxo::null()
        }
    }
}

// === Spent Status ===

/// Check spent status of UTXOs by their absolute_index_set_hash
#[no_mangle]
pub extern "C" fn xnt_sync_check_spent(
    client: *const RpcClientHandle,
    hashes: *const XntDigest,
    count: usize,
) -> XntSpentStatus {
    ffi_begin!();
    if client.is_null() || hashes.is_null() || count == 0 {
        set_last_error("invalid input");
        return XntSpentStatus::null();
    }

    let client = ffi_ref!(client);
    let digests = unsafe { read_slice(hashes, count) };
    let hashes_vec = parse_digests(digests);

    let result = rpc_try!(client, "archival_getSpentStatus", json!({ "absoluteIndexSetHashes": hashes_vec }), XntSpentStatus::null());
    let spent_heights = rpc_array!(result, "spentAtHeights", XntSpentStatus::null());

    let heights: Vec<i64> = spent_heights.iter().map(|v| v.as_i64().unwrap_or(-1)).collect();
    let len = heights.len();
    XntSpentStatus { heights: vec_to_ptr(heights), len }
}

/// Free spent status result
#[no_mangle]
pub extern "C" fn xnt_sync_spent_status_free(status: *mut XntSpentStatus) {
    if status.is_null() {
        return;
    }
    let s = ffi_mut!(status);
    free_vec!(s.heights, s.len);
    s.heights = std::ptr::null_mut();
    s.len = 0;
}

// === AOCL Indices ===

/// Get AOCL leaf indices for commitments
#[no_mangle]
pub extern "C" fn xnt_sync_get_aocl_indices(
    client: *const RpcClientHandle,
    commitments: *const XntDigest,
    count: usize,
) -> XntAoclIndices {
    ffi_begin!();
    if client.is_null() || commitments.is_null() || count == 0 {
        set_last_error("invalid input");
        return XntAoclIndices::null();
    }

    let client = ffi_ref!(client);
    let digests = unsafe { read_slice(commitments, count) };
    let commitment_vec = parse_digests(digests);

    let result = rpc_try!(client, "archival_getAoclLeafIndices", json!({ "commitments": commitment_vec }), XntAoclIndices::null());
    let indices_arr = rpc_array!(result, "indices", XntAoclIndices::null());

    let indices: Vec<i64> = indices_arr.iter().map(|v| v.as_i64().unwrap_or(-1)).collect();
    let len = indices.len();
    XntAoclIndices { indices: vec_to_ptr(indices), len }
}

/// Free AOCL indices result
#[no_mangle]
pub extern "C" fn xnt_sync_aocl_indices_free(result: *mut XntAoclIndices) {
    if result.is_null() {
        return;
    }
    let r = ffi_mut!(result);
    free_vec!(r.indices, r.len);
    r.indices = std::ptr::null_mut();
    r.len = 0;
}

// === Chain Info ===

/// Get current block height from node
#[no_mangle]
pub extern "C" fn xnt_sync_get_height(client: *const RpcClientHandle) -> i64 {
    ffi_begin!();

    if client.is_null() {
        set_last_error("null pointer");
        return -1;
    }

    let client = ffi_ref!(client);

    rpc_try!(client, "chain_height", json!([]), -1)
        .get("height")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1)
}

// === Commitment & Index Computation ===

/// Compute canonical commitment for UTXO (using receiver_preimage)
/// Use this for inputs where you have the receiver's preimage
#[no_mangle]
pub extern "C" fn xnt_compute_commitment(
    utxo_hash: *const XntDigest,
    sender_randomness: *const XntDigest,
    receiver_preimage: *const XntDigest,
    out_commitment: *mut u8,
) -> XntErrorCode {
    ffi_begin!();
    check_null!(utxo_hash);
    check_null!(sender_randomness);
    check_null!(receiver_preimage);
    check_null!(out_commitment);

    let item = ffi_ref!(utxo_hash).to_digest();
    let sr = ffi_ref!(sender_randomness).to_digest();
    let rp = ffi_ref!(receiver_preimage).to_digest();

    let addition_record = commit(item, sr, rp.hash());
    let commitment: [u8; 40] = addition_record.canonical_commitment.into();
    copy_bytes_out!(commitment, out_commitment, 40)
}

/// Compute canonical commitment for UTXO (using receiver_postimage/privacy_digest)
/// Use this for outputs where you have the receiver's address (privacy_digest)
#[no_mangle]
pub extern "C" fn xnt_compute_commitment_for_output(
    utxo_hash: *const XntDigest,
    sender_randomness: *const XntDigest,
    receiver_postimage: *const XntDigest,  // address.privacy_digest()
    out_commitment: *mut u8,
) -> XntErrorCode {
    ffi_begin!();
    check_null!(utxo_hash);
    check_null!(sender_randomness);
    check_null!(receiver_postimage);
    check_null!(out_commitment);

    let item = ffi_ref!(utxo_hash).to_digest();
    let sr = ffi_ref!(sender_randomness).to_digest();
    let receiver_digest = ffi_ref!(receiver_postimage).to_digest();  // already hashed

    let addition_record = commit(item, sr, receiver_digest);
    let commitment: [u8; 40] = addition_record.canonical_commitment.into();
    copy_bytes_out!(commitment, out_commitment, 40)
}

/// Compute absolute_index_set_hash for spent checking
#[no_mangle]
pub extern "C" fn xnt_compute_absolute_index_set_hash(
    utxo_hash: *const XntDigest,
    sender_randomness: *const XntDigest,
    receiver_preimage: *const XntDigest,
    aocl_leaf_index: u64,
    out_hash: *mut u8,
) -> XntErrorCode {
    ffi_begin!();
    check_null!(utxo_hash);
    check_null!(sender_randomness);
    check_null!(receiver_preimage);
    check_null!(out_hash);

    let item = ffi_ref!(utxo_hash).to_digest();
    let sr = ffi_ref!(sender_randomness).to_digest();
    let rp = ffi_ref!(receiver_preimage).to_digest();

    let abs_indices = AbsoluteIndexSet::compute(item, sr, rp, aocl_leaf_index);
    let hash: [u8; 40] = Tip5::hash(&abs_indices).into();
    copy_bytes_out!(hash, out_hash, 40)
}

/// Compute absolute_index_set raw data for debugging
#[no_mangle]
pub extern "C" fn xnt_compute_absolute_index_set_raw(
    utxo_hash: *const XntDigest,
    sender_randomness: *const XntDigest,
    receiver_preimage: *const XntDigest,
    aocl_leaf_index: u64,
    minimum_out: *mut u128,
    distances_out: *mut u32,
) -> XntErrorCode {
    ffi_begin!();
    check_null!(utxo_hash);
    check_null!(sender_randomness);
    check_null!(receiver_preimage);
    check_null!(minimum_out);
    check_null!(distances_out);

    let item = ffi_ref!(utxo_hash).to_digest();
    let sr = ffi_ref!(sender_randomness).to_digest();
    let rp = ffi_ref!(receiver_preimage).to_digest();

    let abs_indices = AbsoluteIndexSet::compute(item, sr, rp, aocl_leaf_index);
    let array = abs_indices.to_array();
    let minimum = array.iter().copied().min().unwrap();

    unsafe {
        *minimum_out = minimum;
        for (i, &val) in array.iter().enumerate() {
            *distances_out.add(i) = (val - minimum) as u32;
        }
    }

    XntErrorCode::Ok
}

/// Get receiver_preimage from spending key (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_preimage(handle: *const SpendingKeyHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let preimage: [u8; 40] = ffi_ref!(handle).0.privacy_preimage().into();
    copy_bytes_out!(preimage, out, 40)
}

/// Compute UTXO hash (TIP5 hash of UTXO for commitment calculation)
#[no_mangle]
pub extern "C" fn xnt_utxo_hash(utxo: *const UtxoHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(utxo);
    check_null!(out);

    let hash: [u8; 40] = Tip5::hash(&ffi_ref!(utxo).0).into();
    copy_bytes_out!(hash, out, 40)
}

/// Compute hash of AbsoluteIndexSet from raw data (for testing)
#[no_mangle]
pub extern "C" fn xnt_compute_abs_hash_from_raw(minimum: u128, distances: *const u32, out_hash: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(distances);
    check_null!(out_hash);

    let distances_arr: [u32; 45] = unsafe {
        std::slice::from_raw_parts(distances, 45).try_into().unwrap()
    };

    let absolute_indices: [u128; 45] = distances_arr
        .iter()
        .map(|&d| minimum + d as u128)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let hash: [u8; 40] = Tip5::hash(&AbsoluteIndexSet::new(absolute_indices)).into();
    copy_bytes_out!(hash, out_hash, 40)
}

// === Mutator Set & Membership Proof Data ===

/// Opaque handle to MutatorSetAccumulator
pub struct MutatorSetHandle(pub(crate) MutatorSetAccumulator);


/// Get current mutator set accumulator from archival node
#[no_mangle]
pub extern "C" fn xnt_sync_get_mutator_set(client: *const RpcClientHandle) -> *mut MutatorSetHandle {
    ffi_begin!();
    check_null!(client, "null pointer");

    let client = ffi_ref!(client);

    let result = match rpc_call(client, "archival_getArchivalMutatorSet", json!([])) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(&format!("RPC failed: {e}"));
            return std::ptr::null_mut();
        }
    };

    let msa_obj = match result.get("archivalMutatorSet") {
        Some(obj) => obj.clone(),
        None => {
            set_last_error("missing archivalMutatorSet in response");
            return std::ptr::null_mut();
        }
    };

    match serde_json::from_value::<RpcMutatorSetAccumulator>(msa_obj) {
        Ok(rpc_msa) => {
            let msa: MutatorSetAccumulator = rpc_msa.into();
            Box::into_raw(Box::new(MutatorSetHandle(msa)))
        }
        Err(e) => {
            set_last_error(&format!("parse mutator set failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

ffi_free!(xnt_mutator_set_free, MutatorSetHandle);

/// Serialize mutator set to bytes for caching
#[no_mangle]
pub extern "C" fn xnt_mutator_set_serialize(handle: *const MutatorSetHandle) -> *mut crate::types::ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");
    ffi_serialize!(ffi_ref!(handle).0)
}

/// Deserialize mutator set from bytes
#[no_mangle]
pub extern "C" fn xnt_mutator_set_deserialize(data: *const u8, len: usize) -> *mut MutatorSetHandle {
    ffi_begin!();
    if data.is_null() || len == 0 {
        set_last_error("invalid input");
        return std::ptr::null_mut();
    }
    let bytes = unsafe { read_slice(data, len) };
    ffi_result!(bincode::deserialize::<MutatorSetAccumulator>(bytes), MutatorSetHandle, "deserialize failed")
}

// === Membership Proof Handle ===

/// Opaque handle to MsMembershipProof
pub struct MsMembershipProofHandle(pub(crate) MsMembershipProof);

ffi_free!(xnt_ms_membership_proof_free, MsMembershipProofHandle);

/// Serialize membership proof to bytes (for caching or transport)
#[no_mangle]
pub extern "C" fn xnt_ms_membership_proof_serialize(
    handle: *const MsMembershipProofHandle,
) -> *mut crate::types::ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");
    ffi_serialize!(ffi_ref!(handle).0)
}

/// Deserialize membership proof from bytes
#[no_mangle]
pub extern "C" fn xnt_ms_membership_proof_deserialize(
    data: *const u8,
    len: usize,
) -> *mut MsMembershipProofHandle {
    ffi_begin!();
    if data.is_null() || len == 0 {
        set_last_error("invalid input");
        return std::ptr::null_mut();
    }
    let bytes = unsafe { read_slice(data, len) };
    ffi_result!(bincode::deserialize::<MsMembershipProof>(bytes), MsMembershipProofHandle, "deserialize failed")
}

/// Verify membership proof against mutator set
#[no_mangle]
pub extern "C" fn xnt_verify_membership(
    mutator_set: *const MutatorSetHandle,
    utxo_hash: *const XntDigest,
    membership_proof: *const MsMembershipProofHandle,
) -> bool {
    ffi_begin!();
    if mutator_set.is_null() || utxo_hash.is_null() || membership_proof.is_null() {
        return false;
    }

    let msa = &ffi_ref!(mutator_set).0;
    let item = ffi_ref!(utxo_hash).to_digest();
    let mp = &ffi_ref!(membership_proof).0;

    msa.verify(item, mp)
}

/// Get the AOCL leaf index from a membership proof
#[no_mangle]
pub extern "C" fn xnt_ms_membership_proof_aocl_index(
    handle: *const MsMembershipProofHandle,
) -> u64 {
    ffi_begin!();
    if handle.is_null() {
        return 0;
    }
    ffi_ref!(handle).0.aocl_leaf_index
}

/// Get membership proofs for multiple UTXOs in one RPC call
/// Returns array of MsMembershipProofHandle pointers (same order as input)
/// utxo_hashes, sender_randomnesses, aocl_leaf_indices: parallel arrays of count elements
/// receiver_preimage: shared for all UTXOs (same spending key)
#[no_mangle]
pub extern "C" fn xnt_sync_get_membership_proofs(
    client: *const RpcClientHandle,
    utxo_hashes: *const XntDigest,
    sender_randomnesses: *const XntDigest,
    receiver_preimage: *const XntDigest,
    aocl_leaf_indices: *const u64,
    count: usize,
    out_proofs: *mut *mut MsMembershipProofHandle,
) -> XntErrorCode {
    ffi_begin!();
    if client.is_null() || utxo_hashes.is_null() || sender_randomnesses.is_null()
        || receiver_preimage.is_null() || aocl_leaf_indices.is_null() || out_proofs.is_null() || count == 0 {
        set_last_error("invalid input");
        return XntErrorCode::NullPointer;
    }

    let client = ffi_ref!(client);
    let rp = ffi_ref!(receiver_preimage).to_digest();
    let hashes = unsafe { std::slice::from_raw_parts(utxo_hashes, count) };
    let srs = unsafe { std::slice::from_raw_parts(sender_randomnesses, count) };
    let indices = unsafe { std::slice::from_raw_parts(aocl_leaf_indices, count) };

    // Compute AbsoluteIndexSet for each UTXO
    let abs_sets: Vec<AbsoluteIndexSet> = (0..count).map(|i| {
        AbsoluteIndexSet::compute(hashes[i].to_digest(), srs[i].to_digest(), rp, indices[i])
    }).collect();

    // One RPC call for all
    let params = json!([abs_sets]);
    let result = match rpc_call(client, "wallet_restoreMembershipProof", params) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(&format!("RPC failed: {e}"));
            return XntErrorCode::NetworkError;
        }
    };

    let snapshot: RpcMsMembershipSnapshot = match serde_json::from_value(result.get("snapshot").cloned().unwrap_or(result)) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("parse failed: {e}"));
            return XntErrorCode::InvalidInput;
        }
    };

    if snapshot.membership_proofs.len() != count {
        set_last_error("proof count mismatch");
        return XntErrorCode::InternalError;
    }

    // Extract and write to output array
    for (i, pp) in snapshot.membership_proofs.into_iter().enumerate() {
        match pp.extract_ms_membership_proof(indices[i], srs[i].to_digest(), rp) {
            Some(mp) => unsafe { *out_proofs.add(i) = Box::into_raw(Box::new(MsMembershipProofHandle(mp))); },
            None => {
                // Cleanup already written
                for j in 0..i { unsafe { drop(Box::from_raw(*out_proofs.add(j))); } }
                set_last_error(&format!("extract failed at {}", i));
                return XntErrorCode::InternalError;
            }
        }
    }

    XntErrorCode::Ok
}

