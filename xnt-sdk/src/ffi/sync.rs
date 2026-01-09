//! UTXO sync FFI
//!
//! Wraps core sync functions for C FFI.

use crate::core::{
    check_spent, compute_absolute_index_set_hash, compute_commitment,
    compute_commitment_for_output, decrypt_indexed_utxo, fetch_utxos, get_aocl_indices,
    get_membership_proofs, get_mutator_set, MembershipProof, MutatorSet,
};

use super::error::{set_last_error, XntErrorCode};
use super::helpers::{read_slice, vec_to_ptr};
use super::json_rpc::RpcClientHandle;
use super::seed::SpendingKeyHandle;
use super::types::{ByteBuffer, XntDigest};
use super::utxo::{UtxoHandle, XntDecryptedUtxo};

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

/// Opaque handle to MutatorSet
pub struct MutatorSetHandle(pub(crate) MutatorSet);

/// Opaque handle to MembershipProof
pub struct MsMembershipProofHandle(pub(crate) MembershipProof);


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
    let core_digest = crate::core::Digest::from_bytes(digest.bytes);

    match fetch_utxos(&client.0, &core_digest, from_height, to_height) {
        Ok(utxos) => {
            let mut indexed_utxos: Vec<XntIndexedUtxo> = Vec::with_capacity(utxos.len());
            for utxo in utxos {
                let ciphertext = utxo.ciphertext;
                let ciphertext_len = ciphertext.len();
                indexed_utxos.push(XntIndexedUtxo {
                    block_height: utxo.block_height,
                    block_digest: XntDigest::from_bytes(utxo.block_digest.bytes),
                    ciphertext_data: vec_to_ptr(ciphertext),
                    ciphertext_len,
                });
            }
            let len = indexed_utxos.len();
            XntIndexedUtxoArray { data: vec_to_ptr(indexed_utxos), len }
        }
        Err(e) => {
            set_last_error(&format!("{e}"));
            XntIndexedUtxoArray::null()
        }
    }
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
                    drop(Vec::from_raw_parts(utxo.ciphertext_data, utxo.ciphertext_len, utxo.ciphertext_len));
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

    let bytes = unsafe { read_slice(utxo.ciphertext_data, utxo.ciphertext_len) };
    let block_digest = crate::core::Digest::from_bytes(utxo.block_digest.bytes);

    match decrypt_indexed_utxo(&key.0, bytes, utxo.block_height, block_digest) {
        Ok(decrypted) => XntDecryptedUtxo {
            utxo: Box::into_raw(Box::new(UtxoHandle(decrypted.utxo))),
            sender_randomness: XntDigest::from_bytes(decrypted.sender_randomness.bytes),
            payment_id: decrypted.payment_id,
            block_height: decrypted.block_height,
            block_digest: XntDigest::from_bytes(decrypted.block_digest.bytes),
        },
        Err(e) => {
            set_last_error(&format!("{e}"));
            XntDecryptedUtxo::null()
        }
    }
}


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
    let core_digests: Vec<crate::core::Digest> = digests
        .iter()
        .map(|d| crate::core::Digest::from_bytes(d.bytes))
        .collect();

    match check_spent(&client.0, &core_digests) {
        Ok(heights) => {
            let len = heights.len();
            XntSpentStatus { heights: vec_to_ptr(heights), len }
        }
        Err(e) => {
            set_last_error(&format!("{e}"));
            XntSpentStatus::null()
        }
    }
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
    let core_digests: Vec<crate::core::Digest> = digests
        .iter()
        .map(|d| crate::core::Digest::from_bytes(d.bytes))
        .collect();

    match get_aocl_indices(&client.0, &core_digests) {
        Ok(indices) => {
            let len = indices.len();
            XntAoclIndices { indices: vec_to_ptr(indices), len }
        }
        Err(e) => {
            set_last_error(&format!("{e}"));
            XntAoclIndices::null()
        }
    }
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


/// Get current block height from node
#[no_mangle]
pub extern "C" fn xnt_sync_get_height(client: *const RpcClientHandle) -> i64 {
    ffi_begin!();
    if client.is_null() {
        set_last_error("null pointer");
        return -1;
    }

    let client = ffi_ref!(client);
    match client.0.chain_height() {
        Ok(h) => h as i64,
        Err(e) => {
            set_last_error(&format!("{e}"));
            -1
        }
    }
}


/// Compute canonical commitment for UTXO (using receiver_preimage)
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

    let item = crate::core::Digest::from_bytes(ffi_ref!(utxo_hash).bytes);
    let sr = crate::core::Digest::from_bytes(ffi_ref!(sender_randomness).bytes);
    let rp = crate::core::Digest::from_bytes(ffi_ref!(receiver_preimage).bytes);

    let commitment = compute_commitment(&item, &sr, &rp);
    copy_bytes_out!(commitment.bytes, out_commitment, 40)
}

/// Compute canonical commitment for output (using receiver_postimage)
#[no_mangle]
pub extern "C" fn xnt_compute_commitment_for_output(
    utxo_hash: *const XntDigest,
    sender_randomness: *const XntDigest,
    receiver_postimage: *const XntDigest,
    out_commitment: *mut u8,
) -> XntErrorCode {
    ffi_begin!();
    check_null!(utxo_hash);
    check_null!(sender_randomness);
    check_null!(receiver_postimage);
    check_null!(out_commitment);

    let item = crate::core::Digest::from_bytes(ffi_ref!(utxo_hash).bytes);
    let sr = crate::core::Digest::from_bytes(ffi_ref!(sender_randomness).bytes);
    let rd = crate::core::Digest::from_bytes(ffi_ref!(receiver_postimage).bytes);

    let commitment = compute_commitment_for_output(&item, &sr, &rd);
    copy_bytes_out!(commitment.bytes, out_commitment, 40)
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

    let item = crate::core::Digest::from_bytes(ffi_ref!(utxo_hash).bytes);
    let sr = crate::core::Digest::from_bytes(ffi_ref!(sender_randomness).bytes);
    let rp = crate::core::Digest::from_bytes(ffi_ref!(receiver_preimage).bytes);

    let hash = compute_absolute_index_set_hash(&item, &sr, &rp, aocl_leaf_index);
    copy_bytes_out!(hash.bytes, out_hash, 40)
}

/// Hash an AbsoluteIndexSet from JSON (from RPC mempool response)
/// Used to check if a mempool tx input matches a known UTXO
#[no_mangle]
pub extern "C" fn xnt_hash_absolute_index_set(
    json_str: *const std::ffi::c_char,
    out_hash: *mut u8,
) -> XntErrorCode {
    ffi_begin!();
    check_null!(json_str);
    check_null!(out_hash);

    let Some(json) = super::helpers::parse_cstr(json_str) else {
        set_last_error("invalid JSON string");
        return XntErrorCode::InvalidInput;
    };

    match crate::core::hash_absolute_index_set_json(&json) {
        Ok(hash) => copy_bytes_out!(hash.bytes, out_hash, 40),
        Err(e) => {
            set_last_error(&e.to_string());
            XntErrorCode::InvalidInput
        }
    }
}


/// Get current mutator set accumulator from archival node
#[no_mangle]
pub extern "C" fn xnt_sync_get_mutator_set(client: *const RpcClientHandle) -> *mut MutatorSetHandle {
    ffi_begin!();
    check_null!(client, "null pointer");

    let client = ffi_ref!(client);
    match get_mutator_set(&client.0) {
        Ok(ms) => Box::into_raw(Box::new(MutatorSetHandle(ms))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

ffi_free!(xnt_mutator_set_free, MutatorSetHandle);

/// Serialize mutator set to bytes for caching
#[no_mangle]
pub extern "C" fn xnt_mutator_set_serialize(handle: *const MutatorSetHandle) -> *mut ByteBuffer {
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

/// Deserialize mutator set from bytes
#[no_mangle]
pub extern "C" fn xnt_mutator_set_deserialize(data: *const u8, len: usize) -> *mut MutatorSetHandle {
    ffi_begin!();
    if data.is_null() || len == 0 {
        set_last_error("invalid input");
        return std::ptr::null_mut();
    }
    let bytes = unsafe { read_slice(data, len) };
    match MutatorSet::from_bytes(bytes) {
        Ok(ms) => Box::into_raw(Box::new(MutatorSetHandle(ms))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}


ffi_free!(xnt_ms_membership_proof_free, MsMembershipProofHandle);

/// Serialize membership proof to bytes
#[no_mangle]
pub extern "C" fn xnt_ms_membership_proof_serialize(handle: *const MsMembershipProofHandle) -> *mut ByteBuffer {
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

/// Deserialize membership proof from bytes
#[no_mangle]
pub extern "C" fn xnt_ms_membership_proof_deserialize(data: *const u8, len: usize) -> *mut MsMembershipProofHandle {
    ffi_begin!();
    if data.is_null() || len == 0 {
        set_last_error("invalid input");
        return std::ptr::null_mut();
    }
    let bytes = unsafe { read_slice(data, len) };
    match MembershipProof::from_bytes(bytes) {
        Ok(mp) => Box::into_raw(Box::new(MsMembershipProofHandle(mp))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
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
    let item = crate::core::Digest::from_bytes(ffi_ref!(utxo_hash).bytes);
    let mp = &ffi_ref!(membership_proof).0;

    msa.verify(&item, mp)
}

/// Get the AOCL leaf index from a membership proof
#[no_mangle]
pub extern "C" fn xnt_ms_membership_proof_aocl_index(handle: *const MsMembershipProofHandle) -> u64 {
    ffi_begin!();
    if handle.is_null() {
        return 0;
    }
    ffi_ref!(handle).0.aocl_leaf_index()
}

/// Get membership proofs for UTXOs via wallet RPC
#[no_mangle]
pub extern "C" fn xnt_sync_get_membership_proofs(
    client: *const RpcClientHandle,
    utxo_hashes: *const XntDigest,
    sender_randomnesses: *const XntDigest,
    receiver_preimage: *const XntDigest,
    aocl_indices: *const u64,
    count: usize,
    out_proofs: *mut *mut MsMembershipProofHandle,
) -> XntErrorCode {
    ffi_begin!();
    if client.is_null()
        || utxo_hashes.is_null()
        || sender_randomnesses.is_null()
        || receiver_preimage.is_null()
        || aocl_indices.is_null()
        || out_proofs.is_null()
        || count == 0
    {
        set_last_error("invalid input");
        return XntErrorCode::InvalidInput;
    }

    let client = ffi_ref!(client);
    let rp = ffi_ref!(receiver_preimage);

    // Read input arrays
    let hashes_slice = unsafe { read_slice(utxo_hashes, count) };
    let sr_slice = unsafe { read_slice(sender_randomnesses, count) };
    let indices_slice = unsafe { read_slice(aocl_indices, count) };

    // Convert to core types
    let core_hashes: Vec<crate::core::Digest> = hashes_slice
        .iter()
        .map(|d| crate::core::Digest::from_bytes(d.bytes))
        .collect();
    let core_srs: Vec<crate::core::Digest> = sr_slice
        .iter()
        .map(|d| crate::core::Digest::from_bytes(d.bytes))
        .collect();
    let core_rp = crate::core::Digest::from_bytes(rp.bytes);
    let indices_vec: Vec<u64> = indices_slice.to_vec();

    // Call core function
    match get_membership_proofs(&client.0, &core_hashes, &core_srs, &core_rp, &indices_vec) {
        Ok(proofs) => {
            // Write output pointers
            let out_slice = unsafe { std::slice::from_raw_parts_mut(out_proofs, count) };
            for (i, proof) in proofs.into_iter().enumerate() {
                out_slice[i] = Box::into_raw(Box::new(MsMembershipProofHandle(proof)));
            }
            XntErrorCode::Ok
        }
        Err(e) => {
            set_last_error(&format!("{e}"));
            XntErrorCode::RpcError
        }
    }
}
