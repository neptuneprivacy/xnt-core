//! UTXO operations FFI
//!
//! Wraps core::Utxo for C FFI.

use crate::core::{decrypt_announcement, Utxo};

use super::address::AddressHandle;
use super::error::{set_last_error, XntErrorCode};
use super::helpers::{parse_bfes_le, read_slice};
use super::seed::SpendingKeyHandle;
use super::types::{ByteBuffer, XntDigest};

/// Opaque handle to UTXO
pub struct UtxoHandle(pub(crate) Utxo);

/// Decrypted UTXO notification result
#[repr(C)]
pub struct XntDecryptedUtxo {
    pub utxo: *mut UtxoHandle,
    pub sender_randomness: XntDigest,
    pub payment_id: u64,
    pub block_height: u64,
    pub block_digest: XntDigest,
}

impl XntDecryptedUtxo {
    pub(crate) fn null() -> Self {
        Self {
            utxo: std::ptr::null_mut(),
            sender_randomness: XntDigest::new(),
            payment_id: 0,
            block_height: 0,
            block_digest: XntDigest::new(),
        }
    }
}

/// Create UTXO for native currency
#[no_mangle]
pub extern "C" fn xnt_utxo_create_native(address: *const AddressHandle, amount: i128) -> *mut UtxoHandle {
    ffi_begin!();
    check_null!(address, "address handle is null");

    let addr = ffi_ref!(address);
    let utxo = Utxo::new_native(&addr.0, amount);
    Box::into_raw(Box::new(UtxoHandle(utxo)))
}

ffi_free!(xnt_utxo_free, UtxoHandle);

/// Get native currency amount from UTXO (in nau)
#[no_mangle]
pub extern "C" fn xnt_utxo_get_amount(handle: *const UtxoHandle) -> i128 {
    if handle.is_null() {
        return 0;
    }
    ffi_ref!(handle).0.amount()
}

/// Get lock_script_hash from UTXO (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_utxo_lock_script_hash(handle: *const UtxoHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let hash = ffi_ref!(handle).0.lock_script_hash();
    copy_bytes_out!(hash.bytes, out, 40)
}

/// Get UTXO hash (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_utxo_hash(handle: *const UtxoHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let hash = ffi_ref!(handle).0.hash();
    copy_bytes_out!(hash.bytes, out, 40)
}

/// Serialize UTXO to bytes
#[no_mangle]
pub extern "C" fn xnt_utxo_serialize(handle: *const UtxoHandle) -> *mut ByteBuffer {
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

/// Deserialize UTXO from bytes
#[no_mangle]
pub extern "C" fn xnt_utxo_deserialize(data: *const u8, len: usize) -> *mut UtxoHandle {
    ffi_begin!();
    if data.is_null() || len == 0 {
        set_last_error("invalid input");
        return std::ptr::null_mut();
    }

    let bytes = unsafe { read_slice(data, len) };
    match Utxo::from_bytes(bytes) {
        Ok(utxo) => Box::into_raw(Box::new(UtxoHandle(utxo))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get release date if UTXO is timelocked (milliseconds since Unix epoch)
/// Returns 0 if not timelocked
#[no_mangle]
pub extern "C" fn xnt_utxo_release_date(handle: *const UtxoHandle) -> u64 {
    if handle.is_null() {
        return 0;
    }
    ffi_ref!(handle).0.release_date().unwrap_or(0)
}

/// Check if UTXO is timelocked (returns 1 if timelocked, 0 if not)
#[no_mangle]
pub extern "C" fn xnt_utxo_is_timelocked(handle: *const UtxoHandle) -> i32 {
    if handle.is_null() {
        return 0;
    }
    if ffi_ref!(handle).0.is_timelocked() { 1 } else { 0 }
}

/// Check if UTXO can be spent at given timestamp (milliseconds since Unix epoch)
/// Returns 1 if can spend, 0 if not
#[no_mangle]
pub extern "C" fn xnt_utxo_can_spend_at(handle: *const UtxoHandle, timestamp_ms: u64) -> i32 {
    if handle.is_null() {
        return 0;
    }
    if ffi_ref!(handle).0.can_spend_at(timestamp_ms) { 1 } else { 0 }
}

/// Add timelock to UTXO, returns new timelocked UTXO handle
#[no_mangle]
pub extern "C" fn xnt_utxo_with_time_lock(handle: *const UtxoHandle, release_date_ms: u64) -> *mut UtxoHandle {
    ffi_begin!();
    check_null!(handle, "null pointer");

    let utxo = ffi_ref!(handle).0.clone().with_time_lock(release_date_ms);
    Box::into_raw(Box::new(UtxoHandle(utxo)))
}

/// Decrypt announcement with spending key
#[no_mangle]
pub extern "C" fn xnt_announcement_decrypt(
    spending_key: *const SpendingKeyHandle,
    announcement_data: *const u8,
    announcement_count: usize,
) -> XntDecryptedUtxo {
    ffi_begin!();
    if spending_key.is_null() || announcement_data.is_null() || announcement_count < 3 {
        set_last_error("invalid input");
        return XntDecryptedUtxo::null();
    }

    let key = ffi_ref!(spending_key);
    let bytes = unsafe { read_slice(announcement_data, announcement_count * 8) };
    let bfes = parse_bfes_le(bytes);

    match decrypt_announcement(&key.0, &bfes) {
        Ok(decrypted) => XntDecryptedUtxo {
            utxo: Box::into_raw(Box::new(UtxoHandle(decrypted.utxo))),
            sender_randomness: XntDigest::from_bytes(decrypted.sender_randomness.bytes),
            payment_id: decrypted.payment_id,
            block_height: 0, // Not available from announcement
            block_digest: XntDigest::new(),
        },
        Err(e) => {
            set_last_error(&format!("{e}"));
            XntDecryptedUtxo::null()
        }
    }
}

/// Free decrypted UTXO result
#[no_mangle]
pub extern "C" fn xnt_decrypted_utxo_free(result: *mut XntDecryptedUtxo) {
    if !result.is_null() {
        let r = ffi_mut!(result);
        if !r.utxo.is_null() {
            unsafe { drop(Box::from_raw(r.utxo)) };
            r.utxo = std::ptr::null_mut();
        }
    }
}
