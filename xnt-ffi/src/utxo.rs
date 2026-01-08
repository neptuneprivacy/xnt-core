//! UTXO operations FFI
//!
//! UTXO creation, serialization, and announcement decryption.

use neptune_privacy::protocol::consensus::transaction::announcement::Announcement;
use neptune_privacy::protocol::consensus::transaction::utxo::Utxo;
use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_privacy::state::wallet::address::ciphertext_from_announcement;
use neptune_privacy::state::wallet::address::generation_address::GENERATION_FLAG;
use neptune_privacy::state::wallet::address::receiver_identifier_from_announcement;

use crate::address::AddressHandle;
use crate::error::{set_last_error, XntErrorCode};
use crate::helpers::{parse_bfes_le, read_slice};
use crate::seed::SpendingKeyHandle;
use crate::types::XntDigest;

/// Opaque handle to UTXO
pub struct UtxoHandle(pub(crate) Utxo);

/// Decrypted UTXO notification result
#[repr(C)]
pub struct XntDecryptedUtxo {
    pub utxo: *mut UtxoHandle,
    pub sender_randomness: XntDigest,
    pub payment_id: u64,
}

impl XntDecryptedUtxo {
    pub(crate) fn null() -> Self {
        Self {
            utxo: std::ptr::null_mut(),
            sender_randomness: XntDigest::new(),
            payment_id: 0,
        }
    }
}

/// Create UTXO for native currency
/// amount: native currency amount in atomic units (nau)
#[no_mangle]
pub extern "C" fn xnt_utxo_create_native(address: *const AddressHandle, amount: i128) -> *mut UtxoHandle {
    ffi_begin!();
    check_null!(address, "address handle is null");

    let addr = ffi_ref!(address);
    let lock_script_hash = addr.0.lock_script_hash();
    let utxo = Utxo::new_native_currency(lock_script_hash, NativeCurrencyAmount::from_nau(amount));

    Box::into_raw(Box::new(UtxoHandle(utxo)))
}

ffi_free!(xnt_utxo_free, UtxoHandle);

/// Get native currency amount from UTXO (in atomic units - nau)
#[no_mangle]
pub extern "C" fn xnt_utxo_get_amount(handle: *const UtxoHandle) -> i128 {
    if handle.is_null() {
        return 0;
    }
    ffi_ref!(handle).0.get_native_currency_amount().to_nau()
}

/// Get lock_script_hash from UTXO (40 bytes = Digest)
#[no_mangle]
pub extern "C" fn xnt_utxo_lock_script_hash(handle: *const UtxoHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let hash: [u8; 40] = ffi_ref!(handle).0.lock_script_hash().into();
    copy_bytes_out!(hash, out, 40)
}

/// Serialize UTXO to bytes (bincode format)
/// Caller must free with xnt_buffer_free()
#[no_mangle]
pub extern "C" fn xnt_utxo_serialize(handle: *const UtxoHandle) -> *mut crate::types::ByteBuffer {
    ffi_begin!();
    check_null!(handle, "null pointer");
    ffi_serialize!(ffi_ref!(handle).0)
}

/// Deserialize UTXO from bytes (bincode format)
#[no_mangle]
pub extern "C" fn xnt_utxo_deserialize(data: *const u8, len: usize) -> *mut UtxoHandle {
    ffi_begin!();
    if data.is_null() || len == 0 {
        set_last_error("invalid input");
        return std::ptr::null_mut();
    }

    let bytes = unsafe { read_slice(data, len) };
    ffi_result!(bincode::deserialize::<Utxo>(bytes), UtxoHandle, "deserialize failed")
}

/// Try to decrypt announcement with spending key
/// Returns decrypted UTXO info or null UTXO on failure
/// announcement_data: BFieldElement array (8 bytes per element, little-endian)
/// announcement_count: number of BFieldElements
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

    // Parse BFieldElements from bytes (8 bytes per BFE, little-endian)
    let bytes = unsafe { read_slice(announcement_data, announcement_count * 8) };
    let announcement = Announcement::new(parse_bfes_le(bytes));

    // Check announcement format: [flag, receiver_id, ciphertext...]
    if announcement.message.is_empty() {
        set_last_error("empty announcement");
        return XntDecryptedUtxo::null();
    }

    let key_type = announcement.message[0];
    if key_type != GENERATION_FLAG {
        set_last_error("not a generation address announcement");
        return XntDecryptedUtxo::null();
    }

    // Check receiver_id matches
    let ann_receiver_id = match receiver_identifier_from_announcement(&announcement) {
        Ok(id) => id,
        Err(e) => {
            set_last_error(&format!("invalid announcement: {e}"));
            return XntDecryptedUtxo::null();
        }
    };

    if ann_receiver_id != key.0.receiver_identifier() {
        set_last_error("receiver_id mismatch");
        return XntDecryptedUtxo::null();
    }

    // Get ciphertext and decrypt
    let ciphertext = match ciphertext_from_announcement(&announcement) {
        Ok(ct) => ct,
        Err(e) => {
            set_last_error(&format!("invalid announcement: {e}"));
            return XntDecryptedUtxo::null();
        }
    };

    // SpendingKey::decrypt handles both Generation and Symmetric keys
    match key.0.decrypt(&ciphertext) {
        Ok((utxo, sender_randomness, payment_id)) => XntDecryptedUtxo {
            utxo: Box::into_raw(Box::new(UtxoHandle(utxo))),
            sender_randomness: XntDigest::from_digest(sender_randomness),
            payment_id: payment_id.value(),
        },
        Err(e) => {
            set_last_error(&format!("decryption failed: {e}"));
            XntDecryptedUtxo::null()
        }
    }
}

/// Free decrypted UTXO result (only the UTXO handle)
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
