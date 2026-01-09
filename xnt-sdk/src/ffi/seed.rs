//! Wallet seed/entropy FFI
//!
//! Wraps core::WalletEntropy and core::SpendingKey for C FFI.

use std::ffi::c_char;

use crate::core::{SpendingKey, WalletEntropy};

use super::error::{set_last_error, XntErrorCode};
use super::helpers::parse_cstr;
use super::types::XntDigest;

/// Opaque handle to wallet entropy
pub struct WalletEntropyHandle(pub(crate) WalletEntropy);

/// Opaque handle to spending key
pub struct SpendingKeyHandle(pub(crate) SpendingKey);

/// Generate new wallet with random 18-word mnemonic
#[no_mangle]
pub extern "C" fn xnt_wallet_generate() -> *mut WalletEntropyHandle {
    ffi_begin!();
    match WalletEntropy::generate() {
        Ok(entropy) => Box::into_raw(Box::new(WalletEntropyHandle(entropy))),
        Err(_) => {
            set_last_error("wallet generation failed");
            std::ptr::null_mut()
        }
    }
}

/// Create wallet from mnemonic phrase (space-separated words)
#[no_mangle]
pub extern "C" fn xnt_wallet_from_mnemonic(mnemonic: *const c_char) -> *mut WalletEntropyHandle {
    ffi_begin!();

    let Some(phrase) = parse_cstr(mnemonic) else {
        set_last_error("invalid mnemonic string");
        return std::ptr::null_mut();
    };

    match WalletEntropy::from_mnemonic(&phrase) {
        Ok(entropy) => Box::into_raw(Box::new(WalletEntropyHandle(entropy))),
        Err(_) => {
            set_last_error("invalid mnemonic");
            std::ptr::null_mut()
        }
    }
}

/// Get devnet test wallet
#[no_mangle]
pub extern "C" fn xnt_wallet_devnet() -> *mut WalletEntropyHandle {
    ffi_begin!();
    Box::into_raw(Box::new(WalletEntropyHandle(WalletEntropy::devnet())))
}

ffi_free!(xnt_wallet_free, WalletEntropyHandle);

/// Export wallet to mnemonic phrase
#[no_mangle]
pub extern "C" fn xnt_wallet_to_mnemonic(handle: *const WalletEntropyHandle) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "wallet handle is null");

    let wallet = ffi_ref!(handle);
    ffi_cstring!(wallet.0.to_mnemonic())
}

/// Derive Nth generation spending key
#[no_mangle]
pub extern "C" fn xnt_wallet_derive_key(handle: *const WalletEntropyHandle, index: u64) -> *mut SpendingKeyHandle {
    ffi_begin!();
    check_null!(handle, "wallet handle is null");

    let wallet = ffi_ref!(handle);
    Box::into_raw(Box::new(SpendingKeyHandle(wallet.0.derive_spending_key(index))))
}

ffi_free!(xnt_spending_key_free, SpendingKeyHandle);

/// Get receiver_id from spending key
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id(handle: *const SpendingKeyHandle) -> u64 {
    if handle.is_null() {
        return 0;
    }
    ffi_ref!(handle).0.receiver_id()
}

/// Get receiver_id as hex string
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hex(handle: *const SpendingKeyHandle) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "null pointer");
    ffi_cstring!(ffi_ref!(handle).0.receiver_id_hex())
}

/// Get receiver_id_hash for indexer lookups (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hash(handle: *const SpendingKeyHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let key = ffi_ref!(handle);
    let hash = key.0.receiver_id_hash();
    copy_bytes_out!(hash.bytes, out, 40)
}

/// Get receiver_id_hash as XntDigest
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hash_digest(handle: *const SpendingKeyHandle) -> XntDigest {
    if handle.is_null() {
        return XntDigest::new();
    }
    let key = ffi_ref!(handle);
    XntDigest::from_bytes(key.0.receiver_id_hash().bytes)
}

/// Get receiver preimage (privacy_preimage) for commitment computation (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_preimage(handle: *const SpendingKeyHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let key = ffi_ref!(handle);
    let preimage = key.0.receiver_preimage();
    copy_bytes_out!(preimage.bytes, out, 40)
}

/// Get receiver preimage as hex string
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_preimage_hex(handle: *const SpendingKeyHandle) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "null pointer");
    ffi_cstring!(ffi_ref!(handle).0.receiver_preimage().to_hex())
}

/// Get receiver_id_hash as hex string
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hash_hex(handle: *const SpendingKeyHandle) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "null pointer");
    ffi_cstring!(ffi_ref!(handle).0.receiver_id_hash().to_hex())
}

/// Alias for xnt_wallet_derive_key (backwards compatibility)
#[no_mangle]
pub extern "C" fn xnt_wallet_derive_spending_key(handle: *const WalletEntropyHandle, index: u64) -> *mut SpendingKeyHandle {
    xnt_wallet_derive_key(handle, index)
}

