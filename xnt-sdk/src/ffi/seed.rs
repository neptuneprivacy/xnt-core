//! Wallet seed/entropy FFI
//!
//! Wraps core::WalletEntropy and core::SpendingKey for C FFI.

use std::ffi::c_char;

use crate::core::{legacy_dctidh_cutoff, SpendingKey, WalletEntropy};

use super::address::network_from_raw;
use super::error::{ffi_guard, set_last_error, XntErrorCode};
use super::helpers::{free_handle, parse_cstr};
use super::types::XntDigest;

/// Opaque handle to wallet entropy
pub struct WalletEntropyHandle(pub(crate) WalletEntropy);

/// Opaque handle to spending key
pub struct SpendingKeyHandle(pub(crate) SpendingKey);

/// Generate new wallet with random 18-word mnemonic
#[no_mangle]
pub extern "C" fn xnt_wallet_generate() -> *mut WalletEntropyHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        match WalletEntropy::generate() {
            Ok(entropy) => Box::into_raw(Box::new(WalletEntropyHandle(entropy))),
            Err(_) => {
                set_last_error("wallet generation failed");
                std::ptr::null_mut()
            }
        }
    })
}

/// Create wallet from mnemonic phrase (space-separated words)
#[no_mangle]
pub extern "C" fn xnt_wallet_from_mnemonic(mnemonic: *const c_char) -> *mut WalletEntropyHandle {
    ffi_guard(std::ptr::null_mut(), || {
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
    })
}

/// Get devnet test wallet
#[no_mangle]
pub extern "C" fn xnt_wallet_devnet() -> *mut WalletEntropyHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        Box::into_raw(Box::new(WalletEntropyHandle(WalletEntropy::devnet())))
    })
}

/// Free a wallet handle. NULL is ignored.
#[no_mangle]
pub extern "C" fn xnt_wallet_free(handle: *mut WalletEntropyHandle) {
    ffi_guard((), || free_handle(handle))
}

/// Export wallet to mnemonic phrase
#[no_mangle]
pub extern "C" fn xnt_wallet_to_mnemonic(handle: *const WalletEntropyHandle) -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "wallet handle is null");

        let wallet = ffi_ref!(handle);
        ffi_cstring!(wallet.0.to_mnemonic())
    })
}

/// Derive Nth generation spending key
#[no_mangle]
pub extern "C" fn xnt_wallet_derive_key(handle: *const WalletEntropyHandle, index: u64) -> *mut SpendingKeyHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "wallet handle is null");

        let wallet = ffi_ref!(handle);
        Box::into_raw(Box::new(SpendingKeyHandle(
            wallet.0.derive_spending_key(index),
        )))
    })
}

/// Derive Nth CTIDH spending key (CTIDH-512)
#[no_mangle]
pub extern "C" fn xnt_wallet_derive_dctidh_key(
    handle: *const WalletEntropyHandle,
    index: u64,
) -> *mut SpendingKeyHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "wallet handle is null");

        let wallet = ffi_ref!(handle);
        Box::into_raw(Box::new(SpendingKeyHandle(
            wallet.0.derive_dctidh_spending_key(index),
        )))
    })
}

/// Derive Nth CTIDH spending key using the legacy (pre-v0.3) derivation, for
/// recognising and sweeping funds at legacy-format dCTIDH addresses.
///
/// UTXOs of such a key are sweep-only, see xnt_spending_key_is_legacy.
#[no_mangle]
pub extern "C" fn xnt_wallet_derive_legacy_dctidh_key(
    handle: *const WalletEntropyHandle,
    index: u64,
) -> *mut SpendingKeyHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "wallet handle is null");

        let wallet = ffi_ref!(handle);
        Box::into_raw(Box::new(SpendingKeyHandle(
            wallet.0.derive_legacy_dctidh_spending_key(index),
        )))
    })
}

/// Free a spending key handle. NULL is ignored.
#[no_mangle]
pub extern "C" fn xnt_spending_key_free(handle: *mut SpendingKeyHandle) {
    ffi_guard((), || free_handle(handle))
}

/// Get receiver_id from spending key
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id(handle: *const SpendingKeyHandle) -> u64 {
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        ffi_ref!(handle).0.receiver_id()
    })
}

/// Get receiver_id as hex string
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hex(handle: *const SpendingKeyHandle) -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");
        ffi_cstring!(ffi_ref!(handle).0.receiver_id_hex())
    })
}

/// Get receiver_id_hash for indexer lookups (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hash(handle: *const SpendingKeyHandle, out: *mut u8) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        check_null!(handle);
        check_null!(out);

        let key = ffi_ref!(handle);
        let hash = key.0.receiver_id_hash();
        copy_bytes_out!(hash.bytes, out, 40)
    })
}

/// Get receiver_id_hash as XntDigest
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hash_digest(handle: *const SpendingKeyHandle) -> XntDigest {
    ffi_guard(XntDigest::new(), || {
        if handle.is_null() {
            return XntDigest::new();
        }
        let key = ffi_ref!(handle);
        XntDigest::from_bytes(key.0.receiver_id_hash().bytes)
    })
}

/// Get receiver preimage (privacy_preimage) for commitment computation (40 bytes)
///
/// For dCTIDH keys this is also the unlock preimage of the key's lock script:
/// anyone who knows it can spend the key's UTXOs. Treat it as a spending
/// secret: keep it on the device that holds the seed, do not log it, send it
/// to a server or store it unencrypted.
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_preimage(handle: *const SpendingKeyHandle, out: *mut u8) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        check_null!(handle);
        check_null!(out);

        let key = ffi_ref!(handle);
        let preimage = key.0.receiver_preimage();
        copy_bytes_out!(preimage.bytes, out, 40)
    })
}

/// Get receiver preimage as hex string
///
/// A spending secret for dCTIDH keys, see xnt_spending_key_receiver_preimage.
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_preimage_hex(handle: *const SpendingKeyHandle) -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");
        ffi_cstring!(ffi_ref!(handle).0.receiver_preimage().to_hex())
    })
}

/// Get receiver_id_hash as hex string
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hash_hex(handle: *const SpendingKeyHandle) -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");
        ffi_cstring!(ffi_ref!(handle).0.receiver_id_hash().to_hex())
    })
}

/// Get the hash of the lock script this key can satisfy (40 bytes)
///
/// UTXOs whose lock script hash (xnt_utxo_lock_script_hash) differs cannot be
/// spent by this key.
#[no_mangle]
pub extern "C" fn xnt_spending_key_lock_script_hash(
    handle: *const SpendingKeyHandle,
    out: *mut u8,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        check_null!(handle);
        check_null!(out);

        let hash = ffi_ref!(handle).0.lock_script_hash();
        copy_bytes_out!(hash.bytes, out, 40)
    })
}

/// True for dCTIDH keys derived with the legacy (pre-v0.3) lock derivation
/// (xnt_wallet_derive_legacy_dctidh_key). False for other keys and for NULL.
///
/// UTXOs of such a key are sweep-only: move them to a current-format key and
/// never count them towards the available balance.
#[no_mangle]
pub extern "C" fn xnt_spending_key_is_legacy(handle: *const SpendingKeyHandle) -> bool {
    ffi_guard(false, || {
        if handle.is_null() {
            return false;
        }
        ffi_ref!(handle).0.is_legacy()
    })
}

/// Whether UTXOs of this key confirmed in a block of height `block_height`
/// are recognized on `network` (one of the XntNetwork values).
///
/// Always true for keys that are not legacy; for legacy keys true only below
/// xnt_legacy_dctidh_cutoff. False for NULL or an invalid network.
#[no_mangle]
pub extern "C" fn xnt_spending_key_recognizes_utxos_at(
    handle: *const SpendingKeyHandle,
    network: u32,
    block_height: u64,
) -> bool {
    ffi_guard(false, || {
        ffi_begin!();
        if handle.is_null() {
            set_last_error("null pointer");
            return false;
        }
        let Some(network) = network_from_raw(network) else {
            set_last_error("invalid network");
            return false;
        };
        ffi_ref!(handle)
            .0
            .recognizes_utxos_at(network, block_height)
    })
}

/// The block height from which UTXOs at legacy-format (pre-v0.3) dCTIDH locks
/// are no longer recognized on `network` (one of the XntNetwork values).
///
/// Returns UINT64_MAX if there is no cutoff (every height is below it), and 0
/// with the last error set for an invalid network.
#[no_mangle]
pub extern "C" fn xnt_legacy_dctidh_cutoff(network: u32) -> u64 {
    ffi_guard(0, || {
        ffi_begin!();
        let Some(network) = network_from_raw(network) else {
            set_last_error("invalid network");
            return 0;
        };
        legacy_dctidh_cutoff(network).unwrap_or(u64::MAX)
    })
}

/// Alias for xnt_wallet_derive_key (backwards compatibility)
#[no_mangle]
pub extern "C" fn xnt_wallet_derive_spending_key(handle: *const WalletEntropyHandle, index: u64) -> *mut SpendingKeyHandle {
    ffi_guard(std::ptr::null_mut(), || {
        xnt_wallet_derive_key(handle, index)
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::address::XntNetwork;

    #[test]
    fn legacy_keys_and_cutoff() {
        let wallet = xnt_wallet_devnet();
        let current = xnt_wallet_derive_dctidh_key(wallet, 0);
        let legacy = xnt_wallet_derive_legacy_dctidh_key(wallet, 0);

        assert!(!xnt_spending_key_is_legacy(current));
        assert!(xnt_spending_key_is_legacy(legacy));
        assert!(!xnt_spending_key_is_legacy(std::ptr::null()));

        let mut current_lock = [0u8; 40];
        let mut legacy_lock = [0u8; 40];
        let code = xnt_spending_key_lock_script_hash(current, current_lock.as_mut_ptr());
        assert_eq!(XntErrorCode::Ok, code);
        let code = xnt_spending_key_lock_script_hash(legacy, legacy_lock.as_mut_ptr());
        assert_eq!(XntErrorCode::Ok, code);
        assert_ne!(current_lock, legacy_lock);

        let main = XntNetwork::Main as u32;
        let cutoff = xnt_legacy_dctidh_cutoff(main);
        assert!(xnt_spending_key_recognizes_utxos_at(
            legacy,
            main,
            cutoff - 1
        ));
        assert!(!xnt_spending_key_recognizes_utxos_at(legacy, main, cutoff));
        assert!(xnt_spending_key_recognizes_utxos_at(current, main, cutoff));
        assert_eq!(
            u64::MAX,
            xnt_legacy_dctidh_cutoff(XntNetwork::RegTest as u32)
        );

        // not a network
        assert_eq!(0, xnt_legacy_dctidh_cutoff(4));
        assert!(!xnt_spending_key_recognizes_utxos_at(current, 4, 0));

        xnt_spending_key_free(legacy);
        xnt_spending_key_free(current);
        xnt_wallet_free(wallet);
    }
}
