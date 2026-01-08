//! Seed and key management FFI
//!
//! BIP39 mnemonic generation, import/export, and spending key derivation.

use std::ffi::c_char;

use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;

use crate::error::{set_last_error, XntErrorCode};
use crate::helpers::parse_cstr;
use neptune_privacy::state::wallet::address::SpendingKey;
use neptune_privacy::state::wallet::secret_key_material::SecretKeyMaterial;
use neptune_privacy::state::wallet::wallet_entropy::WalletEntropy;

/// Opaque handle to wallet entropy (secret seed)
pub struct WalletHandle(pub(crate) WalletEntropy);

/// Opaque handle to spending key (Generation or Symmetric)
pub struct SpendingKeyHandle(pub(crate) SpendingKey);

/// Generate a new random wallet with 18-word mnemonic
/// Returns NULL on failure, check xnt_get_last_error()
#[no_mangle]
pub extern "C" fn xnt_wallet_generate() -> *mut WalletHandle {
    use bip39::{Language, Mnemonic, MnemonicType};

    ffi_begin!();

    let mnemonic = Mnemonic::new(MnemonicType::Words18, Language::English);
    let words: Vec<String> = mnemonic.phrase().split(' ').map(|s| s.to_string()).collect();

    ffi_result!(WalletEntropy::from_phrase(&words), WalletHandle, "failed to create wallet")
}

/// Create wallet from 18-word mnemonic phrase (space-separated)
/// Returns NULL on failure
#[no_mangle]
pub extern "C" fn xnt_wallet_from_mnemonic(mnemonic: *const c_char) -> *mut WalletHandle {
    ffi_begin!();

    let Some(phrase_str) = parse_cstr(mnemonic) else {
        set_last_error("invalid mnemonic");
        return std::ptr::null_mut();
    };

    let words: Vec<String> = phrase_str.split_whitespace().map(|s| s.to_string()).collect();

    if words.len() != 18 {
        set_last_error(&format!("expected 18 words, got {}", words.len()));
        return std::ptr::null_mut();
    }

    ffi_result!(WalletEntropy::from_phrase(&words), WalletHandle, "invalid mnemonic")
}

/// Export wallet to 18-word mnemonic phrase (space-separated)
/// Caller must free returned string with xnt_string_free()
#[no_mangle]
pub extern "C" fn xnt_wallet_to_mnemonic(handle: *const WalletHandle) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "wallet handle is null");

    let wallet = ffi_ref!(handle);
    let secret: SecretKeyMaterial = wallet.0.clone().into();
    ffi_cstring!(secret.to_phrase().join(" "), "encoding error")
}

ffi_free!(xnt_wallet_free, WalletHandle);

/// Derive Nth generation spending key from wallet
/// index: Key derivation index (0 = guesser/composer fee key)
#[no_mangle]
pub extern "C" fn xnt_wallet_derive_spending_key(
    handle: *const WalletHandle,
    index: u64,
) -> *mut SpendingKeyHandle {
    ffi_begin!();
    check_null!(handle, "wallet handle is null");

    let wallet = ffi_ref!(handle);
    let gen_key = wallet.0.nth_generation_spending_key(index);
    Box::into_raw(Box::new(SpendingKeyHandle(SpendingKey::Generation(gen_key))))
}

ffi_free!(xnt_spending_key_free, SpendingKeyHandle);

/// Get receiver identifier from spending key (8 bytes, little-endian u64)
/// out: Buffer to write 8 bytes
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id(
    handle: *const SpendingKeyHandle,
    out: *mut u8,
) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let key = ffi_ref!(handle);
    let bytes = key.0.receiver_identifier().value().to_le_bytes();
    copy_bytes_out!(bytes, out, 8)
}

/// Get receiver identifier as hex string
/// Caller must free returned string with xnt_string_free()
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hex(handle: *const SpendingKeyHandle) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "null pointer");

    let key = ffi_ref!(handle);
    ffi_cstring!(format!("{:016x}", key.0.receiver_identifier().value()), "encoding error")
}

/// Get receiver_id_hash (TIP5 hash of receiver_identifier) for indexer lookups
/// out: Buffer to write 40 bytes (Digest)
#[no_mangle]
pub extern "C" fn xnt_spending_key_receiver_id_hash(
    handle: *const SpendingKeyHandle,
    out: *mut u8,
) -> XntErrorCode {
    use neptune_privacy::prelude::twenty_first::prelude::Tip5;

    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let key = ffi_ref!(handle);
    let receiver_id: BFieldElement = key.0.receiver_identifier();
    let hash: [u8; 40] = Tip5::hash_varlen(&[receiver_id]).into();
    copy_bytes_out!(hash, out, 40)
}
