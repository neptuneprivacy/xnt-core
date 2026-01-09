//! Cryptographic primitives FFI
//!
//! TIP5 hash, SHAKE256 XOF, AES-256-GCM, and byte conversions.

use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use neptune_privacy::prelude::tasm_lib::prelude::Tip5;
use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;

use super::error::{set_last_error, XntErrorCode};
use super::helpers::{read_bytes, read_slice};
use super::types::{ByteBuffer, XntDigest};


/// Hash arbitrary bytes with TIP5, output = 40 bytes (Digest)
/// out: Buffer to write 40 bytes
#[no_mangle]
pub extern "C" fn xnt_tip5_hash(data: *const u8, data_len: usize, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_data!(data, data_len);
    check_null!(out, "output buffer is null", XntErrorCode::NullPointer);

    let bytes = unsafe { read_bytes(data, data_len) };
    let result: [u8; 40] = Tip5::hash_varlen(&bytes_to_bfes(&bytes)).into();
    copy_bytes_out!(result, out, 40)
}

/// Hash two digests with TIP5 (Merkle tree style), output = 40 bytes
#[no_mangle]
pub extern "C" fn xnt_tip5_hash_pair(left: *const XntDigest, right: *const XntDigest, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(left);
    check_null!(right);
    check_null!(out);

    let result: [u8; 40] = Tip5::hash_pair(ffi_ref!(left).to_digest(), ffi_ref!(right).to_digest()).into();
    copy_bytes_out!(result, out, 40)
}

/// Hash a single digest (self-hash), output = 40 bytes
#[no_mangle]
pub extern "C" fn xnt_tip5_hash_digest(digest: *const XntDigest, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(digest);
    check_null!(out);

    let result: [u8; 40] = ffi_ref!(digest).to_digest().hash().into();
    copy_bytes_out!(result, out, 40)
}


/// Maximum output length for SHAKE256 (1MB) - prevents OOM attacks
const MAX_SHAKE256_OUTPUT: usize = 1_000_000;

/// SHAKE256 XOF - variable output length
/// Returns allocated buffer, caller must free with xnt_buffer_free()
#[no_mangle]
pub extern "C" fn xnt_shake256(data: *const u8, data_len: usize, output_len: usize) -> *mut ByteBuffer {
    ffi_begin!();
    check_data!(data, data_len, std::ptr::null_mut());
    if output_len == 0 {
        set_last_error("output_len must be > 0");
        return std::ptr::null_mut();
    }

    if output_len > MAX_SHAKE256_OUTPUT {
        set_last_error("output_len too large (max 1MB)");
        return std::ptr::null_mut();
    }

    let bytes = unsafe { read_bytes(data, data_len) };
    let mut hasher = Shake256::default();
    hasher.update(&bytes);

    let mut result = vec![0u8; output_len];
    hasher.finalize_xof_into(&mut result);
    ffi_buffer!(result)
}

/// SHAKE256 with fixed 32-byte output (common case for AES keys)
#[no_mangle]
pub extern "C" fn xnt_shake256_32(data: *const u8, data_len: usize, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_data!(data, data_len);
    check_null!(out, "output buffer is null", XntErrorCode::NullPointer);

    let bytes = unsafe { read_bytes(data, data_len) };
    let mut hasher = Shake256::default();
    hasher.update(&bytes);

    let mut result = [0u8; 32];
    hasher.finalize_xof_into(&mut result);
    copy_bytes_out!(result, out, 32)
}


/// AES-256-GCM encrypt
/// key: 32 bytes, nonce: 12 bytes
/// Returns encrypted ciphertext with auth tag, caller must free with xnt_buffer_free()
#[no_mangle]
pub extern "C" fn xnt_aes256gcm_encrypt(
    key: *const u8,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(key, "key is null");
    check_null!(nonce, "nonce is null");
    check_data!(plaintext, plaintext_len, std::ptr::null_mut());

    let key_slice = unsafe { read_slice(key, 32) };
    let nonce_slice = unsafe { read_slice(nonce, 12) };
    let plaintext_slice = unsafe { read_slice(plaintext, plaintext_len) };

    let cipher = match Aes256Gcm::new_from_slice(key_slice) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("invalid key: {e}"));
            return std::ptr::null_mut();
        }
    };
    match cipher.encrypt(Nonce::from_slice(nonce_slice), plaintext_slice) {
        Ok(ciphertext) => ffi_buffer!(ciphertext),
        Err(e) => {
            set_last_error(&format!("encryption failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// AES-256-GCM decrypt
/// key: 32 bytes, nonce: 12 bytes
/// Returns decrypted plaintext, caller must free with xnt_buffer_free()
#[no_mangle]
pub extern "C" fn xnt_aes256gcm_decrypt(
    key: *const u8,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
) -> *mut ByteBuffer {
    ffi_begin!();
    check_null!(key, "key is null");
    check_null!(nonce, "nonce is null");
    if ciphertext.is_null() || ciphertext_len == 0 {
        set_last_error("ciphertext is null or empty");
        return std::ptr::null_mut();
    }

    let key_slice = unsafe { read_slice(key, 32) };
    let nonce_slice = unsafe { read_slice(nonce, 12) };
    let ciphertext_slice = unsafe { read_slice(ciphertext, ciphertext_len) };

    let cipher = match Aes256Gcm::new_from_slice(key_slice) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("invalid key: {e}"));
            return std::ptr::null_mut();
        }
    };
    match cipher.decrypt(Nonce::from_slice(nonce_slice), ciphertext_slice) {
        Ok(plaintext) => ffi_buffer!(plaintext),
        Err(e) => {
            set_last_error(&format!("decryption failed: {e}"));
            std::ptr::null_mut()
        }
    }
}


/// Encodes a slice of bytes to a vec of BFieldElements
fn bytes_to_bfes(bytes: &[u8]) -> Vec<BFieldElement> {
    let mut padded_bytes = bytes.to_vec();
    while padded_bytes.len() % 8 != 0 {
        padded_bytes.push(0u8);
    }
    let mut bfes = vec![BFieldElement::new(bytes.len() as u64)];
    for chunk in padded_bytes.chunks(8) {
        let ch: [u8; 8] = chunk.try_into().unwrap();
        let int = u64::from_be_bytes(ch);
        if int < BFieldElement::P - 1 {
            bfes.push(BFieldElement::new(int));
        } else {
            let rem = int & 0xffffffff;
            bfes.push(BFieldElement::new(BFieldElement::P - 1));
            bfes.push(BFieldElement::new(rem));
        }
    }
    bfes
}
