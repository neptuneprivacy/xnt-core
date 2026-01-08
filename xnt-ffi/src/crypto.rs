//! Cryptographic primitives FFI
//!
//! TIP5 hash, SHAKE256 XOF, AES-256-GCM, and byte conversions.

use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use neptune_privacy::prelude::tasm_lib::prelude::Tip5;
use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;

use crate::error::{set_last_error, XntErrorCode};
use crate::helpers::{read_bytes, read_slice};
use crate::types::XntDigest;

// === TIP5 Hash ===

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

// === SHAKE256 XOF ===

/// SHAKE256 XOF - variable output length
/// Returns allocated buffer, caller must free with xnt_buffer_free()
#[no_mangle]
pub extern "C" fn xnt_shake256(data: *const u8, data_len: usize, output_len: usize) -> *mut crate::types::ByteBuffer {
    ffi_begin!();
    check_data!(data, data_len, std::ptr::null_mut());
    if output_len == 0 {
        set_last_error("output_len must be > 0");
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

// === AES-256-GCM ===

/// AES-256-GCM encrypt
/// key: 32 bytes, nonce: 12 bytes
/// Returns encrypted ciphertext with auth tag, caller must free with xnt_buffer_free()
#[no_mangle]
pub extern "C" fn xnt_aes256gcm_encrypt(
    key: *const u8,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
) -> *mut crate::types::ByteBuffer {
    ffi_begin!();
    check_null!(key, "key is null");
    check_null!(nonce, "nonce is null");
    check_data!(plaintext, plaintext_len, std::ptr::null_mut());

    let key_slice = unsafe { read_slice(key, 32) };
    let nonce_slice = unsafe { read_slice(nonce, 12) };
    let plaintext_slice = unsafe { read_slice(plaintext, plaintext_len) };

    let cipher = Aes256Gcm::new_from_slice(key_slice).expect("key is 32 bytes");
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
) -> *mut crate::types::ByteBuffer {
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

    let cipher = Aes256Gcm::new_from_slice(key_slice).expect("key is 32 bytes");
    match cipher.decrypt(Nonce::from_slice(nonce_slice), ciphertext_slice) {
        Ok(plaintext) => ffi_buffer!(plaintext),
        Err(e) => {
            set_last_error(&format!("decryption failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

// === BFieldElement Encoding ===

/// Convert bytes to BFieldElements encoding
/// Returns allocated buffer containing BFE values (8 bytes each, little-endian)
/// Caller must free with xnt_buffer_free()
#[no_mangle]
pub extern "C" fn xnt_bytes_to_bfes(data: *const u8, data_len: usize) -> *mut crate::types::ByteBuffer {
    ffi_begin!();

    let bytes = unsafe { read_slice(data, data_len) };
    let bfes = bytes_to_bfes(bytes);

    // Serialize BFEs as little-endian u64s
    let result: Vec<u8> = bfes.iter().flat_map(|bfe| bfe.value().to_le_bytes()).collect();
    ffi_buffer!(result)
}

/// Convert BFieldElements back to bytes
/// bfes_data: Buffer of BFE values (8 bytes each, little-endian)
/// Returns decoded bytes, caller must free with xnt_buffer_free()
#[no_mangle]
pub extern "C" fn xnt_bfes_to_bytes(bfes_data: *const u8, bfes_len: usize) -> *mut crate::types::ByteBuffer {
    ffi_begin!();
    if bfes_data.is_null() || bfes_len == 0 {
        set_last_error("bfes_data is null or empty");
        return std::ptr::null_mut();
    }
    if bfes_len % 8 != 0 {
        set_last_error("bfes_len must be multiple of 8");
        return std::ptr::null_mut();
    }

    let data = unsafe { read_slice(bfes_data, bfes_len) };
    let bfes = crate::helpers::parse_bfes_le(data);
    ffi_buffer!(bfes_to_bytes(&bfes), "bfes decode failed")
}

// === Internal helpers ===

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

/// Decodes a slice of BFieldElements to a vec of bytes
fn bfes_to_bytes(bfes: &[BFieldElement]) -> Result<Vec<u8>, &'static str> {
    if bfes.is_empty() {
        return Err("Cannot decode empty byte stream");
    }

    let length = bfes[0].value() as usize;
    if length > std::mem::size_of_val(bfes) {
        return Err("Byte stream shorter than indicated length");
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(length);
    let mut skip_top = false;
    for bfe in bfes.iter().skip(1) {
        let bfe_bytes = bfe.value().to_be_bytes();
        if skip_top {
            bytes.extend_from_slice(&bfe_bytes[4..8]);
            skip_top = false;
        } else {
            bytes.extend_from_slice(&bfe_bytes[0..4]);
            if bfe_bytes[0..4] == [0xff, 0xff, 0xff, 0xff] {
                skip_top = true;
            } else {
                bytes.extend_from_slice(&bfe_bytes[4..8]);
            }
        }
    }

    if bytes.len() < length {
        return Err("Decoded fewer bytes than expected");
    }
    Ok(bytes[0..length].to_vec())
}
