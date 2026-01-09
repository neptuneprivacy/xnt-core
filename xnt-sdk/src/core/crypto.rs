//! Cryptographic primitives

use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use neptune_privacy::prelude::tasm_lib::prelude::Tip5;
use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;

use super::error::{Result, XntError};
use super::types::Digest;


/// Hash arbitrary bytes with TIP5, output = 40 bytes (Digest)
pub fn tip5_hash(data: &[u8]) -> Digest {
    Digest::from_core(Tip5::hash_varlen(&bytes_to_bfes(data)))
}

/// Hash two digests with TIP5 (Merkle tree style)
pub fn tip5_hash_pair(left: &Digest, right: &Digest) -> Digest {
    Digest::from_core(Tip5::hash_pair(left.to_core(), right.to_core()))
}

/// Hash a single digest (self-hash)
pub fn tip5_hash_digest(digest: &Digest) -> Digest {
    Digest::from_core(digest.to_core().hash())
}


/// SHAKE256 XOF - variable output length
pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut result = vec![0u8; output_len];
    hasher.finalize_xof_into(&mut result);
    result
}

/// SHAKE256 with fixed 32-byte output (common case for AES keys)
pub fn shake256_32(data: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut result = [0u8; 32];
    hasher.finalize_xof_into(&mut result);
    result
}


/// AES-256-GCM encrypt
/// key: 32 bytes, nonce: 12 bytes
pub fn aes256gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key is 32 bytes");
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| XntError::CryptoError(format!("encryption failed: {e}")))
}

/// AES-256-GCM decrypt
/// key: 32 bytes, nonce: 12 bytes
pub fn aes256gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key is 32 bytes");
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| XntError::CryptoError(format!("decryption failed: {e}")))
}


/// Convert bytes to BFieldElements encoding
pub fn bytes_to_bfes(bytes: &[u8]) -> Vec<BFieldElement> {
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

/// Convert BFieldElements back to bytes
pub fn bfes_to_bytes(bfes: &[BFieldElement]) -> Result<Vec<u8>> {
    if bfes.is_empty() {
        return Err(XntError::InvalidInput(
            "Cannot decode empty byte stream".to_string(),
        ));
    }

    let length = bfes[0].value() as usize;
    if length > std::mem::size_of_val(bfes) {
        return Err(XntError::InvalidInput(
            "Byte stream shorter than indicated length".to_string(),
        ));
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
        return Err(XntError::InvalidInput(
            "Decoded fewer bytes than expected".to_string(),
        ));
    }
    Ok(bytes[0..length].to_vec())
}

/// Parse bytes as little-endian BFieldElements (8 bytes each)
pub fn parse_bfes_le(data: &[u8]) -> Vec<BFieldElement> {
    data.chunks(8)
        .map(|chunk| {
            let mut arr = [0u8; 8];
            arr[..chunk.len()].copy_from_slice(chunk);
            BFieldElement::new(u64::from_le_bytes(arr))
        })
        .collect()
}
