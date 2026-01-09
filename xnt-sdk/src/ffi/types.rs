//! FFI types
//!
//! Minimal FFI-specific types. Domain types are opaque handles wrapping xnt-core types.

use std::ffi::c_char;

/// Buffer for returning allocated byte arrays to C callers
#[repr(C)]
#[derive(Debug)]
pub struct ByteBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl ByteBuffer {
    pub fn null() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }

    pub fn from_vec(v: Vec<u8>) -> Self {
        let mut boxed = v.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        let len = boxed.len();
        std::mem::forget(boxed);
        Self { data: ptr, len }
    }

    pub fn into_ptr(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }
}

/// Free a byte buffer allocated by xnt-ffi
///
/// # Safety
/// - Must only be called once per buffer
/// - Caller must NOT use the buffer after calling this function
/// - Calling twice on same buffer causes undefined behavior (double-free)
#[no_mangle]
pub extern "C" fn xnt_bytes_free(buf: ByteBuffer) {
    free_vec!(buf.data, buf.len);
}

/// Free a string allocated by xnt-ffi
///
/// # Safety
/// - Must only be called once per string
/// - Caller must NOT use the string after calling this function
/// - Calling twice on same pointer causes undefined behavior (double-free)
#[no_mangle]
pub extern "C" fn xnt_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(std::ffi::CString::from_raw(ptr)) }
    }
}

/// XntDigest - 40 byte digest for FFI (TIP5 output)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct XntDigest {
    pub bytes: [u8; 40],
}

impl Default for XntDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl XntDigest {
    pub const fn new() -> Self {
        Self { bytes: [0u8; 40] }
    }

    pub fn from_digest(d: Digest) -> Self {
        Self { bytes: d.into() }
    }

    pub fn from_bytes(bytes: [u8; 40]) -> Self {
        Self { bytes }
    }

    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 40 {
            return None;
        }
        let mut digest = Self::new();
        digest.bytes.copy_from_slice(&bytes);
        Some(digest)
    }

    pub fn to_digest(&self) -> Digest {
        use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
        use num_traits::ConstZero;
        let mut bfes = [BFieldElement::ZERO; 5];
        for (i, chunk) in self.bytes.chunks(8).enumerate() {
            let arr: [u8; 8] = chunk.try_into().unwrap();
            bfes[i] = BFieldElement::new(u64::from_le_bytes(arr));
        }
        Digest::new(bfes)
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
}

impl From<[u8; 40]> for XntDigest {
    fn from(bytes: [u8; 40]) -> Self {
        Self { bytes }
    }
}

impl From<XntDigest> for [u8; 40] {
    fn from(d: XntDigest) -> [u8; 40] {
        d.bytes
    }
}

impl AsRef<[u8]> for XntDigest {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::ops::Deref for XntDigest {
    type Target = [u8; 40];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl std::ops::DerefMut for XntDigest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

/// Free ByteBuffer pointer allocated by xnt-ffi
///
/// # Safety
/// - Must only be called once per buffer
/// - Caller must NOT use the buffer after calling this function
/// - Calling twice on same pointer causes undefined behavior (double-free)
#[no_mangle]
pub extern "C" fn xnt_buffer_free(buf: *mut ByteBuffer) {
    if !buf.is_null() {
        let b = unsafe { Box::from_raw(buf) };
        free_vec!(b.data, b.len);
    }
}

// Re-export xnt-core types for internal use
// These are wrapped as opaque handles in respective modules

pub use neptune_privacy::prelude::twenty_first::prelude::Digest;
pub use neptune_privacy::protocol::consensus::transaction::utxo::Utxo;
pub use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
pub use neptune_privacy::state::wallet::address::generation_address::{
    GenerationReceivingAddress, GenerationSpendingKey, GenerationSubAddress,
};
pub use neptune_privacy::state::wallet::wallet_entropy::WalletEntropy;
