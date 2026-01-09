//! FFI helper functions
//!
//! Common utilities for FFI operations across modules.

use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
use std::ffi::c_char;

use super::types::XntDigest;

/// Convert Vec to raw pointer, returning null if empty
pub fn vec_to_ptr<T>(v: Vec<T>) -> *mut T {
    if v.is_empty() {
        std::ptr::null_mut()
    } else {
        let mut boxed = v.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        std::mem::forget(boxed);
        ptr
    }
}

/// Parse C string, returns None on null or invalid UTF-8
pub fn parse_cstr(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(ptr).to_str().ok().map(String::from) }
}

/// Read bytes from FFI pointer, returns empty vec if null/zero-length
pub unsafe fn read_bytes(data: *const u8, len: usize) -> Vec<u8> {
    if data.is_null() || len == 0 {
        vec![]
    } else {
        std::slice::from_raw_parts(data, len).to_vec()
    }
}

/// Parse BFieldElements from little-endian bytes (8 bytes per BFE)
pub fn parse_bfes_le(bytes: &[u8]) -> Vec<BFieldElement> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut arr = [0u8; 8];
            arr[..chunk.len()].copy_from_slice(chunk);
            BFieldElement::new(u64::from_le_bytes(arr))
        })
        .collect()
}

/// Read slice from FFI pointer
///
/// # Safety
/// - `ptr` must be valid for `len` elements
/// - The memory must remain valid for the lifetime `'a`
/// - Caller must ensure no mutable aliases exist
#[inline]
pub unsafe fn read_slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

/// Read mutable slice from FFI pointer
///
/// # Safety
/// - `ptr` must be valid for `len` elements
/// - The memory must remain valid for the lifetime `'a`
/// - Caller must ensure exclusive access
#[inline]
pub unsafe fn read_slice_mut<'a, T>(ptr: *mut T, len: usize) -> &'a mut [T] {
    if ptr.is_null() || len == 0 {
        &mut []
    } else {
        std::slice::from_raw_parts_mut(ptr, len)
    }
}

/// Parse XntDigest array to Vec<Digest>
pub fn parse_digests(digests: &[XntDigest]) -> Vec<neptune_privacy::prelude::twenty_first::prelude::Digest> {
    digests.iter().map(|d| d.to_digest()).collect()
}
