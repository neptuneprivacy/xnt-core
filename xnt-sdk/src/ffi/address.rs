//! Address generation FFI
//!
//! Wraps core::Address and core::SubAddress for C FFI.

use std::ffi::c_char;

use crate::core::{Address, Network, SubAddress};

use super::error::{set_last_error, XntErrorCode};
use super::helpers::parse_cstr;
use super::seed::SpendingKeyHandle;

/// Opaque handle to receiving address
pub struct AddressHandle(pub(crate) Address);

/// Opaque handle to subaddress (address + payment_id)
pub struct SubAddressHandle(pub(crate) SubAddress);

/// Network type for address encoding (C-compatible)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum XntNetwork {
    Main = 0,
    TestnetMock = 1,
    RegTest = 2,
    Testnet = 3,
}

impl From<XntNetwork> for Network {
    fn from(n: XntNetwork) -> Self {
        match n {
            XntNetwork::Main => Network::Main,
            XntNetwork::TestnetMock => Network::TestnetMock,
            XntNetwork::RegTest => Network::RegTest,
            XntNetwork::Testnet => Network::Testnet,
        }
    }
}

/// Get receiving address from spending key
#[no_mangle]
pub extern "C" fn xnt_spending_key_to_address(handle: *const SpendingKeyHandle) -> *mut AddressHandle {
    ffi_begin!();
    check_null!(handle, "spending key handle is null");

    let key = ffi_ref!(handle);
    Box::into_raw(Box::new(AddressHandle(key.0.to_address())))
}

ffi_free!(xnt_address_free, AddressHandle);

/// Encode address to bech32m string
#[no_mangle]
pub extern "C" fn xnt_address_to_bech32(handle: *const AddressHandle, network: XntNetwork) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "address handle is null");

    let addr = ffi_ref!(handle);
    match addr.0.to_bech32(network.into()) {
        Ok(s) => ffi_cstring!(s),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

// Neptune addresses contain full cryptographic data and can be ~4000+ chars
const MAX_BECH32_LENGTH: usize = 8192;

/// Decode address from bech32m string
#[no_mangle]
pub extern "C" fn xnt_address_from_bech32(bech32: *const c_char, network: XntNetwork) -> *mut AddressHandle {
    ffi_begin!();

    let Some(s) = parse_cstr(bech32) else {
        set_last_error("invalid bech32 string");
        return std::ptr::null_mut();
    };

    if s.len() > MAX_BECH32_LENGTH {
        set_last_error("bech32 string too long");
        return std::ptr::null_mut();
    }

    match Address::from_bech32(&s, network.into()) {
        Ok(addr) => Box::into_raw(Box::new(AddressHandle(addr))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get lock_script_hash from address (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_address_lock_script_hash(handle: *const AddressHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let addr = ffi_ref!(handle);
    let hash = addr.0.lock_script_hash();
    copy_bytes_out!(hash.bytes, out, 40)
}

/// Get receiver_identifier from address (8 bytes)
#[no_mangle]
pub extern "C" fn xnt_address_receiver_id(handle: *const AddressHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let addr = ffi_ref!(handle);
    let bytes = addr.0.receiver_id().to_le_bytes();
    copy_bytes_out!(bytes, out, 8)
}

/// Get receiver_identifier as hex string
#[no_mangle]
pub extern "C" fn xnt_address_receiver_id_hex(handle: *const AddressHandle) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "null pointer");

    let addr = ffi_ref!(handle);
    ffi_cstring!(addr.0.receiver_id_hex())
}

/// Get privacy_digest from address (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_address_privacy_digest(handle: *const AddressHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let addr = ffi_ref!(handle);
    let digest = addr.0.privacy_digest();
    copy_bytes_out!(digest.bytes, out, 40)
}


/// Create subaddress from address with payment_id
#[no_mangle]
pub extern "C" fn xnt_subaddress_create(address: *const AddressHandle, payment_id: u64) -> *mut SubAddressHandle {
    ffi_begin!();
    check_null!(address, "address handle is null");

    let addr = ffi_ref!(address);
    match addr.0.with_payment_id(payment_id) {
        Ok(subaddr) => Box::into_raw(Box::new(SubAddressHandle(subaddr))),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

ffi_free!(xnt_subaddress_free, SubAddressHandle);

/// Encode subaddress to bech32m string
#[no_mangle]
pub extern "C" fn xnt_subaddress_to_bech32(handle: *const SubAddressHandle, network: XntNetwork) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "subaddress handle is null");

    let subaddr = ffi_ref!(handle);
    match subaddr.0.to_bech32(network.into()) {
        Ok(s) => ffi_cstring!(s),
        Err(e) => {
            set_last_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get payment_id from subaddress
#[no_mangle]
pub extern "C" fn xnt_subaddress_payment_id(handle: *const SubAddressHandle) -> u64 {
    if handle.is_null() {
        return 0;
    }
    ffi_ref!(handle).0.payment_id()
}


use crate::core::ReceivingAddress;

/// Opaque handle to ReceivingAddress - use for transaction outputs
pub struct ReceivingAddressHandle(pub(crate) ReceivingAddress);

/// Convert Address to ReceivingAddress
#[no_mangle]
pub extern "C" fn xnt_address_to_receiving(handle: *const AddressHandle) -> *mut ReceivingAddressHandle {
    ffi_begin!();
    check_null!(handle, "null");
    Box::into_raw(Box::new(ReceivingAddressHandle(ffi_ref!(handle).0.to_receiving_address())))
}

/// Convert SubAddress to ReceivingAddress
#[no_mangle]
pub extern "C" fn xnt_subaddress_to_receiving(handle: *const SubAddressHandle) -> *mut ReceivingAddressHandle {
    ffi_begin!();
    check_null!(handle, "null");
    Box::into_raw(Box::new(ReceivingAddressHandle(ffi_ref!(handle).0.to_receiving_address())))
}

ffi_free!(xnt_receiving_address_free, ReceivingAddressHandle);

/// Get payment_id (0 = main, non-zero = subaddress)
#[no_mangle]
pub extern "C" fn xnt_receiving_address_payment_id(handle: *const ReceivingAddressHandle) -> u64 {
    if handle.is_null() { return 0; }
    ffi_ref!(handle).0.payment_id().unwrap_or(0)
}
