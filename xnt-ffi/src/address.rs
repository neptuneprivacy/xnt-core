//! Address generation FFI
//!
//! GenerationReceivingAddress and SubAddress with payment_id support.

use std::ffi::c_char;

use neptune_privacy::application::config::network::Network;
use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
use neptune_privacy::state::wallet::address::generation_address::{GenerationReceivingAddress, GenerationSubAddress};
use neptune_privacy::state::wallet::address::ReceivingAddress;
use neptune_privacy::state::wallet::address::SubAddress;

use crate::error::{set_last_error, XntErrorCode};
use crate::helpers::parse_cstr;
use crate::seed::SpendingKeyHandle;

/// Opaque handle to receiving address (Generation or Symmetric)
pub struct AddressHandle(pub(crate) ReceivingAddress);

/// Opaque handle to subaddress (address + payment_id)
pub struct SubAddressHandle(pub(crate) GenerationSubAddress);

/// Network type for address encoding
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
            XntNetwork::Testnet => Network::Testnet(0),
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
/// Caller must free with xnt_string_free()
#[no_mangle]
pub extern "C" fn xnt_address_to_bech32(handle: *const AddressHandle, network: XntNetwork) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "address handle is null");

    let addr = ffi_ref!(handle);
    match addr.0.to_bech32m(network.into()) {
        Ok(s) => ffi_cstring!(s),
        Err(e) => {
            set_last_error(&format!("bech32m encoding failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Decode address from bech32m string
#[no_mangle]
pub extern "C" fn xnt_address_from_bech32(bech32: *const c_char, network: XntNetwork) -> *mut AddressHandle {
    ffi_begin!();

    let Some(s) = parse_cstr(bech32) else {
        set_last_error("invalid bech32 string");
        return std::ptr::null_mut();
    };

    ffi_result!(
        ReceivingAddress::from_bech32m(&s, network.into()),
        AddressHandle,
        "bech32m decoding failed"
    )
}

/// Get lock_script_hash from address (40 bytes = Digest)
#[no_mangle]
pub extern "C" fn xnt_address_lock_script_hash(handle: *const AddressHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let addr = ffi_ref!(handle);
    let hash: [u8; 40] = addr.0.lock_script_hash().into();
    copy_bytes_out!(hash, out, 40)
}

/// Get receiver_identifier from address (8 bytes = BFieldElement)
#[no_mangle]
pub extern "C" fn xnt_address_receiver_id(handle: *const AddressHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let addr = ffi_ref!(handle);
    let bytes = addr.0.receiver_identifier().value().to_le_bytes();
    copy_bytes_out!(bytes, out, 8)
}

/// Get receiver_identifier from address as hex string
/// Caller must free with xnt_string_free()
#[no_mangle]
pub extern "C" fn xnt_address_receiver_id_hex(handle: *const AddressHandle) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "null pointer");

    let addr = ffi_ref!(handle);
    ffi_cstring!(format!("{:016x}", addr.0.receiver_identifier().value()))
}

/// Get privacy_digest (receiver_postimage) from address (40 bytes)
/// This is used to compute output commitments
#[no_mangle]
pub extern "C" fn xnt_address_privacy_digest(handle: *const AddressHandle, out: *mut u8) -> XntErrorCode {
    ffi_begin!();
    check_null!(handle);
    check_null!(out);

    let addr = ffi_ref!(handle);
    let digest = addr.0.privacy_digest();
    let bytes: [u8; 40] = digest.into();
    copy_bytes_out!(bytes, out, 40)
}

// === SubAddress (with payment_id) ===

/// Create subaddress from address with payment_id
/// payment_id must be non-zero
/// Only works for Generation addresses
#[no_mangle]
pub extern "C" fn xnt_subaddress_create(address: *const AddressHandle, payment_id: u64) -> *mut SubAddressHandle {
    ffi_begin!();
    check_null!(address, "address handle is null");

    if payment_id == 0 {
        set_last_error("payment_id must be non-zero for subaddress");
        return std::ptr::null_mut();
    }

    let addr = ffi_ref!(address);
    // Subaddresses only work for Generation addresses
    match &addr.0 {
        ReceivingAddress::Generation(gen_addr) => {
            ffi_result!(
                gen_addr.with_payment_id(BFieldElement::new(payment_id)),
                SubAddressHandle,
                "subaddress creation failed"
            )
        }
        _ => {
            set_last_error("subaddress only supported for Generation addresses");
            std::ptr::null_mut()
        }
    }
}

ffi_free!(xnt_subaddress_free, SubAddressHandle);

/// Encode subaddress to bech32m string
/// Caller must free with xnt_string_free()
#[no_mangle]
pub extern "C" fn xnt_subaddress_to_bech32(handle: *const SubAddressHandle, network: XntNetwork) -> *mut c_char {
    ffi_begin!();
    check_null!(handle, "subaddress handle is null");

    let subaddr = ffi_ref!(handle);
    match subaddr.0.to_bech32m(network.into()) {
        Ok(s) => ffi_cstring!(s),
        Err(e) => {
            set_last_error(&format!("bech32m encoding failed: {e}"));
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
    ffi_ref!(handle).0.payment_id().value()
}
