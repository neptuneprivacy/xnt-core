//! Address generation FFI
//!
//! Wraps core::Address and core::SubAddress for C FFI.

use std::ffi::c_char;

use crate::core::{Address, Network, SubAddress};

use super::error::{ffi_guard, set_last_error, XntErrorCode};
use super::helpers::{free_handle, parse_cstr};
use super::seed::SpendingKeyHandle;

/// Opaque handle to receiving address
pub struct AddressHandle(pub(crate) Address);

/// Opaque handle to subaddress (address + payment_id)
pub struct SubAddressHandle(pub(crate) SubAddress);

/// Network type for address encoding (C-compatible)
///
/// Functions take the network as a `uint32_t` holding one of these values
/// and fail for any other value.
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

/// The network for a `uint32_t` network argument, or `None` if it is not one
/// of the [XntNetwork] values.
pub(crate) fn network_from_raw(network: u32) -> Option<Network> {
    [
        XntNetwork::Main,
        XntNetwork::TestnetMock,
        XntNetwork::RegTest,
        XntNetwork::Testnet,
    ]
    .into_iter()
    .find(|n| *n as u32 == network)
    .map(Network::from)
}

/// Get receiving address from spending key. Returns NULL and sets the last
/// error for legacy-derivation dCTIDH keys, which have no receiving address.
#[no_mangle]
pub extern "C" fn xnt_spending_key_to_address(handle: *const SpendingKeyHandle) -> *mut AddressHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "spending key handle is null");

        let key = ffi_ref!(handle);
        ffi_result!(key.0.to_address(), AddressHandle)
    })
}

/// Free an address handle. NULL is ignored.
#[no_mangle]
pub extern "C" fn xnt_address_free(handle: *mut AddressHandle) {
    ffi_guard((), || free_handle(handle))
}

/// Encode address to bech32m string
///
/// `network` is one of the [XntNetwork] values.
#[no_mangle]
pub extern "C" fn xnt_address_to_bech32(handle: *const AddressHandle, network: u32) -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "address handle is null");
        let Some(network) = network_from_raw(network) else {
            set_last_error("invalid network");
            return std::ptr::null_mut();
        };

        let addr = ffi_ref!(handle);
        match addr.0.to_bech32(network) {
            Ok(s) => ffi_cstring!(s),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

// Neptune addresses contain full cryptographic data and can be ~4000+ chars
const MAX_BECH32_LENGTH: usize = 8192;

/// Decode address from bech32m string
///
/// `network` is one of the [XntNetwork] values. Refuses legacy-format dCTIDH
/// addresses and symmetric keys.
#[no_mangle]
pub extern "C" fn xnt_address_from_bech32(bech32: *const c_char, network: u32) -> *mut AddressHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        let Some(network) = network_from_raw(network) else {
            set_last_error("invalid network");
            return std::ptr::null_mut();
        };

        let Some(s) = parse_cstr(bech32) else {
            set_last_error("invalid bech32 string");
            return std::ptr::null_mut();
        };

        if s.len() > MAX_BECH32_LENGTH {
            set_last_error("bech32 string too long");
            return std::ptr::null_mut();
        }

        match Address::from_bech32(&s, network) {
            Ok(addr) => Box::into_raw(Box::new(AddressHandle(addr))),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Get lock_script_hash from address (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_address_lock_script_hash(handle: *const AddressHandle, out: *mut u8) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        check_null!(handle);
        check_null!(out);

        let addr = ffi_ref!(handle);
        let hash = addr.0.lock_script_hash();
        copy_bytes_out!(hash.bytes, out, 40)
    })
}

/// Get receiver_identifier from address (8 bytes)
#[no_mangle]
pub extern "C" fn xnt_address_receiver_id(handle: *const AddressHandle, out: *mut u8) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        check_null!(handle);
        check_null!(out);

        let addr = ffi_ref!(handle);
        let bytes = addr.0.receiver_id().to_le_bytes();
        copy_bytes_out!(bytes, out, 8)
    })
}

/// Get receiver_identifier as hex string
#[no_mangle]
pub extern "C" fn xnt_address_receiver_id_hex(handle: *const AddressHandle) -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");

        let addr = ffi_ref!(handle);
        ffi_cstring!(addr.0.receiver_id_hex())
    })
}

/// Get privacy_digest from address (40 bytes)
#[no_mangle]
pub extern "C" fn xnt_address_privacy_digest(handle: *const AddressHandle, out: *mut u8) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!();
        check_null!(handle);
        check_null!(out);

        let addr = ffi_ref!(handle);
        let digest = addr.0.privacy_digest();
        copy_bytes_out!(digest.bytes, out, 40)
    })
}


/// Create subaddress from address with payment_id
#[no_mangle]
pub extern "C" fn xnt_subaddress_create(address: *const AddressHandle, payment_id: u64) -> *mut SubAddressHandle {
    ffi_guard(std::ptr::null_mut(), || {
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
    })
}

/// Free a subaddress handle. NULL is ignored.
#[no_mangle]
pub extern "C" fn xnt_subaddress_free(handle: *mut SubAddressHandle) {
    ffi_guard((), || free_handle(handle))
}

/// Encode subaddress to bech32m string
///
/// `network` is one of the [XntNetwork] values.
#[no_mangle]
pub extern "C" fn xnt_subaddress_to_bech32(handle: *const SubAddressHandle, network: u32) -> *mut c_char {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "subaddress handle is null");
        let Some(network) = network_from_raw(network) else {
            set_last_error("invalid network");
            return std::ptr::null_mut();
        };

        let subaddr = ffi_ref!(handle);
        match subaddr.0.to_bech32(network) {
            Ok(s) => ffi_cstring!(s),
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Get payment_id from subaddress
#[no_mangle]
pub extern "C" fn xnt_subaddress_payment_id(handle: *const SubAddressHandle) -> u64 {
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        ffi_ref!(handle).0.payment_id()
    })
}


use crate::core::ReceivingAddress;

/// Opaque handle to ReceivingAddress - use for transaction outputs
pub struct ReceivingAddressHandle(pub(crate) ReceivingAddress);

/// Convert Address to ReceivingAddress
#[no_mangle]
pub extern "C" fn xnt_address_to_receiving(handle: *const AddressHandle) -> *mut ReceivingAddressHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null");
        Box::into_raw(Box::new(ReceivingAddressHandle(
            ffi_ref!(handle).0.to_receiving_address(),
        )))
    })
}

/// Convert SubAddress to ReceivingAddress
#[no_mangle]
pub extern "C" fn xnt_subaddress_to_receiving(handle: *const SubAddressHandle) -> *mut ReceivingAddressHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null");
        Box::into_raw(Box::new(ReceivingAddressHandle(
            ffi_ref!(handle).0.to_receiving_address(),
        )))
    })
}

/// Free a receiving address handle. NULL is ignored.
#[no_mangle]
pub extern "C" fn xnt_receiving_address_free(handle: *mut ReceivingAddressHandle) {
    ffi_guard((), || free_handle(handle))
}

/// Get payment_id (0 = main, non-zero = subaddress)
#[no_mangle]
pub extern "C" fn xnt_receiving_address_payment_id(handle: *const ReceivingAddressHandle) -> u64 {
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        ffi_ref!(handle).0.payment_id().unwrap_or(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::seed::xnt_spending_key_free;
    use crate::ffi::seed::{xnt_wallet_derive_dctidh_key, xnt_wallet_devnet, xnt_wallet_free};
    use crate::ffi::types::xnt_string_free;

    #[test]
    fn network_arguments_are_checked() {
        let wallet = xnt_wallet_devnet();
        let key = xnt_wallet_derive_dctidh_key(wallet, 0);
        let addr = xnt_spending_key_to_address(key);
        assert!(!addr.is_null());

        assert!(xnt_address_to_bech32(addr, 4).is_null());
        let encoded = xnt_address_to_bech32(addr, XntNetwork::RegTest as u32);
        assert!(!encoded.is_null());
        assert!(xnt_address_from_bech32(encoded, 4).is_null());
        let decoded = xnt_address_from_bech32(encoded, XntNetwork::RegTest as u32);
        assert!(!decoded.is_null());

        xnt_address_free(decoded);
        xnt_string_free(encoded);
        xnt_address_free(addr);
        xnt_spending_key_free(key);
        xnt_wallet_free(wallet);
    }
}
