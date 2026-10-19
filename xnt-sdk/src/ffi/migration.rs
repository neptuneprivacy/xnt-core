//! dCTIDH migration FFI
//!
//! Wraps core::build_migration for C FFI.

use std::ffi::c_char;

use crate::core::{build_migration_with, BuiltTransaction, MigrationInput, MigrationOptions, MigrationPlan};

use super::address::network_from_raw;
use super::error::{ffi_guard, set_last_error, XntErrorCode};
use super::helpers::{free_handle, parse_cstr, read_amount_le, read_slice};
use super::json_rpc::RpcClientHandle;
use super::seed::WalletEntropyHandle;
use super::transaction::BuiltTransactionHandle;
use super::types::XntDigest;

/// Opaque handle to the transactions that move funds from legacy-format
/// dCTIDH locks, see xnt_build_migration
pub struct MigrationPlanHandle {
    plan: MigrationPlan,
    transactions: Vec<Option<BuiltTransaction>>,
}

/// Build the transactions that move every UTXO at the legacy-format dCTIDH
/// locks of the given key indices of `wallet` that can be spent now to the
/// bech32m address `destination` (a Generation or current-format dCTIDH
/// address of `network`), each with one output and no change, ready for
/// xnt_built_transaction_prove. Nothing is proven or submitted.
///
/// At most 10 inputs per transaction, the largest first, and the fee the node
/// uses for its own migration (0.1 coins for a proof collection); see
/// xnt_build_migration_with. A proof collection is valid only for the mutator
/// set it was built on: prove, check and submit each transaction right away,
/// and build the remaining ones again after a new block.
#[no_mangle]
pub extern "C" fn xnt_build_migration(
    client: *const RpcClientHandle,
    wallet: *const WalletEntropyHandle,
    legacy_indices: *const u64,
    num_indices: usize,
    destination: *const c_char,
    network: u32,
) -> *mut MigrationPlanHandle {
    xnt_build_migration_with(
        client,
        wallet,
        legacy_indices,
        num_indices,
        destination,
        network,
        std::ptr::null(),
        0,
        0,
        u64::MAX,
    )
}

/// xnt_build_migration with options: `fee_le` the fee of each transaction in
/// nau as 16 bytes, little-endian two's complement, or NULL for the default;
/// `max_inputs` the most inputs per transaction, or 0 for the default of 10
/// (before the UpgradeVMv8 fork capped at 10 with time locks, 11 without);
/// the heights scanned from `from_height` to `to_height`, or to the tip for
/// UINT64_MAX.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn xnt_build_migration_with(
    client: *const RpcClientHandle,
    wallet: *const WalletEntropyHandle,
    legacy_indices: *const u64,
    num_indices: usize,
    destination: *const c_char,
    network: u32,
    fee_le: *const u8,
    max_inputs: usize,
    from_height: u64,
    to_height: u64,
) -> *mut MigrationPlanHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        if client.is_null() || wallet.is_null() || legacy_indices.is_null() || num_indices == 0 {
            set_last_error("invalid input");
            return std::ptr::null_mut();
        }
        let Some(network) = network_from_raw(network) else {
            set_last_error("invalid network");
            return std::ptr::null_mut();
        };
        let Some(destination) = parse_cstr(destination) else {
            set_last_error("invalid destination");
            return std::ptr::null_mut();
        };

        let indices = unsafe { read_slice(legacy_indices, num_indices) };
        let mut options = MigrationOptions::default();
        if !fee_le.is_null() {
            options.fee = Some(unsafe { read_amount_le(fee_le) });
        }
        if max_inputs > 0 {
            options.max_inputs = max_inputs;
        }
        options.from_height = from_height;
        if to_height != u64::MAX {
            options.to_height = Some(to_height);
        }

        let client = ffi_ref!(client);
        let wallet = ffi_ref!(wallet);
        match build_migration_with(&client.0, &wallet.0, indices, &destination, network, &options) {
            Ok(mut plan) => {
                let transactions = std::mem::take(&mut plan.transactions)
                    .into_iter()
                    .map(Some)
                    .collect();
                Box::into_raw(Box::new(MigrationPlanHandle { plan, transactions }))
            }
            Err(e) => {
                set_last_error(&format!("{e}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Free a migration handle, with the transactions not taken. NULL is ignored.
#[no_mangle]
pub extern "C" fn xnt_migration_free(handle: *mut MigrationPlanHandle) {
    ffi_guard((), || free_handle(handle))
}

/// Number of transactions of the migration
#[no_mangle]
pub extern "C" fn xnt_migration_num_transactions(handle: *const MigrationPlanHandle) -> usize {
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        ffi_ref!(handle).transactions.len()
    })
}

/// Take the built transaction at `index`, the largest amounts first. Each can
/// be taken once; free it with xnt_built_transaction_free. Returns NULL for an
/// index out of range or a transaction taken already.
#[no_mangle]
pub extern "C" fn xnt_migration_take_transaction(
    handle: *mut MigrationPlanHandle,
    index: usize,
) -> *mut BuiltTransactionHandle {
    ffi_guard(std::ptr::null_mut(), || {
        ffi_begin!();
        check_null!(handle, "null pointer");

        match ffi_mut!(handle).transactions.get_mut(index).and_then(Option::take) {
            Some(built) => Box::into_raw(Box::new(BuiltTransactionHandle(built))),
            None => {
                set_last_error("no transaction at this index");
                std::ptr::null_mut()
            }
        }
    })
}

/// Number of inputs the transaction at `index` spends
#[no_mangle]
pub extern "C" fn xnt_migration_num_inputs(handle: *const MigrationPlanHandle, index: usize) -> usize {
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        ffi_ref!(handle).plan.swept.get(index).map_or(0, Vec::len)
    })
}

/// Write the absolute index set hash (40 bytes) of input `input_index` of the
/// transaction at `index` to `out`, for xnt_sync_check_spent: the transaction
/// is confirmed once its inputs are spent.
#[no_mangle]
pub extern "C" fn xnt_migration_input_hash(
    handle: *const MigrationPlanHandle,
    index: usize,
    input_index: usize,
    out: *mut u8,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(handle, out);
        let Some(input) = ffi_ref!(handle)
            .plan
            .swept
            .get(index)
            .and_then(|inputs| inputs.get(input_index))
        else {
            set_last_error("no input at this index");
            return XntErrorCode::InvalidInput;
        };
        copy_bytes_out!(input.absolute_index_set_hash().bytes, out, 40)
    })
}

/// An input of a migration transaction, or one left out of the transactions,
/// with the legacy key and the payment id it was received with
/// (C-compatible), see xnt_migration_input_info
///
/// A migration transaction merges the UTXOs of many payment ids into one
/// output; record what it moves per payment id from these. `amount` is in
/// nau, before fees, a 128-bit integer, see XntTxInputInfo.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct XntMigrationInputInfo {
    /// Index of the legacy key the UTXO is locked to, see
    /// xnt_wallet_derive_legacy_dctidh_key
    pub key_index: u64,
    /// Payment id the UTXO was received with, 0 for the base address
    pub payment_id: u64,
    pub amount: i128,
    /// Height of the block the UTXO was confirmed in
    pub block_height: u64,
    pub aocl_index: u64,
    /// For xnt_sync_check_spent: the UTXO is spent once the transaction
    /// spending it is confirmed
    pub absolute_index_set_hash: XntDigest,
}

/// Write `input` to `out`, or fail for no input.
fn write_input_info(input: Option<&MigrationInput>, out: *mut XntMigrationInputInfo) -> XntErrorCode {
    let Some(input) = input else {
        set_last_error("no input at this index");
        return XntErrorCode::InvalidInput;
    };
    let info = XntMigrationInputInfo {
        key_index: input.key_index,
        payment_id: input.payment_id,
        amount: input.amount,
        block_height: input.block_height,
        aocl_index: input.aocl_index,
        absolute_index_set_hash: XntDigest::from(input.absolute_index_set_hash.bytes),
    };
    unsafe { out.write(info) };
    XntErrorCode::Ok
}

/// Write the details of input `input_index` of the transaction at `index`
/// to `out`: legacy key index, payment id, amount, block height, AOCL index
/// and absolute index set hash. Inputs are in the order of
/// xnt_migration_input_hash, from 0 to xnt_migration_num_inputs.
#[no_mangle]
pub extern "C" fn xnt_migration_input_info(
    handle: *const MigrationPlanHandle,
    index: usize,
    input_index: usize,
    out: *mut XntMigrationInputInfo,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(handle, out);
        let input = ffi_ref!(handle)
            .plan
            .swept_inputs
            .get(index)
            .and_then(|inputs| inputs.get(input_index));
        write_input_info(input, out)
    })
}

/// Write the details of dust input `input_index` (from 0 to
/// xnt_migration_num_dust_inputs) to `out`, see xnt_migration_input_info:
/// an input left out because its batch holds no more than its fee.
#[no_mangle]
pub extern "C" fn xnt_migration_dust_input_info(
    handle: *const MigrationPlanHandle,
    input_index: usize,
    out: *mut XntMigrationInputInfo,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(handle, out);
        let input = ffi_ref!(handle).plan.dust_inputs.iter().flatten().nth(input_index);
        write_input_info(input, out)
    })
}

/// Write the details of time-locked UTXO `index` (from 0 to
/// xnt_migration_num_time_locked) to `out`, see xnt_migration_input_info: a
/// UTXO left out because its time lock is not released yet.
#[no_mangle]
pub extern "C" fn xnt_migration_time_locked_info(
    handle: *const MigrationPlanHandle,
    index: usize,
    out: *mut XntMigrationInputInfo,
) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(handle, out);
        let input = ffi_ref!(handle).plan.time_locked_inputs.get(index);
        write_input_info(input, out)
    })
}

/// Write the total moved to the destination, after fees, in nau to `out` as
/// 16 bytes, little-endian two's complement
#[no_mangle]
pub extern "C" fn xnt_migration_total_le(handle: *const MigrationPlanHandle, out: *mut u8) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(handle, out);
        copy_bytes_out!(ffi_ref!(handle).plan.total.to_le_bytes(), out, 16)
    })
}

/// Write the total of the fees in nau to `out` as 16 bytes, little-endian
/// two's complement
#[no_mangle]
pub extern "C" fn xnt_migration_fees_le(handle: *const MigrationPlanHandle, out: *mut u8) -> XntErrorCode {
    ffi_guard(XntErrorCode::InternalError, || {
        ffi_begin!(handle, out);
        copy_bytes_out!(ffi_ref!(handle).plan.fees.to_le_bytes(), out, 16)
    })
}

/// Height of the tip whose mutator set and membership proofs the transactions
/// were built on
#[no_mangle]
pub extern "C" fn xnt_migration_tip_height(handle: *const MigrationPlanHandle) -> u64 {
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        ffi_ref!(handle).plan.tip_height
    })
}

/// Number of inputs left out because their batch holds no more than its fee
#[no_mangle]
pub extern "C" fn xnt_migration_num_dust_inputs(handle: *const MigrationPlanHandle) -> usize {
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        ffi_ref!(handle).plan.dust.iter().map(Vec::len).sum()
    })
}

/// Number of UTXOs at legacy-format locks left out because their time lock is
/// not released yet
#[no_mangle]
pub extern "C" fn xnt_migration_num_time_locked(handle: *const MigrationPlanHandle) -> usize {
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        ffi_ref!(handle).plan.time_locked.len()
    })
}

/// Number of indexed entries the scans skipped, see
/// xnt_sync_fetch_utxos_with_skipped
#[no_mangle]
pub extern "C" fn xnt_migration_num_skipped(handle: *const MigrationPlanHandle) -> usize {
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        ffi_ref!(handle).plan.skipped.total()
    })
}
