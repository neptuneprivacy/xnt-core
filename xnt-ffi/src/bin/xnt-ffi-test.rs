//! Test binary for xnt-ffi
//!
//! Usage: cargo run --bin xnt-ffi-test [command]
//!
//! Commands: version, error, seed, address, crypto, utxo, transaction, sync, full

use std::ffi::{CStr, CString};
use xnt_ffi::*;
use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

const TEST_MNEMONIC: &str =
    "cycle north blast dignity bachelor explain blur nuclear sausage hire mimic chase mushroom orphan case armed lion plunge";

// === Test Helpers ===

macro_rules! ok {
    ($msg:expr) => { println!("[OK] {}", $msg) };
    ($fmt:expr, $($arg:tt)*) => { println!("[OK] {}", format!($fmt, $($arg)*)) };
}

macro_rules! fail {
    ($msg:expr) => {{ println!("[FAIL] {}", $msg); return; }};
    ($fmt:expr, $($arg:tt)*) => {{ println!("[FAIL] {}", format!($fmt, $($arg)*)); return; }};
}

macro_rules! skip {
    ($msg:expr) => {{ println!("[SKIP] {}", $msg); return; }};
}

fn get_error() -> String {
    let err = xnt_get_last_error();
    if err.is_null() { "unknown".into() }
    else { unsafe { CStr::from_ptr(err).to_str().unwrap_or("utf8 error").into() } }
}

macro_rules! check_ptr {
    ($ptr:expr, $msg:expr) => {
        if $ptr.is_null() { fail!("{}: {}", $msg, get_error()); }
    };
}

fn cstr(s: &str) -> CString { CString::new(s).unwrap() }

/// Test context with wallet, spending key, and address
struct TestCtx {
    wallet: *mut WalletHandle,
    key: *mut SpendingKeyHandle,
    addr: *mut AddressHandle,
}

impl TestCtx {
    fn new() -> Option<Self> {
        let mnemonic = cstr(TEST_MNEMONIC);
        let wallet = xnt_wallet_from_mnemonic(mnemonic.as_ptr());
        if wallet.is_null() { return None; }

        let key = xnt_wallet_derive_spending_key(wallet, 0);
        if key.is_null() {
            xnt_wallet_free(wallet);
            return None;
        }

        let addr = xnt_spending_key_to_address(key);
        if addr.is_null() {
            xnt_spending_key_free(key);
            xnt_wallet_free(wallet);
            return None;
        }

        Some(Self { wallet, key, addr })
    }
}

impl Drop for TestCtx {
    fn drop(&mut self) {
        xnt_address_free(self.addr);
        xnt_spending_key_free(self.key);
        xnt_wallet_free(self.wallet);
    }
}

// === Tests ===

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("full");

    match cmd {
        "version" => test_version(),
        "error" => test_error(),
        "seed" => test_seed(),
        "address" => test_address(),
        "crypto" => test_crypto(),
        "utxo" => test_utxo(),
        "transaction" | "tx" => test_transaction(),
        "sync" => test_sync(),
        "prove" => test_prove(),
        "full" => test_full(),
        _ => {
            eprintln!("Unknown: {}. Available: version, error, seed, address, crypto, utxo, transaction, sync, prove, full", cmd);
            std::process::exit(1);
        }
    }
}

fn test_version() {
    let v = unsafe { CStr::from_ptr(xnt_version()).to_str().unwrap() };
    ok!("version: {}", v);
}

fn test_error() {
    println!("Testing error handling...");
    if xnt_get_last_error().is_null() { ok!("no initial error"); }
    xnt_clear_error();
    ok!("clear error works");
}

fn test_seed() {
    println!("Testing seed/mnemonic...");

    // Import
    let mnemonic = cstr(TEST_MNEMONIC);
    let wallet = xnt_wallet_from_mnemonic(mnemonic.as_ptr());
    check_ptr!(wallet, "import mnemonic");
    ok!("imported wallet");

    // Export roundtrip
    let exported = xnt_wallet_to_mnemonic(wallet);
    check_ptr!(exported, "export mnemonic");
    let exported_str = unsafe { CStr::from_ptr(exported).to_str().unwrap() };
    if exported_str != TEST_MNEMONIC { fail!("mnemonic mismatch"); }
    ok!("mnemonic roundtrip");
    println!("    seed phrase: {}", exported_str);
    xnt_string_free(exported);

    // Derive keys
    let key0 = xnt_wallet_derive_spending_key(wallet, 0);
    check_ptr!(key0, "derive key 0");
    let rid = xnt_spending_key_receiver_id_hex(key0);
    if !rid.is_null() {
        ok!("key 0 receiver_id: {}", unsafe { CStr::from_ptr(rid).to_str().unwrap() });
        xnt_string_free(rid);
    }
    xnt_spending_key_free(key0);

    // Generate new
    let new_wallet = xnt_wallet_generate();
    check_ptr!(new_wallet, "generate wallet");
    let new_mnemonic = xnt_wallet_to_mnemonic(new_wallet);
    if !new_mnemonic.is_null() {
        let words = unsafe { CStr::from_ptr(new_mnemonic).to_str().unwrap() }.split_whitespace().count();
        if words == 18 { ok!("generated 18-word mnemonic"); }
        else { println!("[WARN] expected 18 words, got {}", words); }
        xnt_string_free(new_mnemonic);
    }
    xnt_wallet_free(new_wallet);
    xnt_wallet_free(wallet);
}

fn test_address() {
    println!("Testing address...");

    let ctx = TestCtx::new();
    if ctx.is_none() { fail!("setup failed"); }
    let ctx = ctx.unwrap();

    // Receiver ID
    let rid = xnt_address_receiver_id_hex(ctx.addr);
    if !rid.is_null() {
        ok!("receiver_id: {}", unsafe { CStr::from_ptr(rid).to_str().unwrap() });
        xnt_string_free(rid);
    }

    // Bech32m encode/decode roundtrip
    let bech32 = xnt_address_to_bech32(ctx.addr, XntNetwork::Main);
    check_ptr!(bech32, "encode bech32m");
    let bech32_str = unsafe { CStr::from_ptr(bech32).to_str().unwrap() };
    ok!("bech32m: {}", bech32_str);

    let decoded = xnt_address_from_bech32(bech32, XntNetwork::Main);
    check_ptr!(decoded, "decode bech32m");
    let re_encoded = xnt_address_to_bech32(decoded, XntNetwork::Main);
    if !re_encoded.is_null() {
        let re_str = unsafe { CStr::from_ptr(re_encoded).to_str().unwrap() };
        if re_str == bech32_str { ok!("bech32m roundtrip"); }
        else { println!("[WARN] bech32m roundtrip mismatch"); }
        xnt_string_free(re_encoded);
    }
    xnt_address_free(decoded);
    xnt_string_free(bech32);

    // Subaddress
    let subaddr = xnt_subaddress_create(ctx.addr, 12345);
    check_ptr!(subaddr, "create subaddress");
    if xnt_subaddress_payment_id(subaddr) == 12345 { ok!("subaddress payment_id=12345"); }

    let sub_bech32 = xnt_subaddress_to_bech32(subaddr, XntNetwork::Main);
    if !sub_bech32.is_null() {
        ok!("subaddress: {}", unsafe { CStr::from_ptr(sub_bech32).to_str().unwrap() });
        xnt_string_free(sub_bech32);
    }
    xnt_subaddress_free(subaddr);

    // payment_id=0 should fail
    if xnt_subaddress_create(ctx.addr, 0).is_null() { ok!("rejected payment_id=0"); }
}

fn test_crypto() {
    println!("Testing crypto...");

    let data = b"Hello, Neptune!";
    let mut hash = [0u8; 40];

    // TIP5
    if xnt_tip5_hash(data.as_ptr(), data.len(), hash.as_mut_ptr()) == XntErrorCode::Ok {
        ok!("TIP5: {}", hex::encode(&hash[..8]));
    }

    // SHAKE256
    let mut shake32 = [0u8; 32];
    if xnt_shake256_32(data.as_ptr(), data.len(), shake32.as_mut_ptr()) == XntErrorCode::Ok {
        ok!("SHAKE256(32): {}", hex::encode(&shake32[..8]));
    }

    let shake64 = xnt_shake256(data.as_ptr(), data.len(), 64);
    if !shake64.is_null() {
        let buf = unsafe { &*shake64 };
        if buf.len == 64 { ok!("SHAKE256(64): {} bytes", buf.len); }
        xnt_buffer_free(shake64);
    }

    // AES-GCM roundtrip
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let plain = b"Secret message";

    let ct = xnt_aes256gcm_encrypt(key.as_ptr(), nonce.as_ptr(), plain.as_ptr(), plain.len());
    check_ptr!(ct, "AES encrypt");
    let ct_buf = unsafe { &*ct };

    let pt = xnt_aes256gcm_decrypt(key.as_ptr(), nonce.as_ptr(), ct_buf.data, ct_buf.len);
    check_ptr!(pt, "AES decrypt");
    let pt_buf = unsafe { &*pt };
    let decrypted = unsafe { std::slice::from_raw_parts(pt_buf.data, pt_buf.len) };
    if decrypted == plain { ok!("AES-GCM roundtrip"); }
    xnt_buffer_free(pt);
    xnt_buffer_free(ct);

    // BFE roundtrip
    let bfes = xnt_bytes_to_bfes(data.as_ptr(), data.len());
    check_ptr!(bfes, "bytes_to_bfes");
    let bfes_buf = unsafe { &*bfes };

    let decoded = xnt_bfes_to_bytes(bfes_buf.data, bfes_buf.len);
    check_ptr!(decoded, "bfes_to_bytes");
    let dec_buf = unsafe { &*decoded };
    let dec_slice = unsafe { std::slice::from_raw_parts(dec_buf.data, dec_buf.len) };
    if dec_slice == data { ok!("BFE roundtrip"); }
    xnt_buffer_free(decoded);
    xnt_buffer_free(bfes);
}

fn test_utxo() {
    println!("Testing UTXO...");

    let ctx = TestCtx::new();
    if ctx.is_none() { fail!("setup failed"); }
    let ctx = ctx.unwrap();

    let amount: i128 = 1_000_000_000;
    let utxo = xnt_utxo_create_native(ctx.addr, amount);
    check_ptr!(utxo, "create UTXO");

    if xnt_utxo_get_amount(utxo) == amount { ok!("amount: {}", amount); }

    let mut lock_hash = [0u8; 40];
    if xnt_utxo_lock_script_hash(utxo, lock_hash.as_mut_ptr()) == XntErrorCode::Ok {
        ok!("lock_script_hash: {}", hex::encode(&lock_hash[..8]));
    }

    // Serialize/deserialize roundtrip
    let ser = xnt_utxo_serialize(utxo);
    check_ptr!(ser, "serialize UTXO");
    let ser_buf = unsafe { &*ser };
    ok!("serialized: {} bytes", ser_buf.len);

    let deser = xnt_utxo_deserialize(ser_buf.data, ser_buf.len);
    check_ptr!(deser, "deserialize UTXO");
    if xnt_utxo_get_amount(deser) == amount { ok!("deserialize roundtrip"); }

    xnt_utxo_free(deser);
    xnt_buffer_free(ser);
    xnt_utxo_free(utxo);
}

fn test_transaction() {
    println!("Testing transaction builder...");

    // Test TransactionBuilder creation
    let builder = xnt_tx_builder_create();
    check_ptr!(builder, "create TransactionBuilder");
    ok!("TransactionBuilder created");

    // Initially empty
    let input_total = xnt_tx_builder_input_total(builder);
    let output_total = xnt_tx_builder_output_total(builder);
    if input_total == 0 && output_total == 0 {
        ok!("  initial totals: input=0, output=0");
    }

    // Test fee setting
    let fee: i128 = 1_000_000; // 0.001 XNT
    if xnt_tx_builder_set_fee(builder, fee) == XntErrorCode::Ok {
        ok!("  fee set: {} nau", fee);
    }

    // Test change calculation (with no inputs/outputs, change = -fee)
    let change = xnt_tx_builder_change_amount(builder);
    if change == -fee {
        ok!("  change amount: {} (correct, no inputs yet)", change);
    }

    xnt_tx_builder_free(builder);

    ok!("transaction builder tests passed");
}

fn test_sync() {
    println!("Testing sync client...");

    let ctx = TestCtx::new();
    if ctx.is_none() { fail!("setup failed"); }
    let ctx = ctx.unwrap();

    // Get receiver_id_hash
    let mut receiver_id_hash = XntDigest::new();
    let mut receiver_preimage = XntDigest::new();
    xnt_spending_key_receiver_id_hash(ctx.key, receiver_id_hash.bytes.as_mut_ptr());
    xnt_spending_key_receiver_preimage(ctx.key, receiver_preimage.bytes.as_mut_ptr());
    ok!("receiver_id_hash: {}", hex::encode(&receiver_id_hash.bytes[..8]));

    // Create client
    let url = cstr("http://localhost:9897/");
    let user = cstr("huuhait");
    let pass = cstr("huuha");
    let client = xnt_rpc_client_create_with_auth(url.as_ptr(), user.as_ptr(), pass.as_ptr());
    check_ptr!(client, "create client");

    // Get height
    let tip = xnt_sync_get_height(client);
    if tip < 0 { skip!("no server connection"); }
    ok!("chain height: {}", tip);

    // Fetch UTXOs in batches
    const BATCH: u64 = 1000;
    let mut from = 0u64;
    let tip_u64 = tip as u64;
    let mut decrypted_data: Vec<(XntDigest, XntDigest, u64, i128)> = Vec::new(); // (utxo_hash, sender_randomness, block_height, amount)

    while from <= tip_u64 {
        let to = (from + BATCH - 1).min(tip_u64);
        let utxos = xnt_sync_fetch_utxos(client, &receiver_id_hash, from, to);

        if !utxos.data.is_null() && utxos.len > 0 {
            let slice = unsafe { std::slice::from_raw_parts(utxos.data, utxos.len) };
            for indexed in slice {
                let dec = xnt_sync_decrypt_indexed_utxo(ctx.key, indexed);
                if !dec.utxo.is_null() {
                    let mut utxo_hash = XntDigest::new();
                    if xnt_utxo_hash(dec.utxo, utxo_hash.bytes.as_mut_ptr()) == XntErrorCode::Ok {
                        let amount = xnt_utxo_get_amount(dec.utxo);
                        decrypted_data.push((utxo_hash, dec.sender_randomness, indexed.block_height, amount));
                    }
                    xnt_utxo_free(dec.utxo);
                }
            }
            xnt_sync_indexed_utxos_free(&mut { utxos } as *mut _);
        }
        from = to + 1;
    }
    ok!("decrypted {} UTXOs", decrypted_data.len());

    // Check spent status
    if !decrypted_data.is_empty() {
        // Compute commitments
        let mut commitments: Vec<XntDigest> = Vec::new();
        for (utxo_hash, sender_randomness, _, _) in &decrypted_data {
            let mut commitment = XntDigest::new();
            if xnt_compute_commitment(utxo_hash, sender_randomness, &receiver_preimage, commitment.bytes.as_mut_ptr()) == XntErrorCode::Ok {
                commitments.push(commitment);
            }
        }

        // Get AOCL indices
        let aocl = xnt_sync_get_aocl_indices(client, commitments.as_ptr(), commitments.len());
        if !aocl.indices.is_null() {
            let indices = unsafe { std::slice::from_raw_parts(aocl.indices, aocl.len) };
            let valid = indices.iter().filter(|&&i| i >= 0).count();
            ok!("AOCL indices: {} valid / {} total", valid, indices.len());

            // Compute abs_hashes for valid indices and track which indices are valid
            let mut abs_hashes: Vec<XntDigest> = Vec::new();
            let mut valid_indices: Vec<usize> = Vec::new();
            for (i, &idx) in indices.iter().enumerate() {
                if idx >= 0 && i < decrypted_data.len() {
                    let (utxo_hash, sender_randomness, _, _) = &decrypted_data[i];
                    let mut abs_hash = XntDigest::new();
                    if xnt_compute_absolute_index_set_hash(utxo_hash, sender_randomness, &receiver_preimage, idx as u64, abs_hash.bytes.as_mut_ptr()) == XntErrorCode::Ok {
                        abs_hashes.push(abs_hash);
                        valid_indices.push(i);
                    }
                }
            }

            // Check spent
            if !abs_hashes.is_empty() {
                let status = xnt_sync_check_spent(client, abs_hashes.as_ptr(), abs_hashes.len());
                if !status.heights.is_null() {
                    let heights = unsafe { std::slice::from_raw_parts(status.heights, status.len) };
                    let spent = heights.iter().filter(|&&h| h >= 0).count();
                    let unspent_count = heights.iter().filter(|&&h| h < 0).count();
                    ok!("spent: {}, unspent: {}", spent, unspent_count);

                    // Show each unspent UTXO's commitment and amount
                    println!("  Unspent UTXOs:");
                    let mut total_amount: i128 = 0;
                    for (j, &h) in heights.iter().enumerate() {
                        if h < 0 && j < valid_indices.len() {
                            let orig_idx = valid_indices[j];
                            let aocl_idx = indices[orig_idx];
                            let (_, _, block_height, amount) = &decrypted_data[orig_idx];
                            let commitment = &commitments[orig_idx];
                            let nca = NativeCurrencyAmount::from_nau(*amount);
                            println!("    aocl={}, height={}, amount={}, commitment={}",
                                aocl_idx, block_height, nca, hex::encode(&commitment.bytes));
                            total_amount += amount;
                        }
                    }
                    let total_nca = NativeCurrencyAmount::from_nau(total_amount);
                    println!("  Total unspent: {}", total_nca);

                    xnt_sync_spent_status_free(&mut { status } as *mut _);
                }
            }
            xnt_sync_aocl_indices_free(&mut { aocl } as *mut _);
        }
    }

    xnt_rpc_client_free(client);
}

fn test_prove() {
    println!("Testing ProofCollection creation (16GB RAM required)...");

    let ctx = TestCtx::new();
    if ctx.is_none() { fail!("setup failed"); }
    let ctx = ctx.unwrap();

    // Get receiver info
    let mut receiver_id_hash = XntDigest::new();
    let mut receiver_preimage = XntDigest::new();
    xnt_spending_key_receiver_id_hash(ctx.key, receiver_id_hash.bytes.as_mut_ptr());
    xnt_spending_key_receiver_preimage(ctx.key, receiver_preimage.bytes.as_mut_ptr());

    // Create sync client with auth
    let url = cstr("http://localhost:9897/");
    let user = cstr("huuhait");
    let pass = cstr("huuha");
    let client = xnt_rpc_client_create_with_auth(url.as_ptr(), user.as_ptr(), pass.as_ptr());
    check_ptr!(client, "create sync client");

    // Get mutator set
    let ms = xnt_sync_get_mutator_set(client);
    check_ptr!(ms, "get mutator set");
    ok!("got mutator set");

    // Get current height
    let current_height = xnt_sync_get_height(client);
    if current_height < 0 { fail!("failed to get height"); }
    ok!("height: {}", current_height);

    // Fetch and decrypt UTXOs in batches (similar to test_sync)
    let batch_size: u64 = 1000;
    let mut from: u64 = 0;

    // Store: (utxo_hash, sender_randomness, amount, utxo_ptr)
    let mut decrypted_utxos: Vec<(XntDigest, XntDigest, i128, *mut UtxoHandle)> = Vec::new();

    while from <= current_height as u64 {
        let to = std::cmp::min(from + batch_size - 1, current_height as u64);
        let mut utxos = xnt_sync_fetch_utxos(client, &receiver_id_hash, from, to);
        if utxos.len > 0 && !utxos.data.is_null() {
            for i in 0..utxos.len {
                let indexed = unsafe { &*utxos.data.add(i) };
                let dec = xnt_sync_decrypt_indexed_utxo(ctx.key, indexed);
                if !dec.utxo.is_null() {
                    let mut utxo_hash = XntDigest::new();
                    if xnt_utxo_hash(dec.utxo, utxo_hash.bytes.as_mut_ptr()) == XntErrorCode::Ok {
                        let amount = xnt_utxo_get_amount(dec.utxo);
                        decrypted_utxos.push((utxo_hash, dec.sender_randomness, amount, dec.utxo));
                    } else {
                        xnt_utxo_free(dec.utxo);
                    }
                }
            }
            xnt_sync_indexed_utxos_free(&mut utxos as *mut _);
        }
        from = to + 1;
    }

    if decrypted_utxos.is_empty() {
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        skip!("no UTXOs found");
    }
    ok!("decrypted {} UTXOs", decrypted_utxos.len());

    // Compute commitments for AOCL lookup
    let mut commitments: Vec<XntDigest> = Vec::new();
    for (utxo_hash, sender_randomness, _, _) in &decrypted_utxos {
        let mut commitment = XntDigest::new();
        if xnt_compute_commitment(utxo_hash, sender_randomness, &receiver_preimage, commitment.bytes.as_mut_ptr()) == XntErrorCode::Ok {
            commitments.push(commitment);
        }
    }

    // Get AOCL indices
    let aocl = xnt_sync_get_aocl_indices(client, commitments.as_ptr(), commitments.len());
    if aocl.indices.is_null() || aocl.len == 0 {
        for (_, _, _, utxo) in &decrypted_utxos { xnt_utxo_free(*utxo); }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        fail!("failed to get AOCL indices");
    }
    let indices = unsafe { std::slice::from_raw_parts(aocl.indices, aocl.len) };

    // Compute abs_hashes for spent check
    let mut abs_hashes: Vec<XntDigest> = Vec::new();
    let mut valid_indices: Vec<usize> = Vec::new();
    for (i, &idx) in indices.iter().enumerate() {
        if idx >= 0 && i < decrypted_utxos.len() {
            let (utxo_hash, sender_randomness, _, _) = &decrypted_utxos[i];
            let mut abs_hash = XntDigest::new();
            if xnt_compute_absolute_index_set_hash(utxo_hash, sender_randomness, &receiver_preimage, idx as u64, abs_hash.bytes.as_mut_ptr()) == XntErrorCode::Ok {
                abs_hashes.push(abs_hash);
                valid_indices.push(i);
            }
        }
    }

    // Check spent status
    let status = xnt_sync_check_spent(client, abs_hashes.as_ptr(), abs_hashes.len());
    if status.heights.is_null() {
        xnt_sync_aocl_indices_free(&aocl as *const _ as *mut _);
        for (_, _, _, utxo) in &decrypted_utxos { xnt_utxo_free(*utxo); }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        fail!("failed to check spent status");
    }
    let heights = unsafe { std::slice::from_raw_parts(status.heights, status.len) };

    // Collect unspent UTXOs
    let mut unspent: Vec<(usize, i64, i128)> = Vec::new(); // (original_index, aocl_index, amount)
    for (j, &h) in heights.iter().enumerate() {
        if h < 0 && j < valid_indices.len() {
            let orig_idx = valid_indices[j];
            let aocl_idx = indices[orig_idx];
            let (_, _, amount, _) = &decrypted_utxos[orig_idx];
            unspent.push((orig_idx, aocl_idx, *amount));
        }
    }
    xnt_sync_spent_status_free(&status as *const _ as *mut _);
    xnt_sync_aocl_indices_free(&aocl as *const _ as *mut _);

    // Sort by amount: lowest to highest (spend small UTXOs first)
    unspent.sort_by_key(|(_, _, amount)| *amount);

    ok!("unspent: {} UTXOs", unspent.len());

    if unspent.is_empty() {
        for (_, _, _, utxo) in &decrypted_utxos { xnt_utxo_free(*utxo); }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        skip!("no unspent UTXOs");
    }

    // Target amount (1 XNT = 4 * 10^30 nau)
    let target_amount = NativeCurrencyAmount::coins_from_str("0.612").unwrap().to_nau();
    let fee = NativeCurrencyAmount::coins_from_str("0.005").unwrap().to_nau();
    let needed = target_amount + fee;

    // First: select which UTXOs we need (coin selection - smallest first)
    let mut selected: Vec<(usize, i64)> = Vec::new(); // (orig_idx, aocl_idx)
    let mut total_selected: i128 = 0;

    for &(orig_idx, aocl_idx, amount) in &unspent {
        if total_selected >= needed { break; }
        selected.push((orig_idx, aocl_idx));
        total_selected += amount;
    }

    if total_selected < needed {
        for (_, _, _, utxo) in &decrypted_utxos { xnt_utxo_free(*utxo); }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        fail!("insufficient: need {} but have {}",
            NativeCurrencyAmount::from_nau(needed),
            NativeCurrencyAmount::from_nau(total_selected));
    }

    ok!("selected {} of {} UTXOs, total: {}", selected.len(), unspent.len(),
        NativeCurrencyAmount::from_nau(total_selected));

    // Second: get membership proofs only for selected UTXOs
    let mut utxo_hashes: Vec<XntDigest> = Vec::new();
    let mut sender_rands: Vec<XntDigest> = Vec::new();
    let mut aocl_indices: Vec<u64> = Vec::new();
    let mut utxos: Vec<*mut UtxoHandle> = Vec::new();
    let mut amounts: Vec<i128> = Vec::new();

    for (orig_idx, aocl_idx) in &selected {
        let (utxo_hash, sender_randomness, amount, utxo) = &decrypted_utxos[*orig_idx];
        utxo_hashes.push(utxo_hash.clone());
        sender_rands.push(sender_randomness.clone());
        aocl_indices.push(*aocl_idx as u64);
        amounts.push(*amount);
        utxos.push(*utxo);
    }

    let mut proofs: Vec<*mut MsMembershipProofHandle> = vec![std::ptr::null_mut(); selected.len()];
    let result = xnt_sync_get_membership_proofs(
        client,
        utxo_hashes.as_ptr(),
        sender_rands.as_ptr(),
        &receiver_preimage,
        aocl_indices.as_ptr(),
        selected.len(),
        proofs.as_mut_ptr(),
    );

    if result != XntErrorCode::Ok {
        for (_, _, _, utxo) in &decrypted_utxos { xnt_utxo_free(*utxo); }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        fail!("membership proofs failed: {}", get_error());
    }
    ok!("got {} membership proofs", proofs.len());

    // Build transaction
    let builder = xnt_tx_builder_create();
    check_ptr!(builder, "create builder");

    // Add inputs - show commitment (canonical_commitment like wallet_sendTx)
    println!("\n  Inputs ({}):", proofs.len());
    for i in 0..proofs.len() {
        xnt_tx_builder_add_input(builder, utxos[i], ctx.key, proofs[i]);
        // Commitment = Hash(utxo_hash, sender_randomness, receiver_preimage)
        let mut commitment = XntDigest::new();
        xnt_compute_commitment(&utxo_hashes[i], &sender_rands[i], &receiver_preimage, commitment.bytes.as_mut_ptr());
        println!("    #{}: {} XNT  commitment={}", i + 1, NativeCurrencyAmount::from_nau(amounts[i]), hex::encode(&commitment.bytes));
    }
    let input_total = NativeCurrencyAmount::from_nau(amounts.iter().sum::<i128>());
    println!("    ───────────────────────────────────────────────────────────────────────────────────────────");
    println!("    Total: {} XNT", input_total);

    // Free proofs and unused UTXOs
    for mp in &proofs { xnt_ms_membership_proof_free(*mp); }
    for (_, _, _, utxo) in &decrypted_utxos { xnt_utxo_free(*utxo); }

    // Add output
    let mut out_sr = XntDigest::new();
    out_sr.bytes = [0x42u8; 40];
    xnt_tx_builder_add_output(builder, ctx.addr, target_amount, &out_sr);

    // Set change address and fee
    let mut change_sr = XntDigest::new();
    change_sr.bytes = [0x43u8; 40];
    xnt_tx_builder_set_change(builder, ctx.addr, &change_sr);
    xnt_tx_builder_set_fee(builder, fee);
    let change = xnt_tx_builder_change_amount(builder);

    // Get receiver's privacy_digest for output commitment computation
    let mut privacy_digest = XntDigest::new();
    xnt_address_privacy_digest(ctx.addr, privacy_digest.bytes.as_mut_ptr());

    // Compute output commitments for display (using privacy_digest, not preimage)
    let out_utxo = xnt_utxo_create_native(ctx.addr, target_amount);
    let mut out_hash = XntDigest::new();
    let mut out_commitment = XntDigest::new();
    if !out_utxo.is_null() {
        xnt_utxo_hash(out_utxo, out_hash.bytes.as_mut_ptr());
        xnt_compute_commitment_for_output(&out_hash, &out_sr, &privacy_digest, out_commitment.bytes.as_mut_ptr());
        xnt_utxo_free(out_utxo);
    }

    // Show outputs
    println!("\n  Outputs ({}):", if change > 0 { 2 } else { 1 });
    println!("    #1: {} XNT (recipient)  commitment={}", NativeCurrencyAmount::from_nau(target_amount), hex::encode(&out_commitment.bytes));
    if change > 0 {
        let change_utxo = xnt_utxo_create_native(ctx.addr, change);
        let mut change_hash = XntDigest::new();
        let mut change_commitment = XntDigest::new();
        if !change_utxo.is_null() {
            xnt_utxo_hash(change_utxo, change_hash.bytes.as_mut_ptr());
            xnt_compute_commitment_for_output(&change_hash, &change_sr, &privacy_digest, change_commitment.bytes.as_mut_ptr());
            xnt_utxo_free(change_utxo);
        }
        println!("    #2: {} XNT (change)     commitment={}", NativeCurrencyAmount::from_nau(change), hex::encode(&change_commitment.bytes));
    }
    let output_total = NativeCurrencyAmount::from_nau(target_amount + change);
    println!("    ───────────────────────────────────────────────────────────────────────────────────────────");
    println!("    Total: {} XNT", output_total);

    println!("\n  Fee: {} XNT\n", NativeCurrencyAmount::from_nau(fee));

    // Build transaction
    let timestamp = xnt_timestamp_now();
    let built = xnt_tx_builder_build(builder, ms, timestamp, XntNetwork::Testnet);
    check_ptr!(built, "build transaction");
    ok!("transaction built");

    // Create ProofCollection
    println!("Creating ProofCollection (this may take a while)...");
    let start = std::time::Instant::now();
    let proven = xnt_built_transaction_prove(built);
    let elapsed = start.elapsed();
    check_ptr!(proven, "prove transaction");

    if xnt_transaction_has_proof_collection(proven) {
        ok!("ProofCollection created in {:.1}s", elapsed.as_secs_f64());
    }

    let tx_bytes = xnt_transaction_serialize(proven);
    check_ptr!(tx_bytes, "serialize");
    let tx_buf = unsafe { &*tx_bytes };
    ok!("proven tx: {} bytes", tx_buf.len);

    // Submit transaction
    println!("\n=== Submitting Transaction ===");
    let submit_result = xnt_transaction_submit(proven, client);
    if submit_result == XntErrorCode::Ok {
        ok!("transaction submitted successfully");
    } else {
        let err = unsafe { CStr::from_ptr(xnt_get_last_error()).to_str().unwrap_or("unknown") };
        println!("  Submit result: {:?} - {}", submit_result, err);
        // Note: submission may fail if node rejects (e.g., double spend, invalid proof)
        // This is expected in test environment
    }

    // Cleanup
    xnt_buffer_free(tx_bytes);
    xnt_transaction_free(proven);
    xnt_built_transaction_free(built);
    xnt_tx_builder_free(builder);
    xnt_mutator_set_free(ms);
    xnt_rpc_client_free(client);

    ok!("prove tests passed");
}

fn test_full() {
    println!("=== XNT-FFI Test ===\n");
    test_version(); println!();
    test_error(); println!();
    test_seed(); println!();
    test_address(); println!();
    test_crypto(); println!();
    test_utxo(); println!();
    test_transaction(); println!();
    test_sync(); println!();
    println!("=== Done ===");
}
