//! XNT-SDK FFI test binary
//!
//! Usage: cargo run --example xnt-sdk-test [command]
//! Commands: version, error, seed, address, crypto, utxo, utils, sync, tx, full

use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use std::ffi::{CStr, CString};
use xnt_sdk::*;

fn test_mnemonic() -> String {
    std::env::var("XNT_TEST_MNEMONIC").expect("XNT_TEST_MNEMONIC required")
}

fn rpc_url() -> String {
    std::env::var("XNT_RPC_URL").expect("XNT_RPC_URL required")
}

macro_rules! ok { ($($arg:tt)*) => { println!("[OK] {}", format!($($arg)*)) }; }
macro_rules! fail { ($($arg:tt)*) => {{ println!("[FAIL] {}", format!($($arg)*)); return; }}; }
macro_rules! skip { ($msg:expr) => {{ println!("[SKIP] {}", $msg); return; }}; }

fn get_error() -> String {
    let err = xnt_get_last_error();
    if err.is_null() { "unknown".into() }
    else { unsafe { CStr::from_ptr(err).to_str().unwrap_or("utf8").into() } }
}

macro_rules! check { ($ptr:expr, $msg:expr) => { if $ptr.is_null() { fail!("{}: {}", $msg, get_error()); } }; }

fn cstr(s: &str) -> CString { CString::new(s).unwrap() }

struct Ctx {
    wallet: *mut WalletHandle,
    key: *mut SpendingKeyHandle,
    addr: *mut AddressHandle,
}

impl Ctx {
    fn new() -> Option<Self> {
        let m = cstr(&test_mnemonic());
        let wallet = xnt_wallet_from_mnemonic(m.as_ptr());
        if wallet.is_null() { return None; }
        let key = xnt_wallet_derive_spending_key(wallet, 0);
        if key.is_null() { xnt_wallet_free(wallet); return None; }
        let addr = xnt_spending_key_to_address(key);
        if addr.is_null() { xnt_spending_key_free(key); xnt_wallet_free(wallet); return None; }
        Some(Self { wallet, key, addr })
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        xnt_address_free(self.addr);
        xnt_spending_key_free(self.key);
        xnt_wallet_free(self.wallet);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()).unwrap_or("full") {
        "version" => test_version(),
        "error" => test_error(),
        "seed" => test_seed(),
        "address" => test_address(),
        "crypto" => test_crypto(),
        "utxo" => test_utxo(),
        "utils" => test_utils(),
        "sync" => test_sync(),
        "tx" => test_tx(),
        "full" => test_full(),
        cmd => { eprintln!("Unknown: {cmd}"); std::process::exit(1); }
    }
}

fn test_version() {
    let v = unsafe { CStr::from_ptr(xnt_version()).to_str().unwrap() };
    ok!("version: {v}");
}

fn test_error() {
    println!("Testing error...");
    if xnt_get_last_error().is_null() { ok!("no initial error"); }
    xnt_clear_error();
    ok!("clear error");
}

fn test_seed() {
    println!("Testing seed...");
    let mnemonic = test_mnemonic();
    let m = cstr(&mnemonic);
    let wallet = xnt_wallet_from_mnemonic(m.as_ptr());
    check!(wallet, "import");
    ok!("imported");

    let exported = xnt_wallet_to_mnemonic(wallet);
    check!(exported, "export");
    let s = unsafe { CStr::from_ptr(exported).to_str().unwrap() };
    if s != mnemonic { fail!("mnemonic mismatch"); }
    ok!("roundtrip: {s}");
    xnt_string_free(exported);

    let key = xnt_wallet_derive_spending_key(wallet, 0);
    check!(key, "derive");
    let rid = xnt_spending_key_receiver_id_hex(key);
    if !rid.is_null() {
        ok!("receiver_id: {}", unsafe { CStr::from_ptr(rid).to_str().unwrap() });
        xnt_string_free(rid);
    }
    xnt_spending_key_free(key);

    let gen = xnt_wallet_generate();
    check!(gen, "generate");
    let gm = xnt_wallet_to_mnemonic(gen);
    if !gm.is_null() {
        let words = unsafe { CStr::from_ptr(gm).to_str().unwrap() }.split_whitespace().count();
        ok!("generated {words} words");
        xnt_string_free(gm);
    }
    xnt_wallet_free(gen);
    xnt_wallet_free(wallet);
}

fn test_address() {
    println!("Testing address...");
    let ctx = Ctx::new().expect("setup");

    let rid = xnt_address_receiver_id_hex(ctx.addr);
    if !rid.is_null() {
        ok!("receiver_id: {}", unsafe { CStr::from_ptr(rid).to_str().unwrap() });
        xnt_string_free(rid);
    }

    let b32 = xnt_address_to_bech32(ctx.addr, XntNetwork::Main);
    check!(b32, "encode");
    let b32s = unsafe { CStr::from_ptr(b32).to_str().unwrap() };
    ok!("bech32: {b32s}");

    let dec = xnt_address_from_bech32(b32, XntNetwork::Main);
    check!(dec, "decode");
    let re = xnt_address_to_bech32(dec, XntNetwork::Main);
    if !re.is_null() {
        let res = unsafe { CStr::from_ptr(re).to_str().unwrap() };
        if res == b32s { ok!("roundtrip"); }
        xnt_string_free(re);
    }
    xnt_address_free(dec);
    xnt_string_free(b32);

    let sub = xnt_subaddress_create(ctx.addr, 12345);
    check!(sub, "subaddress");
    if xnt_subaddress_payment_id(sub) == 12345 { ok!("payment_id=12345"); }
    let sb = xnt_subaddress_to_bech32(sub, XntNetwork::Main);
    if !sb.is_null() {
        ok!("subaddr: {}", unsafe { CStr::from_ptr(sb).to_str().unwrap() });
        xnt_string_free(sb);
    }
    xnt_subaddress_free(sub);

    if xnt_subaddress_create(ctx.addr, 0).is_null() { ok!("rejected payment_id=0"); }
}

fn test_crypto() {
    println!("Testing crypto...");
    let data = b"Hello, Neptune!";
    let mut hash = [0u8; 40];

    if xnt_tip5_hash(data.as_ptr(), data.len(), hash.as_mut_ptr()) == XntErrorCode::Ok {
        ok!("TIP5: {}", hex::encode(&hash[..8]));
    }

    let mut s32 = [0u8; 32];
    if xnt_shake256_32(data.as_ptr(), data.len(), s32.as_mut_ptr()) == XntErrorCode::Ok {
        ok!("SHAKE256: {}", hex::encode(&s32[..8]));
    }

    let s64 = xnt_shake256(data.as_ptr(), data.len(), 64);
    if !s64.is_null() {
        let buf = unsafe { &*s64 };
        if buf.len == 64 { ok!("SHAKE256(64): {} bytes", buf.len); }
        xnt_buffer_free(s64);
    }

    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let plain = b"Secret";
    let ct = xnt_aes256gcm_encrypt(key.as_ptr(), nonce.as_ptr(), plain.as_ptr(), plain.len());
    check!(ct, "encrypt");
    let ctb = unsafe { &*ct };
    let pt = xnt_aes256gcm_decrypt(key.as_ptr(), nonce.as_ptr(), ctb.data, ctb.len);
    check!(pt, "decrypt");
    let ptb = unsafe { &*pt };
    let dec = unsafe { std::slice::from_raw_parts(ptb.data, ptb.len) };
    if dec == plain { ok!("AES-GCM roundtrip"); }
    xnt_buffer_free(pt);
    xnt_buffer_free(ct);
}

fn test_utxo() {
    println!("Testing UTXO...");
    let ctx = Ctx::new().expect("setup");

    let amt: i128 = 1_000_000_000;
    let utxo = xnt_utxo_create_native(ctx.addr, amt);
    check!(utxo, "create");
    if xnt_utxo_get_amount(utxo) == amt { ok!("amount: {amt}"); }

    let mut lh = [0u8; 40];
    if xnt_utxo_lock_script_hash(utxo, lh.as_mut_ptr()) == XntErrorCode::Ok {
        ok!("lock_hash: {}", hex::encode(&lh[..8]));
    }

    // Test timelock methods
    if xnt_utxo_is_timelocked(utxo) == 0 { ok!("not timelocked"); }
    let now = xnt_timestamp_now();
    if xnt_utxo_can_spend_at(utxo, now) == 1 { ok!("can_spend_at(now)"); }

    // Test with_time_lock
    let future = now + 3600_000; // 1 hour from now
    let locked = xnt_utxo_with_time_lock(utxo, future);
    check!(locked, "with_time_lock");
    if xnt_utxo_is_timelocked(locked) == 1 { ok!("timelocked"); }
    if xnt_utxo_release_date(locked) == future { ok!("release_date: {future}"); }
    if xnt_utxo_can_spend_at(locked, now) == 0 { ok!("cannot spend now"); }
    if xnt_utxo_can_spend_at(locked, future + 1) == 1 { ok!("can spend after release"); }
    xnt_utxo_free(locked);

    let ser = xnt_utxo_serialize(utxo);
    check!(ser, "serialize");
    let sb = unsafe { &*ser };
    ok!("serialized: {} bytes", sb.len);

    let des = xnt_utxo_deserialize(sb.data, sb.len);
    check!(des, "deserialize");
    if xnt_utxo_get_amount(des) == amt { ok!("roundtrip"); }

    xnt_utxo_free(des);
    xnt_buffer_free(ser);
    xnt_utxo_free(utxo);
}

fn test_utils() {
    println!("Testing utils...");
    let ts = xnt_timestamp_now();
    ok!("timestamp: {ts}");

    let sr = xnt_random_sender_randomness();
    ok!("random sender_randomness: {}...", hex::encode(&sr.bytes[..8]));

    let hex_sr = xnt_random_sender_randomness_hex();
    if !hex_sr.is_null() {
        let s = unsafe { CStr::from_ptr(hex_sr).to_str().unwrap() };
        ok!("random hex: {}...", &s[..16]);
        xnt_string_free(hex_sr);
    }
}

fn test_sync() {
    println!("Testing sync...");
    let ctx = Ctx::new().expect("setup");

    let mut rid_hash = XntDigest::new();
    let mut preimage = XntDigest::new();
    xnt_spending_key_receiver_id_hash(ctx.key, rid_hash.bytes.as_mut_ptr());
    xnt_spending_key_receiver_preimage(ctx.key, preimage.bytes.as_mut_ptr());
    ok!("rid_hash: {}", hex::encode(&rid_hash.bytes[..8]));

    let url = cstr(&rpc_url());
    let client = xnt_rpc_client_create(url.as_ptr());
    check!(client, "client");

    let tip = xnt_sync_get_height(client);
    if tip < 0 { skip!("no server"); }
    ok!("height: {tip}");

    // Keep UTXO handles for timelock filtering
    let mut utxos: Vec<(XntDigest, XntDigest, u64, i128, *mut UtxoHandle)> = Vec::new();
    let mut from = 0u64;
    while from <= tip as u64 {
        let to = (from + 999).min(tip as u64);
        let arr = xnt_sync_fetch_utxos(client, &rid_hash, from, to);
        if !arr.data.is_null() && arr.len > 0 {
            let slice = unsafe { std::slice::from_raw_parts(arr.data, arr.len) };
            for idx in slice {
                let dec = xnt_sync_decrypt_indexed_utxo(ctx.key, idx);
                if !dec.utxo.is_null() {
                    let mut h = XntDigest::new();
                    if xnt_utxo_hash(dec.utxo, h.bytes.as_mut_ptr()) == XntErrorCode::Ok {
                        utxos.push((h, dec.sender_randomness, idx.block_height, xnt_utxo_get_amount(dec.utxo), dec.utxo));
                    } else {
                        xnt_utxo_free(dec.utxo);
                    }
                }
            }
            xnt_sync_indexed_utxos_free(&mut { arr } as *mut _);
        }
        from = to + 1;
    }
    ok!("decrypted {} UTXOs", utxos.len());

    if !utxos.is_empty() {
        let commits: Vec<XntDigest> = utxos.iter().map(|(h, sr, _, _, _)| {
            let mut c = XntDigest::new();
            xnt_compute_commitment(h, sr, &preimage, c.bytes.as_mut_ptr());
            c
        }).collect();

        let aocl = xnt_sync_get_aocl_indices(client, commits.as_ptr(), commits.len());
        if !aocl.indices.is_null() {
            let indices = unsafe { std::slice::from_raw_parts(aocl.indices, aocl.len) };
            let valid = indices.iter().filter(|&&i| i >= 0).count();
            ok!("AOCL: {valid}/{} valid", indices.len());

            let mut abs: Vec<XntDigest> = Vec::new();
            let mut vi: Vec<usize> = Vec::new();
            for (i, &idx) in indices.iter().enumerate() {
                if idx >= 0 && i < utxos.len() {
                    let (h, sr, _, _, _) = &utxos[i];
                    let mut a = XntDigest::new();
                    if xnt_compute_absolute_index_set_hash(h, sr, &preimage, idx as u64, a.bytes.as_mut_ptr()) == XntErrorCode::Ok {
                        abs.push(a); vi.push(i);
                    }
                }
            }

            if !abs.is_empty() {
                let st = xnt_sync_check_spent(client, abs.as_ptr(), abs.len());
                if !st.heights.is_null() {
                    let hs = unsafe { std::slice::from_raw_parts(st.heights, st.len) };
                    let (spent, unspent) = (hs.iter().filter(|&&h| h >= 0).count(), hs.iter().filter(|&&h| h < 0).count());
                    ok!("spent: {spent}, unspent: {unspent}");

                    let now = xnt_timestamp_now();
                    let mut total: i128 = 0;
                    println!("\n  Unspent UTXOs:");
                    for (j, &h) in hs.iter().enumerate() {
                        if h < 0 && j < vi.len() {
                            let (_, _, bh, amt, utxo) = &utxos[vi[j]];
                            let c = &commits[vi[j]];
                            // Filter by timelock (like TypeScript test)
                            if xnt_utxo_can_spend_at(*utxo, now) == 1 {
                                println!("    aocl={}, h={bh}, amt={}, c={}", indices[vi[j]], NativeCurrencyAmount::from_nau(*amt), hex::encode(&c.bytes));
                                total += amt;
                            }
                        }
                    }
                    println!("  Total: {}", NativeCurrencyAmount::from_nau(total));
                    xnt_sync_spent_status_free(&mut { st } as *mut _);
                }
            }
            xnt_sync_aocl_indices_free(&mut { aocl } as *mut _);
        }
    }

    // Free UTXO handles
    for (_, _, _, _, utxo) in &utxos {
        xnt_utxo_free(*utxo);
    }
    xnt_rpc_client_free(client);
}

fn test_tx() {
    println!("Testing transaction (build & prove, 16GB RAM)...");
    let ctx = Ctx::new().expect("setup");

    let mut rid_hash = XntDigest::new();
    let mut preimage = XntDigest::new();
    xnt_spending_key_receiver_id_hash(ctx.key, rid_hash.bytes.as_mut_ptr());
    xnt_spending_key_receiver_preimage(ctx.key, preimage.bytes.as_mut_ptr());

    let url = cstr(&rpc_url());
    let client = xnt_rpc_client_create(url.as_ptr());
    check!(client, "client");

    let ms = xnt_sync_get_mutator_set(client);
    check!(ms, "mutator_set");

    let tip = xnt_sync_get_height(client);
    if tip < 0 { fail!("no height"); }
    ok!("height: {tip}");

    let mut utxos: Vec<(XntDigest, XntDigest, i128, *mut UtxoHandle)> = Vec::new();
    let mut from = 0u64;
    while from <= tip as u64 {
        let to = (from + 999).min(tip as u64);
        let mut arr = xnt_sync_fetch_utxos(client, &rid_hash, from, to);
        if arr.len > 0 && !arr.data.is_null() {
            for i in 0..arr.len {
                let idx = unsafe { &*arr.data.add(i) };
                let dec = xnt_sync_decrypt_indexed_utxo(ctx.key, idx);
                if !dec.utxo.is_null() {
                    let mut h = XntDigest::new();
                    if xnt_utxo_hash(dec.utxo, h.bytes.as_mut_ptr()) == XntErrorCode::Ok {
                        utxos.push((h, dec.sender_randomness, xnt_utxo_get_amount(dec.utxo), dec.utxo));
                    } else { xnt_utxo_free(dec.utxo); }
                }
            }
            xnt_sync_indexed_utxos_free(&mut arr as *mut _);
        }
        from = to + 1;
    }

    if utxos.is_empty() {
        xnt_mutator_set_free(ms); xnt_rpc_client_free(client);
        skip!("no UTXOs");
    }
    ok!("{} UTXOs", utxos.len());

    let commits: Vec<XntDigest> = utxos.iter().map(|(h, sr, _, _)| {
        let mut c = XntDigest::new();
        xnt_compute_commitment(h, sr, &preimage, c.bytes.as_mut_ptr());
        c
    }).collect();

    let aocl = xnt_sync_get_aocl_indices(client, commits.as_ptr(), commits.len());
    if aocl.indices.is_null() {
        for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }
        xnt_mutator_set_free(ms); xnt_rpc_client_free(client);
        fail!("no AOCL");
    }
    let indices = unsafe { std::slice::from_raw_parts(aocl.indices, aocl.len) };

    let mut abs: Vec<XntDigest> = Vec::new();
    let mut vi: Vec<usize> = Vec::new();
    for (i, &idx) in indices.iter().enumerate() {
        if idx >= 0 && i < utxos.len() {
            let (h, sr, _, _) = &utxos[i];
            let mut a = XntDigest::new();
            if xnt_compute_absolute_index_set_hash(h, sr, &preimage, idx as u64, a.bytes.as_mut_ptr()) == XntErrorCode::Ok {
                abs.push(a); vi.push(i);
            }
        }
    }

    let st = xnt_sync_check_spent(client, abs.as_ptr(), abs.len());
    if st.heights.is_null() {
        xnt_sync_aocl_indices_free(&aocl as *const _ as *mut _);
        for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }
        xnt_mutator_set_free(ms); xnt_rpc_client_free(client);
        fail!("spent check failed");
    }
    let hs = unsafe { std::slice::from_raw_parts(st.heights, st.len) };

    let mut unspent: Vec<(usize, i64, i128)> = Vec::new();
    for (j, &h) in hs.iter().enumerate() {
        if h < 0 && j < vi.len() {
            let oi = vi[j];
            unspent.push((oi, indices[oi], utxos[oi].2));
        }
    }
    xnt_sync_spent_status_free(&st as *const _ as *mut _);
    xnt_sync_aocl_indices_free(&aocl as *const _ as *mut _);
    unspent.sort_by_key(|(_, _, a)| *a);
    ok!("{} unspent", unspent.len());

    if unspent.is_empty() {
        for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }
        xnt_mutator_set_free(ms); xnt_rpc_client_free(client);
        skip!("no unspent");
    }

    let target = NativeCurrencyAmount::coins_from_str("0.612").unwrap().to_nau();
    let fee = NativeCurrencyAmount::coins_from_str("0.005").unwrap().to_nau();
    let needed = target + fee;

    let mut sel: Vec<(usize, i64)> = Vec::new();
    let mut total: i128 = 0;
    for &(oi, ai, amt) in &unspent {
        if total >= needed { break; }
        sel.push((oi, ai)); total += amt;
    }

    if total < needed {
        for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }
        xnt_mutator_set_free(ms); xnt_rpc_client_free(client);
        fail!("insufficient: need {} have {}", NativeCurrencyAmount::from_nau(needed), NativeCurrencyAmount::from_nau(total));
    }
    ok!("selected {}/{}, total: {}", sel.len(), unspent.len(), NativeCurrencyAmount::from_nau(total));

    let (mut uhs, mut srs, mut ais, mut us, mut amts): (Vec<_>, Vec<_>, Vec<_>, Vec<_>, Vec<_>) = (vec![], vec![], vec![], vec![], vec![]);
    for (oi, ai) in &sel {
        let (h, sr, amt, u) = &utxos[*oi];
        uhs.push(h.clone()); srs.push(sr.clone()); ais.push(*ai as u64); amts.push(*amt); us.push(*u);
    }

    let mut proofs: Vec<*mut MsMembershipProofHandle> = vec![std::ptr::null_mut(); sel.len()];
    let r = xnt_sync_get_membership_proofs(client, uhs.as_ptr(), srs.as_ptr(), &preimage, ais.as_ptr(), sel.len(), proofs.as_mut_ptr());
    if r != XntErrorCode::Ok {
        for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }
        xnt_mutator_set_free(ms); xnt_rpc_client_free(client);
        fail!("proofs: {}", get_error());
    }
    ok!("{} proofs", proofs.len());

    let builder = xnt_tx_builder_create();
    check!(builder, "builder");

    println!("\n  Inputs ({}):", proofs.len());
    for i in 0..proofs.len() {
        xnt_tx_builder_add_input(builder, us[i], ctx.key, proofs[i]);
        let mut c = XntDigest::new();
        xnt_compute_commitment(&uhs[i], &srs[i], &preimage, c.bytes.as_mut_ptr());
        println!("    #{}: {}  c={}", i+1, NativeCurrencyAmount::from_nau(amts[i]), hex::encode(&c.bytes));
    }
    println!("    Total: {}", NativeCurrencyAmount::from_nau(amts.iter().sum::<i128>()));

    for mp in &proofs { xnt_ms_membership_proof_free(*mp); }
    for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }

    // Create subaddress with payment_id (like TypeScript test)
    let subaddr = xnt_subaddress_create(ctx.addr, 12345);
    check!(subaddr, "subaddress");
    let recv = xnt_subaddress_to_receiving(subaddr);
    check!(recv, "receiving address");

    let osr = xnt_random_sender_randomness();
    let csr = xnt_random_sender_randomness();
    xnt_tx_builder_add_output(builder, recv, target, &osr);
    xnt_tx_builder_set_change(builder, ctx.addr, &csr);
    xnt_tx_builder_set_fee(builder, fee);

    xnt_receiving_address_free(recv);
    xnt_subaddress_free(subaddr);

    let ts = xnt_timestamp_now();
    let built = xnt_tx_builder_build(builder, ms, ts, XntNetwork::Main);
    check!(built, "build");

    // Show built transaction summary (like TypeScript test)
    let inputs_info = xnt_built_transaction_inputs(built);
    let outputs_info = xnt_built_transaction_outputs(built);
    if !inputs_info.is_null() && !outputs_info.is_null() {
        let inputs = unsafe { std::slice::from_raw_parts((*inputs_info).data, (*inputs_info).len) };
        let outputs = unsafe { std::slice::from_raw_parts((*outputs_info).data, (*outputs_info).len) };

        let in_total: i128 = inputs.iter().map(|i| i.amount).sum();
        let out_total: i128 = outputs.iter().map(|o| o.amount).sum();

        println!("\n  Inputs ({}): {}", inputs.len(), NativeCurrencyAmount::from_nau(in_total));
        for inp in inputs {
            println!("    {}, c={}", NativeCurrencyAmount::from_nau(inp.amount), hex::encode(&inp.commitment.bytes));
        }
        println!("  Outputs ({}): {}", outputs.len(), NativeCurrencyAmount::from_nau(out_total));
        for out in outputs {
            let change = if out.is_change { " (change)" } else { "" };
            let pid = if out.payment_id != 0 { format!(", pid={}", out.payment_id) } else { "".into() };
            println!("    {}{}{}, c={}", NativeCurrencyAmount::from_nau(out.amount), change, pid, hex::encode(&out.commitment.bytes));
        }
        println!("  Fee: {}", NativeCurrencyAmount::from_nau(fee));

        xnt_tx_input_info_array_free(inputs_info);
        xnt_tx_output_info_array_free(outputs_info);
    }

    ok!("built");

    println!("Proving...");
    let start = std::time::Instant::now();
    let proven = xnt_built_transaction_prove(built);
    let elapsed = start.elapsed();
    check!(proven, "prove");

    if xnt_transaction_has_proof_collection(proven) {
        ok!("proven in {:.1}s", elapsed.as_secs_f64());
    }

    let tx = xnt_transaction_serialize(proven);
    check!(tx, "serialize");
    ok!("tx: {} bytes", unsafe { &*tx }.len);

    println!("\nSubmitting...");
    let sub = xnt_transaction_submit(proven, client);
    if sub == XntErrorCode::Ok { ok!("submitted"); }
    else { println!("  result: {:?} - {}", sub, get_error()); }

    xnt_buffer_free(tx);
    xnt_transaction_free(proven);
    xnt_built_transaction_free(built);
    xnt_tx_builder_free(builder);
    xnt_mutator_set_free(ms);
    xnt_rpc_client_free(client);
    ok!("tx passed");
}

fn test_full() {
    println!("=== XNT-SDK FFI Test ===\n");
    test_version(); println!();
    test_error(); println!();
    test_seed(); println!();
    test_address(); println!();
    test_crypto(); println!();
    test_utxo(); println!();
    test_utils(); println!();
    test_sync(); println!();
    println!("=== Done ===");
}
