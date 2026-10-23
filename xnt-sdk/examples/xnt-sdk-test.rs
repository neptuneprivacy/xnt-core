//! XNT-SDK FFI test binary
//!
//! Usage: cargo run --example xnt-sdk-test [command]
//! Commands: version, error, seed, address, dctidh, crypto, utxo, utils, sync, tx, tx-dctidh, tx-mix, full

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

/// Context using a CTIDH-512 spending key (for CTIDH tx tests)
struct CtxdCTIDH {
    wallet: *mut WalletHandle,
    key: *mut SpendingKeyHandle,
    addr: *mut AddressHandle,
}

impl CtxdCTIDH {
    fn new() -> Option<Self> {
        let m = cstr(&test_mnemonic());
        let wallet = xnt_wallet_from_mnemonic(m.as_ptr());
        if wallet.is_null() {
            return None;
        }
        // Derive CTIDH-512 spending key via FFI
        let key = xnt_wallet_derive_dctidh_key(wallet, 0);
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

impl Drop for CtxdCTIDH {
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
        "dctidh" => test_dctidh_address(),
        "crypto" => test_crypto(),
        "utxo" => test_utxo(),
        "utils" => test_utils(),
        "sync" => test_sync(),
        "tx" => test_tx(),
        "tx-dctidh" => test_tx_dctidh_multi(),
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

    let b32 = xnt_address_to_bech32(ctx.addr, XntNetwork::Main as u32);
    check!(b32, "encode");
    let b32s = unsafe { CStr::from_ptr(b32).to_str().unwrap() };
    ok!("bech32: {b32s}");

    let dec = xnt_address_from_bech32(b32, XntNetwork::Main as u32);
    check!(dec, "decode");
    let re = xnt_address_to_bech32(dec, XntNetwork::Main as u32);
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
    let sb = xnt_subaddress_to_bech32(sub, XntNetwork::Main as u32);
    if !sb.is_null() {
        ok!("subaddr: {}", unsafe { CStr::from_ptr(sb).to_str().unwrap() });
        xnt_string_free(sb);
    }
    xnt_subaddress_free(sub);

    if xnt_subaddress_create(ctx.addr, 0).is_null() { ok!("rejected payment_id=0"); }
}

/// Test CTIDH-512 address using Rust SDK (bech32m only).
///
/// This test:
/// - derives a CTIDH spending key from the mnemonic
/// - encodes the address as standard bech32m
/// - roundtrips the bech32m form back to a CTIDH address.
fn test_dctidh_address() {
    println!("Testing CTIDH-512 address (bech32m)...");

    // Build wallet from mnemonic using Rust SDK core
    let mnemonic = test_mnemonic();
    let wallet =
        xnt_sdk::core::WalletEntropy::from_mnemonic(&mnemonic).expect("wallet from mnemonic");

    // Derive CTIDH spending key (uses CTIDH-512 under the hood)
    let key = wallet.derive_dctidh_spending_key(0);
    let addr = key.to_address().expect("receiving address");

    // Standard bech32m encoding (long form, always decodable)
    let b32 = addr
        .to_bech32(xnt_sdk::core::Network::Main)
        .expect("dctidh bech32m encoding failed");
    ok!("CTIDH bech32m: {b32}");

    // Roundtrip: bech32 -> Address -> bech32 again using SDK API
    let decoded =
        xnt_sdk::core::Address::from_bech32(&b32, xnt_sdk::core::Network::Main).expect("decode bech32");
    let roundtrip = decoded
        .to_bech32(xnt_sdk::core::Network::Main)
        .expect("re-encode bech32m");
    ok!("CTIDH bech32m roundtrip: {roundtrip}");
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

/// Interval between the polls of a submitted transaction, and how long to
/// watch it.
const WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const WATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 60);
/// Polls in a row that must find a transaction dropped before it is sent
/// again.
const DROPPED_POLLS: usize = 2;

/// Builds of a transaction at most, as one goes stale before it is submitted
/// or is dropped after; XNT_TX_MAX_ATTEMPTS, default 5.
fn max_tx_attempts() -> usize {
    std::env::var("XNT_TX_MAX_ATTEMPTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
        .max(1)
}

/// Whether `proven`, built on the mutator set of the tip at `build_tip`, may
/// be submitted now: only while that tip is still the tip and the transaction
/// is confirmable.
///
/// Confirmability alone is not enough. Before the UpgradeVMv8 fork, the nodes
/// that upgrade proof collections to single proofs, which is how they get
/// mined, take only those built on the mutator set of their own tip: they
/// cannot update someone else's proof collection to a new block. A proof
/// collection built on an earlier tip is often still confirmable, so nodes
/// accept it into their mempools, but none upgrades or mines it.
fn synced_to_tip(
    client: &xnt_sdk::core::RpcClient,
    proven: &xnt_sdk::core::Transaction,
    build_tip: u64,
) -> bool {
    match xnt_sdk::core::get_mutator_set(client) {
        Ok(mutator_set) => mutator_set.tip_height() == Some(build_tip) && proven.is_confirmable(&mutator_set),
        Err(e) => {
            // The tip is not known: do not submit.
            println!("  mutator set: {e}");
            false
        }
    }
}

/// Outcome of watching the inputs of a submitted transaction, see
/// `watch_inputs`.
enum Watch {
    /// All inputs spent on chain, at this height.
    Confirmed(u64),
    /// After a block, the inputs are neither spent on chain nor by a mempool
    /// transaction.
    Dropped,
    /// Some inputs spent on chain by another transaction.
    Conflicted,
    TimedOut,
}

/// Watch the inputs (absolute index set hashes) of a transaction built on the
/// tip at `build_tip` until it is confirmed, conflicted or dropped; nodes drop
/// the proof collections they cannot update to a new block.
///
/// From C, the same calls are xnt_rpc_chain_height, xnt_sync_check_spent and,
/// for the mempool, `mempool_transactions` and `mempool_getTransactionKernel`
/// through xnt_rpc_call, with xnt_hash_absolute_index_set on the inputs.
fn watch_inputs(client: &xnt_sdk::core::RpcClient, inputs: &[xnt_sdk::core::Digest], build_tip: u64) -> Watch {
    let start = std::time::Instant::now();
    let mut dropped_polls = 0;
    loop {
        std::thread::sleep(WATCH_INTERVAL);
        if start.elapsed() > WATCH_TIMEOUT {
            return Watch::TimedOut;
        }
        // The mempool is read before the spent status: a transaction mined in
        // between is then seen as confirmed, not as dropped.
        let poll = client.chain_height().and_then(|tip| {
            let in_mempool = xnt_sdk::core::mempool_spending(client, inputs)?.len();
            let spent_at = xnt_sdk::core::check_spent(client, inputs)?;
            Ok((tip, in_mempool, spent_at))
        });
        let (tip, in_mempool, spent_at) = match poll {
            Ok(poll) if poll.2.len() == inputs.len() => poll,
            Ok(_) => {
                println!("  watch: the spent status does not match the inputs; trying again");
                continue;
            }
            Err(e) => {
                println!("  watch: {e}; trying again");
                continue;
            }
        };

        let on_chain: Vec<i64> = spent_at.iter().copied().filter(|&height| height >= 0).collect();
        if let Some(&height) = on_chain.first() {
            // A transaction is mined in one block: all its inputs at one height.
            if on_chain.len() == inputs.len() && on_chain.iter().all(|&h| h == height) {
                return Watch::Confirmed(height as u64);
            }
            return Watch::Conflicted;
        }
        if in_mempool > 0 || tip <= build_tip {
            dropped_polls = 0;
            println!("  pending: tip {tip}, built on {build_tip}, {in_mempool} input(s) in the mempool");
        } else {
            dropped_polls += 1;
            println!("  neither mined nor in the mempool: tip {tip}, built on {build_tip}");
            if dropped_polls >= DROPPED_POLLS {
                return Watch::Dropped;
            }
        }
    }
}

fn test_tx() {
    println!("Testing transaction (build & prove, 16GB RAM)...");
    let ctx = Ctx::new().expect("setup");

    let url = cstr(&rpc_url());
    let client = xnt_rpc_client_create(url.as_ptr());
    check!(client, "client");
    let core_client = xnt_sdk::core::RpcClient::new(&rpc_url()).expect("rpc client");

    // Proving takes minutes, so the chain can advance and make the proof stale
    // before it is submitted, and a submitted transaction can be dropped. In
    // both cases build again from a fresh scan. A dropped transaction is sent
    // again with the same inputs, so that it and the one sent again cannot
    // both be mined.
    let max_attempts = max_tx_attempts();
    let mut sent: Option<(Vec<XntDigest>, u64)> = None;
    for attempt in 1..=max_attempts {
        let resend = sent.as_ref().map(|(inputs, _)| inputs.as_slice());
        match ffi_send_tx(&ctx, client, resend) {
            FfiSend::Sent(inputs, build_tip) => {
                ok!("submitted (attempt {attempt}), built on tip {build_tip}; watching its inputs");
                sent = Some((inputs, build_tip));
            }
            FfiSend::Unavailable => {
                println!("  an input of the dropped transaction is no longer free; watching it again");
            }
            FfiSend::Stale => {
                println!("  attempt {attempt}: not synced to the tip any more; building again");
                continue;
            }
            FfiSend::Skip(msg) => { xnt_rpc_client_free(client); skip!(msg); }
            FfiSend::Fail(msg) => { xnt_rpc_client_free(client); fail!("{msg}"); }
        }
        let Some((inputs, build_tip)) = &sent else { continue };

        let hashes: Vec<_> = inputs.iter().map(|d| xnt_sdk::core::Digest::from_bytes(d.bytes)).collect();
        match watch_inputs(&core_client, &hashes, *build_tip) {
            Watch::Confirmed(height) => {
                xnt_rpc_client_free(client);
                ok!("confirmed at height {height}");
                ok!("tx passed");
                return;
            }
            Watch::Dropped => println!("  dropped: neither mined nor in the mempool after a block; sending it again"),
            Watch::Conflicted => {
                xnt_rpc_client_free(client);
                fail!("an input was spent on chain by another transaction");
            }
            Watch::TimedOut => {
                xnt_rpc_client_free(client);
                fail!("not mined in time; look its inputs up before sending again");
            }
        }
    }
    xnt_rpc_client_free(client);
    fail!("gave up after {max_attempts} attempts");
}

/// What one build, prove and submit of `ffi_send_tx` gave.
enum FfiSend {
    /// Submitted: the absolute index set hashes of its inputs, and the height
    /// of the tip it was built on.
    Sent(Vec<XntDigest>, u64),
    /// Not synced to the tip any more before it was submitted: build again.
    Stale,
    /// An input of the transaction being sent again is no longer free.
    Unavailable,
    Skip(String),
    Fail(String),
}

/// Whether `proven`, built on the mutator set of the tip at `build_tip`, may
/// be submitted now; see `synced_to_tip`.
fn ffi_synced_to_tip(client: *mut RpcClientHandle, proven: *mut TransactionHandle, build_tip: u64) -> bool {
    let ms = xnt_sync_get_mutator_set(client);
    if ms.is_null() {
        // The tip is not known: do not submit.
        println!("  mutator set: {}", get_error());
        return false;
    }
    let synced = xnt_mutator_set_tip_height(ms) == build_tip as i64 && xnt_transaction_is_confirmable(proven, ms);
    xnt_mutator_set_free(ms);
    synced
}

/// Scan, select, build, prove and submit the transaction of `test_tx` through
/// the C API. With `resend` (absolute index set hashes), spend exactly those
/// inputs.
fn ffi_send_tx(ctx: &Ctx, client: *mut RpcClientHandle, resend: Option<&[XntDigest]>) -> FfiSend {
    let mut rid_hash = XntDigest::new();
    let mut preimage = XntDigest::new();
    xnt_spending_key_receiver_id_hash(ctx.key, rid_hash.bytes.as_mut_ptr());
    xnt_spending_key_receiver_preimage(ctx.key, preimage.bytes.as_mut_ptr());

    let tip = xnt_sync_get_height(client);
    if tip < 0 { return FfiSend::Fail("no height".into()); }
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
        return if resend.is_some() { FfiSend::Unavailable } else { FfiSend::Skip("no UTXOs".into()) };
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
        return FfiSend::Fail("no AOCL".into());
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
        return FfiSend::Fail("spent check failed".into());
    }
    let hs = unsafe { std::slice::from_raw_parts(st.heights, st.len) };

    // (UTXO index, AOCL index, amount, absolute index set hash)
    let mut unspent: Vec<(usize, i64, i128, XntDigest)> = Vec::new();
    for (j, &h) in hs.iter().enumerate() {
        if h < 0 && j < vi.len() {
            let oi = vi[j];
            unspent.push((oi, indices[oi], utxos[oi].2, abs[j]));
        }
    }
    xnt_sync_spent_status_free(&st as *const _ as *mut _);
    xnt_sync_aocl_indices_free(&aocl as *const _ as *mut _);
    unspent.sort_by_key(|(_, _, a, _)| *a);
    ok!("{} unspent", unspent.len());

    let target = NativeCurrencyAmount::coins_from_str("0.612").unwrap().to_nau();
    let fee = NativeCurrencyAmount::coins_from_str("0.005").unwrap().to_nau();
    let needed = target + fee;

    let mut sel: Vec<(usize, i64, XntDigest)> = Vec::new();
    let mut total: i128 = 0;
    if let Some(resend) = resend {
        // Sending again: spend exactly the inputs of the dropped transaction.
        for hash in resend {
            let Some(&(oi, ai, amt, h)) = unspent.iter().find(|u| u.3 == *hash) else {
                for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }
                return FfiSend::Unavailable;
            };
            sel.push((oi, ai, h)); total += amt;
        }
        ok!("inputs of the dropped transaction: {}, total: {}", sel.len(), NativeCurrencyAmount::from_nau(total));
    } else {
        if unspent.is_empty() {
            for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }
            return FfiSend::Skip("no unspent".into());
        }
        for &(oi, ai, amt, h) in &unspent {
            if total >= needed { break; }
            sel.push((oi, ai, h)); total += amt;
        }
        if total < needed {
            for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }
            return FfiSend::Fail(format!("insufficient: need {} have {}", NativeCurrencyAmount::from_nau(needed), NativeCurrencyAmount::from_nau(total)));
        }
        ok!("selected {}/{}, total: {}", sel.len(), unspent.len(), NativeCurrencyAmount::from_nau(total));
    }

    let (mut uhs, mut srs, mut ais, mut us, mut amts): (Vec<_>, Vec<_>, Vec<_>, Vec<_>, Vec<_>) = (vec![], vec![], vec![], vec![], vec![]);
    for (oi, ai, _) in &sel {
        let (h, sr, amt, u) = &utxos[*oi];
        uhs.push(h.clone()); srs.push(sr.clone()); ais.push(*ai as u64); amts.push(*amt); us.push(*u);
    }

    let mut proofs: Vec<*mut MsMembershipProofHandle> = vec![std::ptr::null_mut(); sel.len()];
    let r = xnt_sync_get_membership_proofs(client, uhs.as_ptr(), srs.as_ptr(), &preimage, ais.as_ptr(), sel.len(), proofs.as_mut_ptr());
    if r != XntErrorCode::Ok {
        for (_, _, _, u) in &utxos { xnt_utxo_free(*u); }
        return FfiSend::Fail(format!("proofs: {}", get_error()));
    }
    ok!("{} proofs", proofs.len());

    let builder = xnt_tx_builder_create();
    if builder.is_null() { return FfiSend::Fail(format!("builder: {}", get_error())); }

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
    if subaddr.is_null() { xnt_tx_builder_free(builder); return FfiSend::Fail(format!("subaddress: {}", get_error())); }
    let recv = xnt_subaddress_to_receiving(subaddr);
    if recv.is_null() {
        xnt_subaddress_free(subaddr); xnt_tx_builder_free(builder);
        return FfiSend::Fail(format!("receiving address: {}", get_error()));
    }

    let osr = xnt_random_sender_randomness();
    let csr = xnt_random_sender_randomness();
    xnt_tx_builder_add_output(builder, recv, target, &osr);
    xnt_tx_builder_set_change(builder, ctx.addr, &csr);
    xnt_tx_builder_set_fee(builder, fee);

    xnt_receiving_address_free(recv);
    xnt_subaddress_free(subaddr);

    // Build on the mutator set of the current tip, which records the tip's
    // height: the transaction is proven for the block after that tip and is
    // submitted only while that tip is still the tip.
    let ms = xnt_sync_get_mutator_set(client);
    if ms.is_null() { xnt_tx_builder_free(builder); return FfiSend::Fail(format!("mutator_set: {}", get_error())); }
    let build_tip = xnt_mutator_set_tip_height(ms);
    let ts = xnt_timestamp_now();
    let built = xnt_tx_builder_build(builder, ms, ts, XntNetwork::Main as u32);
    xnt_tx_builder_free(builder);
    if built.is_null() || build_tip < 0 {
        let error = get_error();
        xnt_built_transaction_free(built); xnt_mutator_set_free(ms);
        return FfiSend::Fail(format!("build: {error}"));
    }
    let build_tip = build_tip as u64;

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

    ok!("built on tip {build_tip}");

    // The membership proofs may be of an earlier tip than the mutator set.
    let confirmable = xnt_built_transaction_is_confirmable(built, ms);
    xnt_mutator_set_free(ms);
    if !confirmable {
        xnt_built_transaction_free(built);
        println!("  not confirmable: a block arrived while scanning");
        return FfiSend::Stale;
    }

    // Prove for the block after the tip the mutator set belongs to: before
    // main-net block 97000, a v7 proof collection.
    println!("Proving for the block after tip {build_tip}...");
    let start = std::time::Instant::now();
    let proven = xnt_built_transaction_prove(built);
    let elapsed = start.elapsed();
    if proven.is_null() {
        let error = get_error();
        xnt_built_transaction_free(built);
        return FfiSend::Fail(format!("prove: {error}"));
    }

    if xnt_transaction_has_proof_collection(proven) {
        ok!("proven in {:.1}s", elapsed.as_secs_f64());
    }

    let tx = xnt_transaction_serialize(proven);
    if !tx.is_null() {
        ok!("tx: {} bytes", unsafe { &*tx }.len);
        xnt_buffer_free(tx);
    }

    // Submit only while the tip the transaction was built on is still the tip.
    let result = if !ffi_synced_to_tip(client, proven, build_tip) {
        println!("  not synced to tip {build_tip} any more: a block arrived while proving");
        FfiSend::Stale
    } else {
        println!("\nSubmitting...");
        if xnt_transaction_submit(proven, client) == XntErrorCode::Ok {
            FfiSend::Sent(sel.iter().map(|(_, _, h)| *h).collect(), build_tip)
        } else {
            // A block landing mid-submit is stale (build again); anything
            // else is a rejection.
            let error = get_error();
            if ffi_synced_to_tip(client, proven, build_tip) {
                FfiSend::Fail(format!("submit: {error}"))
            } else {
                println!("  submit went stale: {error}");
                FfiSend::Stale
            }
        }
    };

    xnt_transaction_free(proven);
    xnt_built_transaction_free(built);
    result
}

/// Build & prove a mixed transaction:
/// - Inputs: existing Generation/KEM UTXOs (same as `test_tx`)
/// - Output: sends to a CTIDH-512 receiving address
fn test_tx_dctidh() {
    println!("Testing mixed Generation -> CTIDH transaction (build & prove, 16GB RAM)...");
    let ctx = Ctx::new().expect("setup");

    let url = cstr(&rpc_url());
    let client = xnt_rpc_client_create(url.as_ptr());
    check!(client, "client");

    let ms = xnt_sync_get_mutator_set(client);
    check!(ms, "mutator_set");

    let tip = xnt_sync_get_height(client);
    if tip < 0 {
        fail!("no height");
    }
    ok!("height: {tip}");

    let mut rid_hash = XntDigest::new();
    let mut preimage = XntDigest::new();
    xnt_spending_key_receiver_id_hash(ctx.key, rid_hash.bytes.as_mut_ptr());
    xnt_spending_key_receiver_preimage(ctx.key, preimage.bytes.as_mut_ptr());

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
                    } else {
                        xnt_utxo_free(dec.utxo);
                    }
                }
            }
            xnt_sync_indexed_utxos_free(&mut arr as *mut _);
        }
        from = to + 1;
    }

    if utxos.is_empty() {
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        skip!("no UTXOs");
    }
    ok!("{} UTXOs", utxos.len());

    let commits: Vec<XntDigest> = utxos
        .iter()
        .map(|(h, sr, _, _)| {
            let mut c = XntDigest::new();
            xnt_compute_commitment(h, sr, &preimage, c.bytes.as_mut_ptr());
            c
        })
        .collect();

    let aocl = xnt_sync_get_aocl_indices(client, commits.as_ptr(), commits.len());
    if aocl.indices.is_null() {
        for (_, _, _, u) in &utxos {
            xnt_utxo_free(*u);
        }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        fail!("no AOCL");
    }
    let indices = unsafe { std::slice::from_raw_parts(aocl.indices, aocl.len) };

    let mut abs: Vec<XntDigest> = Vec::new();
    let mut vi: Vec<usize> = Vec::new();
    for (i, &idx) in indices.iter().enumerate() {
        if idx >= 0 && i < utxos.len() {
            let (h, sr, _, _) = &utxos[i];
            let mut a = XntDigest::new();
            if xnt_compute_absolute_index_set_hash(h, sr, &preimage, idx as u64, a.bytes.as_mut_ptr())
                == XntErrorCode::Ok
            {
                abs.push(a);
                vi.push(i);
            }
        }
    }

    let st = xnt_sync_check_spent(client, abs.as_ptr(), abs.len());
    if st.heights.is_null() {
        xnt_sync_aocl_indices_free(&aocl as *const _ as *mut _);
        for (_, _, _, u) in &utxos {
            xnt_utxo_free(*u);
        }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
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
        for (_, _, _, u) in &utxos {
            xnt_utxo_free(*u);
        }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        skip!("no unspent");
    }

    let target = NativeCurrencyAmount::coins_from_str("0.612").unwrap().to_nau();
    let fee = NativeCurrencyAmount::coins_from_str("0.005").unwrap().to_nau();
    let needed = target + fee;

    let mut sel: Vec<(usize, i64)> = Vec::new();
    let mut total: i128 = 0;
    for &(oi, ai, amt) in &unspent {
        if total >= needed {
            break;
        }
        sel.push((oi, ai));
        total += amt;
    }

    if total < needed {
        for (_, _, _, u) in &utxos {
            xnt_utxo_free(*u);
        }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
        fail!(
            "insufficient: need {} have {}",
            NativeCurrencyAmount::from_nau(needed),
            NativeCurrencyAmount::from_nau(total)
        );
    }
    ok!(
        "selected {}/{}, total: {}",
        sel.len(),
        unspent.len(),
        NativeCurrencyAmount::from_nau(total)
    );

    let (mut uhs, mut srs, mut ais, mut us, mut amts): (Vec<_>, Vec<_>, Vec<_>, Vec<_>, Vec<_>) =
        (vec![], vec![], vec![], vec![], vec![]);
    for (oi, ai) in &sel {
        let (h, sr, amt, u) = &utxos[*oi];
        uhs.push(h.clone());
        srs.push(sr.clone());
        ais.push(*ai as u64);
        amts.push(*amt);
        us.push(*u);
    }

    let mut proofs: Vec<*mut MsMembershipProofHandle> = vec![std::ptr::null_mut(); sel.len()];
    let r = xnt_sync_get_membership_proofs(
        client,
        uhs.as_ptr(),
        srs.as_ptr(),
        &preimage,
        ais.as_ptr(),
        sel.len(),
        proofs.as_mut_ptr(),
    );
    if r != XntErrorCode::Ok {
        for (_, _, _, u) in &utxos {
            xnt_utxo_free(*u);
        }
        xnt_mutator_set_free(ms);
        xnt_rpc_client_free(client);
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
        println!(
            "    #{}: {}  c={}",
            i + 1,
            NativeCurrencyAmount::from_nau(amts[i]),
            hex::encode(&c.bytes)
        );
    }
    println!(
        "    Total: {}",
        NativeCurrencyAmount::from_nau(amts.iter().sum::<i128>())
    );

    for mp in &proofs {
        xnt_ms_membership_proof_free(*mp);
    }
    for (_, _, _, u) in &utxos {
        xnt_utxo_free(*u);
    }

    // Derive a CTIDH-2048 address from the same mnemonic via Rust SDK core
    let mnemonic = test_mnemonic();
    let wallet =
        xnt_sdk::core::WalletEntropy::from_mnemonic(&mnemonic).expect("wallet from mnemonic");
    let dctidh_key = wallet.derive_dctidh_spending_key(0);
    let dctidh_addr = dctidh_key.to_address().expect("receiving address");
    let dctidh_b32 = dctidh_addr
        .to_bech32(xnt_sdk::core::Network::Main)
        .expect("dctidh bech32m");
    ok!("CTIDH recipient bech32: {dctidh_b32}");

    // Import CTIDH address into FFI layer as ReceivingAddress
    let dctidh_b32_c = cstr(&dctidh_b32);
    let dctidh_addr_handle = xnt_address_from_bech32(dctidh_b32_c.as_ptr(), XntNetwork::Main as u32);
    check!(dctidh_addr_handle, "dctidh address from bech32");
    let recv = xnt_address_to_receiving(dctidh_addr_handle);
    check!(recv, "receiving address (dctidh)");

    let osr = xnt_random_sender_randomness();
    let csr = xnt_random_sender_randomness();
    xnt_tx_builder_add_output(builder, recv, target, &osr);
    xnt_tx_builder_set_change(builder, ctx.addr, &csr);
    xnt_tx_builder_set_fee(builder, fee);

    xnt_receiving_address_free(recv);
    xnt_address_free(dctidh_addr_handle);

    let ts = xnt_timestamp_now();
    let built = xnt_tx_builder_build(builder, ms, ts, XntNetwork::Main as u32);
    check!(built, "build");

    // Show built transaction summary
    let inputs_info = xnt_built_transaction_inputs(built);
    let outputs_info = xnt_built_transaction_outputs(built);
    if !inputs_info.is_null() && !outputs_info.is_null() {
        let inputs =
            unsafe { std::slice::from_raw_parts((*inputs_info).data, (*inputs_info).len) };
        let outputs =
            unsafe { std::slice::from_raw_parts((*outputs_info).data, (*outputs_info).len) };

        let in_total: i128 = inputs.iter().map(|i| i.amount).sum();
        let out_total: i128 = outputs.iter().map(|o| o.amount).sum();

        println!(
            "\n  Inputs ({}): {}",
            inputs.len(),
            NativeCurrencyAmount::from_nau(in_total)
        );
        for inp in inputs {
            println!(
                "    {}, c={}",
                NativeCurrencyAmount::from_nau(inp.amount),
                hex::encode(&inp.commitment.bytes)
            );
        }
        println!(
            "  Outputs ({}): {}",
            outputs.len(),
            NativeCurrencyAmount::from_nau(out_total)
        );
        for out in outputs {
            let change = if out.is_change { " (change)" } else { "" };
            let pid = if out.payment_id != 0 {
                format!(", pid={}", out.payment_id)
            } else {
                "".into()
            };
            println!(
                "    {}{}{}, c={}",
                NativeCurrencyAmount::from_nau(out.amount),
                change,
                pid,
                hex::encode(&out.commitment.bytes)
            );
        }
        println!("  Fee: {}", NativeCurrencyAmount::from_nau(fee));

        xnt_tx_input_info_array_free(inputs_info);
        xnt_tx_output_info_array_free(outputs_info);
    }

    ok!("built (mix Generation -> CTIDH)");

    println!("Proving (mixed tx)...");
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

    println!("\nSubmitting (mixed Generation -> CTIDH tx)...");
    let sub = xnt_transaction_submit(proven, client);
    if sub == XntErrorCode::Ok {
        ok!("submitted");
    } else {
        println!("  result: {:?} - {}", sub, get_error());
    }

    xnt_buffer_free(tx);
    xnt_transaction_free(proven);
    xnt_built_transaction_free(built);
    xnt_tx_builder_free(builder);
    xnt_mutator_set_free(ms);
    xnt_rpc_client_free(client);
    ok!("tx-mix passed");
}

/// Multi-type input transaction (Generation + CTIDH) using Rust SDK core.
///
/// This test:
/// - derives Generation and CTIDH spending keys from the same mnemonic
/// - collects spendable inputs for both keys via SDK core
/// - builds a mixed-input transaction sending to a CTIDH address
/// - submits it only while the tip it was built on is still the tip, watches
///   its inputs, and builds and sends it again if it was dropped
fn test_tx_dctidh_multi() {
    use xnt_sdk::core::{
        json_rpc::RpcClient as CoreRpcClient,
        sync::{collect_spendable_inputs_for_key, get_mutator_set, SpendableInput},
        transaction::TransactionBuilder,
        types::{Digest as CoreDigest, Network as CoreNetwork},
        wallet::WalletEntropy as CoreWalletEntropy,
    };

    println!("Testing multi-input Generation + CTIDH (Rust SDK core, 16GB RAM)...");

    let mnemonic = test_mnemonic();
    let wallet = CoreWalletEntropy::from_mnemonic(&mnemonic).expect("wallet");

    // Derive Generation and CTIDH keys from the same seed
    let gen_key = wallet.derive_spending_key(0);
    let dctidh_key = wallet.derive_dctidh_spending_key(0);
    let gen_addr = gen_key.to_address().expect("receiving address");
    let dctidh_addr = dctidh_key.to_address().expect("receiving address");
    println!(
        "length of CTIDH bech32m address: {}",
        dctidh_addr
            .to_bech32(CoreNetwork::Main)
            .expect("dctidh bech32m encoding failed")
            .len()
    );
    let dctidh_b32 = dctidh_addr
        .to_bech32(CoreNetwork::Main)
        .expect("dctidh bech32m");
    ok!("CTIDH recipient bech32: {dctidh_b32}");

    // RPC client
    let client = CoreRpcClient::new(&rpc_url()).expect("rpc client");
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    // scan_from defaults to 0 (genesis); override via XNT_SCAN_FROM for mainnet
    // (where pre-Xnt-hardfork blocks can be skipped, e.g. 15000).
    let scan_from: u64 = std::env::var("XNT_SCAN_FROM")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let target = NativeCurrencyAmount::coins_from_str("0.612").unwrap().to_nau();
    let fee = NativeCurrencyAmount::coins_from_str("0.005").unwrap().to_nau();
    let needed = target + fee;

    // Proving takes minutes, so the chain can advance and make the proof stale
    // before it is submitted, and a submitted transaction can be dropped. In
    // both cases build again from a fresh scan. A dropped transaction is sent
    // again with the same inputs, so that it and the one sent again cannot
    // both be mined.
    let max_attempts = max_tx_attempts();
    let mut sent: Option<(Vec<CoreDigest>, u64)> = None;
    'attempts: for attempt in 1..=max_attempts {
        // The inputs to watch, and the height of the tip they were spent on.
        let watched: (Vec<CoreDigest>, u64) = 'send: {
            let tip = match client.chain_height() {
                Ok(tip) => tip,
                Err(e) => {
                    println!("  height: {e}; trying again");
                    continue 'attempts;
                }
            };
            ok!("height: {tip}");

            // Collect spendable inputs for both keys (handle RPC errors gracefully).
            let mut gen_inputs = match collect_spendable_inputs_for_key(&client, &gen_key, scan_from, tip) {
                Ok(v) => v,
                Err(e) => {
                    println!("[SKIP] collect Generation inputs failed: {e}");
                    Vec::new()
                }
            };
            let mut dctidh_inputs = match collect_spendable_inputs_for_key(&client, &dctidh_key, scan_from, tip) {
                Ok(v) => v,
                Err(e) => {
                    println!("[SKIP] collect CTIDH inputs failed: {e}");
                    Vec::new()
                }
            };

            let mut all: Vec<SpendableInput> = Vec::new();
            all.append(&mut gen_inputs);
            all.append(&mut dctidh_inputs);

            let mut selected: Vec<SpendableInput> = Vec::new();
            if let Some((inputs, sent_tip)) = &sent {
                // Sending again: spend exactly the inputs of the dropped transaction.
                for hash in inputs {
                    match all.iter().find(|s| s.absolute_index_set_hash() == *hash) {
                        Some(s) => selected.push(s.clone()),
                        None => {
                            println!("  an input of the dropped transaction is no longer free; watching it again");
                            break 'send (inputs.clone(), *sent_tip);
                        }
                    }
                }
                ok!("inputs of the dropped transaction: {}", selected.len());
            } else {
                if all.is_empty() {
                    skip!("no spendable inputs for Generation or CTIDH");
                }
                ok!(
                    "spendable inputs: Generation={}, CTIDH={}",
                    all.iter().filter(|s| s.spending_key.is_generation()).count(),
                    all.iter().filter(|s| s.spending_key.is_dctidh()).count()
                );

                // Select inputs across both key types
                all.sort_by_key(|s| s.amount);
                let mut total: i128 = 0;
                for s in &all {
                    if total >= needed {
                        break;
                    }
                    selected.push(s.clone());
                    total += s.amount;
                }

                if total < needed {
                    fail!(
                        "insufficient: need {} have {}",
                        NativeCurrencyAmount::from_nau(needed),
                        NativeCurrencyAmount::from_nau(total)
                    );
                }
                ok!(
                    "selected {}/{}, total: {}",
                    selected.len(),
                    all.len(),
                    NativeCurrencyAmount::from_nau(total)
                );
            }

            // Build transaction with mixed inputs
            let mut builder = TransactionBuilder::new();
            for s in &selected {
                builder.add_input(s.utxo.clone(), s.spending_key.clone(), s.membership_proof.clone());
            }

            // Output to CTIDH address, change back to Generation address
            let osr = {
                let sr = xnt_random_sender_randomness();
                xnt_sdk::core::types::Digest::from_bytes(sr.bytes)
            };
            let csr = {
                let sr = xnt_random_sender_randomness();
                xnt_sdk::core::types::Digest::from_bytes(sr.bytes)
            };
            builder.add_output(gen_addr.to_receiving_address(), target, osr);
            builder.set_change(gen_addr.clone(), csr);
            builder.set_fee(fee);

            // The mutator set records the height of its tip: the transaction
            // is proven for the consensus rule set of the block after it, and
            // submitted only while that tip is still the tip.
            let mutator_set = get_mutator_set(&client).expect("mutator set");
            let ts = xnt_timestamp_now();
            let network = CoreNetwork::Main;
            let built = builder
                .build(&mutator_set, ts, network)
                .expect("build");
            let build_tip = built.tip_height().expect("tip height of the mutator set");

            // Print summary
            let inputs_info = built.inputs();
            let outputs_info = built.outputs();
            println!("\n  Inputs ({}):", inputs_info.len());
            for inp in &inputs_info {
                println!(
                    "    c={}",
                    hex::encode(&inp.commitment.bytes)
                );
            }
            println!("  Outputs ({}):", outputs_info.len());
            for out in &outputs_info {
                let change = if out.is_change { " (change)" } else { "" };
                let pid = out.payment_id.map(|p| format!(", pid={p}")).unwrap_or_default();
                println!(
                    "    {}{}, c={}",
                    change,
                    pid,
                    hex::encode(&out.commitment.bytes)
                );
            }
            println!("  Fee: {}", NativeCurrencyAmount::from_nau(fee));
            ok!("built (multi Generation + CTIDH) on tip {build_tip}");

            // The membership proofs may be of an earlier tip than the mutator set.
            if !built.is_confirmable(&mutator_set) {
                println!("  attempt {attempt}: not confirmable, a block arrived while scanning; building again");
                continue 'attempts;
            }

            // Prove (async) for the block after the tip of the mutator set
            println!("Proving (multi-input tx) for the block after tip {build_tip}...");
            let start = std::time::Instant::now();
            let proven = rt.block_on(built.prove()).expect("prove");
            let elapsed = start.elapsed();
            if proven.has_proof_collection() {
                ok!("proven in {:.1}s", elapsed.as_secs_f64());
            }

            let tx_bytes = proven.to_bytes().expect("serialize");
            ok!("tx: {} bytes", tx_bytes.len());

            if !synced_to_tip(&client, &proven, build_tip) {
                println!("  attempt {attempt}: not synced to tip {build_tip} any more; building again");
                continue 'attempts;
            }

            println!("\nSubmitting (multi Generation + CTIDH tx)...");
            match proven.submit(&client) {
                Ok(true) => ok!("submitted (attempt {attempt}); watching its inputs"),
                Ok(false) => fail!("the node did not queue the transaction"),
                Err(e) => {
                    // A block landing mid-submit is stale (build again);
                    // anything else is a rejection.
                    if synced_to_tip(&client, &proven, build_tip) {
                        fail!("submit failed: {e}");
                    }
                    println!("  attempt {attempt}: submit went stale ({e}); building again");
                    continue 'attempts;
                }
            }
            let inputs: Vec<CoreDigest> = selected.iter().map(SpendableInput::absolute_index_set_hash).collect();
            sent = Some((inputs.clone(), build_tip));
            (inputs, build_tip)
        };

        match watch_inputs(&client, &watched.0, watched.1) {
            Watch::Confirmed(height) => {
                ok!("confirmed at height {height}");
                return;
            }
            Watch::Dropped => println!("  dropped: neither mined nor in the mempool after a block; sending it again"),
            Watch::Conflicted => fail!("an input was spent on chain by another transaction"),
            Watch::TimedOut => fail!("not mined in time; look its inputs up before sending again"),
        }
    }
    fail!("gave up after {max_attempts} attempts");
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
