//! Deterministic secret-key sampler for dCTIDH-512.
//!
//! The group action of the C library (`action` in `csidh.c`) expects private
//! keys whose exponents, per batch of the 512-bit parameter set, have an L1
//! norm of at most `primes_batchbound[b]`, as produced by the library's own key
//! generator (`csidh_private`, which calls `random_boundedl1` once per batch).
//!
//! This module derives such keys from a wallet seed. It runs the library's
//! `random_boundedl1` sampler step for step, with its randomness read from a
//! SHAKE256 XOF over the seed and a domain instead of the system random number
//! generator, so the same seed and domain always give the same key.
//!
//! Byte layout matches the C FFI: the secret key is the 74 signed exponents
//! `e[0..74]` in prime order, one `int8_t` per byte (two's complement), which
//! is exactly what `secsidh_oct2sk` / `action` read.

use sha3::digest::ExtendableOutput;
use sha3::digest::Update;
use sha3::digest::XofReader;
use sha3::Shake256;

use dctidh512::SecretKey;

/// `primes_batchsize` for the 512-bit parameter set (see `primes512.c`).
const BATCH_SIZE: [usize; 14] = [2, 3, 4, 4, 5, 5, 6, 7, 7, 8, 8, 6, 8, 1];

/// `primes_batchbound` for the 512-bit parameter set (see `primes512.c`).
const BATCH_BOUND: [usize; 14] = [10, 14, 16, 17, 17, 17, 18, 18, 18, 18, 18, 13, 13, 1];

/// The batch sizes must cover exactly the 74 private exponents.
const _: () = {
    let mut sum = 0usize;
    let mut i = 0usize;
    while i < BATCH_SIZE.len() {
        sum += BATCH_SIZE[i];
        i += 1;
    }
    assert!(
        sum == 74,
        "batch sizes must sum to the 74-exponent private key"
    );
    assert!(core::mem::size_of::<SecretKey>() == 74);
};

/// Whether the exponents of `secret_key` stay, per batch, within the L1 bound
/// that the group action expects.
pub(super) fn is_within_batch_bounds(secret_key: &SecretKey) -> bool {
    let mut pos = 0usize;
    BATCH_SIZE.iter().zip(BATCH_BOUND).all(|(&size, bound)| {
        let l1: usize = secret_key[pos..pos + size]
            .iter()
            .map(|&byte| usize::from((byte as i8).unsigned_abs()))
            .sum();
        pos += size;
        l1 <= bound
    })
}

/// Derive a dCTIDH-512 secret key from `seed_bytes`, domain-separated by
/// `domain`, using the library's bounded-L1 sampler over a SHAKE256 XOF.
///
/// The keys follow the distribution of the library's own key generator.
pub(super) fn secret_key_from_seed(seed_bytes: &[u8], domain: &[u8]) -> SecretKey {
    let mut hasher = Shake256::default();
    hasher.update(seed_bytes);
    hasher.update(domain);
    let mut reader = hasher.finalize_xof();

    let mut e = [0i8; 74];
    let mut pos = 0usize;
    for b in 0..BATCH_SIZE.len() {
        let w = BATCH_SIZE[b];
        random_bounded_l1(&mut reader, &mut e[pos..pos + w], w, BATCH_BOUND[b]);
        pos += w;
    }

    let mut sk = [0u8; 74];
    for i in 0..74 {
        sk[i] = e[i] as u8;
    }
    sk
}

/// Read the next little-endian `i32` from the XOF stream.
///
/// Matches the C library reading 4 bytes into an `int32_t` on a little-endian
/// target (the only targets this crate builds for).
#[inline]
fn next_i32(reader: &mut impl XofReader) -> i32 {
    let mut b = [0u8; 4];
    reader.read(&mut b);
    i32::from_le_bytes(b)
}

/// `-1` if `x == 0`, else `0`.
#[inline]
fn mask_zero(x: i32) -> i32 {
    -((x == 0) as i32)
}

/// `-1` if `x == y`, else `0`.
#[inline]
fn mask_equal(x: i32, y: i32) -> i32 {
    -((x == y) as i32)
}

/// `-1` if `x < 0`, else `0`.
#[inline]
fn mask_negative(x: i32) -> i32 {
    x >> 31
}

/// Faithful port of `random_boundedl1` from the dCTIDH C library
/// (`common/random.c`), driven by a XOF instead of `randombytes`.
///
/// Fills `e[0..w]` with signed exponents whose absolute values sum to at most
/// `s`, uniformly over that bounded-L1 ball. Requires `w == e.len()`,
/// `w < 128`, `s < 128`, and `s + w <= 254`.
fn random_bounded_l1(reader: &mut impl XofReader, e: &mut [i8], w: usize, s: usize) {
    debug_assert_eq!(e.len(), w);
    debug_assert!(w < 128 && s < 128);
    if w == 0 {
        return;
    }
    let rnum = s + w;
    debug_assert!(rnum <= 254);

    let mut r = [0i32; 254];
    loop {
        for j in 0..rnum {
            r[j] = next_i32(reader);
        }
        // correspondence trick: clear low bit everywhere, set it on the first w
        for j in 0..rnum {
            r[j] &= !1;
        }
        for j in 0..w {
            r[j] |= 1;
        }
        r[..rnum].sort_unstable();

        // reject if two selected (odd) values share their high bits
        let mut repeated = 0i32;
        for j in 1..w {
            repeated |= mask_zero((r[j] ^ r[j - 1]) & !1);
        }
        if repeated != 0 {
            continue;
        }

        // r becomes a 0/1 vector of Hamming weight w, then its prefix sums
        for j in 0..rnum {
            r[j] &= 1;
        }
        for j in 1..rnum {
            r[j] += r[j - 1];
        }

        // e[i] = (number of positions whose prefix sum equals i)
        for i in 0..w {
            let mut numi = 0i32;
            for j in 0..rnum {
                numi -= mask_equal(r[j], i as i32);
            }
            e[i] = numi as i8;
        }
        for i in 1..w {
            e[i] -= 1;
        }
        // now e[i] >= 0 and sum(e) <= s

        // allow negative exponents without over-weighting zeros:
        // keep this sample with probability 2^zmin / 2^z
        let mut counter: i32 = w as i32 - s as i32;
        let words = (w + 31) / 32;
        for j in 0..words {
            r[j] = next_i32(reader);
        }
        let mut reject = 0i32;
        for i in 0..w {
            let rbit = 1 & (r[i / 32] >> (i & 31));
            let eizero = mask_zero(e[i] as i32);
            counter += eizero;
            reject |= mask_negative(counter) & eizero & rbit;
        }
        if reject != 0 {
            continue;
        }

        // apply the sign bits (branchless conditional negation)
        for i in 0..w {
            let rbit = 1 & (r[i / 32] >> (i & 31));
            let v = (e[i] as i32) ^ (-rbit);
            e[i] = (v + rbit) as i8;
        }
        return;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Re-split a secret key into per-batch signed exponents.
    fn exponents(sk: &SecretKey) -> Vec<i8> {
        sk.iter().map(|&b| b as i8).collect()
    }

    /// The core precondition: every batch's L1 norm is within its bound.
    fn assert_within_bounds(sk: &SecretKey) {
        assert!(is_within_batch_bounds(sk));
        let e = exponents(sk);
        let mut pos = 0usize;
        for b in 0..BATCH_SIZE.len() {
            let w = BATCH_SIZE[b];
            let l1: i64 = e[pos..pos + w].iter().map(|&x| (x as i64).abs()).sum();
            assert!(
                l1 <= BATCH_BOUND[b] as i64,
                "batch {b}: L1 norm {l1} exceeds bound {}",
                BATCH_BOUND[b]
            );
            pos += w;
        }
        assert_eq!(pos, 74);
    }

    #[test]
    fn sampled_keys_satisfy_the_batch_bounds() {
        for seed in 0u64..512 {
            let sk = secret_key_from_seed(&seed.to_le_bytes(), b"test_sk");
            assert_within_bounds(&sk);
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = secret_key_from_seed(&[1, 2, 3, 4], b"dctidh512_sk");
        let b = secret_key_from_seed(&[1, 2, 3, 4], b"dctidh512_sk");
        assert_eq!(a, b);
    }

    #[test]
    fn domain_separation_changes_the_key() {
        let a = secret_key_from_seed(&[1, 2, 3, 4], b"dctidh512_sk");
        let b = secret_key_from_seed(&[1, 2, 3, 4], b"dctidh512_eph_sk");
        assert_ne!(a, b);
    }

    #[test]
    fn keys_beyond_a_batch_bound_are_recognized() {
        let mut sk = secret_key_from_seed(&[9, 9, 9], b"test_sk");
        assert!(is_within_batch_bounds(&sk));

        // the first batch holds the first two exponents, with bound 10
        sk[0] = 6;
        sk[1] = (-5i8) as u8;
        assert!(!is_within_batch_bounds(&sk));
        sk[1] = (-4i8) as u8;
        assert!(is_within_batch_bounds(&sk));

        assert!(!is_within_batch_bounds(&[7u8; 74]));
        assert!(is_within_batch_bounds(&[0u8; 74]));
    }

    #[test]
    fn distinct_seeds_give_distinct_keys() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for seed in 0u64..2000 {
            let sk = secret_key_from_seed(&seed.to_le_bytes(), b"dctidh512_sk");
            seen.insert(sk);
        }
        assert_eq!(seen.len(), 2000, "sampled keys are not all distinct");
    }
}
