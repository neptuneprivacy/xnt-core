//! Benchmark: Tip5 merge operations simulating worst-case exit tree.
//!
//! Simulates: 2048 L0 pairs × 20 burns each = 40960 burns
//! Per pair: 32 leaves (padded) → 31 merges
//! Hierarchy: 2047 merges (L1-L10 + aggregation)
//! Total: ~65535 merges
//!
//! Usage: cargo test -p neptune-privacy --test tip5_merge_bench -- --nocapture

use std::time::Instant;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;

#[test]
fn tip5_merge_worst_case_epoch() {
    let num_pairs: usize = 2048;
    let burns_per_pair: usize = 20;
    let total_burns = num_pairs * burns_per_pair;

    println!("=== Worst-case exit tree benchmark ===");
    println!("L0 pairs: {num_pairs}");
    println!("Burns per pair: {burns_per_pair}");
    println!("Total burns: {total_burns}");

    let start = Instant::now();
    let mut total_merges = 0usize;
    let mut total_hashes = 0usize;

    // Phase 1: Compute L0 exit_roots from burns
    let mut l0_exit_roots = Vec::with_capacity(num_pairs);

    for pair_idx in 0..num_pairs {
        // Hash burns into leaves
        let mut leaves: Vec<Digest> = (0..burns_per_pair)
            .map(|burn_idx| {
                let seed = (pair_idx * 100 + burn_idx) as u64;
                let mut elems = Vec::with_capacity(11);
                // rd(5) + lsh(5) + amount(1) = 11
                for i in 0..11 {
                    elems.push(BFieldElement::new(seed + i as u64));
                }
                total_hashes += 1;
                Tip5::hash_varlen(&elems)
            })
            .collect();

        // Pad to next power of 2 (min 2)
        let mut n = 2;
        while n < leaves.len() {
            n *= 2;
        }
        leaves.resize(n, Digest::default());

        // Build per-pair tree
        while leaves.len() > 1 {
            let mut next = Vec::with_capacity(leaves.len() / 2);
            for pair in leaves.chunks(2) {
                next.push(Tip5::hash_pair(pair[0], pair[1]));
                total_merges += 1;
            }
            leaves = next;
        }

        l0_exit_roots.push(leaves[0]);
    }

    let phase1_time = start.elapsed();
    println!("\nPhase 1 (L0 exit_roots from burns):");
    println!("  Leaf hashes: {total_hashes}");
    println!("  Per-pair merges: {total_merges}");
    println!("  Time: {:?}", phase1_time);

    // Phase 2: Merge L0 exit_roots up hierarchy (L1 → L10 → aggregation)
    let phase2_start = Instant::now();
    let mut level_roots = l0_exit_roots;
    let mut level = 1u32;
    let mut hierarchy_merges = 0usize;

    while level_roots.len() > 1 {
        let mut next = Vec::with_capacity(level_roots.len() / 2);
        for pair in level_roots.chunks(2) {
            next.push(Tip5::hash_pair(pair[0], pair[1]));
            hierarchy_merges += 1;
        }
        level_roots = next;
        level += 1;
    }

    let phase2_time = phase2_start.elapsed();
    let root = level_roots[0];

    println!("\nPhase 2 (hierarchy merges L1-L{}):", level - 1);
    println!("  Hierarchy merges: {hierarchy_merges}");
    println!("  Time: {:?}", phase2_time);

    total_merges += hierarchy_merges;
    let total_time = start.elapsed();

    println!("\n=== Totals ===");
    println!("Total leaf hashes: {total_hashes}");
    println!("Total merges: {total_merges}");
    println!("Total time: {:?}", total_time);
    println!("Per merge: {:?}", total_time / total_merges as u32);
    println!("Root: {:?}", root);
}

#[test]
fn tip5_merge_typical_epoch() {
    // Typical: 10 burns in 3 pairs out of 2048
    let num_pairs: usize = 2048;

    println!("=== Typical epoch benchmark ===");

    let start = Instant::now();
    let mut total_merges = 0usize;

    // Phase 1: only 3 pairs have burns
    let mut l0_exit_roots: Vec<Digest> = vec![Digest::default(); num_pairs];

    for &(pair_idx, burn_count) in &[(42usize, 3usize), (500, 4), (1999, 3)] {
        let mut leaves: Vec<Digest> = (0..burn_count)
            .map(|i| {
                let mut elems = Vec::with_capacity(11);
                for j in 0..11 {
                    elems.push(BFieldElement::new((pair_idx * 100 + i * 11 + j) as u64));
                }
                Tip5::hash_varlen(&elems)
            })
            .collect();

        let mut n = 2;
        while n < leaves.len() {
            n *= 2;
        }
        leaves.resize(n, Digest::default());

        while leaves.len() > 1 {
            let mut next = Vec::with_capacity(leaves.len() / 2);
            for pair in leaves.chunks(2) {
                next.push(Tip5::hash_pair(pair[0], pair[1]));
                total_merges += 1;
            }
            leaves = next;
        }

        l0_exit_roots[pair_idx] = leaves[0];
    }

    // Phase 2: merge all 2048
    let mut level_roots = l0_exit_roots;
    while level_roots.len() > 1 {
        let mut next = Vec::with_capacity(level_roots.len() / 2);
        for pair in level_roots.chunks(2) {
            next.push(Tip5::hash_pair(pair[0], pair[1]));
            total_merges += 1;
        }
        level_roots = next;
    }

    let total_time = start.elapsed();
    println!("Burns: 10 across 3 pairs");
    println!("Total merges: {total_merges}");
    println!("Total time: {:?}", total_time);
    println!("Root: {:?}", level_roots[0]);
}
