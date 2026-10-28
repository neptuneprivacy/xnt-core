//! Simulate the ProofCollection → SingleProof flow for 30k Tip5 hashes.
//!
//! Step 1 (ProofCollection): Prove a program that does 30k Tip5 hashes
//! Step 2 (SingleProof):     Build an outer program that stark_verify's that proof,
//!                            then prove and verify the outer program
//!
//! This demonstrates the actual cost of adding 30k Tip5 hash verification
//! to a SingleProof via the ProofCollection path.
//!
//! Run with: cargo test -p neptune-privacy --test tip5_30k_proof_test -- --nocapture

use std::time::Instant;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::verifier::stark_verify::StarkVerify;

fn insert_claim_into_static_memory(
    ram: &mut std::collections::HashMap<BFieldElement, BFieldElement>,
    claim: &Claim,
) -> BFieldElement {
    let claim_encoded = claim.encode();
    let claim_size = claim_encoded.len();
    let claim_pointer = -BFieldElement::new(claim_size as u64 + 1);
    encode_to_memory(ram, claim_pointer, claim);
    claim_pointer
}

/// Build a program that performs `n` Tip5 hashes and halts.
fn build_tip5_hash_program(n: usize) -> Program {
    let mut instructions = vec![];
    for i in 0..n {
        instructions.extend(triton_asm!(
            push {i} push 1 push 2 push 3 push 4
            push 0 push 0 push 0 push 0 push 0
            hash
            pop 5
        ));
    }
    instructions.extend(triton_asm!(halt));
    Program::new(&instructions)
}

/// Step 1: Prove the inner program (simulates ProofCollection proving a component)
fn prove_inner(program: Program) -> (Claim, Proof, usize) {
    let claim = Claim::about_program(&program);
    let (aet, output) =
        VM::trace_execution(program, PublicInput::default(), NonDeterminism::default()).unwrap();
    let claim = claim.with_output(output);
    let cycles = aet.processor_trace.nrows();

    let stark = Stark::default();
    let proof = stark.prove(&claim, &aet).unwrap();
    (claim, proof, cycles)
}

/// Step 2: Build an outer verifier program that stark_verify's the inner proof
/// (simulates what SingleProof does for each ProofCollection component)
fn build_outer_verifier(claim: &Claim, proof: &Proof) -> (Program, NonDeterminism) {
    let stark = Stark::default();
    let snippet = StarkVerify::new_with_dynamic_layout(stark);

    let mut nondeterminism = NonDeterminism::default();

    // Write proof to nondeterministic memory
    encode_to_memory(
        &mut nondeterminism.ram,
        FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
        proof,
    );

    // Extract authentication path digests
    snippet.update_nondeterminism(&mut nondeterminism, proof, claim);

    // Write claim to static memory
    let claim_pointer = insert_claim_into_static_memory(&mut nondeterminism.ram, claim);

    let proof_pointer = BFieldElement::new(0);

    // Build verifier program
    let mut library = tasm_lib::library::Library::new();
    let entrypoint = library.import(Box::new(snippet));
    let library_code = library.all_imports();

    let code: Vec<LabelledInstruction> = triton_asm!(
        push {claim_pointer}
        push {proof_pointer}
        call {entrypoint}
        halt
        {&library_code}
    );

    (Program::new(&code), nondeterminism)
}

#[test]
fn simulate_single_proof_with_30k_tip5_hashes() {
    println!("\n======================================================================");
    println!("=== ProofCollection → SingleProof: 30k Tip5 Hashes ===");
    println!("======================================================================\n");

    // ── Step 1: ProofCollection ──
    // Prove the 30k Tip5 hash program (like bridge_announcement_validator)
    println!("--- Step 1: ProofCollection (prove 30k Tip5 hashes) ---\n");

    let t0 = Instant::now();
    let inner_program = build_tip5_hash_program(30_000);
    println!("  Program build:     {:?}", t0.elapsed());

    let t1 = Instant::now();
    let (inner_claim, inner_proof, inner_cycles) = prove_inner(inner_program);
    let inner_prove_time = t1.elapsed();

    println!("  Inner cycles:      {inner_cycles}");
    println!("  Inner padded:      {}", inner_cycles.next_power_of_two());
    println!("  Inner proof size:  {} BFEs", inner_proof.encode().len());
    println!("  Inner prove time:  {inner_prove_time:?}");

    // Verify inner proof standalone
    let t2 = Instant::now();
    assert!(tasm_lib::triton_vm::verify(
        Stark::default(),
        &inner_claim,
        &inner_proof
    ));
    println!("  Inner verify time: {:?}", t2.elapsed());

    // ── Step 2: SingleProof ──
    // Build outer program that stark_verify's the inner proof
    // This simulates what SingleProof does for each ProofCollection component
    println!("\n--- Step 2: SingleProof (stark_verify the inner proof) ---\n");

    let (outer_program, outer_nd) = build_outer_verifier(&inner_claim, &inner_proof);

    // First just measure cycle count (fast)
    let t3 = Instant::now();
    let mut vm_state = VMState::new(
        outer_program.clone(),
        PublicInput::default(),
        outer_nd.clone(),
    );
    vm_state.run().unwrap();
    let outer_cycles = vm_state.cycle_count as usize;
    println!("  Outer cycles:      {outer_cycles}");
    println!("  Outer padded:      {}", outer_cycles.next_power_of_two());
    println!("  Outer exec time:   {:?}", t3.elapsed());

    // Now prove the outer program (the actual SingleProof proving step)
    let t4 = Instant::now();
    let outer_claim = Claim::about_program(&outer_program);
    let (outer_aet, outer_output) =
        VM::trace_execution(outer_program, PublicInput::default(), outer_nd).unwrap();
    let outer_claim = outer_claim.with_output(outer_output);
    println!("  Outer trace time:  {:?}", t4.elapsed());

    let t5 = Instant::now();
    let outer_proof = Stark::default().prove(&outer_claim, &outer_aet).unwrap();
    let outer_prove_time = t5.elapsed();
    println!("  Outer proof size:  {} BFEs", outer_proof.encode().len());
    println!("  Outer prove time:  {outer_prove_time:?}");

    // Verify the outer proof
    let t6 = Instant::now();
    let valid = tasm_lib::triton_vm::verify(Stark::default(), &outer_claim, &outer_proof);
    let outer_verify_time = t6.elapsed();
    println!("  Outer verify time: {outer_verify_time:?}");
    println!("  Valid:             {valid}");
    assert!(valid, "SingleProof must verify!");

    // ── Summary ──
    println!("\n======================================================================");
    println!("=== Summary ===\n");
    println!("  Inner (30k hashes):  {inner_cycles} cycles, proved in {inner_prove_time:?}");
    println!("  Outer (stark_verify): {outer_cycles} cycles, proved in {outer_prove_time:?}");
    println!("  Outer verify:        {outer_verify_time:?}");
    println!("  Total wall time:     {:?}", t0.elapsed());
}

/// Compare: how does the outer stark_verify cost change with different inner program sizes?
#[test]
fn compare_inner_sizes_stark_verify_cost() {
    println!("\n=== stark_verify Cost vs Inner Hash Count ===\n");
    println!(
        "{:<12} {:>12} {:>12} {:>15} {:>15}",
        "Hashes", "Inner cyc", "Proof BFEs", "Outer cyc", "Outer padded"
    );
    println!("{}", "-".repeat(70));

    for &count in &[100, 1_000, 10_000, 30_000] {
        let program = build_tip5_hash_program(count);
        let (claim, proof, inner_cycles) = prove_inner(program);

        let proof_size = proof.encode().len();

        let (outer_program, outer_nd) = build_outer_verifier(&claim, &proof);
        let mut vm_state = VMState::new(outer_program, PublicInput::default(), outer_nd);
        vm_state.run().unwrap();
        let outer_cycles = vm_state.cycle_count as usize;
        let outer_padded = outer_cycles.next_power_of_two();

        println!(
            "{:<12} {:>12} {:>12} {:>15} {:>15}",
            count, inner_cycles, proof_size, outer_cycles, outer_padded
        );
    }
}
