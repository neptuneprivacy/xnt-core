//! Measure Triton VM execution for hash operations.
//!
//! Usage: cargo test -p neptune-privacy --test tasm_exit_tree_trace -- --nocapture

use tasm_lib::triton_vm::isa::instruction::{AnInstruction, LabelledInstruction};
use tasm_lib::triton_vm::isa::op_stack::{NumberOfWords, OpStackElement};
use tasm_lib::triton_vm::isa::program::Program;
use tasm_lib::triton_vm::prelude::*;

fn i(a: AnInstruction<String>) -> LabelledInstruction {
    LabelledInstruction::Instruction(a)
}
fn lbl(name: &str) -> LabelledInstruction {
    LabelledInstruction::Label(name.to_string())
}

fn build_program() -> Program {
    let mut c = Vec::new();

    // read count from stdin
    c.push(i(AnInstruction::ReadIo(NumberOfWords::N1)));
    // _ count

    // push idx = 0
    c.push(i(AnInstruction::Push(BFieldElement::new(0))));
    // _ count idx

    c.push(i(AnInstruction::Call("loop".into())));

    c.push(i(AnInstruction::Pop(NumberOfWords::N1)));
    c.push(i(AnInstruction::Pop(NumberOfWords::N1)));
    c.push(i(AnInstruction::Halt));

    c.push(lbl("loop"));

    // check count == idx → return if equal
    c.push(i(AnInstruction::Dup(OpStackElement::ST1)));
    c.push(i(AnInstruction::Dup(OpStackElement::ST1)));
    c.push(i(AnInstruction::Eq));
    c.push(i(AnInstruction::Skiz));
    c.push(i(AnInstruction::Return));

    // push 10 zeros, hash → simulates one merge
    for _ in 0..10 {
        c.push(i(AnInstruction::Push(BFieldElement::new(0))));
    }
    c.push(i(AnInstruction::Hash));
    // hash consumes 10, produces 5
    c.push(i(AnInstruction::Pop(NumberOfWords::N5)));

    // idx += 1
    c.push(i(AnInstruction::Push(BFieldElement::new(1))));
    c.push(i(AnInstruction::Add));

    c.push(i(AnInstruction::Recurse));

    Program::new(&c)
}

fn measure(label: &str, n: usize) {
    let program = build_program();
    let stdin = PublicInput::new(vec![BFieldElement::new(n as u64)]);
    let nd = NonDeterminism::default();

    let start = std::time::Instant::now();
    match VM::trace_execution(program, stdin, nd) {
        Ok((trace, _)) => {
            let elapsed = start.elapsed();
            let rows = trace.processor_trace.nrows();
            let padded = rows.next_power_of_two();
            let log2 = (padded as f64).log2() as u32;
            println!("{label}: n={n}, trace={rows}, padded=2^{log2}, time={elapsed:?}");
        }
        Err(e) => {
            println!("{label}: n={n}, error={e}");
        }
    }
}

#[test]
fn trace_sizes() {
    println!("\n=== Triton VM Hash Bench ===");
    measure("10", 10);
    measure("100", 100);
    measure("2047", 2047);
    measure("65536", 65536);
}
