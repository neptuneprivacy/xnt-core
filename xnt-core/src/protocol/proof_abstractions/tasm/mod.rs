pub mod builtins;
mod environment;
pub mod program;
pub mod prover_job;

use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::isa::triton_instr;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

/// Push `digest` as five `push` instructions in **reverse** value order, so that
/// `digest.values()[0]` ends on the stack top — matching how `read_mem 5` reads
/// a digest back from memory and what `eq_digest` expects on the stack.
///
/// The reversal is load-bearing: pushing forward silently produces a digest that
/// compares unequal, turning any downstream `eq_digest` match into a no-op.
pub(crate) fn push_digest_reversed(digest: Digest) -> Vec<LabelledInstruction> {
    digest
        .values()
        .iter()
        .rev()
        .map(|v| triton_instr!(push v.value()))
        .collect_vec()
}
