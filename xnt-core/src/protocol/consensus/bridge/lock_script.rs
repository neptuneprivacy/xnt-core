//! Bridge lock script for Leviathan-backed UTXOs.
//!
//! [`bridge_lock_script`]: Never spendable. Used for bridge pool UTXOs —
//! permanently locked, only consensus can create unlock outputs.

use tasm_lib::triton_vm::prelude::*;

use crate::protocol::consensus::transaction::lock_script::LockScript;

/// Lock script that can never be spent. Used for bridge pool UTXOs.
///
/// Pool UTXOs are permanently locked — no one can spend them.
/// When an aggregated proof is finalized, consensus auto-creates unlock
/// outputs (like coinbase). No spending key exists.
pub fn bridge_lock_script() -> LockScript {
    LockScript::from(triton_asm!(
        push 0 assert
        halt
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;

    fn random_public_input() -> PublicInput {
        PublicInput::new(vec![
            BFieldElement::new(1),
            BFieldElement::new(2),
            BFieldElement::new(3),
            BFieldElement::new(4),
            BFieldElement::new(5),
        ])
    }

    #[test]
    fn bridge_lock_always_crashes() {
        let lock = bridge_lock_script();
        let lsaw = LockScriptAndWitness::new(lock.program);
        assert!(
            !lsaw.halts_gracefully(random_public_input()),
            "Bridge lock should never halt"
        );
    }
}
