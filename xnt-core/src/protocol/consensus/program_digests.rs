use strum::IntoEnumIterator;

use crate::protocol::consensus::block::validity::block_program::BlockProgram;
use crate::protocol::consensus::chaintx::link_proof::LeviathanLinkProof;
use crate::protocol::consensus::chaintx::link_proof::LinkProof;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScripts;
use crate::protocol::consensus::transaction::validity::collect_type_scripts::CollectTypeScripts;
use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
use crate::protocol::consensus::transaction::validity::kernel_to_outputs::KernelToOutputs;
use crate::protocol::consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
use crate::protocol::consensus::transaction::validity::single_proof_v2::single_proof_program_digest;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

/// Prints every consensus program digest, per era where a program has one, to
/// diff this tree against upstream's.
#[test]
#[ignore = "prints digests to compare trees"]
fn print_consensus_program_digests() {
    for era in ConsensusRuleSet::iter() {
        println!(
            "era {era}: block {} single_proof {}",
            BlockProgram::program_digest_for(era).to_hex(),
            single_proof_program_digest(era).to_hex(),
        );
    }
    let programs: [(&str, String); 10] = [
        ("LinkProof", LinkProof.hash().to_hex()),
        ("LeviathanLinkProof", LeviathanLinkProof.hash().to_hex()),
        (
            "RemovalRecordsIntegrity",
            RemovalRecordsIntegrity.hash().to_hex(),
        ),
        ("CollectLockScripts", CollectLockScripts.hash().to_hex()),
        ("KernelToOutputs", KernelToOutputs.hash().to_hex()),
        ("CollectTypeScripts", CollectTypeScripts.hash().to_hex()),
        ("CollectTypeScriptsV2", CollectTypeScriptsV2.hash().to_hex()),
        ("NativeCurrency", NativeCurrency.hash().to_hex()),
        ("TimeLock", TimeLock.hash().to_hex()),
        ("TimeLockV2", TimeLockV2.hash().to_hex()),
    ];
    for (name, digest) in programs {
        println!("program {name}: {digest}");
    }
}
