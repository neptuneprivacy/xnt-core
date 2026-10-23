//! Tests of the transaction proofs of the `UpgradeVMv7` era.
//!
//! The tests marked `#[ignore]` produce real triton-vm v7 proofs and are run
//! explicitly, in release mode and one at a time:
//!
//! ```text
//! cargo test --release -p neptune-privacy --lib \
//!     validity::legacy_v7::tests -- --ignored --nocapture --test-threads=1
//! ```
//!
//! On a 96-core machine, `v7_proof_collection_end_to_end` takes about 10 s and
//! 9 GB; `v7_single_proof_end_to_end` takes about 200 s and 100 GB (padded
//! height 2^21) and skips proving where the memory available does not hold the
//! proof.
//!
//! With `XNT_V7_EXPORT_DIR` set, both write their transaction to that directory
//! for checking with another node version: `{prefix}_tx_v03.bin` (bincode),
//! `{prefix}_peer_msg_v03.wire` and `{prefix}_notification_v03.wire` (peer
//! wire codec), and `{prefix}_txid_v03.txt`, for the prefixes `pc` and `sp`.

use std::time::Instant;

use bincode::Options;
use macro_rules_attr::apply;
use proptest::prelude::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use proptest_arbitrary_interop::arb;
use tasm_lib::prelude::Digest;

use super::*;
use crate::api::tx_initiation::error::CreateProofError;
use crate::application::config::network::Network;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::consensus_rule_set::TritonProofVersion;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScripts;
use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
use crate::protocol::consensus::transaction::validity::kernel_to_outputs::KernelToOutputs;
use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::VerifyOptions;
use crate::protocol::consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
use crate::protocol::consensus::type_scripts::time_lock_v2::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;
use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;
use crate::protocol::peer::transaction_notification::TransactionNotification;
use crate::protocol::peer::transfer_transaction::TransferTransaction;
use crate::protocol::peer::PeerMessage;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::legacy_v7;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::protocol::proof_abstractions::verifier::cache_true_claim;
use crate::tests::shared_tokio_runtime;

/// The digest of the `UpgradeVMv7` `SingleProofV2` program, as main net
/// verifies it.
const V7_SINGLE_PROOF_DIGEST: &str =
    "5c75cc2d808464503cccf3bf2467ff13bd3fc736d06aa4f661415852549900e04eb667ddd9792d76";

/// The digest of the `UpgradeVMv8` `SingleProofV2` program.
const V8_SINGLE_PROOF_DIGEST: &str =
    "3ab71f45d12c1b1709197789ffe6194b25492fd0e7dd1aed054a68cf369ae14b17d9b80e99a5e8cf";

/// The digest of the `UpgradeVMv8` `SingleProofV2` program without the
/// chaining branches.
const V8_SINGLE_PROOF_WITHOUT_CHAIN_BRANCHES_DIGEST: &str =
    "307f41ff80f6f7af27a6382ae91cf0d54f9464c0cda525652c1e5285c0ab0044374a488c3d7dc75e";

fn main_net_job_options() -> TritonVmProofJobOptions {
    TritonVmProofJobOptions::default_with_network(Network::Main)
}

/// 2 inputs, 2 outputs, 1 announcement, NativeCurrency and expired TimeLockV2
/// coins on every UTXO: 8 proofs in its collection.
fn small_primitive_witness() -> PrimitiveWitness {
    let mut test_runner = TestRunner::deterministic();
    let now = arb::<Timestamp>()
        .new_tree(&mut test_runner)
        .unwrap()
        .current();
    arbitrary_primitive_witness_with_expired_timelocks(2, 2, 1, now)
        .new_tree(&mut test_runner)
        .unwrap()
        .current()
}

/// 1 input, 1 output, no announcement, no time lock: 6 proofs in its
/// collection, the smallest v7 single proof.
fn minimal_primitive_witness() -> PrimitiveWitness {
    let mut test_runner = TestRunner::deterministic();
    PrimitiveWitness::arbitrary_with_size_numbers(Some(1), 1, 0)
        .new_tree(&mut test_runner)
        .unwrap()
        .current()
}

/// Write the transaction to `XNT_V7_EXPORT_DIR`, if set; see the module docs.
fn export_transaction(prefix: &str, transaction: &Transaction) {
    let Ok(dir) = std::env::var("XNT_V7_EXPORT_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let wire_codec = bincode::DefaultOptions::new();

    let transfer = TransferTransaction::try_from(transaction).unwrap();
    let notification = TransactionNotification::try_from(transaction).unwrap();
    let files = [
        ("tx_v03.bin", bincode::serialize(&transfer).unwrap()),
        (
            "notification_v03.wire",
            wire_codec
                .serialize(&PeerMessage::TransactionNotification(notification))
                .unwrap(),
        ),
        (
            "peer_msg_v03.wire",
            wire_codec
                .serialize(&PeerMessage::Transaction(Box::new(transfer)))
                .unwrap(),
        ),
        (
            "txid_v03.txt",
            transaction.kernel.txid().to_string().into_bytes(),
        ),
    ];
    for (name, bytes) in files {
        let path = dir.join(format!("{prefix}_{name}"));
        std::fs::write(&path, bytes).unwrap();
        println!("wrote {}", path.display());
    }
}

#[test]
fn v7_single_proof_program_has_the_pinned_digest() {
    let pinned = Digest::try_from_hex(V7_SINGLE_PROOF_DIGEST).unwrap();
    assert_eq!(pinned, Program::new(&single_proof_v2_v7_code()).hash());
    assert_eq!(pinned, single_proof_v2_v7_program().hash());
    assert_eq!(
        pinned,
        SingleProofV2::program_for(ConsensusRuleSet::UpgradeVMv7)
            .unwrap()
            .hash()
    );

    let claim = single_proof_claim(Digest::default(), ConsensusRuleSet::UpgradeVMv7);
    assert_eq!(pinned, claim.program_digest);
    assert_eq!(5, claim.version);
}

/// Assembling the v7 program leaves the v8 programs as they are.
#[test]
fn v8_single_proof_programs_are_unchanged_by_the_v7_program() {
    let _ = single_proof_v2_v7_code();

    let (_, with_chain_branches) =
        SingleProofV2.assemble_into::<ProofCollection>(Library::new(), true, false);
    let (_, without_chain_branches) =
        SingleProofV2.assemble_into::<ProofCollection>(Library::new(), false, false);
    assert_eq!(
        V8_SINGLE_PROOF_DIGEST,
        Program::new(&with_chain_branches).hash().to_hex()
    );
    assert_eq!(
        V8_SINGLE_PROOF_WITHOUT_CHAIN_BRANCHES_DIGEST,
        Program::new(&without_chain_branches).hash().to_hex()
    );
    assert_eq!(V8_SINGLE_PROOF_DIGEST, SingleProofV2.hash().to_hex());
    assert_eq!(
        SingleProofV2.hash(),
        SingleProofV2::program_for(ConsensusRuleSet::UpgradeVMv8)
            .unwrap()
            .hash()
    );
}

/// The programs proven inside a v7 collection hash as in v0.2.5, the version
/// main net runs before the fork. A difference would make every v7 collection
/// of this version invalid there.
#[test]
fn proof_collection_programs_have_their_v7_digests() {
    let v0_2_5_digests = [
        (
            "RemovalRecordsIntegrity",
            RemovalRecordsIntegrity.hash(),
            "22096d01b54bf8ca4d8203515cbf0207803b707086cad8d3889a638fb2edb5012c9c452a4d065644",
        ),
        (
            "KernelToOutputs",
            KernelToOutputs.hash(),
            "74e12c483cfd1c57a76bfaafa2ea2b92177103367b9cdc0ab2bd3491c051599fbbaef1b77cc00c75",
        ),
        (
            "CollectLockScripts",
            CollectLockScripts.hash(),
            "7b608d9bbe5b5dc9f3f25af57ebb5a26302e404d0485d8b87abe74d9b339921493922b685efad062",
        ),
        (
            "CollectTypeScriptsV2",
            CollectTypeScriptsV2.hash(),
            "1d33643dc5086e915e44d720af4a1efa195254aee6497166f5055a7bcb0d8313ce70f77fe0632c4e",
        ),
        (
            "NativeCurrency",
            NativeCurrency.hash(),
            "11fdd6eba11eda86ac300e63efa28bf8636b1bdcc1c5588f0539e4efb03c665bc779aa347c92e2f4",
        ),
        (
            "TimeLock",
            TimeLock.hash(),
            "4b4d251947a07f9f2c016c1c271c04ce41013ff50031bd42854919be6e0e4849ebf931e856b542ad",
        ),
        (
            "TimeLockV2",
            TimeLockV2.hash(),
            "8b6d23e675c97cb8e1d36a5e926f19449d37673636c64c0769b7778aded85ff29056832e366b580b",
        ),
    ];
    for (name, digest, v0_2_5_digest) in v0_2_5_digests {
        assert_eq!(v0_2_5_digest, digest.to_hex(), "{name}");
    }

    // The table that is checked before every v7 collection is proven holds
    // the same digests.
    assert_eq!(
        v0_2_5_digests.map(|(name, _, digest)| (name, digest)),
        V7_PROOF_COLLECTION_PROGRAM_DIGESTS
    );
    assert_eq!(Ok(()), check_v7_proof_collection_programs());
}

#[test]
fn v7_claims_carry_claim_version_5() {
    assert_eq!(5, v7_claim_version());
    assert_eq!(
        v7_claim_version(),
        ConsensusRuleSet::UpgradeVMv7
            .triton_proof_version()
            .claim_version()
    );
    assert_ne!(v7_claim_version(), TritonProofVersion::V8.claim_version());
}

/// `TransactionProof::verify` checks a collection with the claim version of
/// the rule set. Only the version-5 claims of this collection are known to be
/// true, so it verifies under `UpgradeVMv7` and not under `UpgradeVMv8`.
#[apply(shared_tokio_runtime)]
async fn collections_are_verified_with_the_claim_version_of_the_rule_set() {
    let mut test_runner = TestRunner::deterministic();
    let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 1, 1)
        .new_tree(&mut test_runner)
        .unwrap()
        .current();
    let txk_mast_hash = primitive_witness.kernel.mast_hash();
    let proof_collection = ProofCollection::produce_mock(&primitive_witness, true);
    for (claim, _) in proof_collection.claims_and_proofs(v7_claim_version()) {
        cache_true_claim(claim).await;
    }

    let proof = TransactionProof::ProofCollection(proof_collection.into());
    let network = Network::Main;
    assert!(
        proof
            .verify(
                txk_mast_hash,
                network,
                ConsensusRuleSet::UpgradeVMv7,
                VerifyOptions::default()
            )
            .await
    );
    assert!(
        !proof
            .verify(
                txk_mast_hash,
                network,
                ConsensusRuleSet::UpgradeVMv8,
                VerifyOptions::default()
            )
            .await
    );
}

#[test]
fn v7_single_proof_limit_is_configured_capped_and_bound_by_memory() {
    let plenty = legacy_v7::proving_memory_estimate(30);
    let at_21 = legacy_v7::proving_memory_estimate(21);
    let at_22 = legacy_v7::proving_memory_estimate(22);

    assert_eq!(
        Some(V7_SINGLE_PROOF_MAX_LOG2_PADDED_HEIGHT),
        v7_single_proof_max_log2_padded_height(None, plenty)
    );
    assert_eq!(
        Some(22),
        v7_single_proof_max_log2_padded_height(None, at_22)
    );
    assert_eq!(
        Some(21),
        v7_single_proof_max_log2_padded_height(None, at_22 - 1)
    );
    assert_eq!(
        Some(21),
        v7_single_proof_max_log2_padded_height(None, at_21)
    );
    assert_eq!(
        Some(20),
        v7_single_proof_max_log2_padded_height(Some(20), plenty)
    );
    assert_eq!(
        Some(22),
        v7_single_proof_max_log2_padded_height(Some(25), plenty)
    );
    assert_eq!(None, v7_single_proof_max_log2_padded_height(None, 0));
}

#[test]
fn v7_single_proof_job_options_lower_the_limit() {
    let lowered_limit = |configured_limit| {
        let mut options = main_net_job_options();
        options.job_settings.max_log2_padded_height_for_proofs = Some(configured_limit);
        v7_single_proof_job_options(options)
            .job_settings
            .max_log2_padded_height_for_proofs
            .unwrap()
    };

    assert!(lowered_limit(25) <= V7_SINGLE_PROOF_MAX_LOG2_PADDED_HEIGHT);
    assert!(lowered_limit(12) <= 12);
}

/// The memory estimate assumes an uncached low-degree-extended trace, so the
/// job options ask for it at every padded height a v7 single proof may have,
/// unless the operator decided it: for the node, or for a padded height.
#[test]
fn v7_single_proof_job_options_do_not_cache_the_trace_unless_configured() {
    let lde_trace = |options: &TritonVmProofJobOptions, log2_padded_height: u8| {
        options
            .job_settings
            .triton_vm_env_vars
            .get(&log2_padded_height)
            .and_then(|env_vars| {
                env_vars
                    .iter()
                    .find(|(key, _)| key == "TVM_LDE_TRACE")
                    .map(|(_, value)| value.clone())
            })
    };

    let mut configured = main_net_job_options();
    configured
        .job_settings
        .triton_vm_env_vars
        .insert(21, vec![("TVM_LDE_TRACE".to_string(), "cache".to_string())]);
    let configured = v7_single_proof_job_options(configured);
    assert_eq!(Some("cache".to_string()), lde_trace(&configured, 21));

    let options = v7_single_proof_job_options(main_net_job_options());
    if std::env::var_os("TVM_LDE_TRACE").is_some() {
        // The node's environment decides; the prover inherits it.
        assert_eq!(None, lde_trace(&options, 21));
    } else {
        for log2_padded_height in 0..=V7_SINGLE_PROOF_MAX_LOG2_PADDED_HEIGHT {
            assert_eq!(
                Some("no_cache".to_string()),
                lde_trace(&options, log2_padded_height),
                "2^{log2_padded_height}"
            );
        }
        assert_eq!(Some("no_cache".to_string()), lde_trace(&configured, 20));
    }
}

/// The memory taken as available for a v7 single proof is never more than
/// the host has available.
#[test]
fn available_memory_is_bounded_by_the_host() {
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    assert!(legacy_v7::available_memory() <= system.available_memory());
}

/// The capability check fails before it executes anything if the capability or
/// the memory rules a v7 single proof out.
#[test]
fn v7_single_proof_needs_capability_and_memory() {
    let proof_collection = ProofCollection::invalid();
    let mut job_settings = main_net_job_options().job_settings;
    let plenty = legacy_v7::proving_memory_estimate(30);

    job_settings.tx_proving_capability = TxProvingCapability::ProofCollection;
    assert_eq!(
        Err(V7SingleProofUnavailable::Capability(
            TxProvingCapability::ProofCollection
        )),
        check_v7_single_proof_capability(&proof_collection, &job_settings, plenty)
    );

    job_settings.tx_proving_capability = TxProvingCapability::SingleProof;
    assert_eq!(
        Err(V7SingleProofUnavailable::Memory),
        check_v7_single_proof_capability(&proof_collection, &job_settings, 0)
    );

    // An invalid collection is found out before it is executed: one that
    // fails the preconditions of its verification by them, a well-formed one
    // with invalid proofs by the v7 verifier.
    assert!(matches!(
        check_v7_single_proof_capability(&proof_collection, &job_settings, plenty),
        Err(V7SingleProofUnavailable::Execution(
            LegacyProvingError::MalformedCollection
        ))
    ));
    let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(1), 1, 0)
        .new_tree(&mut TestRunner::deterministic())
        .unwrap()
        .current();
    let well_formed = ProofCollection::produce_mock(&primitive_witness, false);
    assert!(well_formed.meets_verification_preconditions(primitive_witness.kernel.mast_hash()));
    assert!(matches!(
        check_v7_single_proof_capability(&well_formed, &job_settings, plenty),
        Err(V7SingleProofUnavailable::Execution(
            LegacyProvingError::InvalidProof(_)
        ))
    ));
}

#[test]
fn single_proofs_of_eras_before_v7_are_not_producible() {
    for consensus_rule_set in [
        ConsensusRuleSet::Reboot,
        ConsensusRuleSet::TimelockExtension,
        ConsensusRuleSet::UpgradeVMv5,
    ] {
        assert!(matches!(
            SingleProofV2::program_for(consensus_rule_set),
            Err(CreateProofError::NotProducible { .. })
        ));
    }
}

/// A real v7 collection, verified sub-proof by sub-proof with triton-vm v7 and
/// as a whole through the transaction-validation path.
#[ignore = "produces real triton-vm v7 proofs"]
#[apply(shared_tokio_runtime)]
async fn v7_proof_collection_end_to_end() {
    let primitive_witness = small_primitive_witness();
    let kernel = primitive_witness.kernel.clone();
    let txk_mast_hash = kernel.mast_hash();

    let start = Instant::now();
    let proof_collection = ProofCollection::produce_v2(
        &primitive_witness,
        TritonVmJobQueue::get_instance(),
        main_net_job_options(),
        ConsensusRuleSet::UpgradeVMv7,
    )
    .await
    .unwrap();
    println!(
        "v7 ProofCollection: {} proofs in {:.1} s",
        proof_collection.num_proofs(),
        start.elapsed().as_secs_f64()
    );

    for (claim, proof) in proof_collection.claims_and_proofs(v7_claim_version()) {
        assert_eq!(5, claim.version);
        assert!(legacy_v7::verify(&claim, proof), "triton-vm v7 verifier");
    }

    let network = Network::Main;
    let proof = TransactionProof::ProofCollection(proof_collection.into());
    assert!(
        proof
            .verify(
                txk_mast_hash,
                network,
                ConsensusRuleSet::UpgradeVMv7,
                VerifyOptions::default()
            )
            .await
    );
    assert!(
        !proof
            .verify(
                txk_mast_hash,
                network,
                ConsensusRuleSet::UpgradeVMv8,
                VerifyOptions::default()
            )
            .await
    );

    export_transaction("pc", &Transaction { kernel, proof });
}

/// The smallest v7 single proof, raised from a real v7 collection, verified
/// with triton-vm v7 and through the transaction-validation path.
#[ignore = "produces real triton-vm v7 proofs; needs about 100 GB of memory"]
#[apply(shared_tokio_runtime)]
async fn v7_single_proof_end_to_end() {
    let primitive_witness = minimal_primitive_witness();
    let kernel = primitive_witness.kernel.clone();
    let txk_mast_hash = kernel.mast_hash();
    let job_options = main_net_job_options();

    let proof_collection = ProofCollection::produce_v2(
        &primitive_witness,
        TritonVmJobQueue::get_instance(),
        job_options.clone(),
        ConsensusRuleSet::UpgradeVMv7,
    )
    .await
    .unwrap();
    println!(
        "v7 ProofCollection: {} proofs",
        proof_collection.num_proofs()
    );

    let available_memory = legacy_v7::available_memory();
    let check_start = Instant::now();
    let capability = check_v7_single_proof_capability(
        &proof_collection,
        &job_options.job_settings,
        available_memory,
    );
    println!(
        "v7 single proof capability check in {:.1} s, {} GiB available: {capability:?}",
        check_start.elapsed().as_secs_f64(),
        available_memory >> 30,
    );
    if let Err(V7SingleProofUnavailable::PaddedHeight { .. } | V7SingleProofUnavailable::Memory) =
        capability
    {
        println!("not enough memory for the v7 single proof; skipping the proving step");
        return;
    }
    let log2_padded_height = capability.unwrap();
    assert!(log2_padded_height <= V7_SINGLE_PROOF_MAX_LOG2_PADDED_HEIGHT);

    let start = Instant::now();
    let single_proof = SingleProofV2Witness::from_collection(proof_collection)
        .produce(
            TritonVmJobQueue::get_instance(),
            job_options,
            ConsensusRuleSet::UpgradeVMv7,
        )
        .await
        .unwrap();
    println!(
        "v7 SingleProof of padded height 2^{log2_padded_height} in {:.1} s",
        start.elapsed().as_secs_f64()
    );

    let claim = single_proof_claim(txk_mast_hash, ConsensusRuleSet::UpgradeVMv7);
    assert_eq!(5, claim.version);
    assert!(
        legacy_v7::verify(&claim, &single_proof),
        "triton-vm v7 verifier"
    );

    let network = Network::Main;
    let proof = TransactionProof::SingleProof(single_proof);
    assert!(
        proof
            .verify(
                txk_mast_hash,
                network,
                ConsensusRuleSet::UpgradeVMv7,
                VerifyOptions::default()
            )
            .await
    );
    assert!(
        !proof
            .verify(
                txk_mast_hash,
                network,
                ConsensusRuleSet::UpgradeVMv8,
                VerifyOptions::default()
            )
            .await
    );

    export_transaction("sp", &Transaction { kernel, proof });
}
