use tasm_lib::triton_vm;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof as VmProof;
use tasm_lib::triton_vm::proof_stream::ProofStream;
use tasm_lib::triton_vm::stark::Stark;
use tokio::task;
use tracing::warn;

use crate::application::config::network::Network;
use crate::protocol::consensus::consensus_rule_set::TritonProofVersion;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;

// This claims-cache stores mock proof-claims that are simply asserted to be valid.
//
// The cache is only used for tests and regtest mode!!
//
// The cache enables mock proofs to be generated and validated immediately
// which enables mock blocks and transactions.
//
// important:  for regtest mode to work properly, peers must be able to
// verify eachother's proofs. There is presently no mechanism to sync
// the cache between peers, though that could be a possibility.
//
// HOWEVER: given that this is a process-wide cache, it is actually shared
// between in-process peers such as when executing integration tests.
//
// In other words, distributed proving works for integration tests, but not
// yet in a "real" regtest multi-node network.
//
// RAM Usage:
//
// Presently claims are never expired. So there is a very real chance of
// blowing up RAM.  Maybe not so problematic since regtest is generally started
// from genesis block anyway.
//
// see: https://github.com/Neptune-Crypto/neptune-core/issues/539
#[cfg(test)]
static CLAIMS_CACHE: std::sync::LazyLock<tokio::sync::Mutex<std::collections::HashSet<Claim>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashSet::new()));

/// Whether to reject proofs that carry more proof items than the verifier reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuperfluousProofItems {
    Reject,
    Tolerate,
}

/// The number of proof items that Triton VM's verifier reads from a proof of
/// the padded height indicated by the proof.
///
/// Returns `None` if the proof does not encode a padded height, or if no FRI
/// parameters exist for that padded height.
fn expected_num_proof_items(stark: Stark, proof: &VmProof) -> Option<usize> {
    /// Items read outside of FRI: the padded height, three Merkle roots, four
    /// out-of-domain rows, two out-of-domain quotient segments, and, for each of
    /// the three tables, the revealed rows plus their authentication structure.
    ///
    /// NOTE: this was 15 through triton-vm v7. Triton VM v8 randomizes the
    /// quotient table, so the quotient segments are communicated as two items
    /// rather than one. Bumping the linked triton-vm without bumping this
    /// constant makes `has_expected_num_proof_items` reject every honest proof.
    const NUM_ITEMS_OUTSIDE_FRI: usize = 16;

    /// Items read by FRI independently of the number of rounds: the Merkle root
    /// of the first round, the last round's codeword and polynomial, and the
    /// first round's revealed leafs.
    const NUM_ROUND_INDEPENDENT_FRI_ITEMS: usize = 4;

    /// Items read by FRI for every round: a Merkle root, and the revealed leafs
    /// of the round's partial codeword.
    const NUM_FRI_ITEMS_PER_ROUND: usize = 2;

    let padded_height = proof.padded_height().ok()?;
    let num_fri_rounds = stark.fri(padded_height).ok()?.num_rounds();

    Some(
        NUM_ITEMS_OUTSIDE_FRI
            + NUM_ROUND_INDEPENDENT_FRI_ITEMS
            + NUM_FRI_ITEMS_PER_ROUND * num_fri_rounds,
    )
}

/// Determine whether the proof holds exactly those proof items that Triton VM's
/// verifier reads, and no others.
///
/// Through triton-vm v7 the native verifier ignored any items beyond the ones it
/// reads, whereas the verifier running *inside* the VM rejected them, so a
/// transaction carrying such a proof would be relayed by every node yet could
/// never be merged into a block transaction. triton-vm v8 rejects them natively
/// as well, so this is now defence in depth; it still earns its place by keeping
/// such proofs out of the mempool before the prover is ever invoked.
fn has_expected_num_proof_items(proof: &VmProof) -> bool {
    let Some(expected_num_items) = expected_num_proof_items(Stark::default(), proof) else {
        return false;
    };
    let Ok(proof_stream) = ProofStream::try_from(proof) else {
        return false;
    };

    proof_stream.items.len() == expected_num_items
}

/// Verify a Triton VM (claim, proof) pair for default STARK parameters.
///
/// When the test flag is set, this function checks whether the claim is present
/// in the `CLAIMS_CACHE` and if so returns true early (*i.e.*, without running
/// the verifier). When the test flag is set and the cache does not contain the
/// claim and verification succeeds, the claim is added to the cache. The only
/// other way to populate the cache is through method `cache_true_claim`.
pub(crate) async fn verify(claim: Claim, proof: Proof, network: Network) -> bool {
    verify_inner(claim, proof, network, SuperfluousProofItems::Tolerate).await
}

/// Verify a Triton VM (claim, proof) pair belonging to a transaction.
///
/// Behaves like [`verify`], except that proofs holding more proof items than
/// the verifier reads are rejected up front. Since triton-vm v8 the native
/// verifier rejects them too, so this is defence in depth; it still keeps such
/// proofs out of the mempool cheaply. See `has_expected_num_proof_items`.
pub(crate) async fn verify_transaction_proof(claim: Claim, proof: Proof, network: Network) -> bool {
    verify_inner(claim, proof, network, SuperfluousProofItems::Reject).await
}

async fn verify_inner(
    claim: Claim,
    proof: Proof,
    network: Network,
    superfluous_proof_items: SuperfluousProofItems,
) -> bool {
    // security: we do not accept mock proofs unless we ourselves
    // are running a network that accepts mock-proofs, eg regtest.
    if network.use_mock_proof() {
        return proof.is_valid_mock();
    }

    // presently this is used by certain unit tests.
    #[cfg(test)]
    if CLAIMS_CACHE.lock().await.contains(&claim) {
        return true;
    }

    // The claim's version names the Triton VM proof format the proof was made
    // in, and only a verifier of that format can check it: format 8 for the
    // current era, format 5 for `UpgradeVMv7`, which the legacy triton-vm v7
    // verifies. Claims of any other format belong to checkpointed eras.
    let reject_superfluous = superfluous_proof_items == SuperfluousProofItems::Reject;
    let verify_job: Box<dyn FnOnce() -> bool + Send> =
        if claim.version == TritonProofVersion::V8.claim_version() {
            if reject_superfluous && !has_expected_num_proof_items(&proof) {
                warn!("rejecting proof that holds an unexpected number of proof items");
                return false;
            }
            let claim = claim.clone();
            Box::new(move || triton_vm::verify(Stark::default(), &claim, &proof.into()))
        } else if claim.version == TritonProofVersion::V7.claim_version() {
            let legacy_claim = legacy_v7::claim(&claim);
            let legacy_proof = legacy_v7::proof(&proof.into());
            if reject_superfluous && !legacy_v7::has_expected_num_proof_items(&legacy_proof) {
                warn!("rejecting legacy v7 proof that holds an unexpected number of proof items");
                return false;
            }
            Box::new(move || legacy_v7::verify(&legacy_claim, &legacy_proof))
        } else {
            warn!(
                "rejecting proof of unsupported proof format version {}",
                claim.version
            );
            return false;
        };

    #[cfg(test)]
    let claim_clone = claim.clone();

    let verdict = task::spawn_blocking(verify_job)
        .await
        .expect("should be able to verify proof in new tokio task");

    // tbd: we might want to enable a cache for mainnet usage.
    // but we should probably use a cache that has a configurable max
    // size, so we don't blow up RAM.
    #[cfg(test)]
    if verdict {
        cache_true_claim(claim_clone).await;
    }

    verdict
}

/// Verification of `UpgradeVMv7` proofs (proof format 5) with the linked
/// legacy triton-vm v7, so that a node running this release before the
/// `UpgradeVMv8` fork checks v7 blocks instead of trusting them. Field elements
/// are carried across by value; both versions use the same field.
mod legacy_v7 {
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::proof::Claim;
    use tasm_lib::triton_vm::proof::Proof as VmProof;
    use triton_vm_v7 as tvm7;

    fn to_v7(elements: &[BFieldElement]) -> Vec<tvm7::prelude::BFieldElement> {
        elements
            .iter()
            .map(|element| tvm7::prelude::BFieldElement::new(element.value()))
            .collect()
    }

    pub(super) fn claim(claim: &Claim) -> tvm7::proof::Claim {
        let digest: [tvm7::prelude::BFieldElement; 5] = to_v7(&claim.program_digest.values())
            .try_into()
            .expect("a digest has five elements");
        tvm7::proof::Claim::new(tvm7::prelude::Digest::new(digest))
            .about_version(claim.version)
            .with_input(to_v7(&claim.input))
            .with_output(to_v7(&claim.output))
    }

    pub(super) fn proof(proof: &VmProof) -> tvm7::proof::Proof {
        tvm7::proof::Proof(to_v7(&proof.0))
    }

    /// Like [`super::has_expected_num_proof_items`], for triton-vm v7, which
    /// sends one item fewer outside of FRI: its quotient segments are a single
    /// item.
    pub(super) fn has_expected_num_proof_items(proof: &tvm7::proof::Proof) -> bool {
        const NUM_ITEMS_OUTSIDE_FRI: usize = 15;
        const NUM_ROUND_INDEPENDENT_FRI_ITEMS: usize = 4;
        const NUM_FRI_ITEMS_PER_ROUND: usize = 2;

        let Ok(padded_height) = proof.padded_height() else {
            return false;
        };
        let Ok(fri) = tvm7::prelude::Stark::default().fri(padded_height) else {
            return false;
        };
        let Ok(proof_stream) = tvm7::proof_stream::ProofStream::try_from(proof) else {
            return false;
        };
        let expected = NUM_ITEMS_OUTSIDE_FRI
            + NUM_ROUND_INDEPENDENT_FRI_ITEMS
            + NUM_FRI_ITEMS_PER_ROUND * fri.num_rounds();
        proof_stream.items.len() == expected
    }

    pub(super) fn verify(claim: &tvm7::proof::Claim, proof: &tvm7::proof::Proof) -> bool {
        tvm7::verify(tvm7::prelude::Stark::default(), claim, proof)
    }
}

/// Add a claim to the [`CLAIMS_CACHE`].
/// only used for tests at present.
#[cfg(test)]
pub(crate) async fn cache_true_claim(claim: Claim) {
    CLAIMS_CACHE.lock().await.insert(claim);
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use std::collections::HashSet;

    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::RngExt;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::isa::triton_asm;
    use tasm_lib::triton_vm::isa::triton_program;
    use tasm_lib::triton_vm::proof_item::ProofItem;
    use tasm_lib::triton_vm::vm::NonDeterminism;
    use triton_vm::prelude::BFieldCodec;

    use super::*;
    use crate::tests::shared_tokio_runtime;

    pub(crate) fn bogus_proof(claim: &Claim) -> Proof {
        Proof::from(Tip5::hash_varlen(&claim.encode()).values().to_vec())
    }

    /// An honestly produced (claim, proof) pair for a program of the given
    /// length. Longer programs have larger padded heights, and thus more FRI
    /// rounds.
    fn honest_claim_and_proof(num_instructions: usize) -> (Claim, VmProof) {
        let program = triton_program!({&triton_asm![nop; num_instructions]} halt);
        let claim = Claim::about_program(&program);
        let proof = triton_vm::prove(Stark::default(), &claim, program, NonDeterminism::default())
            .expect("should be able to prove trivial program");

        (claim, proof)
    }

    /// The conformance test tying [`expected_num_proof_items`] to the number of
    /// proof items that Triton VM's prover actually emits. If Triton VM changes
    /// how many items a proof holds, this test must fail, since the count is
    /// hard-coded here but only implied over there.
    #[test]
    fn expected_num_proof_items_matches_honest_proofs() {
        let mut observed_num_fri_rounds = HashSet::new();
        for num_instructions in [0, 200, 2000] {
            let (_, proof) = honest_claim_and_proof(num_instructions);
            let actual_num_items = ProofStream::try_from(&proof).unwrap().items.len();
            assert_eq!(
                Some(actual_num_items),
                expected_num_proof_items(Stark::default(), &proof),
                "expected number of proof items must match actual number for a \
                 program of {num_instructions} instructions"
            );

            let padded_height = proof.padded_height().unwrap();
            observed_num_fri_rounds
                .insert(Stark::default().fri(padded_height).unwrap().num_rounds());
        }

        assert!(
            observed_num_fri_rounds.len() > 1,
            "test assumption: proofs must span more than one FRI round count, \
             otherwise the per-round term goes untested. Observed: {observed_num_fri_rounds:?}"
        );
    }

    #[test]
    fn superfluous_proof_items_are_detected() {
        let (claim, proof) = honest_claim_and_proof(200);
        assert!(
            has_expected_num_proof_items(&proof),
            "honest proof must hold exactly the expected number of proof items"
        );

        let mut appended_proof_stream = ProofStream::try_from(&proof).unwrap();
        appended_proof_stream
            .items
            .push(ProofItem::Log2PaddedHeight(8));
        let appended_proof = VmProof::from(appended_proof_stream);

        assert!(
            !has_expected_num_proof_items(&appended_proof),
            "proof with a trailing proof item must be detected"
        );

        // Through triton-vm v7 the native verifier ACCEPTED the padded proof
        // while the verifier running inside the VM rejected it, and
        // `has_expected_num_proof_items` existed to close that divergence.
        // triton-vm v8 fixed it at the source ("Reject proofs with superfluous
        // items"), so the native verifier now rejects it too and the check above
        // is defence in depth rather than the only line of defence. Keep both:
        // the in-tree check also keeps such proofs out of the mempool.
        assert!(
            !triton_vm::verify(Stark::default(), &claim, &appended_proof),
            "since triton-vm v8 the native verifier must reject trailing items"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn transaction_proofs_with_superfluous_items_are_rejected() {
        let network = Network::Main;
        let (claim, proof) = honest_claim_and_proof(200);

        let mut appended_proof_stream = ProofStream::try_from(&proof).unwrap();
        appended_proof_stream
            .items
            .push(ProofItem::Log2PaddedHeight(8));
        let appended_proof = Proof::from(VmProof::from(appended_proof_stream));

        // Must precede the `verify` call below, which caches the claim as true
        // in test builds.
        assert!(
            !verify_transaction_proof(claim.clone(), appended_proof.clone(), network).await,
            "transaction proof with trailing proof item must be rejected"
        );
        // Block proofs are still exempt from the in-tree item-count check, but
        // since triton-vm v8 the native verifier rejects superfluous items, so a
        // padded block proof no longer verifies either.
        assert!(
            !verify(claim, appended_proof, network).await,
            "since triton-vm v8 a block proof with a trailing item must be rejected"
        );
    }

    /// Proofs made by triton-vm v7 (format 5), as `UpgradeVMv7` proofs are, are
    /// routed to the linked legacy verifier: an honest one verifies, one with a
    /// trailing item fails v7's item count, and the same proof does not satisfy
    /// a format-8 claim.
    mod legacy_v7_route {
        use macro_rules_attr::apply;
        use tasm_lib::prelude::Digest;
        use tasm_lib::triton_vm::prelude::BFieldElement;
        use tasm_lib::triton_vm::proof::Claim;
        use tasm_lib::triton_vm::proof::Proof as VmProof;
        use triton_vm_v7::prelude::triton_asm;
        use triton_vm_v7::prelude::triton_program;
        use triton_vm_v7::prelude::BFieldElement as V7Bfe;
        use triton_vm_v7::prelude::NonDeterminism as V7NonDeterminism;
        use triton_vm_v7::prelude::Stark as V7Stark;
        use triton_vm_v7::proof::Claim as V7Claim;
        use triton_vm_v7::proof::Proof as V7Proof;
        use triton_vm_v7::proof_item::ProofItem as V7ProofItem;
        use triton_vm_v7::proof_stream::ProofStream as V7ProofStream;

        use crate::application::config::network::Network;
        use crate::protocol::consensus::consensus_rule_set::TritonProofVersion;
        use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
        use crate::protocol::proof_abstractions::verifier::verify_transaction_proof;
        use crate::tests::shared_tokio_runtime;

        fn to_current(elements: &[V7Bfe]) -> Vec<BFieldElement> {
            elements
                .iter()
                .map(|e| BFieldElement::new(e.value()))
                .collect()
        }

        fn current_claim(claim: &V7Claim, version: u32) -> Claim {
            let digest: [BFieldElement; 5] = to_current(&claim.program_digest.values())
                .try_into()
                .unwrap();
            Claim::new(Digest::new(digest))
                .about_version(version)
                .with_input(to_current(&claim.input))
                .with_output(to_current(&claim.output))
        }

        #[apply(shared_tokio_runtime)]
        async fn legacy_v7_proofs_are_routed_to_the_v7_verifier() {
            let network = Network::Main;
            let program = triton_program!({&triton_asm![nop; 200]} halt);
            let claim7 = V7Claim::about_program(&program);
            assert_eq!(claim7.version, TritonProofVersion::V7.claim_version());
            let proof7 = triton_vm_v7::prove(
                V7Stark::default(),
                &claim7,
                program,
                V7NonDeterminism::default(),
            )
            .unwrap();
            let proof = Proof::from(VmProof(to_current(&proof7.0)));

            let mut padded_stream = V7ProofStream::try_from(&proof7).unwrap();
            padded_stream.items.push(V7ProofItem::Log2PaddedHeight(8));
            let padded7 = V7Proof::from(padded_stream);
            let padded = Proof::from(VmProof(to_current(&padded7.0)));

            // Negative cases first: test builds cache claims that verified.
            let claim = current_claim(&claim7, claim7.version);
            assert!(
                !verify_transaction_proof(claim.clone(), padded, network).await,
                "a v7 proof with a trailing item must fail v7's item count"
            );
            let as_v8 = current_claim(&claim7, TritonProofVersion::V8.claim_version());
            assert!(
                !verify_transaction_proof(as_v8, proof.clone(), network).await,
                "a v7 proof must not satisfy a format-8 claim"
            );
            assert!(
                verify_transaction_proof(claim, proof, network).await,
                "an honest v7 proof must verify with the legacy verifier"
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn test_claims_cache() {
        let network = Network::Main;

        // generate random claim and bogus proof
        let mut rng = rand::rng();
        let some_claim = Claim::new(rng.random())
            .with_input((0..10).map(|_| rng.random()).collect_vec())
            .with_output((0..10).map(|_| rng.random()).collect_vec());
        let some_proof = bogus_proof(&some_claim);

        // verification must fail
        assert!(!verify(some_claim.clone(), some_proof.clone(), network).await);

        // put claim into cache
        cache_true_claim(some_claim.clone()).await;

        // verification must succeed
        assert!(verify(some_claim, some_proof, network).await);
    }
}
