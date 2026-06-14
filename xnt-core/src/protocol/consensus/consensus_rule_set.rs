use strum_macros::EnumIter;

use crate::api::export::BlockHeight;
use crate::api::export::Network;
use crate::protocol::consensus::block::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;
use crate::BFieldElement;

/// Height of 1st block that follows the Xnt consensus ruleset (with Triton VM v1).
pub const BLOCK_HEIGHT_HARDFORK_XNT_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(15256u64));

/// Height of the 1st block that follows the `TimelockExtension` consensus
/// ruleset on mainnet.
pub const BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(52540u64));

/// Height of the 1st block that follows the `UpgradeVM` consensus ruleset on
/// mainnet. UpgradeVM is the triton-vm v3 / tasm-lib upgrade: it changes the
/// bytecode (hence program digest) of every consensus program. Pre-upgrade history
/// stays verifiable under the single v3 verifier via hardcoded per-era program
/// digests; UpgradeVM blocks use the recomputed v3 digests.
pub const BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(55800u64));

/// Height of the 1st block that follows the `UpgradeVMv4` consensus ruleset on
/// mainnet. UpgradeVMv4 is the triton-vm v4 upgrade: it re-hashes every consensus
/// program again (the proof format version bumps 1 -> 2, and the leaf type-script
/// length-bound is lifted for single-word coin state). Pre-v4 history stays
/// verifiable via the hardcoded UpgradeVM (v3) program digests; UpgradeVMv4 blocks
/// use the recomputed v4 digests.
///
/// Mainnet v4 activation height.
pub const BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(56700u64));

/// Height of the 1st block that follows the `UpgradeVMv5` consensus ruleset on
/// mainnet. UpgradeVMv5 is the triton-vm v5 upgrade: triton-vm's ISA and proof
/// format changed (proof version 2 -> 5), so the proof programs that embed the
/// STARK verifier (`SingleProofV2`, `BlockProgram`) compile to different bytecode
/// and re-hash. The v5 verifier cannot re-check v4 proofs, so pre-v5 history is
/// checkpointed via the hardcoded v4 program digests.
///
/// NOTE: unlike the v3→v4 upgrade, the leaf TYPE SCRIPTS (`NativeCurrency`,
/// `TimeLock`, `TimeLockV2`, `CollectTypeScriptsV2`) are byte-identical across
/// v4 and v5 — their digests did NOT change — so existing coins need NO remap and
/// remain spendable directly.
///
/// Mainnet v5 activation height.
pub const BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(57650u64));

/// Enumerates all possible sets of consensus rules.
///
/// Specifically, this enum captures *differences* between consensus rules,
/// across
///  - networks, and
///  - hard and soft forks triggered by blocks.
///
/// Consensus logic not captured by this encapsulation lives on
/// [`Transaction::is_valid`][super::transaction::Transaction::is_valid] and
/// ultimately [`Block::is_valid`][super::block::Block::is_valid].
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, Default, strum_macros::Display)]
pub enum ConsensusRuleSet {
    Reboot,
    HardforkAlpha,
    #[default]
    Xnt,
    /// The +1 year timelock extension hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET`] on
    /// Main (mainnet-only). Under this ruleset, any coin still tagged with the
    /// legacy `TimeLock` hash is governed by `TimeLockV2`, which enforces
    /// `release_date + 1 year < timestamp` instead of the original
    /// `release_date < timestamp`. New post-fork timelock UTXOs use
    /// `TimeLockV2`'s own hash and follow normal release rules.
    TimelockExtension,
    /// The triton-vm v3 / tasm-lib upgrade hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET`] on Main. The VM
    /// upgrade changes the bytecode — and therefore the program digest — of
    /// every consensus program. The single (v3) verifier still validates
    /// pre-upgrade proofs because their program digests are hardcoded per era and
    /// the proof version is carried in the `Claim`; UpgradeVM blocks use the
    /// recomputed v3 program digests.
    UpgradeVM,
    /// The triton-vm v4 upgrade hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET`] on Main. The
    /// VM upgrade bumps the proof format version (1 -> 2) and re-hashes every
    /// consensus program; the leaf type scripts additionally drop the single-word
    /// length-bound. The single (v4) verifier still validates pre-v4 proofs via
    /// hardcoded per-era digests + the claim version; UpgradeVMv4 blocks use the
    /// recomputed v4 program digests. Coins committed under the UpgradeVM (v3) era
    /// remain spendable via the type-script remap (`CollectTypeScriptsV2`).
    UpgradeVMv4,
    /// The triton-vm v5 upgrade hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET`] on Main.
    /// triton-vm's ISA changed, so the proof programs that embed the STARK
    /// verifier (`SingleProofV2`, `BlockProgram`) re-hash; the leaf type scripts
    /// are unchanged. The current (v5) verifier validates only v5 proofs; pre-v5
    /// history is checkpointed via hardcoded per-era digests. UpgradeVMv5 blocks
    /// use the recomputed v5 proof-program digests. Because the type scripts did
    /// not change, coins from every prior era remain spendable with no remap.
    UpgradeVMv5,
}

/// The triton-vm crate major a rule set's proofs were produced under. The
/// program digest changes per era, but a single (current) verifier can check
/// every era's proofs given the era-correct digest + claim version, because the
/// version is absorbed into the verifier's Fiat-Shamir transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum_macros::Display)]
pub enum TritonProofVersion {
    /// triton-vm v1.0.0 (proof format version 0) — Reboot, HardforkAlpha.
    V1,
    /// triton-vm v2.0.0 (proof format version 1) — Xnt, TimelockExtension.
    V2,
    /// triton-vm v3.0.0 (proof format version 1) — UpgradeVM.
    V3,
    /// triton-vm v4.0.0 (proof format version 2) — UpgradeVMv4.
    V4,
    /// triton-vm v5.0.0 (proof format version 5; ISA changed) — UpgradeVMv5.
    V5,
}

impl TritonProofVersion {
    /// The `version` field stamped into a [`Claim`]: triton-vm's own
    /// proof-format version (0 for v1.0.0, 1 for v2.0.0+), which is distinct
    /// from the crate major named by this enum.
    pub(crate) fn claim_version(self) -> u32 {
        match self {
            TritonProofVersion::V1 => 0,
            TritonProofVersion::V2 | TritonProofVersion::V3 => 1,
            // v4 is frozen at proof format version 2.
            TritonProofVersion::V4 => 2,
            // v5 is the CURRENT era: its claim version must match the version the
            // linked triton-vm v5 actually stamps into proofs, so track the live
            // constant rather than a literal (keeps `BlockProgram::claim` in sync
            // with the live `SingleProofV2`/`BlockProgram` provers).
            TritonProofVersion::V5 => tasm_lib::triton_vm::proof::CURRENT_VERSION,
        }
    }
}

impl ConsensusRuleSet {
    /// triton-vm crate major the blocks of this rule set were produced under.
    pub(crate) fn triton_proof_version(&self) -> TritonProofVersion {
        match self {
            ConsensusRuleSet::Reboot | ConsensusRuleSet::HardforkAlpha => TritonProofVersion::V1,
            ConsensusRuleSet::Xnt | ConsensusRuleSet::TimelockExtension => TritonProofVersion::V2,
            ConsensusRuleSet::UpgradeVM => TritonProofVersion::V3,
            ConsensusRuleSet::UpgradeVMv4 => TritonProofVersion::V4,
            ConsensusRuleSet::UpgradeVMv5 => TritonProofVersion::V5,
        }
    }

    /// Rule sets whose proofs the current verifier cannot check, so their blocks
    /// are trusted (checkpointed) rather than re-verified.
    ///
    /// triton-vm's proof format (`proof::CURRENT_VERSION`) changes only when the
    /// STARK/ISA changes; a verifier can re-check only proofs of its OWN format
    /// version. The current binary links triton-vm v5 (which changed the ISA, so
    /// its verifier can re-check ONLY `UpgradeVMv5` proofs). Every earlier era —
    /// including `UpgradeVMv4` — was produced under a superseded triton-vm whose
    /// proofs this verifier cannot re-check, and is therefore checkpointed.
    ///
    /// This mirrors neptune-core's house pattern ("Upgrade Triton VM … with
    /// checkpoint"): rather than link multiple triton-vm versions, the superseded
    /// history is trusted. Re-verifying it would require linking the matching
    /// older triton-vm crate, which we deliberately do not do.
    pub(crate) fn proofs_are_trusted(&self) -> bool {
        !matches!(self, ConsensusRuleSet::UpgradeVMv5)
    }

    /// Maximum block size in number of BFieldElements
    pub(crate) const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5 => {
                // This size is 8MB which should keep it feasible to run archival nodes for
                // many years without requiring excessive disk space.
                1_000_000
            }
        }
    }

    /// Infer the [`ConsensusRuleSet`] from the [`Network`] and the
    /// [`BlockHeight`]. The second argument is necessary to take into account
    /// planned hard or soft forks that activate at a given height. The first
    /// argument is necessary because the forks can activate at different
    /// heights based on the network.
    pub fn infer_from(network: Network, block_height: BlockHeight) -> Self {
        match network {
            Network::Main => {
                // Old Neptune blocks (before Xnt hardfork) use Reboot consensus
                // These blocks were created with Triton VM v0
                if block_height < BLOCK_HEIGHT_HARDFORK_XNT_MAIN_NET {
                    ConsensusRuleSet::Reboot
                } else if block_height < BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET {
                    ConsensusRuleSet::Xnt
                } else if block_height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET {
                    ConsensusRuleSet::TimelockExtension
                } else if block_height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET {
                    ConsensusRuleSet::UpgradeVM
                } else if block_height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET {
                    ConsensusRuleSet::UpgradeVMv4
                } else {
                    ConsensusRuleSet::UpgradeVMv5
                }
            }
            Network::TestnetMock | Network::RegTest | Network::Testnet(_) => {
                ConsensusRuleSet::UpgradeVMv5
            }
        }
    }

    pub(crate) fn max_num_inputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5 => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_outputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5 => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_announcements(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5 => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use std::sync::Arc;

    use futures::channel::oneshot;
    use itertools::Itertools;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::export::GlobalStateLock;
    use crate::api::export::InputSelectionPolicy;
    use crate::api::export::KeyType;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::OutputFormat;
    use crate::api::export::ReceivingAddress;
    use crate::api::export::StateLock;
    use crate::api::export::Timestamp;
    use crate::api::export::TransactionProofType;
    use crate::api::export::TxCreationArtifacts;
    use crate::api::export::TxProvingCapability;
    use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
    use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
    use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
    use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
    use crate::api::tx_initiation::builder::tx_input_list_builder::SortOrder;
    use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
    use crate::application::config::cli_args;
    use crate::application::loops::channel::NewBlockFound;
    use crate::application::loops::mine_loop::compose_block_helper;
    use crate::application::loops::mine_loop::create_block_transaction_from;
    use crate::application::loops::mine_loop::guess_nonce;
    use crate::application::loops::mine_loop::GuessingConfiguration;
    use crate::application::loops::mine_loop::TxMergeOrigin;
    use crate::application::triton_vm_job_queue::vm_job_queue;
    use crate::protocol::consensus::block::difficulty_control::Difficulty;
    use crate::protocol::consensus::block::validity::block_primitive_witness::BlockPrimitiveWitness;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::next_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state_with_block;
    use crate::tests::tokio_runtime;

    async fn tx_with_n_outputs(
        mut state: GlobalStateLock,
        num_outputs: usize,
        timestamp: Timestamp,
    ) -> TxCreationArtifacts {
        let mut addresses_and_amts = vec![];
        let same_address = state
            .api()
            .wallet_mut()
            .next_receiving_address(KeyType::Symmetric)
            .await
            .unwrap();
        for _ in 0..num_outputs {
            let value = OutputFormat::AddressAndAmount(
                same_address.clone(),
                NativeCurrencyAmount::from_nau(1),
            );
            addresses_and_amts.push(value);
        }

        let initiator = state.api().tx_initiator();
        let tx_outputs = initiator.generate_tx_outputs(addresses_and_amts).await;
        drop(initiator);

        let fee = NativeCurrencyAmount::from_nau(14);
        let tx_inputs = TxInputListBuilder::new()
            .spendable_inputs(
                state
                    .lock_guard()
                    .await
                    .wallet_spendable_inputs(timestamp, 0)
                    .await
                    .into_iter()
                    .collect(),
            )
            .policy(InputSelectionPolicy::ByUtxoSize(SortOrder::Ascending))
            .spend_amount(tx_outputs.total_native_coins() + fee)
            .build();
        let tx_inputs = tx_inputs.into_iter().collect_vec();

        let tx_details = TransactionDetailsBuilder::new()
            .inputs(tx_inputs.into_iter().into())
            .outputs(tx_outputs)
            .fee(fee)
            .timestamp(timestamp)
            .build(&mut StateLock::write_guard(&mut state).await)
            .await
            .unwrap();

        // use cli options for building proof, but override proof-type
        let options = TritonVmProofJobOptionsBuilder::new()
            .proof_type(TransactionProofType::SingleProof)
            .proving_capability(TxProvingCapability::SingleProof)
            .build();

        // generate proof
        let block_height = state.lock_guard().await.chain.light_state().header().height;
        let network = state.cli().network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .transaction_details(&tx_details)
            .job_queue(vm_job_queue())
            .proof_job_options(options)
            .build()
            .await
            .unwrap();

        let transaction = TransactionBuilder::new()
            .transaction_details(&tx_details)
            .transaction_proof(proof)
            .build()
            .unwrap();

        TxCreationArtifacts {
            transaction: Arc::new(transaction),
            details: Arc::new(tx_details),
        }
    }

    async fn block_with_n_outputs(
        me: GlobalStateLock,
        num_outputs: usize,
        timestamp: Timestamp,
    ) -> Block {
        let current_tip = me.lock_guard().await.chain.archival_state().get_tip().await;
        let tx_many_outputs = tx_with_n_outputs(me.clone(), num_outputs, timestamp).await;
        let (block_tx, _) = create_block_transaction_from(
            &current_tip,
            me,
            timestamp,
            TritonVmProofJobOptions::default(),
            TxMergeOrigin::ExplicitList(vec![tx_many_outputs.transaction.into()]),
        )
        .await
        .unwrap();
        Block::compose(
            &current_tip,
            block_tx,
            timestamp,
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap()
    }

    async fn mine_to_own_wallet(
        me: GlobalStateLock,
        timestamp: Timestamp,
    ) -> (Block, Vec<ExpectedUtxo>) {
        let current_tip = me.lock_guard().await.chain.archival_state().get_tip().await;
        compose_block_helper(
            current_tip,
            me,
            timestamp,
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap()
    }

    // v5 block-production readiness: build a chain at the v5 fork height (57650)
    // and mine the first post-fork blocks (57651, 57652) under UpgradeVMv5, to
    // confirm v5 nodes can actually compose+prove+validate blocks across the fork.
    // (No `#[traced_test]`: keeps the output to the readable step logs below.)
    #[test]
    fn new_blocks_at_upgrade_vm_height() {
        // We want to use the following block primitive witness generator (which
        // uses async code on the inside) in combination with async code. We
        // make this test function async because we would be entering into the
        // same runtime twice. Therefore, we generate the block primitive
        // witness once, in this synchronous wrapper, and continue
        // asynchronously with the helper function.

        // Build on top of a chain at the UpgradeVMv5 fork height. Producing new
        // blocks only works under the current (v5) rule set: pre-v5 history is
        // verifiable via hardcoded per-era program digests but cannot be
        // *extended*, since those claims reference digests that no v5 bytecode
        // reproduces.
        use crate::protocol::consensus::block::difficulty_control::Difficulty;
        let init_block_heigth = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET;
        // MINIMUM difficulty so PoW guessing for the mined blocks is instant; the
        // STARK proving cost is unchanged (independent of difficulty).
        let bpw = BlockPrimitiveWitness::deterministic_with_block_height_and_difficulty(
            init_block_heigth,
            Difficulty::MINIMUM,
        );

        tokio_runtime().block_on(new_blocks_at_upgrade_vm_height_async(bpw));
    }

    async fn new_blocks_at_upgrade_vm_height_async(block_primitive_witness: BlockPrimitiveWitness) {
        // 1. generate state synced to height
        let mut rng = StdRng::seed_from_u64(55512345);
        let network = Network::Main;
        let bob_wallet = WalletEntropy::new_pseudorandom(rng.random());
        let cli = cli_args::Args {
            network,
            compose: true,
            guess: true,
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            ..Default::default()
        };

        let (fake_genesis, block_10_000) =
            Block::fake_block_pair_genesis_and_child_from_witness(block_primitive_witness).await;
        let mut now = block_10_000.header().timestamp;
        assert!(block_10_000.is_valid(&fake_genesis, now, network).await);

        let mut bob = mock_genesis_global_state_with_block(0, bob_wallet, cli, fake_genesis).await;
        bob.set_new_tip(block_10_000.clone()).await.unwrap();

        let observed_block_height = bob.lock_guard().await.chain.light_state().header().height;
        assert_eq!(
            BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET,
            observed_block_height,
        );

        // 2. mine the first 2 post-fork blocks (57651, 57652) under UpgradeVMv5,
        //    confirming each is BOTH consensus-valid AND proof-of-work mineable.
        use crate::protocol::consensus::block::pow::Pow;
        use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
        eprintln!(
            "\n=== UpgradeVMv5 mining readiness: chain synced to fork height {observed_block_height} ==="
        );
        let blocks_to_mine = 2;
        let mut predecessor = block_10_000;
        for i in 1..=blocks_to_mine {
            now += Timestamp::hours(1);
            let next_height = predecessor.header().height.next();
            eprintln!(
                "\n[mine {i}/{blocks_to_mine}] height {next_height}: composing + proving (coinbase SingleProof + block proof) ..."
            );
            let (next_block, expected_composer_utxos) = mine_to_own_wallet(bob.clone(), now).await;

            // a) consensus validity: every block/tx proof verifies under UpgradeVMv5.
            assert!(
                next_block.is_valid(&predecessor, now, network).await,
                "height {next_height}: block must be consensus-valid under UpgradeVMv5",
            );
            eprintln!("[mine {i}/{blocks_to_mine}] height {next_height}: consensus-valid [OK] (all proofs verify)");

            // b) proof-of-work: grind a winning nonce at the block's own difficulty
            //    and verify it — i.e. prove the block is actually *mineable*. Done
            //    on a clone so the tip-chain stays byte-identical to a real node's.
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, next_height);
            let target = next_block.header().difficulty.target();
            let mut pow_block = next_block.clone();
            let mast_auth_paths = pow_block.pow_mast_paths();
            let guesser_buffer = pow_block.guess_preprocess(None, None, consensus_rule_set);
            let index_picker_preimage = guesser_buffer.index_picker_preimage(&mast_auth_paths);
            let mut guesses = 0u64;
            let valid_pow = loop {
                guesses += 1;
                if let Some(valid_pow) = Pow::guess(
                    &guesser_buffer,
                    &mast_auth_paths,
                    index_picker_preimage,
                    rng.random(),
                    target,
                ) {
                    break valid_pow;
                }
            };
            pow_block.set_header_pow(valid_pow);
            assert!(
                pow_block.pow_verify(target, consensus_rule_set),
                "height {next_height}: solved PoW must verify",
            );
            eprintln!(
                "[mine {i}/{blocks_to_mine}] height {next_height}: PoW solved in {guesses} guesses + verified [MINEABLE]"
            );

            // c) the GUESSER fee for this block must be a positive, UNLOCKED
            //    (immediately-spendable) reward. The guesser fee UTXOs are derived
            //    straight off the block, so they can be checked here. (The COMPOSER
            //    reward lands in the wallet and is verified after the loop via
            //    spendable_inputs, which only counts non-time-locked UTXOs.) This
            //    is the period-0 coinbase fix in action: under v4 a time-locked
            //    reward would have tripped the coinbase rule.
            let guesser_utxos = next_block.kernel.guesser_fee_utxos().unwrap();
            let guesser_total = guesser_utxos
                .iter()
                .map(|u| u.get_native_currency_amount())
                .sum::<NativeCurrencyAmount>();
            assert!(
                !guesser_utxos.is_empty() && guesser_total.is_positive(),
                "height {next_height}: guesser must earn a positive fee",
            );
            assert!(
                guesser_utxos.iter().all(|u| u.release_date().is_none()),
                "height {next_height}: guesser fee UTXOs must be UNLOCKED (liquid)",
            );
            eprintln!(
                "[mine {i}/{blocks_to_mine}] height {next_height}: guesser earns {:.6} coins ({} UTXO) — UNLOCKED [OK]",
                guesser_total.to_coins_f64_lossy(),
                guesser_utxos.len(),
            );

            bob.set_new_self_composed_tip(next_block.clone(), expected_composer_utxos)
                .await
                .unwrap();
            predecessor = next_block;
        }
        eprintln!(
            "\n=== {blocks_to_mine} post-fork blocks: composed + proven + validated + mined [OK] ===\n"
        );

        let hopefully_plus_5 = bob.lock_guard().await.chain.light_state().header().height;
        assert_eq!(
            BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET + 2,
            hopefully_plus_5
        );
        // The COMPOSER reward landed in the wallet and must be UNLOCKED: it shows
        // up as confirmed, spendable balance. `spendable_inputs` only counts
        // immediately-spendable (non-time-locked) UTXOs, so a positive count here
        // proves the composer earned liquid coins under v5.
        let composer_available = bob.api().wallet().balances(now).await.confirmed_available;
        let spendable_inputs = bob.api().wallet().spendable_inputs(now, 0).await;
        assert!(
            composer_available.is_positive(),
            "composer must earn spendable (unlocked) balance",
        );
        assert_eq!(
            blocks_to_mine,
            spendable_inputs.len(),
            "Bob must have {blocks_to_mine} spendable inputs after mining {blocks_to_mine} blocks"
        );
        eprintln!(
            "composer earned {:.6} coins across {} UNLOCKED spendable UTXO(s) [OK]",
            composer_available.to_coins_f64_lossy(),
            spendable_inputs.len(),
        );

        // 3. create a block with many outputs so some owned UTXOs get non-empty
        //    chunk dictionaries — checks membership-proof/removal-record updates
        //    across the fork. Kept to 1 block to keep this run focused.
        let num_blocks_with_many_outputs = 1;
        for j in 1..=num_blocks_with_many_outputs {
            now += Timestamp::hours(1);
            let next_height = predecessor.header().height.next();
            eprintln!("[outputs {j}/{num_blocks_with_many_outputs}] height {next_height}: composing block with 24 outputs ...");
            let next_block = block_with_n_outputs(bob.clone(), 24, now).await;
            assert!(next_block.is_valid(&predecessor, now, network).await);
            bob.set_new_tip(next_block.clone()).await.unwrap();
            predecessor = next_block;
            eprintln!("[outputs {j}/{num_blocks_with_many_outputs}] height {next_height}: valid + applied [OK]");
        }
        eprintln!("\n=== TEST PASSED: v5 blocks are composable, provable, valid, and mineable ===\n");
    }

    #[test]
    fn timelock_extension_inactive_on_main_below_activation_height() {
        let below = BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET
            .previous()
            .expect("activation height should not be genesis");
        let rule_set = ConsensusRuleSet::infer_from(Network::Main, below);
        assert_ne!(
            rule_set,
            ConsensusRuleSet::TimelockExtension,
            "TimelockExtension must NOT activate one block before its mainnet activation height"
        );
    }

    #[test]
    fn timelock_extension_active_on_main_at_activation_height() {
        let activation = BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET;
        let rule_set = ConsensusRuleSet::infer_from(Network::Main, activation);
        assert_eq!(
            rule_set,
            ConsensusRuleSet::TimelockExtension,
            "TimelockExtension must activate at exactly its mainnet activation height"
        );
    }

    #[test]
    fn timelock_extension_never_activates_off_mainnet() {
        // The fork is mainnet-only. Off-mainnet networks (Testnet, RegTest,
        // TestnetMock) run the newest ruleset (UpgradeVMv5) from genesis, so they
        // never pass through the TimelockExtension ruleset regardless of height.
        let high = BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET;
        for nw in [
            Network::Testnet(0),
            Network::Testnet(255),
            Network::RegTest,
            Network::TestnetMock,
        ] {
            assert_eq!(
                ConsensusRuleSet::infer_from(nw, high),
                ConsensusRuleSet::UpgradeVMv5,
                "{nw:?} must never activate TimelockExtension"
            );
        }
    }

    #[test]
    fn upgrade_vm_active_on_main_at_activation_height() {
        let activation = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET;
        let rule_set = ConsensusRuleSet::infer_from(Network::Main, activation);
        assert_eq!(
            rule_set,
            ConsensusRuleSet::UpgradeVM,
            "UpgradeVM must activate at exactly its mainnet activation height"
        );
    }

    #[test]
    fn upgrade_vm_v4_active_on_main_at_activation_height() {
        // At exactly the v4 activation height, mainnet switches to UpgradeVMv4;
        // one block below it, mainnet is still on UpgradeVM (v3 verifier).
        let activation = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET;
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation),
            ConsensusRuleSet::UpgradeVMv4,
            "UpgradeVMv4 must activate at exactly its mainnet activation height"
        );
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation.previous().unwrap()),
            ConsensusRuleSet::UpgradeVM,
            "the block below the v4 height must still be UpgradeVM (v3 verifier)"
        );
    }

    #[test]
    fn upgrade_vm_v5_active_on_main_at_activation_height() {
        // At exactly the v5 activation height, mainnet switches to UpgradeVMv5;
        // one block below it, mainnet is still on UpgradeVMv4 (v4 verifier).
        let activation = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET;
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation),
            ConsensusRuleSet::UpgradeVMv5,
            "UpgradeVMv5 must activate at exactly its mainnet activation height"
        );
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation.previous().unwrap()),
            ConsensusRuleSet::UpgradeVMv4,
            "the block below the v5 height must still be UpgradeVMv4 (v4 verifier)"
        );
    }


    #[test]
    fn current_v5_program_hashes_are_stable() {
        // Drift-detection for the CURRENT (UpgradeVMv5 / triton-vm v5) program
        // hashes. If any of these change accidentally, the activation height
        // would refer to a different program-set and the fork would become
        // incompatible.
        //
        // NOTE: the triton-vm v5 ISA change re-hashed only the proof programs
        // that embed the STARK verifier. `TimeLockV2` and `CollectTypeScriptsV2`
        // are byte-identical to v4 (their digests did NOT change); only
        // `SingleProofV2` (and `BlockProgram`) moved v4 -> v5.
        use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
        use crate::protocol::consensus::transaction::validity::single_proof_v2::SingleProofV2;
        use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;
        use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

        // Unchanged across v4 -> v5.
        let timelock_v2 = TimeLockV2.hash().to_hex();
        assert_eq!(
            timelock_v2,
            "8b6d23e675c97cb8e1d36a5e926f19449d37673636c64c0769b7778aded85ff29056832e366b580b",
            "TimeLockV2 program hash drifted"
        );

        let cts_v2 = CollectTypeScriptsV2.hash().to_hex();
        assert_eq!(
            cts_v2,
            "1d33643dc5086e915e44d720af4a1efa195254aee6497166f5055a7bcb0d8313ce70f77fe0632c4e",
            "CollectTypeScriptsV2 program hash drifted"
        );

        // Re-hashed v4 (15312e1a…) -> v5.
        let sp_v2 = SingleProofV2.hash().to_hex();
        assert_eq!(
            sp_v2,
            "e66985a98e4d5e455c5d11e57a16c3dca3cce2bd2a16d6f5e791f592801cc32eb99c57c32bf90e88",
            "SingleProofV2 program hash drifted"
        );
    }
}
