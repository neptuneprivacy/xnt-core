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
    BlockHeight::new(BFieldElement::new(55500u64));

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
}

impl TritonProofVersion {
    /// The `version` field stamped into a [`Claim`]: triton-vm's own
    /// proof-format version (0 for v1.0.0, 1 for v2.0.0+), which is distinct
    /// from the crate major named by this enum.
    pub(crate) fn claim_version(self) -> u32 {
        match self {
            TritonProofVersion::V1 => 0,
            TritonProofVersion::V2 | TritonProofVersion::V3 => 1,
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
        }
    }

    /// Rule sets whose proofs the current verifier cannot check, so their
    /// blocks are trusted (checkpointed) rather than re-verified. These are the
    /// proof-version-0 eras (triton-vm v1.0.0): the v3 verifier only handles
    /// proof version 1, so Reboot/HardforkAlpha proofs are unverifiable here.
    /// Xnt and TimelockExtension are proof version 1 and ARE re-verified, using
    /// their hardcoded pre-upgrade program digests.
    pub(crate) fn proofs_are_trusted(&self) -> bool {
        matches!(
            self,
            ConsensusRuleSet::Reboot | ConsensusRuleSet::HardforkAlpha
        )
    }

    /// Maximum block size in number of BFieldElements
    pub(crate) const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM => {
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
                } else {
                    ConsensusRuleSet::UpgradeVM
                }
            }
            Network::TestnetMock | Network::RegTest | Network::Testnet(_) => {
                ConsensusRuleSet::UpgradeVM
            }
        }
    }

    pub(crate) fn max_num_inputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_outputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_announcements(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
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

    #[traced_test]
    #[test]
    fn new_blocks_at_upgrade_vm_height() {
        // We want to use the following block primitive witness generator (which
        // uses async code on the inside) in combination with async code. We
        // make this test function async because we would be entering into the
        // same runtime twice. Therefore, we generate the block primitive
        // witness once, in this synchronous wrapper, and continue
        // asynchronously with the helper function.

        // Build on top of a chain at the UpgradeVM fork height. Producing new
        // blocks only works under the current (v3) rule set: pre-UpgradeVM
        // history is verifiable via hardcoded per-era program digests but cannot
        // be *extended*, since those claims reference digests that no v3
        // bytecode reproduces.
        let init_block_heigth = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET;
        let bpw = BlockPrimitiveWitness::deterministic_with_block_height(init_block_heigth);

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
            BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET,
            observed_block_height,
        );

        // 2. get a positive balance, by mining.
        let blocks_to_mine = 5;
        let mut predecessor = block_10_000;
        for _ in 0..blocks_to_mine {
            now += Timestamp::hours(1);
            let (next_block, expected_composer_utxos) = mine_to_own_wallet(bob.clone(), now).await;
            assert!(next_block.is_valid(&predecessor, now, network).await);
            bob.set_new_self_composed_tip(next_block.clone(), expected_composer_utxos)
                .await
                .unwrap();
            predecessor = next_block;
        }

        let hopefully_plus_5 = bob.lock_guard().await.chain.light_state().header().height;
        assert_eq!(
            BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET + 5,
            hopefully_plus_5
        );
        assert!(
            bob.api()
                .wallet()
                .balances(now)
                .await
                .confirmed_available
                .is_positive(),
            "Bob must have money"
        );
        assert_eq!(
            blocks_to_mine,
            bob.api().wallet().spendable_inputs(now, 0).await.len(),
            "Bob must have {blocks_to_mine} spendable inputs after mining {blocks_to_mine} blocks"
        );

        // 3. create blocks with enough outputs to give some/all owned UTXOs
        //    non-empty chunk dictionaries. This serves to check that the
        //    membership proofs/removal records are updated correctly.
        let num_blocks_with_many_outputs = 4;
        for _ in 0..num_blocks_with_many_outputs {
            now += Timestamp::hours(1);
            let next_block = block_with_n_outputs(bob.clone(), 24, now).await;
            assert!(next_block.is_valid(&predecessor, now, network).await);
            bob.set_new_tip(next_block.clone()).await.unwrap();
            predecessor = next_block;
        }
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
        // TestnetMock) run UpgradeVM from genesis, so they never pass through
        // the TimelockExtension ruleset regardless of block height.
        let high = BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET;
        for nw in [
            Network::Testnet(0),
            Network::Testnet(255),
            Network::RegTest,
            Network::TestnetMock,
        ] {
            assert_eq!(
                ConsensusRuleSet::infer_from(nw, high),
                ConsensusRuleSet::UpgradeVM,
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
    fn timelock_extension_program_hashes_are_stable() {
        // Frozen hashes from the hardfork commits. If any of these change
        // accidentally, the activation height will refer to a different
        // program-set and the fork will become incompatible.
        use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
        use crate::protocol::consensus::transaction::validity::single_proof_v2::SingleProofV2;
        use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;
        use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

        let timelock_v2 = TimeLockV2.hash().to_hex();
        assert_eq!(
            timelock_v2,
            "f4a43667f051636c8c7e0c8d25cc7eeecfc8f8d2e8aa8d9f36e51eaa473219b20950f2844ea504ce",
            "TimeLockV2 program hash drifted"
        );

        let cts_v2 = CollectTypeScriptsV2.hash().to_hex();
        assert_eq!(
            cts_v2,
            "253714df987bb7ff9c017de9cd25683274ec0597f9879a31dfc6a7faac10a7e32ca2fc8e26316575",
            "CollectTypeScriptsV2 program hash drifted"
        );

        let sp_v2 = SingleProofV2.hash().to_hex();
        assert_eq!(
            sp_v2,
            "6f6ea3083e506c048203a8505f8793aa70e4b1f610a352b14360f9e3fde21aa9373d607ddcf69888",
            "SingleProofV2 program hash drifted"
        );
    }
}
