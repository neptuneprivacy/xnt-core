//! Consolidation of UTXOs: spend a batch of the wallet's oldest UTXOs to a
//! single output, reducing the number of UTXOs under management.

use num_traits::CheckedSub;
use tracing::debug;
use tracing::info;

use crate::api::export::Timestamp;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::error::CreateTxError;
use crate::api::tx_initiation::error::SendError;
use crate::api::tx_initiation::initiator::TransactionInitiator;
use crate::application::config::auto_consolidation::MAX_NUM_CONSOLIDATION_INPUTS;
use crate::application::config::auto_consolidation::MIN_NUM_CONSOLIDATION_INPUTS;
use crate::application::triton_vm_job_queue::vm_job_queue;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;
use crate::state::wallet::address::KeyType;
use crate::state::wallet::address::ReceivingAddress;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::state::wallet::transaction_input::TxInput;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;

/// Fee for a consolidation transaction initiated by a node that can only
/// produce proof collections. A third party has to upgrade the transaction,
/// and is paid for that out of this fee.
pub const CONSOLIDATION_FEE_PC: NativeCurrencyAmount =
    NativeCurrencyAmount::from_nau(NativeCurrencyAmount::coin_as_nau() / 10);

/// Fee for a consolidation transaction initiated by a node that produces the
/// single proof itself.
pub const CONSOLIDATION_FEE_SP: NativeCurrencyAmount =
    NativeCurrencyAmount::from_nau(NativeCurrencyAmount::coin_as_nau() / 200);

/// Inputs with less than this number of confirmations will not be selected for
/// consolidation.
pub const NUM_CONFIRMATIONS_REQUIRED_FOR_CONSOLIDATION: usize = 10;

/// Derivation index of the Generation key that receives consolidated funds
/// when no address is given. Index 0 is the key every wallet derives from the
/// seed, including the mobile wallet, so the funds stay visible everywhere
/// the seed is used. No wallet counter is advanced.
pub const CONSOLIDATION_KEY_INDEX: u64 = 0;

/// Inputs of transactions this wallet sent within this many recent blocks are
/// not selected, also when those transactions are no longer in the mempool.
const NUM_RECENT_BLOCKS_EXCLUDED: usize = 3;

impl TransactionInitiator {
    /// Initiate a transaction that spends a batch of UTXOs to the node's own
    /// wallet, thereby reducing the total number of UTXOs under management.
    ///
    /// Spends exactly `num_inputs` of the oldest spendable UTXOs that have at
    /// least [`NUM_CONFIRMATIONS_REQUIRED_FOR_CONSOLIDATION`] confirmations,
    /// and fails if fewer qualify. The fee is fixed per transaction and
    /// depends on the node's proving capability, see [`CONSOLIDATION_FEE_SP`]
    /// and [`CONSOLIDATION_FEE_PC`]. The single output goes to
    /// `consolidation_address` if set, else to this wallet's Generation key at
    /// [`CONSOLIDATION_KEY_INDEX`], and is always announced on-chain so that it
    /// can be recovered from the seed.
    ///
    /// Returns the number of inputs consumed by the consolidating transaction.
    pub async fn consolidate(
        &mut self,
        num_inputs: usize,
        consolidation_address: Option<ReceivingAddress>,
        timestamp: Timestamp,
    ) -> Result<usize, ConsolidationError> {
        debug!("consolidate: Attempting to consolidate {num_inputs} UTXOs in wallet");

        let allowed_num_inputs =
            usize::from(MIN_NUM_CONSOLIDATION_INPUTS)..=usize::from(MAX_NUM_CONSOLIDATION_INPUTS);
        if !allowed_num_inputs.contains(&num_inputs) {
            return Err(ConsolidationError::InvalidNumInputs {
                requested: num_inputs,
            });
        }

        let capability = self.global_state_lock.cli().proving_capability();
        let fee = match capability {
            TxProvingCapability::LockScript | TxProvingCapability::PrimitiveWitness => {
                return Err(ConsolidationError::NoTransactionInitiation);
            }
            TxProvingCapability::ProofCollection => CONSOLIDATION_FEE_PC,
            TxProvingCapability::SingleProof => CONSOLIDATION_FEE_SP,
        };

        self.private()
            .check_proceed_with_send(fee)
            .await
            .map_err(ConsolidationError::from_send_error)?;

        let tip_height = self
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height;
        let network = self.global_state_lock.cli().network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, tip_height);
        if consensus_rule_set.is_legacy_era() {
            return Err(ConsolidationError::LegacyEra(consensus_rule_set));
        }

        let selected_inputs = self.consolidation_inputs(num_inputs, timestamp).await;

        let num_selected_inputs = selected_inputs.len();
        if num_selected_inputs < num_inputs {
            debug!(
                "Nothing to consolidate in wallet as only {num_selected_inputs} were available \
                 for consolidation"
            );
            return Err(ConsolidationError::NotEnoughUtxos {
                requested: num_inputs,
                present: num_selected_inputs,
            });
        }

        let unlocked_amount: NativeCurrencyAmount = selected_inputs
            .iter()
            .map(|input| input.native_currency_amount())
            .sum();
        debug!(
            "Selected {} inputs for consolidation, in total amount {}.",
            num_selected_inputs, unlocked_amount
        );

        let output_amount = unlocked_amount
            .checked_sub(&fee)
            .filter(|amount| amount.is_positive())
            .ok_or(ConsolidationError::Dust {
                amount: unlocked_amount,
                fee,
            })?;

        let receiving_address = match consolidation_address {
            Some(address) => address,
            None => self
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .nth_spending_key(KeyType::Generation, CONSOLIDATION_KEY_INDEX)
                .to_address(),
        };

        // Announce the output on-chain even when it is owned by this wallet,
        // so that it can be found again from the seed alone.
        let outputs = self
            .generate_tx_outputs(vec![OutputFormat::AddressAndAmountAndMedium(
                receiving_address,
                output_amount,
                UtxoNotificationMedium::OnChain,
            )])
            .await;

        let tx_details = TransactionDetailsBuilder::new()
            .timestamp(timestamp)
            .inputs(selected_inputs.into())
            .outputs(outputs)
            .fee(fee)
            .change_policy(ChangePolicy::ExactChange)
            .build(&mut self.global_state_lock.clone().into())
            .await?;

        // The proof is upgraded by the main loop, like for any other
        // transaction this node initiates.
        let options = TritonVmProofJobOptionsBuilder::new()
            .template(&self.global_state_lock.cli().as_proof_job_options())
            .proof_type(TransactionProofType::PrimitiveWitness)
            .build();
        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .transaction_details(&tx_details)
            .job_queue(vm_job_queue())
            .proof_job_options(options)
            .build()
            .await
            .map_err(|err| ConsolidationError::CreateProofError(err.to_string()))?;

        let transaction = self.assemble_transaction(&tx_details, proof)?;
        let artifacts = TxCreationArtifactsBuilder::new()
            .transaction_details(tx_details)
            .transaction(transaction)
            .build()?;

        info!("creating consolidation transaction");

        self.record_and_broadcast_transaction(&artifacts)
            .await
            .map_err(ConsolidationError::from_send_error)?;

        info!("consolidation transaction recorded and broadcast");

        Ok(num_selected_inputs)
    }

    /// The oldest spendable UTXOs with enough confirmations for consolidation,
    /// at most `num_inputs` of them.
    async fn consolidation_inputs(&self, num_inputs: usize, timestamp: Timestamp) -> Vec<TxInput> {
        // Read the tip height first: should the tip move while the inputs are
        // collected, confirmations are undercounted rather than overcounted.
        let tip_height = self
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height;
        let spendable_inputs: Vec<TxInput> = self
            .spendable_inputs(timestamp, NUM_RECENT_BLOCKS_EXCLUDED)
            .await
            .into();
        let confirmation_heights = self
            .global_state_lock
            .lock_guard()
            .await
            .wallet_state
            .confirmation_heights()
            .await;
        let next_block_height = tip_height.next();

        let mut candidates: Vec<(u64, TxInput)> = spendable_inputs
            .into_iter()
            .filter_map(|input| {
                let aocl_leaf_index = input.mutator_set_mp().aocl_leaf_index;
                let confirmed_in = *confirmation_heights.get(&aocl_leaf_index)?;
                let num_confirmations =
                    usize::try_from(next_block_height - confirmed_in).unwrap_or(0);
                (num_confirmations >= NUM_CONFIRMATIONS_REQUIRED_FOR_CONSOLIDATION)
                    .then_some((aocl_leaf_index, input))
            })
            .collect();

        // A lower AOCL leaf index means an older UTXO.
        candidates.sort_by_key(|(aocl_leaf_index, _)| *aocl_leaf_index);

        candidates
            .into_iter()
            .take(num_inputs)
            .map(|(_, input)| input)
            .collect()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ConsolidationError {
    #[error(
        "Cannot consolidate {requested} UTXOs: a consolidation transaction has between \
         {MIN_NUM_CONSOLIDATION_INPUTS} and {MAX_NUM_CONSOLIDATION_INPUTS} inputs."
    )]
    InvalidNumInputs { requested: usize },

    #[error(
        "Not enough UTXOs for consolidation: {present} UTXOs qualify but attempting to \
         consolidate {requested}."
    )]
    NotEnoughUtxos { requested: usize, present: usize },

    #[error(
        "Cannot initiate consolidation transaction because node is not initiating transactions."
    )]
    NoTransactionInitiation,

    #[error("Cannot initiate consolidation transaction in the {0} era.")]
    LegacyEra(ConsensusRuleSet),

    #[error(
        "Cannot consolidate dust UTXOs because total amount {amount} is not worth fee of {fee}."
    )]
    Dust {
        amount: NativeCurrencyAmount,
        fee: NativeCurrencyAmount,
    },

    #[error("Error creating transaction: {0}.")]
    CreateTxError(#[from] CreateTxError),

    #[error("Error creating proof: {0}.")]
    CreateProofError(String),

    #[error("Error sending consolidation transaction: {0}")]
    SendError(String),
}

impl ConsolidationError {
    /// Whether the error only means that there is nothing to consolidate
    /// right now, as opposed to a failure worth reporting.
    pub fn is_nothing_to_do(&self) -> bool {
        matches!(
            self,
            Self::NotEnoughUtxos { .. } | Self::Dust { .. } | Self::LegacyEra(_)
        )
    }

    fn from_send_error(error: SendError) -> Self {
        match error {
            // CLI flag `--no-transaction-initiation`
            SendError::Unsupported => Self::NoTransactionInitiation,
            SendError::Tx(create_tx_error) => Self::CreateTxError(create_tx_error),
            other => Self::SendError(other.to_string()),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::random;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::block::block_height::BlockHeight;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::transaction::Transaction;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;
    use crate::GlobalStateLock;

    /// A wallet that composed `num_blocks` blocks on top of genesis.
    async fn alice_with_mined_blocks(
        num_blocks: usize,
        capability: TxProvingCapability,
    ) -> GlobalStateLock {
        let network = Network::Main;
        let cli = cli_args::Args {
            tx_proving_capability: Some(capability),
            rate_limit_until_height: 0,
            ..cli_args::Args::default_with_network(network)
        };

        let wallet = WalletEntropy::new_random();
        let composer_key = wallet.nth_generation_spending_key_for_tests(0);
        let mut alice = mock_genesis_global_state(0, wallet, cli).await;

        let mut tip = Block::genesis(network);
        for _ in 0..num_blocks {
            let timestamp = tip.header().timestamp + Timestamp::minutes(10);
            let (block, expected_utxos) =
                make_mock_block(&tip, Some(timestamp), composer_key, random(), network).await;
            alice
                .set_new_self_composed_tip(block.clone(), expected_utxos)
                .await
                .unwrap();
            tip = block;
        }

        alice
    }

    fn consolidation_timestamp(alice_tip: &Block) -> Timestamp {
        alice_tip.header().timestamp + Timestamp::minutes(1)
    }

    async fn tip(alice: &GlobalStateLock) -> Block {
        alice.lock_guard().await.chain.light_state().clone()
    }

    /// AOCL leaf index and confirmation height of each spendable UTXO, in
    /// ascending order of AOCL leaf index.
    async fn spendable_utxos(alice: &GlobalStateLock) -> Vec<(u64, BlockHeight)> {
        let timestamp = consolidation_timestamp(&tip(alice).await);
        let heights = alice
            .lock_guard()
            .await
            .wallet_state
            .confirmation_heights()
            .await;
        let inputs: Vec<TxInput> = alice
            .api()
            .tx_initiator()
            .spendable_inputs(timestamp, 0)
            .await
            .into();
        inputs
            .iter()
            .map(|input| {
                let aocl_leaf_index = input.mutator_set_mp().aocl_leaf_index;
                (aocl_leaf_index, heights[&aocl_leaf_index])
            })
            .sorted_by_key(|(aocl_leaf_index, _)| *aocl_leaf_index)
            .collect()
    }

    /// AOCL leaf indices of the spendable UTXOs confirmed at or below
    /// `max_height`, in ascending order.
    async fn spendable_confirmed_at_or_below(alice: &GlobalStateLock, max_height: u64) -> Vec<u64> {
        spendable_utxos(alice)
            .await
            .into_iter()
            .filter(|(_, height)| height.value() <= max_height)
            .map(|(aocl_leaf_index, _)| aocl_leaf_index)
            .collect()
    }

    async fn spendable_aocl_indices(alice: &GlobalStateLock) -> Vec<u64> {
        spendable_utxos(alice)
            .await
            .into_iter()
            .map(|(aocl_leaf_index, _)| aocl_leaf_index)
            .collect()
    }

    async fn spendable_amounts(alice: &GlobalStateLock) -> HashMap<u64, NativeCurrencyAmount> {
        let timestamp = consolidation_timestamp(&tip(alice).await);
        let inputs: Vec<TxInput> = alice
            .api()
            .tx_initiator()
            .spendable_inputs(timestamp, 0)
            .await
            .into();
        inputs
            .iter()
            .map(|input| {
                (
                    input.mutator_set_mp().aocl_leaf_index,
                    input.native_currency_amount(),
                )
            })
            .collect()
    }

    async fn only_mempool_transaction(alice: &GlobalStateLock) -> Transaction {
        let state = alice.lock_guard().await;
        assert_eq!(1, state.mempool.len(), "expected exactly one transaction");
        let (txid, _) = state.mempool.fee_density_iter().next().unwrap();
        state.mempool.get(txid).unwrap().clone()
    }

    async fn run_consolidation(
        alice: &GlobalStateLock,
        num_inputs: usize,
        address: Option<ReceivingAddress>,
    ) -> Result<usize, ConsolidationError> {
        let timestamp = consolidation_timestamp(&tip(alice).await);
        alice
            .api()
            .tx_initiator()
            .consolidate(num_inputs, address, timestamp)
            .await
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn consolidates_oldest_confirmed_utxos_into_one_onchain_output() {
        // At tip height 12, blocks 1 to 3 have at least 10 confirmations.
        let alice = alice_with_mined_blocks(12, TxProvingCapability::SingleProof).await;
        let old_enough = spendable_confirmed_at_or_below(&alice, 3).await;
        assert!(old_enough.len() >= 2, "need at least two old UTXOs");
        let spendable_before = spendable_aocl_indices(&alice).await;
        let amounts_before = spendable_amounts(&alice).await;

        let num_inputs = 2;
        assert_eq!(
            num_inputs,
            run_consolidation(&alice, num_inputs, None).await.unwrap()
        );

        let tx = only_mempool_transaction(&alice).await;
        assert_eq!(num_inputs, tx.kernel.inputs.len());
        assert_eq!(1, tx.kernel.outputs.len());
        assert_eq!(
            1,
            tx.kernel.announcements.len(),
            "output must be announced on-chain"
        );
        assert_eq!(CONSOLIDATION_FEE_SP, tx.kernel.fee);

        // The two oldest qualifying UTXOs are the ones spent.
        let spendable_after = spendable_aocl_indices(&alice).await;
        let spent = spendable_before
            .iter()
            .filter(|index| !spendable_after.contains(index))
            .copied()
            .collect_vec();
        assert_eq!(old_enough[..num_inputs].to_vec(), spent);

        // The output goes to this wallet's Generation key at the fixed index,
        // and is found by scanning the announcement with that key alone, as a
        // wallet restored from the seed does.
        let key = alice
            .lock_guard()
            .await
            .wallet_state
            .nth_spending_key(KeyType::Generation, CONSOLIDATION_KEY_INDEX);
        let found = key.scan_for_announced_utxos(&tx.kernel);
        assert_eq!(1, found.len());
        assert!(tx.kernel.outputs.contains(&found[0].addition_record()));
        let total: NativeCurrencyAmount = old_enough[..num_inputs]
            .iter()
            .map(|index| amounts_before[index])
            .sum();
        assert_eq!(
            total.checked_sub(&CONSOLIDATION_FEE_SP).unwrap(),
            found[0].utxo.get_native_currency_amount()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn ignores_utxos_with_too_few_confirmations() {
        // At tip height 9, no block has 10 confirmations yet.
        let alice = alice_with_mined_blocks(9, TxProvingCapability::SingleProof).await;
        assert!(!spendable_aocl_indices(&alice).await.is_empty());

        let result = run_consolidation(&alice, 2, None).await;
        assert!(matches!(
            result,
            Err(ConsolidationError::NotEnoughUtxos {
                requested: 2,
                present: 0
            })
        ));
        assert!(alice.lock_guard().await.mempool.is_empty());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn never_consolidates_fewer_inputs_than_requested() {
        let alice = alice_with_mined_blocks(12, TxProvingCapability::SingleProof).await;
        let old_enough = spendable_confirmed_at_or_below(&alice, 3).await;

        let requested = old_enough.len() + 1;
        let result = run_consolidation(&alice, requested, None).await;
        let Err(ConsolidationError::NotEnoughUtxos { present, .. }) = result else {
            panic!("expected NotEnoughUtxos, got {result:?}");
        };
        assert_eq!(old_enough.len(), present);
        assert!(alice.lock_guard().await.mempool.is_empty());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn never_consolidates_a_single_input() {
        let alice = alice_with_mined_blocks(12, TxProvingCapability::SingleProof).await;
        let result = run_consolidation(&alice, 1, None).await;
        assert!(matches!(
            result,
            Err(ConsolidationError::InvalidNumInputs { requested: 1 })
        ));
        assert!(alice.lock_guard().await.mempool.is_empty());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn consolidates_to_a_fixed_address() {
        let alice = alice_with_mined_blocks(12, TxProvingCapability::SingleProof).await;
        let address: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(random()).into();

        assert_eq!(
            2,
            run_consolidation(&alice, 2, Some(address)).await.unwrap()
        );

        let tx = only_mempool_transaction(&alice).await;
        assert_eq!(1, tx.kernel.outputs.len());
        assert_eq!(1, tx.kernel.announcements.len());

        let found_by_own_keys = alice
            .lock_guard()
            .await
            .wallet_state
            .get_known_spending_keys(KeyType::Generation)
            .flat_map(|key| key.scan_for_announced_utxos(&tx.kernel))
            .count();
        assert_eq!(0, found_by_own_keys);
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn fee_follows_proving_capability() {
        let alice = alice_with_mined_blocks(12, TxProvingCapability::ProofCollection).await;
        assert_eq!(2, run_consolidation(&alice, 2, None).await.unwrap());
        assert_eq!(
            CONSOLIDATION_FEE_PC,
            only_mempool_transaction(&alice).await.kernel.fee
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn requires_proof_collection_capability() {
        let alice = alice_with_mined_blocks(12, TxProvingCapability::PrimitiveWitness).await;
        assert!(matches!(
            run_consolidation(&alice, 2, None).await,
            Err(ConsolidationError::NoTransactionInitiation)
        ));
        assert!(alice.lock_guard().await.mempool.is_empty());
    }

    #[test]
    fn fees_are_as_specified() {
        assert_eq!(
            NativeCurrencyAmount::coins_from_str("0.005").unwrap(),
            CONSOLIDATION_FEE_SP
        );
        assert_eq!(
            NativeCurrencyAmount::coins_from_str("0.1").unwrap(),
            CONSOLIDATION_FEE_PC
        );
    }
}
