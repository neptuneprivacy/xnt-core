//! Migration of funds held at legacy-format dCTIDH locks: spend a batch of
//! such UTXOs to a single output at a current-format lock.
//!
//! Funds at legacy-format locks are not part of the available balance. See
//! [`TransactionInitiator::migrate_dctidh_utxos`].

use std::cmp::Reverse;
use std::collections::HashSet;

use anyhow::bail;
use anyhow::ensure;
use num_traits::CheckedSub;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tracing::info;
use tracing::warn;

use crate::api::export::Timestamp;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::consolidate::CONSOLIDATION_FEE_PC;
use crate::api::tx_initiation::consolidate::CONSOLIDATION_FEE_SP;
use crate::api::tx_initiation::error::CreateTxError;
use crate::api::tx_initiation::error::SendError;
use crate::api::tx_initiation::initiator::TransactionInitiator;
use crate::api::tx_initiation::legacy_era::check_proof_collection_terms;
use crate::api::tx_initiation::legacy_era::legacy_era_max_num_inputs;
use crate::api::tx_initiation::legacy_era::rule_set_for_new_transaction;
use crate::application::config::network::Network;
use crate::application::database::storage::storage_schema::traits::StorageWriter;
use crate::application::triton_vm_job_queue::vm_job_queue;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::state::transaction::tx_creation_artifacts::TxCreationArtifacts;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;
use crate::state::wallet::address::KeyType;
use crate::state::wallet::address::ReceivingAddress;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::state::wallet::transaction_input::TxInput;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::state::wallet::wallet_state::WalletState;
use crate::state::RecordTransactionError;

/// Where [`TransactionInitiator::migrate_dctidh_utxos`] sends the moved funds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationDestination {
    /// An explicit destination address.
    Address(Box<ReceivingAddress>),

    /// A Generation address of this wallet: the one at the given derivation
    /// index, or else the next unused one, a new one for every transaction.
    Generation { index: Option<u64> },

    /// A current-format dCTIDH address of this wallet, chosen as for
    /// [`Self::Generation`].
    Dctidh { index: Option<u64> },
}

impl MigrationDestination {
    /// Parse a destination given as `generation`, `dctidh`, or a bech32m
    /// address for `network`. The derivation `index` applies to `generation`
    /// and `dctidh` only.
    ///
    /// Symmetric keys are not accepted as destinations. Whether an address can
    /// receive funds is checked where the transaction is built, see
    /// [`ReceivingAddress::validate_as_recipient`].
    pub fn parse(spec: &str, index: Option<u64>, network: Network) -> anyhow::Result<Self> {
        match spec {
            "generation" => Ok(Self::Generation { index }),
            "dctidh" => Ok(Self::Dctidh { index }),
            encoded => {
                ensure!(
                    index.is_none(),
                    "a derivation index applies to the destinations `generation` and `dctidh` \
                     only, not to an explicit address"
                );
                let address = ReceivingAddress::from_bech32m(encoded, network)?;
                if matches!(address, ReceivingAddress::Symmetric(_)) {
                    bail!("a symmetric key is not a destination address");
                }
                Ok(Self::Address(Box::new(address)))
            }
        }
    }
}

/// Whether the address belongs to one of the wallet's known keys.
pub(crate) fn is_own_address(wallet_state: &WalletState, address: &ReceivingAddress) -> bool {
    let lock_script_hash = address.lock_script_hash();
    wallet_state
        .get_all_known_addressable_spending_keys()
        .any(|key| key.lock_script_hash() == lock_script_hash)
}

/// The fee of a migration transaction with `num_inputs` inputs, when no fee is
/// given: the consolidation fee for the node's proving capability, see
/// [`CONSOLIDATION_FEE_PC`] and [`CONSOLIDATION_FEE_SP`], and no less than
/// `min_relay_fee_per_input` per input, the minimum at which peers relay a
/// proof-collection-backed transaction.
pub fn migration_fee(
    capability: TxProvingCapability,
    min_relay_fee_per_input: NativeCurrencyAmount,
    num_inputs: usize,
) -> NativeCurrencyAmount {
    let capability_fee = match capability {
        TxProvingCapability::ProofCollection => CONSOLIDATION_FEE_PC,
        TxProvingCapability::LockScript
        | TxProvingCapability::PrimitiveWitness
        | TxProvingCapability::SingleProof => CONSOLIDATION_FEE_SP,
    };
    let relay_minimum = u32::try_from(num_inputs)
        .ok()
        .and_then(|num_inputs| min_relay_fee_per_input.checked_scalar_mul(num_inputs));
    match relay_minimum {
        Some(relay_minimum) if relay_minimum > capability_fee => relay_minimum,
        _ => capability_fee,
    }
}

/// An input's share of the fee of a transaction with `num_inputs` inputs.
pub fn fee_share(fee: NativeCurrencyAmount, num_inputs: usize) -> NativeCurrencyAmount {
    let num_inputs = i128::try_from(num_inputs.max(1)).unwrap_or(i128::MAX);
    NativeCurrencyAmount::from_nau(fee.to_nau() / num_inputs)
}

/// The number of inputs to spend out of candidates with the given amounts,
/// sorted in descending order, and the fee: as many of the largest, at most
/// `max_inputs`, as are each worth more than their share of the fee. `None`
/// if no candidate is.
pub fn num_inputs_worth_moving(
    amounts: &[NativeCurrencyAmount],
    max_inputs: usize,
    fee_for: impl Fn(usize) -> NativeCurrencyAmount,
) -> Option<(usize, NativeCurrencyAmount)> {
    (1..=max_inputs.min(amounts.len()))
        .rev()
        .find_map(|num_inputs| {
            let fee = fee_for(num_inputs);
            (amounts[num_inputs - 1] > fee_share(fee, num_inputs)).then_some((num_inputs, fee))
        })
}

/// The outcome of one pass of [`TransactionInitiator::migrate_dctidh_utxos`].
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct DctidhMigrationReport {
    /// The transaction that moves the funds, if one was created.
    pub txid: Option<TransactionKernelId>,

    /// The number of UTXOs the transaction spends.
    pub num_inputs: usize,

    /// The amount the transaction sends to the destination.
    pub amount: NativeCurrencyAmount,

    /// The fee the transaction pays.
    pub fee: NativeCurrencyAmount,

    /// The number of spendable UTXOs at legacy-format dCTIDH locks that are
    /// left for later passes.
    pub num_waiting: usize,

    /// The amount held by the UTXOs left for later passes.
    pub amount_waiting: NativeCurrencyAmount,

    /// The number of UTXOs left for later passes that are not worth more than
    /// their share of the fee even in a full batch, and are not moved.
    pub num_dust: usize,

    /// The amount held by the UTXOs that are not moved for their size.
    pub amount_dust: NativeCurrencyAmount,

    /// The number of UTXOs left out of this pass because no valid transaction
    /// spends them.
    pub num_skipped: usize,
}

impl TransactionInitiator {
    /// Move funds held at legacy-format dCTIDH locks to `destination`,
    /// spending a batch of such UTXOs to one output.
    ///
    /// Only UTXOs at legacy-format dCTIDH locks are spent; everything else in
    /// the wallet is left untouched. The largest of them are spent first, at
    /// most `max_inputs`, and only those worth more than their share of the
    /// fee. The fee is `fee` if given, or else [`migration_fee`] for the
    /// node's proving capability and the number of inputs. The inputs, minus
    /// the fee, go to `destination` as one output, which is always announced
    /// on-chain, also when it is owned by this wallet, so that the moved funds
    /// can be found again from the seed alone. Because the destination is
    /// never a legacy-format lock, the moved funds are not selected again.
    ///
    /// A destination of this wallet with a derivation index at or above the
    /// wallet's counter raises the counter, so that the wallet watches it;
    /// without an index, every transaction goes to the next unused address.
    ///
    /// Inputs for which no valid transaction can be built are left out, and
    /// the others are spent. Call once per block to drain a large set; the
    /// returned report counts the UTXOs left for later.
    ///
    /// Before the `UpgradeVMv8` fork, the transaction is made for the legacy
    /// era (see [`legacy_era`](super::legacy_era)): it spends at most
    /// [`legacy_era_max_num_inputs`] inputs, pays at least the proof
    /// collection fee, and fails with
    /// [`CreateProofError::LegacyEra`](super::error::CreateProofError::LegacyEra)
    /// once the fork is too close.
    pub async fn migrate_dctidh_utxos(
        &mut self,
        destination: MigrationDestination,
        fee: Option<NativeCurrencyAmount>,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
        max_inputs: usize,
    ) -> Result<DctidhMigrationReport, SendError> {
        self.private()
            .check_proceed_with_send(fee.unwrap_or_else(NativeCurrencyAmount::zero))
            .await?;

        let tip_height = self
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height;
        let cli = self.global_state_lock.cli();
        let consensus_rule_set =
            rule_set_for_new_transaction(cli.network, tip_height, cli.fork_tx_cutoff_margin)?;

        let candidates = self
            .legacy_dctidh_inputs(timestamp, exclude_recent_blocks)
            .await;
        self.migrate_inputs(
            candidates,
            destination,
            fee,
            timestamp,
            max_inputs,
            consensus_rule_set,
        )
        .await
    }

    /// The spendable inputs held at legacy-format dCTIDH locks.
    async fn legacy_dctidh_inputs(
        &self,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
    ) -> Vec<TxInput> {
        let legacy_locks: HashSet<Digest> = self
            .global_state_lock
            .lock_guard()
            .await
            .wallet_state
            .legacy_dctidh_lock_hashes();
        let mut inputs: Vec<TxInput> = self
            .spendable_inputs(timestamp, exclude_recent_blocks)
            .await
            .into();
        inputs.retain(|input| legacy_locks.contains(&input.utxo.lock_script_hash()));
        inputs
    }

    /// Spend a batch of `candidates` to `destination`, see
    /// [`Self::migrate_dctidh_utxos`].
    async fn migrate_inputs(
        &mut self,
        mut candidates: Vec<TxInput>,
        destination: MigrationDestination,
        fixed_fee: Option<NativeCurrencyAmount>,
        timestamp: Timestamp,
        max_inputs: usize,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<DctidhMigrationReport, SendError> {
        let (capability, min_relay_fee_per_input, network) = {
            let cli = self.global_state_lock.cli();
            (
                cli.proving_capability(),
                cli.min_relay_pctx_fee_per_input,
                cli.network,
            )
        };

        // A transaction for the legacy era may end up with its proof
        // collection: it pays the proof collection fee, and has no more inputs
        // than that era's proof upgraders take, also with a time lock.
        let legacy_era = consensus_rule_set.is_legacy_era();
        let (capability, max_inputs) = if legacy_era {
            (
                TxProvingCapability::ProofCollection,
                max_inputs.min(legacy_era_max_num_inputs(2)),
            )
        } else {
            (capability, max_inputs)
        };
        let fee_for = |num_inputs| {
            fixed_fee
                .unwrap_or_else(|| migration_fee(capability, min_relay_fee_per_input, num_inputs))
        };
        let dust_threshold = fee_share(fee_for(max_inputs), max_inputs);

        candidates.sort_by_key(|input| Reverse(input.native_currency_amount()));

        let mut skipped = vec![];
        let mut destination_address = None;
        loop {
            let amounts = candidates
                .iter()
                .map(TxInput::native_currency_amount)
                .collect::<Vec<_>>();
            let Some((num_inputs, fee)) = num_inputs_worth_moving(&amounts, max_inputs, fee_for)
            else {
                return Ok(Self::migration_report(
                    None,
                    &[],
                    &candidates,
                    &skipped,
                    dust_threshold,
                ));
            };

            // Derive the destination only once there is something to move,
            // so that no address is used up for nothing.
            let address = match destination_address.take() {
                Some(address) => address,
                None => self.migration_address(&destination).await,
            };

            let rest = candidates.split_off(num_inputs);
            let inputs = std::mem::replace(&mut candidates, rest);
            let artifacts = self
                .migration_transaction(
                    inputs.clone(),
                    address.clone(),
                    fee,
                    timestamp,
                    consensus_rule_set,
                )
                .await?;
            if legacy_era {
                check_proof_collection_terms(&artifacts.details.primitive_witness())?;
            }
            let error = match self.record_and_broadcast_transaction(&artifacts).await {
                Ok(()) => {
                    let txid = artifacts.transaction().txid();
                    let report = Self::migration_report(
                        Some((txid, fee)),
                        &inputs,
                        &candidates,
                        &skipped,
                        dust_threshold,
                    );
                    info!(
                        "Moving {} UTXOs held at legacy-format dCTIDH locks, {} after a fee of \
                         {fee}, in transaction {txid}",
                        report.num_inputs, report.amount
                    );
                    return Ok(report);
                }
                Err(SendError::RecordTransaction(RecordTransactionError::InvalidTransaction(
                    error,
                ))) => error,
                Err(other) => return Err(other),
            };

            // Leave out the inputs that do not form a valid transaction on
            // their own, and try again with the others.
            let mut failing = vec![];
            let mut passing = vec![];
            if inputs.len() == 1 {
                failing = inputs;
            } else {
                for input in inputs {
                    let is_valid = match self
                        .migration_transaction(
                            vec![input.clone()],
                            address.clone(),
                            NativeCurrencyAmount::zero(),
                            timestamp,
                            consensus_rule_set,
                        )
                        .await
                    {
                        Ok(probe) => probe.verify(network, consensus_rule_set).await.is_ok(),
                        Err(_) => false,
                    };
                    if is_valid {
                        passing.push(input);
                    } else {
                        failing.push(input);
                    }
                }
            }
            if failing.is_empty() {
                warn!(
                    "UTXOs held at legacy-format dCTIDH locks that can each be moved on their \
                     own do not form a valid transaction together: {error}"
                );
                return Err(SendError::RecordTransaction(
                    RecordTransactionError::InvalidTransaction(error),
                ));
            }
            for input in &failing {
                warn!(
                    "Leaving out the UTXO with AOCL leaf index {} ({}) held at a legacy-format \
                     dCTIDH lock: no valid transaction spends it: {error}",
                    input.mutator_set_mp().aocl_leaf_index,
                    input.native_currency_amount()
                );
            }
            skipped.append(&mut failing);

            // The inputs that passed go back in front, where they were.
            passing.append(&mut candidates);
            candidates = passing;
            destination_address = Some(address);
        }
    }

    /// The address a migration transaction pays to.
    ///
    /// For a destination of this wallet, derives the key at the given index
    /// and raises the wallet's derivation counter past it if needed, so that
    /// the wallet watches the address, or else derives the next unused key.
    async fn migration_address(&mut self, destination: &MigrationDestination) -> ReceivingAddress {
        let (key_type, index) = match destination {
            MigrationDestination::Address(address) => return *address.clone(),
            MigrationDestination::Generation { index } => (KeyType::Generation, *index),
            MigrationDestination::Dctidh { index } => (KeyType::dCTIDH, *index),
        };

        let mut state = self.global_state_lock.lock_guard_mut().await;
        let key = match index {
            Some(index) => {
                state
                    .wallet_state
                    .bump_derivation_counter(key_type, index)
                    .await;
                state.wallet_state.nth_spending_key(key_type, index)
            }
            None => state.wallet_state.next_unused_spending_key(key_type).await,
        };
        state.wallet_state.wallet_db.persist().await;

        key.to_address()
    }

    /// A transaction spending `inputs` to one on-chain-announced output at
    /// `address`, paying `fee`. Not validated, not recorded.
    async fn migration_transaction(
        &self,
        inputs: Vec<TxInput>,
        address: ReceivingAddress,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<TxCreationArtifacts, SendError> {
        let total: NativeCurrencyAmount = inputs.iter().map(TxInput::native_currency_amount).sum();
        let amount = total
            .checked_sub(&fee)
            .ok_or(CreateTxError::InsufficientFunds {
                requested: fee,
                available: total,
            })?;

        // Announce the output on-chain even when it is owned by this wallet.
        // An off-chain notification would only live in the local wallet
        // database, and the funds could not be found when restoring from seed.
        let outputs = self
            .generate_tx_outputs(vec![OutputFormat::AddressAndAmountAndMedium(
                address,
                amount,
                UtxoNotificationMedium::OnChain,
            )])
            .await;

        let tx_details = TransactionDetailsBuilder::new()
            .timestamp(timestamp)
            .inputs(inputs.into())
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
            .await?;

        let transaction = self.assemble_transaction(&tx_details, proof)?;
        Ok(TxCreationArtifactsBuilder::new()
            .transaction_details(tx_details)
            .transaction(transaction)
            .build()?)
    }

    fn migration_report(
        transaction: Option<(TransactionKernelId, NativeCurrencyAmount)>,
        inputs: &[TxInput],
        waiting: &[TxInput],
        skipped: &[TxInput],
        dust_threshold: NativeCurrencyAmount,
    ) -> DctidhMigrationReport {
        fn total<'a>(inputs: impl IntoIterator<Item = &'a TxInput>) -> NativeCurrencyAmount {
            inputs
                .into_iter()
                .map(TxInput::native_currency_amount)
                .sum()
        }

        let (txid, fee) = transaction.unzip();
        let fee = fee.unwrap_or_else(NativeCurrencyAmount::zero);
        let waiting = waiting.iter().chain(skipped).collect::<Vec<_>>();
        let dust = waiting
            .iter()
            .copied()
            .filter(|input| input.native_currency_amount() <= dust_threshold)
            .collect::<Vec<_>>();

        DctidhMigrationReport {
            txid,
            num_inputs: inputs.len(),
            amount: total(inputs)
                .checked_sub(&fee)
                .unwrap_or_else(NativeCurrencyAmount::zero),
            fee,
            num_waiting: waiting.len(),
            amount_waiting: total(waiting.iter().copied()),
            num_dust: dust.len(),
            amount_dust: total(dust),
            num_skipped: skipped.len(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use macro_rules_attr::apply;
    use rand::random;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::tx_initiation::error::CreateProofError;
    use crate::application::config::cli_args;
    use crate::application::loops::channel::MainToPeerTask;
    use crate::application::loops::main_loop::proof_upgrader::PrimitiveWitnessToSingleProof;
    use crate::application::loops::main_loop::proof_upgrader::UpgradeJob;
    use crate::protocol::consensus::block::block_height::BlockHeight;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::BlockProof;
    use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::transaction::Transaction;
    use crate::protocol::consensus::transaction::TransactionProof;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::address::symmetric_key::SymmetricKey;
    use crate::state::wallet::address::SpendingKey;
    use crate::state::wallet::incoming_utxo::IncomingUtxo;
    use crate::state::wallet::unlocked_utxo::UnlockedUtxo;
    use crate::state::wallet::utxo_notification::UtxoNotificationPayload;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::blocks::invalid_empty_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;
    use crate::BFieldElement;
    use crate::GlobalStateLock;

    /// Runs `LeviathanSettlement` from genesis, without legacy cutoff, and without
    /// mock proofs.
    const NETWORK: Network = Network::Testnet(0);

    pub(crate) fn coins(amount: &str) -> NativeCurrencyAmount {
        NativeCurrencyAmount::coins_from_str(amount).unwrap()
    }

    /// A wallet whose dCTIDH indices `0..num_indices` were in use when this
    /// version first opened it.
    pub(crate) async fn wallet_with_legacy_indices(
        num_indices: u64,
        capability: TxProvingCapability,
    ) -> GlobalStateLock {
        let cli = cli_args::Args {
            tx_proving_capability: Some(capability),
            rate_limit_until_height: 0,
            ..cli_args::Args::default_with_network(NETWORK)
        };
        let mut alice = mock_genesis_global_state(0, WalletEntropy::new_random(), cli).await;
        {
            let mut state = alice.lock_guard_mut().await;
            state
                .wallet_state
                .bump_derivation_counter(KeyType::dCTIDH, num_indices - 1)
                .await;
            state
                .wallet_state
                .set_legacy_dctidh_key_bound(num_indices)
                .await;
        }
        alice
    }

    /// Confirm a block that pays each amount to the wallet's dCTIDH key at
    /// the given index, at its legacy-format lock if so flagged, announced
    /// on-chain the way a sender using the address of that format would.
    pub(crate) async fn receive_at_dctidh_locks(
        alice: &mut GlobalStateLock,
        payments: &[(u64, NativeCurrencyAmount, bool)],
    ) {
        let (tip, wallet_entropy) = {
            let state = alice.lock_guard().await;
            (
                state.chain.light_state().clone(),
                state.wallet_state.wallet_entropy.clone(),
            )
        };

        let mut outputs = vec![];
        let mut announcements = vec![];
        for &(index, amount, is_legacy) in payments {
            let (key, legacy) = wallet_entropy.nth_dctidh_spending_key_with_legacy(index);
            let (lock, address) = if is_legacy {
                (SpendingKey::from(legacy), legacy.pre_v0_3_address())
            } else {
                (SpendingKey::from(key), key.to_address())
            };
            let utxo = Utxo::new_native_currency(lock.lock_script_hash(), amount);
            let sender_randomness: Digest = random();

            // A sender encrypts to the public key of the address it pays to.
            let payload = UtxoNotificationPayload::new(utxo.clone(), sender_randomness);
            announcements.push(
                ReceivingAddress::from(address)
                    .generate_announcement(payload)
                    .unwrap(),
            );
            let incoming = IncomingUtxo {
                utxo,
                sender_randomness,
                receiver_preimage: lock.privacy_preimage(),
                is_guesser_fee: false,
                payment_id: BFieldElement::new(0),
            };
            outputs.push(incoming.addition_record());
        }

        let kernel = TransactionKernelProxy {
            inputs: vec![],
            outputs,
            announcements,
            fee: NativeCurrencyAmount::zero(),
            coinbase: None,
            timestamp: tip.header().timestamp + Timestamp::minutes(10),
            mutator_set_hash: tip.mutator_set_accumulator_after().unwrap().hash(),
            merge_bit: false,
        }
        .into_kernel();
        let transaction = Transaction {
            kernel,
            proof: TransactionProof::invalid(),
        };
        let block = invalid_block_with_transaction(&tip, transaction);
        alice.set_new_tip(block).await.unwrap();
    }

    fn migration_timestamp(tip: &Block) -> Timestamp {
        tip.header().timestamp + Timestamp::minutes(1)
    }

    pub(crate) async fn tip(alice: &GlobalStateLock) -> Block {
        alice.lock_guard().await.chain.light_state().clone()
    }

    async fn migrate(
        alice: &GlobalStateLock,
        destination: MigrationDestination,
        fee: Option<NativeCurrencyAmount>,
        max_inputs: usize,
    ) -> Result<DctidhMigrationReport, SendError> {
        let timestamp = migration_timestamp(&tip(alice).await);
        alice
            .api()
            .tx_initiator()
            .migrate_dctidh_utxos(destination, fee, timestamp, 0, max_inputs)
            .await
    }

    async fn legacy_inputs(alice: &GlobalStateLock) -> Vec<TxInput> {
        let timestamp = migration_timestamp(&tip(alice).await);
        alice
            .api()
            .tx_initiator()
            .legacy_dctidh_inputs(timestamp, 0)
            .await
    }

    async fn only_mempool_transaction(alice: &GlobalStateLock) -> Transaction {
        let state = alice.lock_guard().await;
        assert_eq!(1, state.mempool.len(), "expected exactly one transaction");
        let (txid, _) = state.mempool.fee_density_iter().next().unwrap();
        state.mempool.get(txid).unwrap().clone()
    }

    /// The native-currency amounts of the inputs of a witness-backed
    /// transaction, in descending order.
    fn input_amounts(transaction: &Transaction) -> Vec<NativeCurrencyAmount> {
        let TransactionProof::Witness(primitive_witness) = &transaction.proof else {
            panic!("migration transaction must start out as a primitive witness");
        };
        let mut amounts = primitive_witness
            .input_utxos
            .utxos
            .iter()
            .map(Utxo::get_native_currency_amount)
            .collect::<Vec<_>>();
        amounts.sort_by_key(|amount| Reverse(*amount));
        amounts
    }

    async fn key_counter(alice: &GlobalStateLock, key_type: KeyType) -> u64 {
        alice
            .lock_guard()
            .await
            .wallet_state
            .spending_key_counter(key_type)
    }

    #[test]
    fn fee_follows_proving_capability_and_covers_the_relay_minimum() {
        let per_input = coins("0.0005");
        let sp = TxProvingCapability::SingleProof;
        let pc = TxProvingCapability::ProofCollection;
        assert_eq!(CONSOLIDATION_FEE_SP, migration_fee(sp, per_input, 1));
        assert_eq!(CONSOLIDATION_FEE_SP, migration_fee(sp, per_input, 10));
        assert_eq!(coins("0.01"), migration_fee(sp, per_input, 20));
        assert_eq!(CONSOLIDATION_FEE_PC, migration_fee(pc, per_input, 1));
        assert_eq!(CONSOLIDATION_FEE_PC, migration_fee(pc, per_input, 200));
        assert_eq!(coins("0.2"), migration_fee(pc, coins("0.001"), 200));
    }

    #[test]
    fn largest_inputs_worth_their_share_of_the_fee_are_selected() {
        let fee_for = |_| coins("0.01");
        let amounts = [coins("5"), coins("0.004"), coins("0.003"), coins("0.001")];

        // With four inputs, 0.001 is not worth more than its share of 0.0025;
        // with three, 0.003 not more than 0.00333...; with two, 0.004 not more
        // than 0.005.
        assert_eq!(
            Some((1, coins("0.01"))),
            num_inputs_worth_moving(&amounts, 10, fee_for)
        );
        assert_eq!(
            Some((4, coins("0.003"))),
            num_inputs_worth_moving(&amounts, 10, |_| coins("0.003"))
        );
        assert_eq!(
            Some((2, coins("0.003"))),
            num_inputs_worth_moving(&amounts, 2, |_| coins("0.003"))
        );
        assert_eq!(None, num_inputs_worth_moving(&amounts[1..], 10, fee_for));
        assert_eq!(None, num_inputs_worth_moving(&amounts, 0, fee_for));
        assert_eq!(None, num_inputs_worth_moving(&[], 10, fee_for));
    }

    #[test]
    fn destination_is_parsed() {
        let network = NETWORK;
        assert_eq!(
            MigrationDestination::Generation { index: None },
            MigrationDestination::parse("generation", None, network).unwrap()
        );
        assert_eq!(
            MigrationDestination::Dctidh { index: Some(3) },
            MigrationDestination::parse("dctidh", Some(3), network).unwrap()
        );

        let address: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(random()).into();
        let encoded = address.to_bech32m(network).unwrap();
        assert_eq!(
            MigrationDestination::Address(Box::new(address)),
            MigrationDestination::parse(&encoded, None, network).unwrap()
        );
        assert!(MigrationDestination::parse(&encoded, Some(0), network).is_err());
        assert!(MigrationDestination::parse(&encoded, None, Network::Main).is_err());
        assert!(MigrationDestination::parse("foo", None, network).is_err());

        let symmetric_key: ReceivingAddress = SymmetricKey::from_seed(random()).into();
        let encoded_key = symmetric_key.to_bech32m(network).unwrap();
        assert!(MigrationDestination::parse(&encoded_key, None, network).is_err());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn moves_the_largest_legacy_utxos_to_the_next_unused_generation_address() {
        let mut alice = wallet_with_legacy_indices(2, TxProvingCapability::SingleProof).await;
        receive_at_dctidh_locks(
            &mut alice,
            &[
                (0, coins("1"), true),
                (1, coins("5"), true),
                (0, coins("3"), true),
                (1, coins("7"), false),
            ],
        )
        .await;
        assert_eq!(3, legacy_inputs(&alice).await.len());
        let generation_counter = key_counter(&alice, KeyType::Generation).await;

        let report = migrate(
            &alice,
            MigrationDestination::Generation { index: None },
            None,
            2,
        )
        .await
        .unwrap();

        let tx = only_mempool_transaction(&alice).await;
        assert_eq!(Some(tx.kernel.txid()), report.txid);
        assert_eq!(vec![coins("5"), coins("3")], input_amounts(&tx));
        assert_eq!(1, tx.kernel.outputs.len());
        assert_eq!(
            1,
            tx.kernel.announcements.len(),
            "output must be announced on-chain"
        );
        assert_eq!(CONSOLIDATION_FEE_SP, tx.kernel.fee);
        assert_eq!(2, report.num_inputs);
        assert_eq!(CONSOLIDATION_FEE_SP, report.fee);
        let amount = coins("8").checked_sub(&CONSOLIDATION_FEE_SP).unwrap();
        assert_eq!(amount, report.amount);
        assert_eq!(1, report.num_waiting);
        assert_eq!(coins("1"), report.amount_waiting);
        assert_eq!(0, report.num_dust);
        assert_eq!(0, report.num_skipped);

        // The output goes to the next unused Generation key, and is found by
        // scanning the announcement with that key alone.
        assert_eq!(
            generation_counter + 1,
            key_counter(&alice, KeyType::Generation).await
        );
        let key = alice
            .lock_guard()
            .await
            .wallet_state
            .nth_spending_key(KeyType::Generation, generation_counter);
        let found = key.scan_for_announced_utxos(&tx.kernel);
        assert_eq!(1, found.len());
        assert_eq!(amount, found[0].utxo.get_native_currency_amount());

        // The UTXO at the current-format lock is left untouched, and the
        // next pass moves the remaining legacy-format UTXO.
        let remaining = legacy_inputs(&alice).await;
        assert_eq!(1, remaining.len());
        assert_eq!(coins("1"), remaining[0].native_currency_amount());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn proof_collection_node_pays_the_proof_collection_fee() {
        let mut alice = wallet_with_legacy_indices(1, TxProvingCapability::ProofCollection).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("2"), true), (0, coins("3"), true)]).await;

        let report = migrate(
            &alice,
            MigrationDestination::Generation { index: None },
            None,
            10,
        )
        .await
        .unwrap();

        assert_eq!(2, report.num_inputs);
        assert_eq!(CONSOLIDATION_FEE_PC, report.fee);
        assert_eq!(
            CONSOLIDATION_FEE_PC,
            only_mempool_transaction(&alice).await.kernel.fee
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn utxos_not_worth_their_share_of_the_fee_are_not_moved() {
        let mut alice = wallet_with_legacy_indices(1, TxProvingCapability::SingleProof).await;
        receive_at_dctidh_locks(
            &mut alice,
            &[
                (0, coins("2"), true),
                (0, coins("0.001"), true),
                (0, coins("0.0002"), true),
            ],
        )
        .await;

        // With 0.005 per transaction, only the largest UTXO is worth more
        // than its share of the fee. Below 0.0005, a UTXO is not worth its
        // share even in a full batch of 10.
        let report = migrate(
            &alice,
            MigrationDestination::Generation { index: None },
            None,
            10,
        )
        .await
        .unwrap();
        assert_eq!(1, report.num_inputs);
        assert_eq!(
            vec![coins("2")],
            input_amounts(&only_mempool_transaction(&alice).await)
        );
        assert_eq!(2, report.num_waiting);
        assert_eq!(coins("0.0012"), report.amount_waiting);
        assert_eq!(1, report.num_dust);
        assert_eq!(coins("0.0002"), report.amount_dust);

        // Nothing else is worth moving, and no address is used up for it.
        let generation_counter = key_counter(&alice, KeyType::Generation).await;
        let second_report = migrate(
            &alice,
            MigrationDestination::Generation { index: None },
            None,
            10,
        )
        .await
        .unwrap();
        assert!(second_report.txid.is_none());
        assert_eq!(0, second_report.num_inputs);
        assert_eq!(2, second_report.num_waiting);
        assert_eq!(1, alice.lock_guard().await.mempool.len());
        assert_eq!(
            generation_counter,
            key_counter(&alice, KeyType::Generation).await
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn given_derivation_index_is_used_and_raises_the_counter() {
        let mut alice = wallet_with_legacy_indices(1, TxProvingCapability::SingleProof).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("4"), true)]).await;

        let index = key_counter(&alice, KeyType::dCTIDH).await + 2;
        let destination = MigrationDestination::Dctidh { index: Some(index) };
        let report = migrate(&alice, destination, None, 10).await.unwrap();
        assert_eq!(1, report.num_inputs);

        assert_eq!(index + 1, key_counter(&alice, KeyType::dCTIDH).await);
        let tx = only_mempool_transaction(&alice).await;
        let key = alice
            .lock_guard()
            .await
            .wallet_state
            .nth_spending_key(KeyType::dCTIDH, index);
        let found = key.scan_for_announced_utxos(&tx.kernel);
        assert_eq!(1, found.len());
        assert_eq!(key.lock_script_hash(), found[0].utxo.lock_script_hash());
        assert!(!alice
            .lock_guard()
            .await
            .wallet_state
            .legacy_dctidh_lock_hashes()
            .contains(&found[0].utxo.lock_script_hash()));
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn explicit_fee_is_paid() {
        let mut alice = wallet_with_legacy_indices(1, TxProvingCapability::SingleProof).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("4"), true)]).await;
        let address: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(random()).into();

        let fee = coins("0.02");
        let report = migrate(
            &alice,
            MigrationDestination::Address(Box::new(address)),
            Some(fee),
            10,
        )
        .await
        .unwrap();

        assert_eq!(fee, report.fee);
        assert_eq!(coins("3.98"), report.amount);
        assert_eq!(fee, only_mempool_transaction(&alice).await.kernel.fee);
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn input_without_a_valid_transaction_is_left_out() {
        let mut alice = wallet_with_legacy_indices(1, TxProvingCapability::SingleProof).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("5"), true), (0, coins("3"), true)]).await;

        // The largest input comes with a membership proof that does not match
        // its UTXO.
        let mut candidates = legacy_inputs(&alice).await;
        candidates.sort_by_key(|input| Reverse(input.native_currency_amount()));
        let mut membership_proof = candidates[0].mutator_set_mp().clone();
        membership_proof.sender_randomness = random();
        candidates[0] = UnlockedUtxo::unlock(
            candidates[0].utxo.clone(),
            candidates[0].lock_script_and_witness().clone(),
            membership_proof,
        )
        .into();

        let timestamp = migration_timestamp(&tip(&alice).await);
        let report = alice
            .api()
            .tx_initiator()
            .migrate_inputs(
                candidates,
                MigrationDestination::Generation { index: None },
                None,
                timestamp,
                10,
                ConsensusRuleSet::LeviathanSettlement,
            )
            .await
            .unwrap();

        assert_eq!(1, report.num_inputs);
        assert_eq!(1, report.num_skipped);
        assert_eq!(1, report.num_waiting);
        assert_eq!(coins("5"), report.amount_waiting);
        assert_eq!(
            vec![coins("3")],
            input_amounts(&only_mempool_transaction(&alice).await)
        );
    }

    /// A placeholder for a main-net block at the given height: its body
    /// extends the mutator set of the tip. This version cannot make blocks of
    /// the legacy era, not even mock ones.
    pub(crate) fn main_net_placeholder_block(tip: &Block, height: BlockHeight) -> Block {
        let successor = invalid_empty_block(tip, Network::Main);
        let mut header = *successor.header();
        header.height = height;
        Block::new(
            header,
            successor.body().clone(),
            successor.appendix().clone(),
            BlockProof::Invalid,
        )
    }

    /// A main-net wallet whose dCTIDH indices `0..num_indices` were in use when
    /// this version first opened it.
    pub(crate) async fn main_net_wallet_with_legacy_indices(num_indices: u64) -> GlobalStateLock {
        let cli = cli_args::Args {
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            rate_limit_until_height: 0,
            ..cli_args::Args::default_with_network(Network::Main)
        };
        let mut alice = mock_genesis_global_state(0, WalletEntropy::new_random(), cli).await;
        {
            let mut state = alice.lock_guard_mut().await;
            state
                .wallet_state
                .bump_derivation_counter(KeyType::dCTIDH, num_indices - 1)
                .await;
            state
                .wallet_state
                .set_legacy_dctidh_key_bound(num_indices)
                .await;
        }
        alice
    }

    /// Within `--fork-tx-cutoff-margin` blocks of the v8 fork, no migration
    /// transaction is made, and no address is used up for it.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn refused_close_to_the_v8_fork_without_using_up_an_address() {
        let mut alice = main_net_wallet_with_legacy_indices(1).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("4"), true)]).await;
        let margin = alice.cli().fork_tx_cutoff_margin;
        let cutoff_height = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET.value() - margin;
        let block = main_net_placeholder_block(&tip(&alice).await, cutoff_height.into());
        alice.set_new_tip(block).await.unwrap();

        let generation_counter = key_counter(&alice, KeyType::Generation).await;
        let result = migrate(
            &alice,
            MigrationDestination::Generation { index: None },
            None,
            10,
        )
        .await;
        assert!(matches!(
            result,
            Err(SendError::Proof(CreateProofError::LegacyEra(
                ConsensusRuleSet::UpgradeVMv7
            )))
        ));
        assert_eq!(
            generation_counter,
            key_counter(&alice, KeyType::Generation).await
        );
        let state = alice.lock_guard().await;
        assert!(state.mempool.is_empty());
        assert!(state.legacy_relay_pool.is_empty());
    }

    /// Before the v8 fork, migration makes transactions for the legacy era:
    /// at most 10 inputs, the proof collection fee whatever the node proves,
    /// and held in the legacy relay pool instead of the mempool. One block
    /// before the cutoff, it still does.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn migrates_for_the_legacy_era_before_the_v8_fork() {
        let mut alice = main_net_wallet_with_legacy_indices(1).await;
        let payments = (0..12).map(|_| (0, coins("1"), true)).collect::<Vec<_>>();
        receive_at_dctidh_locks(&mut alice, &payments).await;
        let margin = alice.cli().fork_tx_cutoff_margin;
        let last_height = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET.value() - margin - 1;
        let block = main_net_placeholder_block(&tip(&alice).await, last_height.into());
        alice.set_new_tip(block).await.unwrap();

        let report = migrate(
            &alice,
            MigrationDestination::Generation { index: None },
            None,
            50,
        )
        .await
        .unwrap();
        assert_eq!(10, report.num_inputs);
        assert_eq!(CONSOLIDATION_FEE_PC, report.fee);
        assert_eq!(2, report.num_waiting);

        let state = alice.lock_guard().await;
        assert!(state.mempool.is_empty(), "no v7 transaction in the mempool");
        assert_eq!(1, state.legacy_relay_pool.len());
        assert_eq!(1, state.legacy_relay_pool.num_own());
        let txid = report.txid.unwrap();
        let transaction = state.legacy_relay_pool.get(txid).unwrap();
        assert_eq!(CONSOLIDATION_FEE_PC, transaction.kernel.fee);
        assert!(matches!(transaction.proof, TransactionProof::Witness(_)));
    }

    /// Like the main loop does for a transaction this node initiates, but
    /// with a proof the node cannot produce.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn own_transaction_is_released_when_its_proof_upgrade_keeps_failing() {
        let mut alice = wallet_with_legacy_indices(1, TxProvingCapability::ProofCollection).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("5"), true)]).await;
        migrate(
            &alice,
            MigrationDestination::Generation { index: None },
            None,
            10,
        )
        .await
        .unwrap();
        assert!(legacy_inputs(&alice).await.is_empty());

        let TransactionProof::Witness(primitive_witness) =
            only_mempool_transaction(&alice).await.proof
        else {
            panic!("migration transaction must start out as a primitive witness");
        };
        let upgrade_job =
            UpgradeJob::PrimitiveWitnessToSingleProof(PrimitiveWitnessToSingleProof {
                primitive_witness,
            });
        let (main_to_peer_tx, _main_to_peer_rx) =
            tokio::sync::broadcast::channel::<MainToPeerTask>(10);
        upgrade_job
            .handle_upgrade(vm_job_queue(), alice.clone(), main_to_peer_tx)
            .await;

        assert!(logs_contain(
            "Retrying the proof upgrade of own transaction"
        ));
        assert!(alice.lock_guard().await.mempool.is_empty());
        assert_eq!(1, legacy_inputs(&alice).await.len());
    }
}
