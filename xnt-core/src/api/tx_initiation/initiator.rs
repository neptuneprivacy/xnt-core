//! provides flexible APIs for creating and sending neptune transactions.
//!
//! [TransactionInitiator] wraps the [builder](super::builder) API.
//!
//! The builder API is a bit more verbose but is also easy to use.
//!
//! This API is callable by rust users of this crate as well as the RPC server.
//!
//! The intent is to present the same (or similar) API for both rust usage and
//! RPC usage when creating transactions.
//!
//! see [tx_initiation](super) for other APIs.

use std::collections::HashSet;
use std::sync::Arc;

use tasm_lib::prelude::Digest;

use super::error;
use super::legacy_era;
use crate::api::export::Timestamp;
use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
use crate::api::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::api::tx_initiation::builder::tx_input_list_builder::SortOrder;
use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::application::loops::main_loop::proof_upgrader::CastJob;
use crate::application::loops::main_loop::proof_upgrader::ChainJob;
use crate::application::loops::main_loop::proof_upgrader::ForgeJob;
use crate::application::loops::main_loop::proof_upgrader::UpdateLinkJob;
use crate::application::loops::main_loop::proof_upgrader::SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE;
use crate::application::triton_vm_job_queue::vm_job_queue;
use crate::protocol::consensus::chaintx::link_tx::LinkTx;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::lock_script::LockScript;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::transaction::validity::single_proof_v2::fix_link_tx;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::state::transaction::chained_transaction_details::ChainedTransactionDetails;
use crate::state::transaction::chained_transaction_details::ThruputInput;
use crate::state::transaction::chained_tx_artifacts::ChainedTxArtifacts;
use crate::state::transaction::link_tx_artifacts::LinkTxArtifacts;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::state::transaction::tx_creation_artifacts::TxCreationArtifacts;
use itertools::Itertools;
use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use num_traits::Zero;

use crate::state::wallet::address::KeyType;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::state::wallet::transaction_input::TxInput;
use crate::state::wallet::transaction_input::TxInputList;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::transaction_output::TxOutputList;
use crate::GlobalStateLock;

/// A mempool transaction a chained transaction spends an unconfirmed output of.
///
/// A standard predecessor must be cast into the chain pipeline before it can
/// be chained onto; a link predecessor is chained onto directly.
enum ChainPredecessor {
    Standard(Box<Transaction>),
    Link(Box<LinkTx>),
}

/// The proof-backed link transaction a chained send builds, together with what
/// it was built from and under.
struct ChainedLink {
    link_tx: LinkTx,
    details: ChainedTransactionDetails,
    consensus_rule_set: ConsensusRuleSet,
    proof_job_options: TritonVmProofJobOptions,
    predecessor_txids: Vec<TransactionKernelId>,
}

/// provides an API for building and sending neptune transactions.
#[derive(Debug)]
pub struct TransactionInitiator {
    pub(super) global_state_lock: GlobalStateLock,
}

impl From<GlobalStateLock> for TransactionInitiator {
    fn from(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }
}

impl TransactionInitiator {
    /// returns all spendable inputs in the wallet.
    ///
    /// the order of inputs is undefined.
    pub async fn spendable_inputs(
        &self,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
    ) -> TxInputList {
        // sadly we have to collect here because we can't hold ref after lock guard is dropped.
        self.global_state_lock
            .lock_guard()
            .await
            .wallet_spendable_inputs(timestamp, exclude_recent_blocks)
            .await
            .into_iter()
            .into()
    }

    /// retrieve spendable inputs sufficient to cover spend_amount by applying selection policy.
    ///
    /// see [InputSelectionPolicy] for a description of available policies.
    ///
    /// see [TxInputListBuilder] for details.
    pub async fn select_spendable_inputs(
        &self,
        policy: InputSelectionPolicy,
        spend_amount: NativeCurrencyAmount,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
        max_inputs: Option<usize>,
    ) -> impl IntoIterator<Item = TxInput> {
        TxInputListBuilder::new()
            .spendable_inputs(
                self.spendable_inputs(timestamp, exclude_recent_blocks)
                    .await
                    .into(),
            )
            .policy(policy)
            .spend_amount(spend_amount)
            .max_inputs(max_inputs)
            .build()
    }

    /// generate a list of outputs from a list of [OutputFormat].
    ///
    /// note that the outputs can be expressed in tuple format, so long
    /// as there exists a suitable From adapter on `OutputFormat`.
    ///
    /// Each output may use either `OnChain` or `OffChain` notifications.
    ///
    /// See [TxOutputListBuilder] for details.
    pub async fn generate_tx_outputs(
        &self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
    ) -> TxOutputList {
        TxOutputListBuilder::new()
            .outputs(outputs)
            .build(&self.global_state_lock.clone().into())
            .await
    }

    /// generates [TransactionDetails] from inputs and outputs
    ///
    /// see [TransactionDetailsBuilder] for details.
    pub async fn generate_tx_details(
        &mut self,
        inputs: TxInputList,
        outputs: TxOutputList,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
    ) -> Result<TransactionDetails, error::CreateTxError> {
        TransactionDetailsBuilder::new()
            .timestamp(Timestamp::now())
            .inputs(inputs)
            .outputs(outputs)
            .fee(fee)
            .change_policy(change_policy)
            .build(&mut self.global_state_lock.clone().into())
            .await
    }

    /// generates a witness proof from [TransactionDetails]
    ///
    /// a witness proof is sufficient for initiating a transaction
    /// although it will not actually be broadcast to peer until
    /// xnt-core can upgrade it to a `ProofCollection`.
    ///
    /// this function should return immediately.
    ///
    /// see [builder::transaction_proof_builder](super::builder::transaction_proof_builder) for details.
    pub fn generate_witness_proof(&self, tx_details: Arc<TransactionDetails>) -> TransactionProof {
        let primitive_witness = PrimitiveWitness::from_transaction_details(&tx_details);
        TransactionProof::Witness(primitive_witness)
    }

    /// assembles transaction details and a proof into a transaction.
    ///
    /// note: normally assemble_transaction_artifacts() should be preferred
    /// because its output can be directly used as input for
    /// record_and_broadcast_transaction().
    ///
    /// see [TransactionBuilder] for details.
    pub fn assemble_transaction(
        &self,
        transaction_details: &TransactionDetails,
        transaction_proof: TransactionProof,
    ) -> Result<Transaction, error::CreateTxError> {
        TransactionBuilder::new()
            .transaction_details(transaction_details)
            .transaction_proof(transaction_proof)
            .build()
    }

    /// assembles transaction details and a proof into transaction artifacts.
    ///
    /// see [TransactionBuilder] for details.
    pub fn assemble_transaction_artifacts(
        &self,
        transaction_details: TransactionDetails,
        transaction_proof: TransactionProof,
    ) -> Result<TxCreationArtifacts, error::CreateTxError> {
        let transaction = TransactionBuilder::new()
            .transaction_details(&transaction_details)
            .transaction_proof(transaction_proof)
            .build()?;

        TxCreationArtifactsBuilder::new()
            .transaction(transaction)
            .transaction_details(transaction_details)
            .build()
    }

    /// records a transaction into the wallet, mempool, and begins
    /// preparing to broadcast to peers.
    ///
    /// This is the core API that needs to be called in order for a xnt-core
    /// node to send a transaction.
    ///
    /// Note that in a typical scenario, the transaction will not be broadcast
    /// or confirmed into a block right away. The proof must be upgraded first.
    ///
    /// Those with a powerful machine have the option to upgrade the proof
    /// themself before calling this method, in which case the transaction will
    /// be broadcast and available for confirmation right away.
    ///
    /// see [Transaction Initiation Sequence](super#transaction-initiation-sequence)
    pub async fn record_and_broadcast_transaction(
        &mut self,
        tx: &TxCreationArtifacts,
    ) -> Result<(), error::SendError> {
        // may have been checked before, but just in case.
        self.worker().check_rate_limit().await?;

        // Refuse to broadcast a transaction that can never be mined: peers
        // reject it on admission and it would only occupy our own mempool.
        {
            let kernel = &tx.transaction.kernel;
            let network = self.global_state_lock.cli().network;
            let next_block_height = self
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .header()
                .height
                .next();

            ConsensusRuleSet::infer_from(network, next_block_height).mempool_size_check(
                kernel.inputs.len(),
                kernel.outputs.len(),
                kernel.announcements.len(),
            )?;
        }

        // Before the fork, the terms of that era apply, as for every
        // submission, see `legacy_era::submitted_transaction_meets_terms`.
        {
            let cli = self.global_state_lock.cli();
            let state = self.global_state_lock.lock_guard().await;
            let tip_height = state.chain.light_state().header().height;
            if state.next_block_consensus_rule_set().is_legacy_era()
                && !legacy_era::submitted_transaction_meets_terms(
                    &tx.transaction,
                    cli.network,
                    tip_height,
                    cli.fork_tx_cutoff_margin,
                )
            {
                return Err(error::SendError::BelowLegacyEraTerms);
            }
        }

        // note: acquires write-lock.
        // note: tx is validated internally.
        self.global_state_lock.record_own_transaction(tx).await?;

        // note: cheap arc clone of tx.
        self.worker()
            .broadcast_transaction(tx.transaction.clone())
            .await?;

        tracing::info!(
            "transaction accepted for sending!  recorded tx and initiated broadcast sequence:\n{}",
            tx.details
        );

        Ok(())
    }

    /// returns the type of proof that the queried transaction (in mempool)
    /// presently has.
    ///
    /// returns an error if the transaction is not in the mempool.
    pub async fn proof_type(
        &self,
        txid: TransactionKernelId,
    ) -> Result<TransactionProofType, error::UpgradeProofError> {
        self.global_state_lock
            .lock_guard()
            .await
            .mempool
            .get(txid)
            .map(|tx| (&tx.proof).into())
            .ok_or(error::UpgradeProofError::TxNotInMempool)
    }

    /// Verify, between the proving steps of a chained send, that proving on
    /// is still worthwhile: every predecessor must still sit in the mempool.
    ///
    /// A vanished predecessor is unrecoverable -- mined away, double-spent,
    /// or replaced, the thruput it resolves can never confirm. A moved tip,
    /// by contrast, is no reason to stop: every kernel in the chain still
    /// agrees on the old mutator set, and the result is one `Advance` proof
    /// away from the new tip.
    ///
    /// Proof construction can take a long time, so the world may well move
    /// while a step runs; checking costs one read lock.
    async fn chained_send_still_viable(
        &self,
        predecessor_txids: &[TransactionKernelId],
    ) -> Result<(), error::SendError> {
        let state = self.global_state_lock.lock_guard().await;
        if let Some(gone) = predecessor_txids
            .iter()
            .find(|txid| !state.mempool.contains(**txid))
        {
            return Err(error::SendError::Chained(format!(
                "predecessor transaction {gone} left the mempool while proving"
            )));
        }

        Ok(())
    }

    /// Build and broadcast a chained transaction, paying with unconfirmed
    /// funds: UTXOs created by transactions that sit in the mempool but are
    /// not yet confirmed by any block.
    ///
    /// Internally this runs the chain pipeline on this node alone: the
    /// unconfirmed UTXOs become thruputs of a forged link transaction, the
    /// predecessor transactions are cast into the pipeline and chained on --
    /// cut-through cancelling each thruput against the predecessor output it
    /// spends -- and the resolved link is fixed into an ordinary
    /// `SingleProof`-backed transaction. Only that final transaction is
    /// recorded and broadcast; no link transaction leaves the node.
    pub async fn send_chained(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<ChainedTxArtifacts, error::SendError> {
        let ChainedLink {
            link_tx,
            details,
            consensus_rule_set,
            proof_job_options,
            predecessor_txids,
        } = self
            .build_chained_link(outputs, change_policy, fee, timestamp, true)
            .await?;

        if !link_tx.kernel.thruputs.is_empty() {
            return Err(error::SendError::Chained(
                "chained transaction has unresolved thruputs".into(),
            ));
        }
        self.chained_send_still_viable(&predecessor_txids).await?;
        let transaction = fix_link_tx(
            link_tx,
            consensus_rule_set,
            vm_job_queue(),
            proof_job_options,
        )
        .await
        .map_err(|err| error::SendError::Chained(err.to_string()))?;

        self.chained_send_still_viable(&predecessor_txids).await?;
        let tx_artifacts = ChainedTxArtifacts {
            transaction: Arc::new(transaction),
            details: Arc::new(details),
        };
        self.global_state_lock
            .record_own_chained_transaction(&tx_artifacts)
            .await?;
        self.private()
            .broadcast_transaction(tx_artifacts.transaction.clone())
            .await?;

        Ok(tx_artifacts)
    }

    /// Like [`Self::send_chained`], but the result stays a [`LinkTx`]: the
    /// chain pipeline runs without the final `Fix`, and the chained,
    /// cut-through link transaction is inserted into the mempool and shared
    /// with peers. Whoever finalizes the chain pays for the `Fix`; unresolved
    /// thruputs are not an error here.
    pub async fn send_chained_link(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<LinkTxArtifacts, error::SendError> {
        let ChainedLink {
            link_tx,
            details,
            predecessor_txids,
            ..
        } = self
            .build_chained_link(outputs, change_policy, fee, timestamp, false)
            .await?;

        self.chained_send_still_viable(&predecessor_txids).await?;
        let tx_artifacts = LinkTxArtifacts {
            link_tx: Arc::new(link_tx),
            details: Arc::new(details),
        };
        self.global_state_lock
            .record_own_link_transaction(&tx_artifacts)
            .await?;
        self.private()
            .broadcast_link_transaction(tx_artifacts.link_tx.clone())
            .await?;

        Ok(tx_artifacts)
    }

    /// The shared front of [`Self::send_chained`] and
    /// [`Self::send_chained_link`]: select unconfirmed inputs, build the link
    /// witness, forge, chain with every predecessor, and -- if blocks arrived
    /// while proving -- re-target the chained link at the current mutator
    /// set.
    ///
    /// If `resolved`, only predecessors without thruputs of their own are
    /// chained onto, so that the chained link has none either and can be
    /// fixed.
    async fn build_chained_link(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        resolved: bool,
    ) -> Result<ChainedLink, error::SendError> {
        self.private().check_proceed_with_send(fee).await?;

        // Every step of the chain pipeline is a recursive proof.
        let cli = self.global_state_lock.cli();
        let capability = cli.proving_capability();
        let proof_type = TransactionProofType::SingleProof;
        if !cli.network.use_mock_proof() && !capability.can_prove(proof_type) {
            return Err(error::CreateProofError::TooWeak {
                proof_type,
                capability,
            }
            .into());
        }

        let mut tx_outputs = self.generate_tx_outputs(outputs).await;
        let spend_amount = tx_outputs
            .total_native_coins()
            .checked_add(&fee)
            .ok_or(error::CreateTxError::TotalSpendTooLarge)?;

        let (link_primitive_witness, details, predecessors, consensus_rule_set, proof_job_options) = {
            let mut gsm = self.global_state_lock.lock_guard_mut().await;
            let network = gsm.cli().network;
            let tip = gsm.chain.light_state_clone();
            let block_height = tip.header().height;
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
            if !consensus_rule_set.has_chain_branches() {
                return Err(error::SendError::Chained(format!(
                    "consensus rule set {consensus_rule_set} has no chain branches"
                )));
            }
            let mutator_set_accumulator = tip
                .mutator_set_accumulator_after()
                .map_err(|_| error::CreateTxError::NoMutatorSetAccumulatorAfter)?;
            let tip_mutator_set_hash = mutator_set_accumulator.hash();

            // Select unconfirmed incoming UTXOs whose creating transaction is
            // a tip-synced, proof-backed mempool member -- on either
            // pipeline: single-proof transactions are cast into the chain,
            // link transactions are chained onto directly.
            let mut selected: Vec<(TransactionKernelId, ThruputInput)> = vec![];
            let mut selected_amount = NativeCurrencyAmount::zero();
            for (predecessor_txid, incoming_utxo) in
                gsm.wallet_state.mempool_incoming_utxos_with_txid()
            {
                if selected_amount >= spend_amount {
                    break;
                }
                if incoming_utxo.is_guesser_fee || !incoming_utxo.utxo.can_spend_at(timestamp) {
                    continue;
                }
                let predecessor_is_chainable = match gsm.mempool.get(predecessor_txid) {
                    Some(predecessor) => {
                        matches!(predecessor.proof, TransactionProof::SingleProof(_))
                            && predecessor.kernel.mutator_set_hash == tip_mutator_set_hash
                    }
                    None => gsm.mempool.get_link(predecessor_txid).is_some_and(|link| {
                        link.proof.is_proof()
                            && link.kernel.kernel.mutator_set_hash == tip_mutator_set_hash
                            && (!resolved || link.kernel.thruputs.is_empty())
                    }),
                };
                if !predecessor_is_chainable {
                    continue;
                }
                let Some(spending_key) = gsm
                    .wallet_state
                    .find_spending_key_for_utxo(&incoming_utxo.utxo)
                else {
                    continue;
                };

                selected_amount = selected_amount + incoming_utxo.utxo.get_native_currency_amount();
                selected.push((
                    predecessor_txid,
                    ThruputInput {
                        incoming_utxo: incoming_utxo.clone(),
                        lock_script_and_witness: spending_key.lock_script_and_witness(),
                    },
                ));
            }
            if selected_amount < spend_amount {
                return Err(error::CreateTxError::InsufficientFunds {
                    requested: spend_amount,
                    available: selected_amount,
                }
                .into());
            }

            let change_amount = selected_amount
                .checked_sub(&spend_amount)
                .expect("selected amount covers spend amount");
            if change_amount.is_positive() {
                let change_output = match change_policy {
                    ChangePolicy::ExactChange => {
                        return Err(error::CreateTxError::NotExactChange.into());
                    }
                    ChangePolicy::RecoverToNextUnusedKey { key_type, medium } => {
                        let key = gsm.wallet_state.next_unused_spending_key(key_type).await;
                        TransactionDetailsBuilder::create_change_output(
                            &gsm.wallet_state,
                            block_height,
                            change_amount,
                            key,
                            medium,
                        )
                    }
                    ChangePolicy::RecoverToProvidedKey { key, medium } => {
                        TransactionDetailsBuilder::create_change_output(
                            &gsm.wallet_state,
                            block_height,
                            change_amount,
                            (*key).clone(),
                            medium,
                        )
                    }
                    ChangePolicy::Burn => TxOutput::no_notification_as_change(
                        Utxo::new_native_currency(LockScript::burn().hash(), change_amount),
                        Digest::default(),
                        Digest::default(),
                    ),
                };
                tx_outputs.push(change_output);
            }

            let details = ChainedTransactionDetails {
                thruput_inputs: selected
                    .iter()
                    .map(|(_, thruput)| thruput.clone())
                    .collect(),
                tx_outputs,
                fee,
                timestamp,
                mutator_set_accumulator,
                network,
            };

            // The reference validation is the integrity gate: under mock
            // proofs, nothing else checks the kernel this pipeline produces.
            let link_primitive_witness = details.link_primitive_witness();
            link_primitive_witness
                .validate()
                .await
                .map_err(|err| error::SendError::Chained(err.to_string()))?;

            let predecessors: Vec<(TransactionKernelId, ChainPredecessor)> = selected
                .iter()
                .map(|(txid, _)| *txid)
                .unique()
                .map(|txid| {
                    let predecessor = if let Some(transaction) = gsm.mempool.get(txid) {
                        ChainPredecessor::Standard(Box::new(transaction.clone()))
                    } else {
                        ChainPredecessor::Link(Box::new(
                            gsm.mempool
                                .get_link(txid)
                                .expect("selected predecessor must be in mempool")
                                .clone(),
                        ))
                    };
                    (txid, predecessor)
                })
                .collect();

            let proof_job_options = gsm.cli().as_proof_job_options();

            (
                link_primitive_witness,
                details,
                predecessors,
                consensus_rule_set,
                proof_job_options,
            )
        };
        let predecessor_txids = predecessors.iter().map(|(txid, _)| *txid).collect_vec();

        // Run the chain pipeline, one step at a time, checking between the
        // (potentially long-running) steps that the chain is still worth
        // proving.
        let job_queue = vm_job_queue();
        self.chained_send_still_viable(&predecessor_txids).await?;
        let mut link_tx = ForgeJob {
            link_primitive_witness,
            consensus_rule_set,
        }
        .upgrade(job_queue.clone(), proof_job_options.clone())
        .await
        .map_err(|err| error::SendError::Chained(err.to_string()))?;
        for (_, predecessor) in predecessors {
            self.chained_send_still_viable(&predecessor_txids).await?;
            let predecessor_link = match predecessor {
                ChainPredecessor::Link(link) => *link,
                ChainPredecessor::Standard(transaction) => CastJob {
                    transaction: *transaction,
                    consensus_rule_set,
                }
                .upgrade(job_queue.clone(), proof_job_options.clone())
                .await
                .map_err(|err| error::SendError::Chained(err.to_string()))?,
            };
            link_tx = ChainJob {
                left: link_tx,
                right: predecessor_link,
                shuffle_seed: rand::random(),
                consensus_rule_set,
            }
            .upgrade(job_queue.clone(), proof_job_options.clone())
            .await
            .map_err(|err| error::SendError::Chained(err.to_string()))?;
        }

        // If blocks arrived while proving, re-target the chain at the current
        // mutator set -- repeatedly, since blocks may keep arriving while the
        // update itself proves. The predecessors still being in the mempool
        // means the chain's inputs are still unspent, so the update must
        // succeed. Peers only accept tip-synced link transactions, so a
        // shared link must leave this loop synced.
        loop {
            let lookup = {
                let state = self.global_state_lock.lock_guard().await;
                let tip_mutator_set_hash = state
                    .chain
                    .light_state()
                    .mutator_set_accumulator_after()
                    .map_err(|_| error::CreateTxError::NoMutatorSetAccumulatorAfter)?
                    .hash();
                if tip_mutator_set_hash == link_tx.kernel.kernel.mutator_set_hash {
                    break;
                }
                state
                    .chain
                    .archival_state()
                    .old_mutator_set_and_mutator_set_update_to_tip(
                        link_tx.kernel.kernel.mutator_set_hash,
                        SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE,
                    )
                    .await
            };
            let Some((old_mutator_set_accumulator, mutator_set_update)) = lookup else {
                return Err(error::SendError::Chained(
                    "could not find mutator-set path from chained link to tip".into(),
                ));
            };

            self.chained_send_still_viable(&predecessor_txids).await?;
            link_tx = UpdateLinkJob {
                link_tx,
                old_mutator_set_accumulator,
                mutator_set_update,
                consensus_rule_set,
            }
            .upgrade(job_queue.clone(), proof_job_options.clone())
            .await
            .map_err(|err| error::SendError::Chained(err.to_string()))?;
        }

        Ok(ChainedLink {
            link_tx,
            details,
            consensus_rule_set,
            proof_job_options,
            predecessor_txids,
        })
    }

    fn worker(&self) -> super::private::TransactionInitiatorPrivate {
        super::private::TransactionInitiatorPrivate::new(self.global_state_lock.clone())
    }

    /// Build and broadcast a regular transaction.
    pub async fn send(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
        max_inputs: Option<usize>,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        self.send_inner(
            outputs,
            change_policy,
            fee,
            timestamp,
            false,
            exclude_recent_blocks,
            max_inputs,
        )
        .await
    }

    /// Build and broadcast a *transparent* transaction.
    ///
    /// While transactions are private by default, an initiator can opt to make
    /// it transparent. In this case, the transaction contains an announcement
    /// containing the consumed and produced UTXOs along with the commitment
    /// randomness. Only UTXOs held by Generation keys are spent as inputs.
    pub async fn send_transparent(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
        max_inputs: Option<usize>,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        self.send_inner(
            outputs,
            change_policy,
            fee,
            timestamp,
            true,
            exclude_recent_blocks,
            max_inputs,
        )
        .await
    }

    /// Build a transaction and broadcast it.
    ///
    // Locking: this function uses an incrementally lower-level interface, which
    // takes locks where-ever needed and releases them as soon as possible
    // afterwards. As a result, no single lock is held over the bulk of the
    // function's duration, potentially leading to funky race conditions if
    // multiple invocations are made in parallel.
    async fn send_inner(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        transparent: bool,
        exclude_recent_blocks: usize,
        max_inputs: Option<usize>,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        self.private().check_proceed_with_send(fee).await?;

        tracing::debug!("tx send initiated.");

        // The transaction is made for the rule set of the next block. Before
        // the fork, that may be the legacy era's, see `legacy_era`.
        let cli_args = self.global_state_lock.cli();
        let network = cli_args.network;
        let tip_height = self
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height;
        let consensus_rule_set = legacy_era::rule_set_for_new_transaction(
            network,
            tip_height,
            cli_args.fork_tx_cutoff_margin,
        )?;

        // The target proof-type is set to the lowest possible value here,
        // since we don't want the client (CLI or dashboard) to hang while
        // producing proofs. Instead, we let (a task started by) main loop
        // handle the proving.
        let target_proof_type = TransactionProofType::PrimitiveWitness;

        // generate outputs
        let tx_outputs = self.generate_tx_outputs(outputs).await;

        // select inputs: the smallest first, but before the fork, where a
        // transaction may have only a few inputs (see
        // `legacy_era::check_proof_collection_terms`), the largest first
        let spend_amount = tx_outputs.total_native_coins() + fee;
        let sort_order = if consensus_rule_set.is_legacy_era() {
            SortOrder::Descending
        } else {
            SortOrder::Ascending
        };
        let policy = InputSelectionPolicy::ByNativeCoinAmount(sort_order);
        let mut spendable_inputs: Vec<TxInput> = self
            .spendable_inputs(timestamp, exclude_recent_blocks)
            .await
            .into();
        if transparent {
            // Transparent transactions only spend UTXOs held by Generation keys.
            let generation_locks: HashSet<Digest> = self
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .get_known_spending_keys(KeyType::Generation)
                .map(|key| key.lock_script_hash())
                .collect();
            spendable_inputs
                .retain(|input| generation_locks.contains(&input.utxo.lock_script_hash()));
        }
        let tx_inputs = TxInputListBuilder::new()
            .spendable_inputs(spendable_inputs)
            .policy(policy)
            .spend_amount(spend_amount)
            .max_inputs(max_inputs)
            .build();

        // generate tx details (may add change output)
        let tx_details = TransactionDetailsBuilder::new()
            .timestamp(timestamp)
            .inputs(tx_inputs.into())
            .outputs(tx_outputs)
            .fee(fee)
            .change_policy(change_policy)
            .transparent(transparent)
            .build(&mut self.global_state_lock.clone().into())
            .await?;

        // A transaction for the legacy era may end up with its proof
        // collection, so it must meet the terms on which that era's nodes
        // relay and upgrade one.
        if consensus_rule_set.is_legacy_era() {
            legacy_era::check_proof_collection_terms(&tx_details.primitive_witness())?;
        }

        tracing::info!("send: proving tx:\n{}", tx_details);

        // use cli options for building proof, but override proof-type
        let options = TritonVmProofJobOptionsBuilder::new()
            .template(&cli_args.as_proof_job_options())
            .proof_type(target_proof_type)
            .build();

        // generate proof
        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .transaction_details(&tx_details)
            .job_queue(vm_job_queue())
            .proof_job_options(options)
            .build()
            .await?;

        tracing::info!("send: assembling tx");

        // create transaction
        let transaction = self.assemble_transaction(&tx_details, proof)?;

        // assemble transaction artifacts
        let tx_creation_artifacts = TxCreationArtifactsBuilder::new()
            .transaction_details(tx_details)
            .transaction(transaction)
            .build()?;

        tracing::info!("send: recording tx");

        self.record_and_broadcast_transaction(&tx_creation_artifacts)
            .await?;

        tracing::info!("send: all done!");

        Ok(tx_creation_artifacts)
    }

    pub(super) fn private(&self) -> super::private::TransactionInitiatorPrivate {
        super::private::TransactionInitiatorPrivate::new(self.global_state_lock.clone())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::time::Duration;

    use macro_rules_attr::apply;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::block::Block;
    use crate::state::mempool::mempool_event::AddReason;
    use crate::state::mempool::upgrade_priority::UpgradePriority;
    use crate::state::transaction::tx_proving_capability::TxProvingCapability;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::address::ReceivingAddress;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::globalstate::single_proof_payment;
    use crate::tests::shared::wait_until;
    use crate::tests::shared_tokio_runtime;

    /// A chained send stops, and records nothing, once a predecessor leaves
    /// the mempool while the chain pipeline proves -- whether it was mined,
    /// double-spent, or replaced.
    ///
    /// Real proofs give the pipeline its duration: the predecessor leaves
    /// right after the inputs are selected, while `Forge` proves. The change
    /// key that the selection derives marks that moment.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn chained_send_stops_when_a_predecessor_leaves_the_mempool_while_proving() {
        let network = Network::Testnet(0);
        let cli = cli_args::Args {
            network,
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            ..Default::default()
        };
        let alice = mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli.clone()).await;
        let mut bob = mock_genesis_global_state(2, WalletEntropy::new_random(), cli).await;
        let genesis_block = Block::genesis(network);
        let now = std::cmp::max(
            Timestamp::now(),
            genesis_block.header().timestamp + network.minimum_block_time(),
        );

        let bob_address = bob
            .api_mut()
            .wallet_mut()
            .next_receiving_address(KeyType::Generation)
            .await
            .unwrap();
        let fee = NativeCurrencyAmount::coins(1);
        let alice_tx = single_proof_payment(
            &alice,
            bob_address,
            NativeCurrencyAmount::coins(5),
            fee,
            now,
        )
        .await
        .transaction
        .as_ref()
        .clone();
        bob.lock_guard_mut()
            .await
            .mempool_insert(
                alice_tx.clone(),
                UpgradePriority::Irrelevant,
                AddReason::FromPeer,
            )
            .await;

        // The default change policy derives the next symmetric key.
        let change_key_type = KeyType::Symmetric;
        let num_change_keys = bob
            .lock_guard()
            .await
            .wallet_state
            .spending_key_counter(change_key_type);
        let charlie_address: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(rand::random()).into();
        let mut sender = bob.clone();
        let send = tokio::spawn(async move {
            sender
                .api_mut()
                .tx_sender_mut()
                .send_chained(
                    vec![(charlie_address, NativeCurrencyAmount::coins(3))],
                    ChangePolicy::default(),
                    fee,
                    now,
                )
                .await
        });

        // The selection derives the change key under the state's write lock;
        // the predecessor leaves as soon as that lock is free again.
        let watched = bob.clone();
        wait_until(Duration::from_secs(120), move || {
            let watched = watched.clone();
            async move {
                watched
                    .lock_guard()
                    .await
                    .wallet_state
                    .spending_key_counter(change_key_type)
                    > num_change_keys
            }
        })
        .await
        .unwrap();
        bob.lock_guard_mut()
            .await
            .mempool_remove(alice_tx.txid())
            .await;
        assert!(
            !send.is_finished(),
            "the predecessor must leave while the pipeline proves"
        );

        let result = send.await.unwrap();
        let Err(error::SendError::Chained(reason)) = &result else {
            panic!("chained send must stop, got {result:?}");
        };
        assert!(reason.contains("left the mempool"), "{reason}");
        assert!(
            bob.lock_guard().await.mempool.is_empty(),
            "a stopped chained send must not record anything"
        );
    }
}
