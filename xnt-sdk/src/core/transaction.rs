//! Transaction building
//!
//! Shared transaction building logic for both FFI and NAPI bindings.

use neptune_privacy::api::export::NativeCurrencyAmount;
use neptune_privacy::api::export::PrimitiveWitness;
use neptune_privacy::api::export::Timestamp;
use neptune_privacy::api::export::TransactionDetails;
use neptune_privacy::api::export::TransactionProof;
use neptune_privacy::api::export::TxInputList;
use neptune_privacy::api::export::TxOutput;
use neptune_privacy::api::export::TxOutputList;
use neptune_privacy::api::export::UnlockedUtxo;
use neptune_privacy::protocol::consensus::transaction::Transaction as CoreTransaction;
use neptune_privacy::state::wallet::address::SpendingKey as CoreSpendingKey;

use super::address::{Address, ReceivingAddress};
use super::error::{Result, XntError};
use super::sync::{MembershipProof, MutatorSet};
use super::types::{Digest, Network};
use super::utxo::Utxo;
use super::wallet::SpendingKey;

/// Most inputs a transaction built by [TransactionBuilder] may have.
///
/// [BuiltTransaction::prove] produces a ProofCollection, and nodes relay
/// ProofCollection-backed transactions only up to this many inputs.
pub const MAX_INPUTS: usize = 200;

/// Minimum fee per input, in nau, of a ProofCollection-backed transaction that
/// nodes with the default `--min-relay-pctx-fee-per-input` (0.0005 coins)
/// accept into their mempool and relay.
pub const MIN_RELAY_FEE_PER_INPUT_NAU: i128 = 2 * 10i128.pow(27);

/// Select UTXOs to cover target amount with minimum inputs.
/// Uses sliding window on sorted amounts to find smallest UTXOs that fit within limit.
///
/// `limit` is capped at [MAX_INPUTS].
pub fn select_inputs(amounts: &[i128], target: i128, limit: usize) -> Result<Vec<usize>> {
    let limit = limit.min(MAX_INPUTS);

    // Filter positive amounts and sort ascending
    let mut indexed: Vec<(usize, i128)> = amounts
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, amt)| *amt > 0)
        .collect();
    indexed.sort_by(|a, b| a.1.cmp(&b.1));

    if indexed.is_empty() {
        return Err(XntError::TransactionError("no UTXOs available".into()));
    }

    // UTXO consolidation: pick the best window of up to `limit`
    // contiguous inputs (sorted ascending) that covers the spend
    // amount while maximizing the number of small UTXOs consumed.
    let max_window = limit.min(indexed.len());

    for start in 0..=(indexed.len() - max_window) {
        let window = &indexed[start..start + max_window];
        let sum = window
            .iter()
            .try_fold(0i128, |acc, (_, amt)| acc.checked_add(*amt))
            .ok_or_else(|| XntError::TransactionError("amount overflow".into()))?;
        if sum >= target {
            return Ok(window.iter().map(|(idx, _)| *idx).collect());
        }
    }

    // No valid window found
    let total: i128 = indexed.iter().map(|(_, amt)| amt).fold(0i128, |a, b| a.saturating_add(*b));
    Err(XntError::TransactionError(format!(
        "insufficient: total={} need={} (limit={})",
        total, target, limit
    )))
}

/// Transaction input
pub struct TxInput {
    pub utxo: Utxo,
    pub spending_key: SpendingKey,
    pub membership_proof: MembershipProof,
}

/// Transaction output - stores ReceivingAddress for type-based dispatch
pub struct TxOutputSpec {
    /// The receiving address (main or subaddress)
    pub(crate) receiving_address: ReceivingAddress,
    pub amount: i128,
    pub sender_randomness: Digest,
}

impl TxOutputSpec {
    /// Get payment_id if this is a subaddress output
    pub fn payment_id(&self) -> Option<u64> {
        self.receiving_address.payment_id()
    }
}

/// Transaction builder - collects inputs and outputs
pub struct TransactionBuilder {
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutputSpec>,
    change_address: Option<Address>,
    change_sender_randomness: Option<Digest>,
    fee: i128,
    allow_low_fee: bool,
}

impl TransactionBuilder {
    /// Create new transaction builder
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            change_address: None,
            change_sender_randomness: None,
            fee: 0,
            allow_low_fee: false,
        }
    }

    /// Add input UTXO to spend
    pub fn add_input(
        &mut self,
        utxo: Utxo,
        spending_key: SpendingKey,
        membership_proof: MembershipProof,
    ) {
        self.inputs.push(TxInput {
            utxo,
            spending_key,
            membership_proof,
        });
    }

    /// Add output (takes ReceivingAddress - works for both main and subaddresses)
    pub fn add_output(
        &mut self,
        receiving_address: ReceivingAddress,
        amount: i128,
        sender_randomness: Digest,
    ) {
        self.outputs.push(TxOutputSpec {
            receiving_address,
            amount,
            sender_randomness,
        });
    }

    /// Get outputs for inspection
    pub fn outputs(&self) -> &[TxOutputSpec] {
        &self.outputs
    }

    /// Set change address
    pub fn set_change(&mut self, address: Address, sender_randomness: Digest) {
        self.change_address = Some(address);
        self.change_sender_randomness = Some(sender_randomness);
    }

    /// Set transaction fee
    ///
    /// [Self::build] refuses a fee below [MIN_RELAY_FEE_PER_INPUT_NAU] times
    /// the number of inputs, including a zero fee, unless
    /// [Self::set_allow_low_fee] is set.
    pub fn set_fee(&mut self, fee: i128) {
        self.fee = fee;
    }

    /// Allow a fee below the default minimum relay fee, including a zero fee.
    ///
    /// Nodes with the default `--min-relay-pctx-fee-per-input` neither keep
    /// nor relay such a transaction; use this only with a node configured to
    /// accept it.
    pub fn set_allow_low_fee(&mut self, allow: bool) {
        self.allow_low_fee = allow;
    }

    /// Get total input amount
    pub fn input_total(&self) -> i128 {
        self.inputs.iter().map(|i| i.utxo.amount()).sum()
    }

    /// Get total output amount (excluding change)
    pub fn output_total(&self) -> i128 {
        self.outputs.iter().map(|o| o.amount).sum()
    }

    /// Get calculated change amount
    pub fn change_amount(&self) -> i128 {
        self.input_total() - self.output_total() - self.fee
    }

    /// Build the transaction
    pub fn build(
        &self,
        mutator_set: &MutatorSet,
        timestamp_ms: u64,
        network: Network,
    ) -> Result<BuiltTransaction> {
        // Validate inputs
        if self.inputs.is_empty() {
            return Err(XntError::TransactionError("no inputs".into()));
        }
        if self.inputs.len() > MAX_INPUTS {
            return Err(XntError::TransactionError(format!(
                "too many inputs: {} > {MAX_INPUTS}",
                self.inputs.len()
            )));
        }

        // Check for duplicate inputs (same UTXO spent twice).
        // Use AOCL leaf index which is unique per UTXO, matching how the
        // core wallet checks via removal record absolute_indices.
        let mut seen_indices = std::collections::HashSet::new();
        for input in &self.inputs {
            if !seen_indices.insert(input.membership_proof.aocl_leaf_index()) {
                return Err(XntError::TransactionError("duplicate input UTXO".into()));
            }
        }

        // Validate fee
        if self.fee < 0 {
            return Err(XntError::TransactionError("negative fee".into()));
        }
        if !self.allow_low_fee {
            let min_fee = MIN_RELAY_FEE_PER_INPUT_NAU * self.inputs.len() as i128;
            if self.fee < min_fee {
                return Err(XntError::TransactionError(format!(
                    "fee {} nau is below the minimum relay fee of {min_fee} nau for {} inputs",
                    self.fee,
                    self.inputs.len()
                )));
            }
        }

        // Validate outputs
        for (i, output) in self.outputs.iter().enumerate() {
            if output.amount <= 0 {
                return Err(XntError::TransactionError(format!(
                    "output {} has invalid amount: {}",
                    i, output.amount
                )));
            }
        }

        // Calculate totals with overflow checking
        let input_total = self
            .inputs
            .iter()
            .try_fold(0i128, |acc, i| acc.checked_add(i.utxo.amount()))
            .ok_or_else(|| XntError::TransactionError("input total overflow".into()))?;

        let output_total = self
            .outputs
            .iter()
            .try_fold(0i128, |acc, o| acc.checked_add(o.amount))
            .ok_or_else(|| XntError::TransactionError("output total overflow".into()))?;

        let change_amount = input_total
            .checked_sub(output_total)
            .and_then(|v| v.checked_sub(self.fee))
            .ok_or_else(|| XntError::TransactionError("change calculation overflow".into()))?;

        if change_amount < 0 {
            return Err(XntError::TransactionError("insufficient funds".into()));
        }

        if change_amount > 0 && self.change_address.is_none() {
            return Err(XntError::TransactionError("change address required".into()));
        }

        // Build TxInputList
        let mut tx_inputs = TxInputList::empty();
        for input in &self.inputs {
            let lock_script_and_witness = match &input.spending_key.inner {
                CoreSpendingKey::Generation(gen_key) => gen_key.lock_script_and_witness(),
                CoreSpendingKey::Symmetric(_) => {
                    return Err(XntError::TransactionError(
                        "symmetric keys not supported".to_string(),
                    ));
                }
                CoreSpendingKey::dCTIDH(dctidh_key) => dctidh_key.lock_script_and_witness(),
            };
            let unlocked = UnlockedUtxo::unlock(
                input.utxo.inner.clone(),
                lock_script_and_witness,
                input.membership_proof.inner.clone(),
            );
            tx_inputs.push(unlocked.into());
        }

        // Build TxOutputList - use .inner to get Neptune's ReceivingAddress
        let mut tx_outputs = TxOutputList::default();
        for output in &self.outputs {
            let nca = NativeCurrencyAmount::from_nau(output.amount);
            let tx_out = TxOutput::onchain_native_currency(
                nca,
                output.sender_randomness.to_core(),
                output.receiving_address.inner.clone(),
                false,
            );
            tx_outputs.push(tx_out);
        }

        // Add change output if needed
        if change_amount > 0 {
            if let (Some(addr), Some(sr)) = (&self.change_address, &self.change_sender_randomness) {
                let nca = NativeCurrencyAmount::from_nau(change_amount);
                let change_output = TxOutput::onchain_native_currency_as_change(
                    nca,
                    sr.to_core(),
                    addr.inner.clone().into(),
                );
                tx_outputs.push(change_output);
            }
        }

        // Every output must be able to carry a UTXO notification for its
        // recipient: refuses legacy-format dCTIDH locks and invalid dCTIDH
        // public keys.
        tx_outputs
            .validate_recipients()
            .map_err(|e| XntError::InvalidAddress(e.to_string()))?;

        // Create TransactionDetails
        let details = TransactionDetails::new(
            tx_inputs,
            tx_outputs,
            NativeCurrencyAmount::from_nau(self.fee),
            None,
            Timestamp::millis(timestamp_ms),
            mutator_set.inner.clone(),
            network.into(),
        );

        // Create PrimitiveWitness
        let witness = PrimitiveWitness::from_transaction_details(&details);

        Ok(BuiltTransaction {
            details,
            witness,
            tip_height: mutator_set.tip_height,
        })
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Input info from built transaction
#[derive(Clone, Debug)]
pub struct TxInputInfo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub commitment: Digest,
}

/// Output info from built transaction
#[derive(Clone, Debug)]
pub struct TxOutputInfo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_digest: Digest,
    pub is_change: bool,
    pub payment_id: Option<u64>,
    pub commitment: Digest,
}

/// Built transaction ready for proving
pub struct BuiltTransaction {
    pub(crate) details: TransactionDetails,
    pub(crate) witness: PrimitiveWitness,
    /// Height of the tip whose mutator set the transaction was built on, if
    /// known, see [MutatorSet::tip_height].
    pub(crate) tip_height: Option<u64>,
}

impl BuiltTransaction {
    /// Height of the tip whose mutator set the transaction was built on, if
    /// known: [Self::prove] proves it for the block after that tip.
    pub fn tip_height(&self) -> Option<u64> {
        self.tip_height
    }

    /// Get transaction kernel bytes
    pub fn kernel_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.details.transaction_kernel())
            .map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Get primitive witness bytes
    ///
    /// The witness holds the unlock data of every input, which for dCTIDH
    /// inputs is the key's spending secret (see
    /// [SpendingKey::receiver_preimage]). Keep it on the device that holds
    /// the seed.
    pub fn witness_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.witness).map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Serialize full transaction with Witness proof
    ///
    /// Contains the primitive witness, see [Self::witness_bytes]: keep it on
    /// the device that holds the seed.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let tx = CoreTransaction {
            kernel: self.witness.kernel.clone(),
            proof: TransactionProof::Witness(self.witness.clone()),
        };
        bincode::serialize(&tx).map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Get the primitive witness, see [Self::witness_bytes]
    pub fn witness(&self) -> &PrimitiveWitness {
        &self.witness
    }

    /// Check the (still unproven) transaction is confirmable against `mutator_set`.
    ///
    /// Confirmability is a property of the transaction kernel's removal records,
    /// not of the proof, so it can be checked before proving and predicts the
    /// post-prove result exactly (the kernel is unchanged by [`Self::prove`]).
    ///
    /// This mirrors core's `TransactionKernel::is_confirmable_relative_to` (which
    /// is not exported): every input removal record must validate against the
    /// mutator set, the inputs must be unique, and none may already be spent.
    ///
    /// Intended use: fetch the current tip via [`super::sync::get_mutator_set`] and
    /// call this BEFORE [`Self::prove`] to avoid spending minutes proving a
    /// snapshot that has already gone stale.
    pub fn is_confirmable(&self, mutator_set: &MutatorSet) -> bool {
        let msa = &mutator_set.inner;
        let inputs = &self.witness.kernel.inputs;
        let unique = inputs
            .iter()
            .map(|rr| rr.absolute_indices)
            .collect::<std::collections::HashSet<_>>()
            .len()
            == inputs.len();
        unique
            && inputs.iter().all(|rr| rr.validate(msa))
            && inputs.iter().all(|rr| msa.can_remove(rr))
    }

    /// Get all inputs
    pub fn inputs(&self) -> Vec<TxInputInfo> {
        use neptune_privacy::prelude::twenty_first::prelude::Tip5;
        self.witness
            .input_utxos
            .utxos
            .iter()
            .zip(self.witness.input_membership_proofs.iter())
            .map(|(utxo, mp)| {
                let item = Tip5::hash(utxo);
                let commitment = mp.addition_record(item).canonical_commitment;
                TxInputInfo {
                    utxo: Utxo { inner: utxo.clone() },
                    sender_randomness: Digest::from_core(mp.sender_randomness),
                    commitment: Digest::from_core(commitment),
                }
            })
            .collect()
    }

    /// Get all outputs (including change)
    pub fn outputs(&self) -> Vec<TxOutputInfo> {
        self.witness
            .output_utxos
            .utxos
            .iter()
            .zip(self.witness.output_sender_randomnesses.iter())
            .zip(self.witness.output_receiver_digests.iter())
            .zip(self.witness.kernel.outputs.iter())
            .zip(self.details.tx_outputs.iter())
            .map(|((((utxo, sr), rd), ar), tx_out)| TxOutputInfo {
                utxo: Utxo { inner: utxo.clone() },
                sender_randomness: Digest::from_core(*sr),
                receiver_digest: Digest::from_core(*rd),
                is_change: tx_out.is_change(),
                payment_id: tx_out.receiving_address().and_then(|a| a.payment_id()),
                commitment: Digest::from_core(ar.canonical_commitment),
            })
            .collect()
    }

    /// Prove transaction (creates ProofCollection) for the consensus rule set of
    /// the block that follows the tip whose mutator set it was built on, as
    /// [Self::prove_for_tip] does with that tip's height: before the
    /// UpgradeVMv8 hard fork at main-net block 97000, a v7 proof collection.
    ///
    /// Fails if that height is unknown, as for a mutator set restored with
    /// [MutatorSet::from_bytes]: then pass it with [MutatorSet::with_tip_height]
    /// before building, or prove with [Self::prove_for_tip].
    pub async fn prove(&self) -> Result<Transaction> {
        let tip_height = self.known_tip_height()?;
        self.prove_for_tip(tip_height).await
    }

    /// [Self::tip_height], or an error saying how to provide it.
    fn known_tip_height(&self) -> Result<u64> {
        self.tip_height.ok_or_else(|| {
            XntError::TransactionError(
                "the height of the tip whose mutator set the transaction was built on is unknown, \
                 so the consensus rule set to prove it for is unknown: build it on a mutator set \
                 from get_mutator_set, or on one given its tip height with \
                 MutatorSet::with_tip_height, or prove it with prove_for_tip(tip_height)"
                    .into(),
            )
        })
    }

    /// Prove transaction (creates ProofCollection) for the consensus rule set of
    /// the block that follows a tip at `tip_height`.
    ///
    /// Before the UpgradeVMv8 hard fork on main net, that is the UpgradeVMv7
    /// rule set, and the result a v7 proof collection, which is verified before
    /// it is returned. Nodes of that era relay and upgrade it only if it meets
    /// their terms, a minimum fee and at most 10 inputs (11 without time locks),
    /// see `legacy_era::check_proof_collection_terms`; this fails if it does not,
    /// and also within `legacy_era::DEFAULT_FORK_TX_CUTOFF_MARGIN` blocks of the
    /// fork, when the transaction might not be mined before it.
    pub async fn prove_for_tip(&self, tip_height: u64) -> Result<Transaction> {
        let consensus_rule_set = self.rule_set_for_tip(tip_height)?;
        self.prove_for(consensus_rule_set).await
    }

    /// The consensus rule set [Self::prove_for_tip] proves for: that of the
    /// block after a tip at `tip_height`. Fails within the cutoff margin
    /// before the fork, and for the era before it if the transaction does not
    /// meet that era's terms.
    fn rule_set_for_tip(
        &self,
        tip_height: u64,
    ) -> Result<neptune_privacy::api::export::ConsensusRuleSet> {
        use neptune_privacy::api::export::BlockHeight;
        use neptune_privacy::api::export::ConsensusRuleSet;
        use neptune_privacy::api::tx_initiation::legacy_era;

        let consensus_rule_set = legacy_era::rule_set_for_new_transaction(
            self.details.network,
            BlockHeight::from(tip_height),
            legacy_era::DEFAULT_FORK_TX_CUTOFF_MARGIN,
        )
        .map_err(|e| XntError::TransactionError(e.to_string()))?;
        if consensus_rule_set == ConsensusRuleSet::UpgradeVMv7 {
            legacy_era::check_proof_collection_terms(&self.witness)
                .map_err(|e| XntError::TransactionError(e.to_string()))?;
        }

        Ok(consensus_rule_set)
    }

    /// Prove transaction (creates ProofCollection) for the given consensus rule
    /// set: UpgradeVMv8, or UpgradeVMv7 before the hard fork, whose proof
    /// collection is verified before it is returned.
    async fn prove_for(&self, consensus_rule_set: neptune_privacy::api::export::ConsensusRuleSet) -> Result<Transaction> {
        use neptune_privacy::api::export::ConsensusRuleSet;
        use neptune_privacy::api::export::ProofCollection;
        use neptune_privacy::api::export::TritonVmJobQueue;
        use neptune_privacy::api::export::TritonVmProofJobOptionsBuilder;
        use neptune_privacy::api::export::TxProvingCapability;
        use neptune_privacy::protocol::proof_abstractions::mast_hash::MastHash;

        let job_queue = TritonVmJobQueue::get_instance();
        let options = TritonVmProofJobOptionsBuilder::new()
            .proving_capability(TxProvingCapability::ProofCollection)
            .network(self.details.network)
            .build();

        let proof_collection =
            ProofCollection::produce_v2(&self.witness, job_queue, options, consensus_rule_set)
                .await
                .map_err(|e| XntError::TransactionError(format!("proving failed: {e}")))?;

        let tx = CoreTransaction {
            kernel: self.witness.kernel.clone(),
            proof: TransactionProof::ProofCollection(proof_collection),
        };

        // Nodes of the era before the fork sanction peers that relay a proof they
        // reject, so a v7 proof is checked before it leaves the SDK.
        if consensus_rule_set == ConsensusRuleSet::UpgradeVMv7
            && !tx.proof.verify(tx.kernel.mast_hash(), self.details.network, consensus_rule_set).await
        {
            return Err(XntError::TransactionError(
                "proving failed: the v7 proof collection does not verify".into(),
            ));
        }

        Ok(Transaction { inner: tx })
    }
}

/// Final transaction
pub struct Transaction {
    pub(crate) inner: CoreTransaction,
}

impl Transaction {
    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let inner: CoreTransaction =
            bincode::deserialize(data).map_err(|e| XntError::EncodingError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.inner).map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Check if has ProofCollection
    pub fn has_proof_collection(&self) -> bool {
        matches!(self.inner.proof, TransactionProof::ProofCollection(_))
    }

    /// Check if has SingleProof (ready for broadcast)
    pub fn has_single_proof(&self) -> bool {
        matches!(self.inner.proof, TransactionProof::SingleProof(_))
    }

    /// Check the (proven) transaction is confirmable against `mutator_set`.
    ///
    /// Mirrors the node's submit gate: every input removal record must still
    /// validate against the given mutator set and none of the inputs may
    /// already be spent. Fetch the current tip via [`super::sync::get_mutator_set`]
    /// and call this BEFORE [`Self::submit`] to detect a transaction that went
    /// stale while proving.
    pub fn is_confirmable(&self, mutator_set: &MutatorSet) -> bool {
        self.inner.is_confirmable_relative_to(&mutator_set.inner)
    }

    /// Submit the transaction to the node.
    ///
    /// Returns the node's `success` field from the `mempool_submitTransaction`
    /// response. `true` only means the transaction passed the node's validity
    /// and confirmability checks and was queued for its mempool: the node can
    /// still drop it, for example if the fee is below its relay minimum or the
    /// mempool is full. Confirm by looking the transaction up in the mempool or
    /// by waiting for its outputs on chain. `false` means the node did not
    /// queue it. Rejections the node reports as errors (for example
    /// `NotConfirmable`) and RPC/transport failures are returned as `Err`.
    pub fn submit(&self, client: &super::json_rpc::RpcClient) -> Result<bool> {
        use neptune_privacy::application::json_rpc::core::model::wallet::transaction::RpcTransaction;

        // Check proof type
        match &self.inner.proof {
            TransactionProof::Witness(_) => {
                return Err(XntError::TransactionError(
                    "cannot submit transaction with Witness proof".to_string(),
                ));
            }
            TransactionProof::ProofCollection(_) | TransactionProof::SingleProof(_) => {}
        }

        let rpc_tx: RpcTransaction = self.inner.clone().into();
        let params = serde_json::json!({ "transaction": rpc_tx });

        let result = client.call("mempool_submitTransaction", params)?;

        Ok(result
            .get("success")
            .and_then(|s| s.as_bool())
            .unwrap_or(false))
    }
}

/// Get current timestamp in milliseconds
pub fn timestamp_now() -> u64 {
    Timestamp::now().0.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wallet::WalletEntropy;

    fn coins(amount: &str) -> i128 {
        NativeCurrencyAmount::coins_from_str(amount)
            .unwrap()
            .to_nau()
    }

    /// Membership proof with the given AOCL leaf index and no authentication
    /// data: enough for the checks [TransactionBuilder::build] makes before it
    /// uses the proofs.
    fn dummy_membership_proof(aocl_leaf_index: u64) -> MembershipProof {
        // sender randomness, receiver preimage, AOCL authentication path
        // length, AOCL leaf index, number of target chunks
        let mut bytes = vec![0u8; 40 + 40 + 8];
        bytes.extend_from_slice(&aocl_leaf_index.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        MembershipProof::from_bytes(&bytes).unwrap()
    }

    /// Builder spending `num_inputs` UTXOs of `amount` nau each, and the
    /// Generation address they are locked to.
    fn builder_with_inputs(num_inputs: usize, amount: i128) -> (TransactionBuilder, Address) {
        let key = WalletEntropy::devnet().derive_spending_key(0);
        let address = key.to_address().unwrap();
        let mut builder = TransactionBuilder::new();
        for i in 0..num_inputs {
            let utxo = Utxo::new_native(&address, amount);
            builder.add_input(utxo, key.clone(), dummy_membership_proof(i as u64));
        }
        (builder, address)
    }

    fn build_error(builder: &TransactionBuilder) -> String {
        let mutator_set = MutatorSet::from_core(Default::default());
        match builder.build(&mutator_set, 0, Network::RegTest) {
            Ok(_) => panic!("build must fail"),
            Err(e) => e.to_string(),
        }
    }

    /// A main-net payment of 1 coin from two inputs of 1 coin, with the given
    /// fee, built on a mutator set of the tip at `tip_height`, if given.
    fn main_net_payment(fee: &str, tip_height: Option<u64>) -> BuiltTransaction {
        let (mut builder, address) = builder_with_inputs(2, coins("1"));
        builder.add_output(address.to_receiving_address(), coins("1"), Digest::new());
        builder.set_change(address, Digest::new());
        builder.set_fee(coins(fee));
        let mut mutator_set = MutatorSet::from_core(Default::default());
        if let Some(tip_height) = tip_height {
            mutator_set = mutator_set.with_tip_height(tip_height);
        }
        builder.build(&mutator_set, 0, Network::Main).unwrap()
    }

    #[test]
    fn the_tip_height_of_the_mutator_set_goes_to_the_built_transaction() {
        assert_eq!(Some(94_000), main_net_payment("0.02", Some(94_000)).tip_height());

        let unknown = main_net_payment("0.02", None);
        assert_eq!(None, unknown.tip_height());
        let err = unknown.known_tip_height().unwrap_err().to_string();
        assert!(err.contains("prove_for_tip"), "{err}");
        assert!(err.contains("with_tip_height"), "{err}");
    }

    #[test]
    fn the_rule_set_follows_the_tip_the_transaction_was_built_on() {
        use neptune_privacy::api::export::ConsensusRuleSet;

        // With the default cutoff margin of 10 blocks, the last transactions of
        // the era before the fork at 97000 are made on top of block 96989.
        let rule_set = |tip_height: u64| {
            let built = main_net_payment("0.02", Some(tip_height));
            built.rule_set_for_tip(built.known_tip_height().unwrap())
        };
        assert_eq!(ConsensusRuleSet::UpgradeVMv7, rule_set(96_989).unwrap());
        for tip_height in [96_990, 96_998] {
            let err = rule_set(tip_height).unwrap_err().to_string();
            assert!(err.contains("UpgradeVMv7"), "tip {tip_height}: {err}");
        }
        assert_eq!(ConsensusRuleSet::UpgradeVMv8, rule_set(96_999).unwrap());
        assert_eq!(ConsensusRuleSet::UpgradeVMv8, rule_set(97_000).unwrap());

        // Before the fork, the terms of that era apply: a fee of 0.017 at least.
        let low_fee = main_net_payment("0.01", Some(94_000));
        assert!(low_fee.rule_set_for_tip(94_000).is_err());
        assert_eq!(
            ConsensusRuleSet::UpgradeVMv8,
            low_fee.rule_set_for_tip(97_000).unwrap()
        );
    }

    #[test]
    fn min_relay_fee_per_input_is_the_node_default() {
        assert_eq!(coins("0.0005"), MIN_RELAY_FEE_PER_INPUT_NAU);
    }

    #[test]
    fn build_refuses_more_than_max_inputs() {
        let (mut builder, _) = builder_with_inputs(MAX_INPUTS + 1, coins("1"));
        builder.set_fee(coins("1"));
        let err = build_error(&builder);
        assert!(err.contains("too many inputs"), "{err}");
    }

    #[test]
    fn build_refuses_a_fee_below_the_relay_minimum_unless_allowed() {
        let (mut builder, address) = builder_with_inputs(2, coins("1"));
        // More than the inputs hold, so that a build that passes the fee
        // check fails right after it.
        builder.add_output(address.to_receiving_address(), coins("3"), Digest::new());

        for fee in [0, 2 * MIN_RELAY_FEE_PER_INPUT_NAU - 1] {
            builder.set_fee(fee);
            let err = build_error(&builder);
            assert!(err.contains("minimum relay fee"), "{err}");
        }

        builder.set_fee(2 * MIN_RELAY_FEE_PER_INPUT_NAU);
        let err = build_error(&builder);
        assert!(err.contains("insufficient funds"), "{err}");

        builder.set_fee(0);
        builder.set_allow_low_fee(true);
        let err = build_error(&builder);
        assert!(err.contains("insufficient funds"), "{err}");
    }

    /// Bech32m encoding (BIP 350) of `payload`, to build an address string with
    /// a chosen payload.
    fn bech32m(hrp: &str, payload: &[u8]) -> String {
        const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

        let mut data = Vec::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for &byte in payload {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                data.push(((acc >> bits) & 31) as u8);
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            data.push(((acc << (5 - bits)) & 31) as u8);
        }

        let mut values: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
        values.push(0);
        values.extend(hrp.bytes().map(|c| c & 31));
        values.extend(&data);
        values.extend([0; 6]);
        let mut checksum = 1u32;
        for value in values {
            let top = checksum >> 25;
            checksum = ((checksum & 0x1ff_ffff) << 5) ^ u32::from(value);
            for (i, generator) in GENERATOR.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    checksum ^= generator;
                }
            }
        }
        checksum ^= 0x2bc8_30a3;
        data.extend((0..6).map(|i| ((checksum >> (5 * (5 - i))) & 31) as u8));

        let data: String = data
            .iter()
            .map(|&d| char::from(CHARSET[usize::from(d)]))
            .collect();
        format!("{hrp}1{data}")
    }

    #[test]
    fn build_refuses_a_dctidh_recipient_with_an_invalid_public_key() {
        let network = Network::RegTest;
        let valid = WalletEntropy::devnet()
            .derive_dctidh_spending_key(0)
            .to_address()
            .unwrap();
        let hrp = valid.inner.get_hrp(network.into());

        // public key, then a zero lock postimage
        let mut payload = vec![0x5a; 64];
        payload.extend([0; 40]);
        let encoded = bech32m(&hrp, &payload);
        // Decoding does not check the public key, see
        // dCTIDHReceivingAddress::validate_encryption_key.
        let recipient = Address::from_bech32(&encoded, network).unwrap();

        let (mut builder, _) = builder_with_inputs(1, coins("1"));
        builder.add_output(
            recipient.to_receiving_address(),
            coins("0.5"),
            Digest::new(),
        );
        builder.set_fee(coins("0.5"));
        let err = build_error(&builder);
        assert!(err.contains("invalid public key"), "{err}");
    }

    #[test]
    fn select_inputs_selects_at_most_max_inputs() {
        let amounts = vec![1; MAX_INPUTS + 50];
        let limit = amounts.len();
        assert!(select_inputs(&amounts, MAX_INPUTS as i128 + 1, limit).is_err());
        let selected = select_inputs(&amounts, MAX_INPUTS as i128, limit).unwrap();
        assert_eq!(MAX_INPUTS, selected.len());
    }
}
