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

/// Select UTXOs to cover target amount with minimum inputs.
/// Uses sliding window on sorted amounts to find smallest UTXOs that fit within limit.
pub fn select_inputs(amounts: &[i128], target: i128, limit: usize) -> Result<Vec<usize>> {
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

    // Sliding window: prefer fewer inputs, but use smallest UTXOs that work
    let max_window = limit.min(indexed.len());

    for window_size in 1..=max_window {
        for start in 0..=(indexed.len() - window_size) {
            let window = &indexed[start..start + window_size];
            // Use checked arithmetic to prevent overflow
            let sum = window
                .iter()
                .try_fold(0i128, |acc, (_, amt)| acc.checked_add(*amt))
                .ok_or_else(|| XntError::TransactionError("amount overflow".into()))?;
            if sum >= target {
                return Ok(window.iter().map(|(idx, _)| *idx).collect());
            }
        }
    }

    // No valid window found - use saturating arithmetic for error message
    let total: i128 = indexed.iter().map(|(_, amt)| amt).fold(0i128, |a, b| a.saturating_add(*b));
    let best: i128 = indexed.iter().rev().take(max_window).map(|(_, amt)| amt).fold(0i128, |a, b| a.saturating_add(*b));
    Err(XntError::TransactionError(format!(
        "insufficient: best={} total={} need={} (limit={})",
        best, total, target, limit
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
    pub fn set_fee(&mut self, fee: i128) {
        self.fee = fee;
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

        // Check for duplicate inputs (same UTXO spent twice)
        let mut seen_utxos = std::collections::HashSet::new();
        for input in &self.inputs {
            let hash = input.utxo.hash().to_hex();
            if !seen_utxos.insert(hash) {
                return Err(XntError::TransactionError("duplicate input UTXO".into()));
            }
        }

        // Validate fee
        if self.fee < 0 {
            return Err(XntError::TransactionError("negative fee".into()));
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

        Ok(BuiltTransaction { details, witness })
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
}

impl BuiltTransaction {
    /// Get transaction kernel bytes
    pub fn kernel_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.details.transaction_kernel())
            .map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Get primitive witness bytes
    pub fn witness_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.witness).map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Serialize full transaction with Witness proof
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let tx = CoreTransaction {
            kernel: self.witness.kernel.clone(),
            proof: TransactionProof::Witness(self.witness.clone()),
        };
        bincode::serialize(&tx).map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Get the primitive witness
    pub fn witness(&self) -> &PrimitiveWitness {
        &self.witness
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

    /// Prove transaction (creates ProofCollection)
    pub async fn prove(&self) -> Result<Transaction> {
        use neptune_privacy::api::export::ProofCollection;
        use neptune_privacy::api::export::TritonVmJobQueue;
        use neptune_privacy::api::export::TritonVmProofJobOptionsBuilder;
        use neptune_privacy::api::export::TxProvingCapability;

        let job_queue = TritonVmJobQueue::get_instance();
        let options = TritonVmProofJobOptionsBuilder::new()
            .proving_capability(TxProvingCapability::ProofCollection)
            .build();

        let proof_collection = ProofCollection::produce(&self.witness, job_queue, options)
            .await
            .map_err(|e| XntError::TransactionError(format!("proving failed: {e}")))?;

        let tx = CoreTransaction {
            kernel: self.witness.kernel.clone(),
            proof: TransactionProof::ProofCollection(proof_collection),
        };

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

    /// Submit to node via RPC
    pub fn submit(&self, client: &super::json_rpc::RpcClient) -> Result<()> {
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

        if result.get("success").and_then(|s| s.as_bool()).unwrap_or(false) {
            Ok(())
        } else {
            Err(XntError::TransactionError(
                "transaction submission failed".to_string(),
            ))
        }
    }
}

/// Get current timestamp in milliseconds
pub fn timestamp_now() -> u64 {
    Timestamp::now().0.into()
}
