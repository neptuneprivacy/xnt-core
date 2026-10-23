//! provides error types related to initiating transactions.

use tasm_lib::prelude::Digest;

use crate::api::export::BlockHeight;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::RecordTransactionError;
use crate::application::job_queue::errors::AddJobError;
use crate::application::job_queue::errors::JobHandleError;
use crate::protocol::consensus::consensus_rule_set::TransactionTooBig;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::proof_abstractions::tasm::prover_job::ProverJobError;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;

/// enumerates possible transaction send errors
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum CreateTxError {
    #[error("missing required data to build transaction")]
    MissingRequirement,

    #[error("Transaction with negative fees not allowed")]
    NegativeFee,

    #[error("total spend amount is too large")]
    TotalSpendTooLarge,

    #[error(
        "insufficient funds. requested: {}, available: {}",
        requested,
        available
    )]
    InsufficientFunds {
        requested: NativeCurrencyAmount,
        available: NativeCurrencyAmount,
    },

    #[error("ChangePolicy = ExactChange, but input amount exceeds output amount")]
    NotExactChange,

    #[error("provided key_type cannot be used for receiving change.")]
    InvalidKeyForChange,

    #[error("cannot generate change key for immutable wallet.")]
    CantGenChangeKeyForImmutableWallet,

    #[error("tip does not have mutator-set-after")]
    NoMutatorSetAccumulatorAfter,

    #[error("covering the amount needs {needed} inputs, more than the {max} allowed; consolidate UTXOs first")]
    TooManyInputs { needed: usize, max: usize },

    #[error("the bridge is not active under consensus rule set {0}")]
    BridgeNotActive(crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet),

    #[error("bridge deposit of {amount} is below the minimum of {min}")]
    BelowBridgeMinimum {
        amount: NativeCurrencyAmount,
        min: NativeCurrencyAmount,
    },
    #[error("transparent transactions can only spend UTXOs held by Generation keys")]
    TransparentInputNotAllowed,

    #[error("cannot send to this address: {0}")]
    InvalidRecipient(String),

    /// The fee of a transaction for the `UpgradeVMv7` era is below what nodes
    /// of that era require to relay and upgrade its proof collection. See
    /// [`legacy_era`](super::legacy_era).
    #[error(
        "fee {fee} is below {min_fee}, the least fee at which nodes of the current main-net \
         release relay and upgrade a proof collection with {num_inputs} inputs before the \
         next hard fork"
    )]
    LegacyEraFeeTooLow {
        fee: NativeCurrencyAmount,
        min_fee: NativeCurrencyAmount,
        num_inputs: usize,
    },

    /// A transaction for the `UpgradeVMv7` era has more inputs than nodes of
    /// that era upgrade the proof collection of. See
    /// [`legacy_era`](super::legacy_era).
    #[error(
        "{num_inputs} inputs are more than the {max_num_inputs} that nodes of the current \
         main-net release upgrade a proof collection with before the next hard fork; send \
         the amount in several transactions"
    )]
    LegacyEraTooManyInputs {
        num_inputs: usize,
        max_num_inputs: usize,
    },

    /// An output of a transaction for the `UpgradeVMv7` era carries a type
    /// script that is not known under its current hash in both eras. See
    /// [`legacy_era`](super::legacy_era).
    #[error(
        "an output carries type script {0:x}; before the next hard fork, outputs carry only the \
         native currency and time locks"
    )]
    LegacyEraTypeScript(Digest),
}

#[derive(Debug, Clone, thiserror::Error, strum::Display)]
#[non_exhaustive]
pub enum ProofRequirement {
    Program,
    Claim,
    NonDeterminism,
    ProofJobOptions,
    TransactionProofInput,
    ConsensusRuleSet,
}

/// enumerates possible proof generation errors
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CreateProofError {
    #[error("missing required data to build proof: {0}")]
    MissingRequirement(#[from] ProofRequirement),

    #[error(
        "machine capability {capability} is insufficient to generate proof of type: {proof_type}"
    )]
    TooWeak {
        proof_type: TransactionProofType,
        capability: TxProvingCapability,
    },

    #[error("target proof type {0} is not a triton-vm proof.")]
    NotVmProof(TransactionProofType),

    #[error(transparent)]
    AddJobError(#[from] AddJobError),

    #[error(transparent)]
    ProverJobError(#[from] ProverJobError),

    #[error(transparent)]
    JobHandleError(#[from] JobHandleError),

    #[error("Could not forward job cancellation msg to proving job. {0}")]
    JobCancelSendError(#[from] tokio::sync::watch::error::SendError<()>),

    #[error("in-process proving failed: {0}")]
    InProcessProving(#[from] tasm_lib::triton_vm::error::ProvingError),

    #[error("in-process proving task did not finish: {0}")]
    InProcessTask(tokio::task::JoinError),
    /// No new transaction is created for this rule set, the one of the era
    /// before the next hard fork: the fork is too close for the transaction to
    /// be mined before it. See [`legacy_era`](super::legacy_era). Transactions
    /// are created again once the next block belongs to the era after the
    /// fork.
    #[error(
        "no new transactions are created for consensus rule set {0}: the next hard fork is too \
         close; new transactions are created again from the fork on"
    )]
    LegacyEra(crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet),

    #[error("link transaction cannot be fixed: {0}")]
    LinkTxNotFixable(&'static str),

    #[error("this version cannot produce {proof} for consensus rule set {consensus_rule_set}")]
    NotProducible {
        proof: &'static str,
        consensus_rule_set: crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet,
    },

    /// A freshly produced proof was rejected by the verifier of its era, so it
    /// was not used.
    #[error("the proof produced for program {0:x} does not verify")]
    ProducedProofDoesNotVerify(Digest),

    #[error(transparent)]
    LegacyProving(#[from] crate::protocol::proof_abstractions::tasm::legacy_v7::LegacyProvingError),

    #[error("no v7 single proof is made: {0}")]
    V7SingleProofUnavailable(
        #[from]
        crate::protocol::consensus::transaction::validity::legacy_v7::V7SingleProofUnavailable,
    ),

    /// A program proven inside a v7 proof collection does not hash as the
    /// nodes of the era before the fork compute it, so the collection would be
    /// invalid there. See
    /// `validity::legacy_v7::V7_PROOF_COLLECTION_PROGRAM_DIGESTS`.
    #[error("no v7 proof collection is made: program {0} does not have its v7 digest")]
    V7ProgramDigestMismatch(&'static str),
}

/// enumerates possible upgrade-proof errors
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum UpgradeProofError {
    #[error("transaction is not found in mempool")]
    TxNotInMempool,

    #[error("input proof is not an upgrade.  ignoring.")]
    ProofNotAnUpgrade,

    #[error("provided proof is not valid for specified transaction.")]
    InvalidProof,
}

/// enumerates possible transaction send errors
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    #[error("send() is not supported by this node")]
    Unsupported,

    #[error("transaction could not be broadcast.")]
    NotBroadcast,

    #[error(transparent)]
    Tx(#[from] CreateTxError),

    #[error(transparent)]
    Proof(#[from] CreateProofError),

    #[error(transparent)]
    RecordTransaction(#[from] RecordTransactionError),

    #[error("Send rate limit reached for block height {height} ({digest}). A maximum of {max} tx may be sent per block.", digest = tip_digest.to_hex())]
    RateLimit {
        height: BlockHeight,
        tip_digest: Digest,
        max: usize,
    },

    #[error("transaction can never be mined: {0}")]
    TooBig(#[from] TransactionTooBig),

    #[error("chained send failed: {0}")]
    Chained(String),

    /// Before the next hard fork: the transaction comes within the cutoff
    /// margin of the fork, or its proof collection pays too low a fee or has
    /// too many proofs for the nodes of the era before the fork to relay and
    /// upgrade it. See `legacy_era::submitted_transaction_meets_terms`.
    #[error(
        "transaction does not meet the terms of the era before the next hard fork: it comes \
         within the cutoff margin of the fork, or its proof collection pays too low a fee or has \
         too many proofs"
    )]
    BelowLegacyEraTerms,
}
