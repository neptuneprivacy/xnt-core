use crate::api::export::Transaction;
use crate::api::export::TransactionKernelId;
use crate::protocol::consensus::chaintx::link_tx::LinkTx;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::tasm_lib::prelude::Digest;

pub(crate) enum MempoolUpdateJobResult {
    Failure(TransactionKernelId),
    /// Updating a link transaction failed.
    LinkFailure(TransactionKernelId),
    Success {
        /// The primitive witness, with updated mutator set data
        new_primitive_witness: Option<Box<PrimitiveWitness>>,

        /// The transaction, with updated mutator set data.
        new_transaction: Box<Transaction>,
    },
    SuccessLink {
        /// The link transaction, with updated mutator set data.
        new_link_tx: Box<LinkTx>,

        /// The digest of the `SingleProof` program the link proof was made
        /// for.
        single_proof_digest: Digest,
    },
}
