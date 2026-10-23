//! The sum of the two transaction types the mempool can hold.

use get_size2::GetSize;

use crate::protocol::consensus::chaintx::link_tx::LinkTx;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::Transaction;

/// A transaction on either transaction pipeline: a single-proof [`Transaction`]
/// or a chainable [`LinkTx`].
///
/// The mempool stores both populations in one table so that its machinery,
/// fee-density queue, size bound, eviction policy, and conflict detection on
/// inputs, covers both.
#[derive(Debug, Clone, GetSize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) enum AnyTx {
    Standard(Box<Transaction>),
    Link(Box<LinkTx>),
}

impl AnyTx {
    /// The transaction kernel; for a link transaction, the wrapped
    /// [`TransactionKernel`].
    ///
    /// The wrapped kernel's fields mean the same thing on both pipelines.
    pub(crate) fn kernel(&self) -> &TransactionKernel {
        match self {
            AnyTx::Standard(transaction) => &transaction.kernel,
            AnyTx::Link(link_tx) => &link_tx.kernel.kernel,
        }
    }

    /// Like [`Self::kernel`], but consuming.
    pub(crate) fn into_kernel(self) -> TransactionKernel {
        match self {
            AnyTx::Standard(transaction) => transaction.kernel,
            AnyTx::Link(link_tx) => link_tx.kernel.kernel,
        }
    }

    /// The fee density, on whichever pipeline. See
    /// [`Transaction::fee_density`] and [`LinkTx::fee_density`].
    pub(crate) fn fee_density(&self) -> num_rational::BigRational {
        match self {
            AnyTx::Standard(transaction) => transaction.fee_density(),
            AnyTx::Link(link_tx) => link_tx.fee_density(),
        }
    }

    /// The single-proof pipeline transaction, if that is what this is.
    pub(crate) fn as_standard(&self) -> Option<&Transaction> {
        match self {
            AnyTx::Standard(transaction) => Some(transaction),
            AnyTx::Link(_) => None,
        }
    }

    /// The link transaction, if that is what this is.
    pub(crate) fn as_link(&self) -> Option<&LinkTx> {
        match self {
            AnyTx::Standard(_) => None,
            AnyTx::Link(link_tx) => Some(link_tx),
        }
    }

    /// Like [`Self::as_standard`], but mutable.
    #[cfg(test)]
    pub(crate) fn as_standard_mut(&mut self) -> Option<&mut Transaction> {
        match self {
            AnyTx::Standard(transaction) => Some(transaction),
            AnyTx::Link(_) => None,
        }
    }
}
