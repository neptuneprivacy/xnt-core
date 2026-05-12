use std::collections::HashMap;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::proof_abstractions::mast_hash::MastHash;

/// Reason why a transaction was removed from the mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalReason {
    /// Conflicting transaction was confirmed in a block (double spend)
    DoubleSpend,

    /// ProofCollection from peer with no primitive witness — cannot update
    StaleNoUpdate,

    /// Transaction had empty inputs
    EmptyInputs,

    /// Mempool full, lowest fee-density tx evicted
    MempoolFull,

    /// Chain reorganization (orphaned block), mempool cleared
    Orphaned,

    /// Transaction too old (pruned)
    Pruned,

    /// Replaced by a transaction with higher fee density or better proof
    Replaced,

    /// Replaced by updated version (same logical tx, new mutator set data)
    Updated,

    /// Explicit removal (e.g. by RPC call)
    Explicit,
}

/// Reason why a transaction was added to the mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddReason {
    /// Submitted by the local wallet
    Submitted,

    /// Received from a peer
    FromPeer,

    /// Restored from merge input cache after block
    Restored,

    /// Re-inserted after mutator set update
    Updated,

    /// Upgraded proof (e.g. ProofCollection → SingleProof, or merge)
    Upgraded,
}

/// Represents a mempool state change.
///
/// For purpose of notifying interested parties
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolEvent {
    /// a transaction was added to the mempool
    AddTx(TransactionKernel, AddReason),

    /// a transaction was removed from the mempool
    RemoveTx(TransactionKernel, RemovalReason),
}

impl MempoolEvent {
    fn kernel_mast_hash(&self) -> Digest {
        match self {
            MempoolEvent::AddTx(transaction_kernel, _) => transaction_kernel.mast_hash(),
            MempoolEvent::RemoveTx(transaction_kernel, _) => transaction_kernel.mast_hash(),
        }
    }

    /// Remove pairs of the form (add, remove) referring to the same
    /// transaction.
    ///
    /// Shortens the list of [`MempoolEvent`]s such that pairs of events
    /// referring to the same transaction first being added, and then removed
    /// are eliminated from the list.
    pub(super) fn normalize(events: Vec<Self>) -> Vec<Self> {
        let mut added = HashMap::new();
        let mut removed = HashMap::new();
        for event in events {
            // We use kernel MAST hash as hash map key because we want two
            // events if an insertion is used for updating a mutator set.
            let tx_key = event.kernel_mast_hash();
            match event {
                MempoolEvent::AddTx(transaction_kernel, reason) => {
                    if removed.contains_key(&tx_key) {
                        removed.remove(&tx_key);
                    } else {
                        added.insert(tx_key, (transaction_kernel, reason));
                    }
                }
                MempoolEvent::RemoveTx(transaction_kernel, reason) => {
                    if added.contains_key(&tx_key) {
                        added.remove(&tx_key);
                    } else {
                        removed.insert(tx_key, (transaction_kernel, reason));
                    }
                }
            }
        }

        removed
            .into_values()
            .map(|(kernel, reason)| Self::RemoveTx(kernel, reason))
            .chain(
                added
                    .into_values()
                    .map(|(kernel, reason)| Self::AddTx(kernel, reason)),
            )
            .collect()
    }
}

/// A batch of mempool events, optionally triggered by a specific block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolEventBatch {
    /// The block that triggered these events, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<BlockHeight>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_digest: Option<Digest>,
    pub events: Vec<MempoolEventInfo>,
}

impl MempoolEventBatch {
    /// Create a batch triggered by a block.
    pub fn from_block(
        block_height: BlockHeight,
        block_digest: Digest,
        events: Vec<MempoolEventInfo>,
    ) -> Self {
        Self {
            block_height: Some(block_height),
            block_digest: Some(block_digest),
            events,
        }
    }

    /// Create a batch not tied to any block.
    pub fn standalone(events: Vec<MempoolEventInfo>) -> Self {
        Self {
            block_height: None,
            block_digest: None,
            events,
        }
    }
}

/// Serializable mempool event for the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MempoolEventInfo {
    Add {
        kernel: TransactionKernel,
        reason: AddReason,
    },
    Remove {
        kernel: TransactionKernel,
        reason: RemovalReason,
    },
}

impl From<&MempoolEvent> for MempoolEventInfo {
    fn from(event: &MempoolEvent) -> Self {
        match event {
            MempoolEvent::AddTx(kernel, reason) => MempoolEventInfo::Add {
                kernel: kernel.clone(),
                reason: *reason,
            },
            MempoolEvent::RemoveTx(kernel, reason) => MempoolEventInfo::Remove {
                kernel: kernel.clone(),
                reason: *reason,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl MempoolEvent {
        pub(crate) fn is_add(&self) -> bool {
            matches!(self, Self::AddTx(..))
        }

        pub(crate) fn is_remove(&self) -> bool {
            matches!(self, Self::RemoveTx(..))
        }

        pub(crate) fn num_removes(events: &[Self]) -> usize {
            events.iter().filter(|x| x.is_remove()).count()
        }

        pub(crate) fn num_adds(events: &[Self]) -> usize {
            events.iter().filter(|x| x.is_add()).count()
        }
    }
}
