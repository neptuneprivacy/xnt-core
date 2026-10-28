use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::api::export::AdditionRecord;
use crate::api::export::Announcement;
use crate::api::export::Timestamp;
use crate::api::export::TransactionKernelId;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::application::json_rpc::core::model::common::RpcNativeCurrencyAmount;
use crate::application::json_rpc::core::model::wallet::mutator_set::RpcMmrMembershipProof;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::chunk::Chunk;
use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

pub type RpcAbsoluteIndexSet = AbsoluteIndexSet;

/// Uses Vec to preserve the original ChunkDictionary entry ordering.
/// BTreeMap<u64> would re-sort keys numerically, changing the BFieldCodec
/// encoding and thus the block hash.
#[derive(Clone, Debug, Serialize, PartialEq, Eq, Default)]
pub struct RpcChunkDictionary(pub Vec<(u64, (RpcMmrMembershipProof, Vec<u32>))>);

/// Also reads upstream nodes' JSON object form, whose keys are already sorted.
impl<'de> Deserialize<'de> for RpcChunkDictionary {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        type Entry = (RpcMmrMembershipProof, Vec<u32>);

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Ordered(Vec<(u64, Entry)>),
            // Keys stay strings: untagged buffering does not parse them as numbers.
            Upstream(std::collections::BTreeMap<String, Entry>),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Ordered(entries) => Ok(Self(entries)),
            Repr::Upstream(entries) => {
                let mut entries = entries
                    .into_iter()
                    .map(|(index, entry)| {
                        index
                            .parse::<u64>()
                            .map(|index| (index, entry))
                            .map_err(serde::de::Error::custom)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                entries.sort_by_key(|(index, _)| *index);
                Ok(Self(entries))
            }
        }
    }
}

impl From<ChunkDictionary> for RpcChunkDictionary {
    fn from(value: ChunkDictionary) -> Self {
        Self(
            value
                .dictionary
                .into_iter()
                .map(|(index, (proof, chunk))| (index, (proof.into(), chunk.relative_indices)))
                .collect(),
        )
    }
}

impl From<RpcChunkDictionary> for ChunkDictionary {
    fn from(value: RpcChunkDictionary) -> Self {
        let dictionary = value
            .0
            .into_iter()
            .map(|(index, (authentication_path, relative_indices))| {
                (
                    index,
                    (authentication_path.into(), Chunk { relative_indices }),
                )
            })
            .collect();

        Self { dictionary }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcRemovalRecord {
    pub absolute_indices: RpcAbsoluteIndexSet,
    pub target_chunks: RpcChunkDictionary,
}

impl From<RemovalRecord> for RpcRemovalRecord {
    fn from(record: RemovalRecord) -> Self {
        Self {
            absolute_indices: record.absolute_indices,
            target_chunks: record.target_chunks.into(),
        }
    }
}

impl From<RpcRemovalRecord> for RemovalRecord {
    fn from(record: RpcRemovalRecord) -> Self {
        Self {
            absolute_indices: record.absolute_indices,
            target_chunks: record.target_chunks.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RpcAdditionRecord(pub Digest);

impl From<AdditionRecord> for RpcAdditionRecord {
    fn from(record: AdditionRecord) -> Self {
        Self(record.canonical_commitment)
    }
}

impl From<RpcAdditionRecord> for AdditionRecord {
    fn from(record: RpcAdditionRecord) -> Self {
        Self {
            canonical_commitment: record.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcAnnouncement(RpcBFieldElements);

impl From<Announcement> for RpcAnnouncement {
    fn from(announcement: Announcement) -> Self {
        Self(announcement.message.into())
    }
}

impl From<RpcAnnouncement> for Announcement {
    fn from(announcement: RpcAnnouncement) -> Self {
        Announcement {
            message: announcement.0.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionKernel {
    pub inputs: Vec<RpcRemovalRecord>,
    pub outputs: Vec<RpcAdditionRecord>,
    pub announcements: Vec<RpcAnnouncement>,
    pub fee: RpcNativeCurrencyAmount,
    pub coinbase: Option<RpcNativeCurrencyAmount>,
    pub timestamp: Timestamp,
    pub mutator_set_hash: Digest,
    pub merge_bit: bool,
}

impl PartialEq for RpcTransactionKernel {
    fn eq(&self, o: &Self) -> bool {
        self.inputs == o.inputs
            && self.outputs == o.outputs
            && self.announcements == o.announcements
            && self.fee == o.fee
            && self.coinbase == o.coinbase
            && self.timestamp == o.timestamp
            && self.mutator_set_hash == o.mutator_set_hash
            && self.merge_bit == o.merge_bit
    }
}

impl From<&TransactionKernel> for RpcTransactionKernel {
    fn from(kernel: &TransactionKernel) -> Self {
        Self {
            inputs: kernel.inputs.clone().into_iter().map(Into::into).collect(),
            outputs: kernel.outputs.iter().copied().map(Into::into).collect(),
            announcements: kernel
                .announcements
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
            fee: kernel.fee.into(),
            coinbase: kernel.coinbase.map(|c| c.into()),
            timestamp: kernel.timestamp,
            mutator_set_hash: kernel.mutator_set_hash,
            merge_bit: kernel.merge_bit,
        }
    }
}

impl From<RpcTransactionKernel> for TransactionKernel {
    fn from(kernel: RpcTransactionKernel) -> Self {
        let kernel_proxy = TransactionKernelProxy {
            inputs: kernel.inputs.into_iter().map(Into::into).collect(),
            outputs: kernel.outputs.into_iter().map(Into::into).collect(),
            announcements: kernel.announcements.into_iter().map(Into::into).collect(),
            fee: kernel.fee.into(),
            coinbase: kernel.coinbase.map(Into::into),
            timestamp: kernel.timestamp,
            mutator_set_hash: kernel.mutator_set_hash,
            merge_bit: kernel.merge_bit,
        };

        kernel_proxy.into_kernel()
    }
}

pub type RpcTransactionKernelId = TransactionKernelId;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn chunk_dictionary_reads_its_own_and_upstreams_json() {
        let entry = |seed: u32| (RpcMmrMembershipProof::default(), vec![seed, seed + 1]);
        let ours = RpcChunkDictionary(vec![(1, entry(10)), (3, entry(30))]);
        let ordered = serde_json::to_value(&ours).unwrap();
        let upstream = serde_json::json!({
            "3": serde_json::to_value(entry(30)).unwrap(),
            "1": serde_json::to_value(entry(10)).unwrap(),
        });

        assert_eq!(ours, serde_json::from_value(ordered).unwrap());
        assert_eq!(ours, serde_json::from_value(upstream).unwrap());
    }
}
