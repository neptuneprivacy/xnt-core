use serde::Deserialize;
use serde::Serialize;

use crate::application::json_rpc::core::model::block::appendix::RpcBlockAppendix;
use crate::application::json_rpc::core::model::block::body::RpcBlockBody;
use crate::application::json_rpc::core::model::block::header::RpcBlockHeader;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::protocol::consensus::block::block_kernel::BlockKernel;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::BlockProof;

pub mod appendix;
pub mod body;
pub mod header;
pub mod transaction_kernel;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockKernel {
    pub header: RpcBlockHeader,
    pub body: RpcBlockBody,
    pub appendix: RpcBlockAppendix,
}

impl From<&BlockKernel> for RpcBlockKernel {
    fn from(kernel: &BlockKernel) -> Self {
        RpcBlockKernel {
            header: RpcBlockHeader::from(&kernel.header),
            body: RpcBlockBody::from(&kernel.body),
            appendix: RpcBlockAppendix::from(&kernel.appendix),
        }
    }
}

pub type RpcBlockProof = Option<RpcBFieldElements>;

impl From<&BlockProof> for RpcBlockProof {
    fn from(proof: &BlockProof) -> Self {
        match proof {
            BlockProof::Genesis | BlockProof::Invalid => None,
            BlockProof::SingleProof(proof) => Some(proof.0.clone().into()),
        }
    }
}

impl From<RpcBlockProof> for BlockProof {
    fn from(proof: RpcBlockProof) -> Self {
        match proof {
            None => BlockProof::Invalid,
            Some(bfes) => BlockProof::SingleProof(bfes.0.into()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlock {
    pub kernel: RpcBlockKernel,
    pub proof: RpcBlockProof,
}

impl From<&Block> for RpcBlock {
    fn from(block: &Block) -> Self {
        RpcBlock {
            kernel: RpcBlockKernel::from(&block.kernel),
            proof: RpcBlockProof::from(&block.proof),
        }
    }
}

impl From<RpcBlock> for Block {
    fn from(block: RpcBlock) -> Self {
        Block::new(
            block.kernel.header.into(),
            block.kernel.body.into(),
            block.kernel.appendix.into(),
            block.proof.into(),
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use super::*;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::block::block_body::BlockBody;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    #[test]
    fn json_round_trip_keeps_hash_of_block_with_packed_inputs() {
        let records = RemovalRecord::arbitrary_synchronized_set(1 << 20, 10)
            .new_tree(&mut TestRunner::deterministic())
            .unwrap()
            .current();
        let packed = RemovalRecordList::pack(records, true);
        assert!(
            packed.iter().any(|record| {
                let keys = record.target_chunks.dictionary.iter().map(|(key, _)| *key);
                !keys.clone().is_sorted() || keys.filter(|key| *key == u64::MAX).count() > 1
            }),
            "need a dictionary that a sorted map would reorder or collapse"
        );

        let genesis = Block::genesis(Network::RegTest);
        let body = genesis.body();
        let kernel = TransactionKernelModifier::default()
            .inputs(packed)
            .clone_modify(body.transaction_kernel());
        let block = Block::new(
            *genesis.header(),
            BlockBody::new(
                kernel,
                body.mutator_set_accumulator_without_guesser_fees(),
                body.lock_free_mmr_accumulator.clone(),
                body.block_mmr_accumulator.clone(),
            ),
            genesis.appendix().clone(),
            BlockProof::SingleProof(vec![BFieldElement::new(7)].into()),
        );

        let json = serde_json::to_string(&RpcBlock::from(&block)).unwrap();
        let rebuilt: Block = serde_json::from_str::<RpcBlock>(&json).unwrap().into();
        assert_eq!(block.hash(), rebuilt.hash());
    }
}
