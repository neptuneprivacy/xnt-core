use async_trait::async_trait;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use thiserror::Error;

use crate::application::json_rpc::core::model::block::header::RpcBlockHeight;
use crate::application::json_rpc::core::model::block::header::RpcBlockPow;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcAbsoluteIndexSet;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcAdditionRecord;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcTransactionKernelId;
use crate::application::json_rpc::core::model::block::RpcBlock;
use crate::application::json_rpc::core::model::common::RpcBlockSelector;
use crate::application::json_rpc::core::model::json::JsonError;
use crate::application::json_rpc::core::model::message::*;
use crate::application::json_rpc::core::model::wallet::transaction::RpcTransaction;

#[derive(Debug, Clone, Copy, Error, Eq, PartialEq, Serialize, Deserialize)]
pub enum RestoreMembershipProofError {
    #[error("Failed for index {0}")]
    Failed(usize),

    #[error("Exceeds the allowed limit")]
    ExceedsAllowed,
}

#[derive(Debug, Clone, Copy, Error, Eq, PartialEq, Serialize, Deserialize)]
pub enum SubmitTransactionError {
    #[error("Invalid transaction")]
    InvalidTransaction,

    #[error("Coinbase transactions are not allowed")]
    CoinbaseTransaction,

    #[error("Transaction fee is negative")]
    FeeNegative,

    #[error("Transaction is future-dated")]
    FutureDated,

    #[error("Transaction not confirmable relative to the mutator set")]
    NotConfirmable,
}

#[derive(Debug, Clone, Copy, Error, Eq, PartialEq, Serialize, Deserialize)]
pub enum SubmitBlockError {
    #[error("Invalid block")]
    InvalidBlock,

    #[error("The block's proof-of-work does not meet the required target")]
    InsufficientWork,
}

#[derive(Debug, Clone, Error, Eq, PartialEq, Serialize, Deserialize)]
pub enum RpcError {
    #[error("JSON-RPC server error: {0}")]
    Server(JsonError),

    // Call-specific errors
    #[error("Failed to restore membership proof: {0}")]
    RestoreMembershipProof(RestoreMembershipProofError),

    #[error("Failed to submit transaction: {0}")]
    SubmitTransaction(SubmitTransactionError),

    #[error("Failed to submit block: {0}")]
    SubmitBlock(SubmitBlockError),

    // Common case errors
    #[error("Invalid address provided in arguments")]
    InvalidAddress,

    #[error("UTXO indexer not enabled")]
    UtxoIndexerDisabled,

    #[error("Block range exceeds limit of {0}")]
    BlockRangeExceedsLimit(u64),
}

pub type RpcResult<T> = Result<T, RpcError>;

#[async_trait]
pub trait RpcApi: Sync + Send {
    /* Node */

    async fn network(&self) -> RpcResult<NetworkResponse> {
        self.network_call(NetworkRequest {}).await
    }
    async fn network_call(&self, request: NetworkRequest) -> RpcResult<NetworkResponse>;

    /* Chain */

    async fn height(&self) -> RpcResult<HeightResponse> {
        self.height_call(HeightRequest {}).await
    }
    async fn height_call(&self, request: HeightRequest) -> RpcResult<HeightResponse>;

    async fn tip_digest(&self) -> RpcResult<TipDigestResponse> {
        self.tip_digest_call(TipDigestRequest {}).await
    }
    async fn tip_digest_call(&self, request: TipDigestRequest) -> RpcResult<TipDigestResponse>;

    async fn tip(&self) -> RpcResult<TipResponse> {
        self.tip_call(TipRequest {}).await
    }
    async fn tip_call(&self, request: TipRequest) -> RpcResult<TipResponse>;

    async fn tip_proof(&self) -> RpcResult<TipProofResponse> {
        self.tip_proof_call(TipProofRequest {}).await
    }
    async fn tip_proof_call(&self, request: TipProofRequest) -> RpcResult<TipProofResponse>;

    async fn tip_kernel(&self) -> RpcResult<TipKernelResponse> {
        self.tip_kernel_call(TipKernelRequest {}).await
    }
    async fn tip_kernel_call(&self, request: TipKernelRequest) -> RpcResult<TipKernelResponse>;

    async fn tip_header(&self) -> RpcResult<TipHeaderResponse> {
        self.tip_header_call(TipHeaderRequest {}).await
    }
    async fn tip_header_call(&self, request: TipHeaderRequest) -> RpcResult<TipHeaderResponse>;

    async fn tip_body(&self) -> RpcResult<TipBodyResponse> {
        self.tip_body_call(TipBodyRequest {}).await
    }
    async fn tip_body_call(&self, request: TipBodyRequest) -> RpcResult<TipBodyResponse>;

    async fn tip_transaction_kernel(&self) -> RpcResult<TipTransactionKernelResponse> {
        self.tip_transaction_kernel_call(TipTransactionKernelRequest {})
            .await
    }
    async fn tip_transaction_kernel_call(
        &self,
        request: TipTransactionKernelRequest,
    ) -> RpcResult<TipTransactionKernelResponse>;

    async fn tip_announcements(&self) -> RpcResult<TipAnnouncementsResponse> {
        self.tip_announcements_call(TipAnnouncementsRequest {})
            .await
    }
    async fn tip_announcements_call(
        &self,
        request: TipAnnouncementsRequest,
    ) -> RpcResult<TipAnnouncementsResponse>;

    /* Archival */

    async fn get_block_digests(&self, height: BFieldElement) -> RpcResult<GetBlockDigestsResponse> {
        self.get_block_digests_call(GetBlockDigestsRequest { height })
            .await
    }
    async fn get_block_digests_call(
        &self,
        request: GetBlockDigestsRequest,
    ) -> RpcResult<GetBlockDigestsResponse>;

    async fn get_block_digest(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockDigestResponse> {
        self.get_block_digest_call(GetBlockDigestRequest { selector })
            .await
    }
    async fn get_block_digest_call(
        &self,
        request: GetBlockDigestRequest,
    ) -> RpcResult<GetBlockDigestResponse>;

    async fn get_block(&self, selector: RpcBlockSelector) -> RpcResult<GetBlockResponse> {
        self.get_block_call(GetBlockRequest { selector }).await
    }
    async fn get_block_call(&self, request: GetBlockRequest) -> RpcResult<GetBlockResponse>;

    async fn get_block_proof(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockProofResponse> {
        self.get_block_proof_call(GetBlockProofRequest { selector })
            .await
    }
    async fn get_block_proof_call(
        &self,
        request: GetBlockProofRequest,
    ) -> RpcResult<GetBlockProofResponse>;

    async fn get_block_kernel(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockKernelResponse> {
        self.get_block_kernel_call(GetBlockKernelRequest { selector })
            .await
    }
    async fn get_block_kernel_call(
        &self,
        request: GetBlockKernelRequest,
    ) -> RpcResult<GetBlockKernelResponse>;

    async fn get_block_header(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockHeaderResponse> {
        self.get_block_header_call(GetBlockHeaderRequest { selector })
            .await
    }
    async fn get_block_header_call(
        &self,
        request: GetBlockHeaderRequest,
    ) -> RpcResult<GetBlockHeaderResponse>;

    async fn get_block_body(&self, selector: RpcBlockSelector) -> RpcResult<GetBlockBodyResponse> {
        self.get_block_body_call(GetBlockBodyRequest { selector })
            .await
    }
    async fn get_block_body_call(
        &self,
        request: GetBlockBodyRequest,
    ) -> RpcResult<GetBlockBodyResponse>;

    async fn get_block_transaction_kernel(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockTransactionKernelResponse> {
        self.get_block_transaction_kernel_call(GetBlockTransactionKernelRequest { selector })
            .await
    }
    async fn get_block_transaction_kernel_call(
        &self,
        request: GetBlockTransactionKernelRequest,
    ) -> RpcResult<GetBlockTransactionKernelResponse>;

    async fn get_block_announcements(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockAnnouncementsResponse> {
        self.get_block_announcements_call(GetBlockAnnouncementsRequest { selector })
            .await
    }
    async fn get_block_announcements_call(
        &self,
        request: GetBlockAnnouncementsRequest,
    ) -> RpcResult<GetBlockAnnouncementsResponse>;

    async fn is_block_canonical(&self, digest: Digest) -> RpcResult<IsBlockCanonicalResponse> {
        self.is_block_canonical_call(IsBlockCanonicalRequest { digest })
            .await
    }
    async fn is_block_canonical_call(
        &self,
        request: IsBlockCanonicalRequest,
    ) -> RpcResult<IsBlockCanonicalResponse>;

    async fn get_utxo_digest_call(
        &self,
        request: GetUtxoDigestRequest,
    ) -> RpcResult<GetUtxoDigestResponse>;

    async fn find_utxo_leaf_index_call(
        &self,
        request: FindUtxoLeafIndexRequest,
    ) -> RpcResult<FindUtxoLeafIndexResponse>;

    async fn find_utxo_origin(
        &self,
        addition_record: RpcAdditionRecord,
        search_depth: Option<u64>,
    ) -> RpcResult<FindUtxoOriginResponse> {
        self.find_utxo_origin_call(FindUtxoOriginRequest {
            addition_record,
            search_depth,
        })
        .await
    }
    async fn find_utxo_origin_call(
        &self,
        request: FindUtxoOriginRequest,
    ) -> RpcResult<FindUtxoOriginResponse>;

    /* Wallet */

    async fn block_info(&self, selector: RpcBlockSelector) -> RpcResult<BlockInfoResponse> {
        self.block_info_call(BlockInfoRequest { selector }).await
    }
    async fn block_info_call(&self, request: BlockInfoRequest) -> RpcResult<BlockInfoResponse>;

    async fn get_blocks(
        &self,
        from_height: RpcBlockHeight,
        to_height: RpcBlockHeight,
    ) -> RpcResult<GetBlocksResponse> {
        self.get_blocks_call(GetBlocksRequest {
            from_height,
            to_height,
        })
        .await
    }
    async fn get_blocks_call(&self, request: GetBlocksRequest) -> RpcResult<GetBlocksResponse>;

    async fn restore_membership_proof(
        &self,
        absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
    ) -> RpcResult<RestoreMembershipProofResponse> {
        self.restore_membership_proof_call(RestoreMembershipProofRequest {
            absolute_index_sets,
        })
        .await
    }
    async fn restore_membership_proof_call(
        &self,
        request: RestoreMembershipProofRequest,
    ) -> RpcResult<RestoreMembershipProofResponse>;

    /* Mining */

    async fn get_block_template(
        &self,
        guesser_address: String,
    ) -> RpcResult<GetBlockTemplateResponse> {
        self.get_block_template_call(GetBlockTemplateRequest { guesser_address })
            .await
    }
    async fn get_block_template_call(
        &self,
        request: GetBlockTemplateRequest,
    ) -> RpcResult<GetBlockTemplateResponse>;

    async fn submit_block(
        &self,
        template: RpcBlock,
        pow: RpcBlockPow,
    ) -> RpcResult<SubmitBlockResponse> {
        self.submit_block_call(SubmitBlockRequest { template, pow })
            .await
    }
    async fn submit_block_call(
        &self,
        request: SubmitBlockRequest,
    ) -> RpcResult<SubmitBlockResponse>;

    /* Mempool */

    async fn transactions(&self) -> RpcResult<TransactionsResponse> {
        self.transactions_call(TransactionsRequest {}).await
    }
    async fn transactions_call(
        &self,
        request: TransactionsRequest,
    ) -> RpcResult<TransactionsResponse>;

    async fn get_transaction_kernel(
        &self,
        id: RpcTransactionKernelId,
    ) -> RpcResult<GetTransactionKernelResponse> {
        self.get_transaction_kernel_call(GetTransactionKernelRequest { id })
            .await
    }
    async fn get_transaction_kernel_call(
        &self,
        request: GetTransactionKernelRequest,
    ) -> RpcResult<GetTransactionKernelResponse>;

    async fn get_transaction_proof(
        &self,
        id: RpcTransactionKernelId,
    ) -> RpcResult<GetTransactionProofResponse> {
        self.get_transaction_proof_call(GetTransactionProofRequest { id })
            .await
    }
    async fn get_transaction_proof_call(
        &self,
        request: GetTransactionProofRequest,
    ) -> RpcResult<GetTransactionProofResponse>;

    async fn submit_transaction(
        &self,
        transaction: RpcTransaction,
    ) -> RpcResult<SubmitTransactionResponse> {
        self.submit_transaction_call(SubmitTransactionRequest { transaction })
            .await
    }
    async fn submit_transaction_call(
        &self,
        request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse>;

    /* Wallet */

    async fn generate_address(&self) -> RpcResult<GenerateAddressResponse> {
        self.generate_address_call(GenerateAddressRequest {}).await
    }
    async fn generate_address_call(
        &self,
        request: GenerateAddressRequest,
    ) -> RpcResult<GenerateAddressResponse>;

    async fn count_sent_transactions_at_block(
        &self,
        block: RpcBlockSelector,
    ) -> RpcResult<CountSentTransactionsAtBlockResponse> {
        self.count_sent_transactions_at_block_call(CountSentTransactionsAtBlockRequest { block })
            .await
    }
    async fn count_sent_transactions_at_block_call(
        &self,
        request: CountSentTransactionsAtBlockRequest,
    ) -> RpcResult<CountSentTransactionsAtBlockResponse>;

    async fn get_balance(&self) -> RpcResult<GetBalanceResponse> {
        self.get_balance_call(GetBalanceRequest {}).await
    }
    async fn get_balance_call(&self, request: GetBalanceRequest) -> RpcResult<GetBalanceResponse>;

    async fn history(&self, request: HistoryRequest) -> RpcResult<HistoryResponse> {
        self.history_call(request).await
    }
    async fn history_call(&self, request: HistoryRequest) -> RpcResult<HistoryResponse>;

    async fn sent_transaction(
        &self,
        request: SentTransactionRequest,
    ) -> RpcResult<SentTransactionResponse> {
        self.sent_transaction_call(request).await
    }
    async fn sent_transaction_call(
        &self,
        request: SentTransactionRequest,
    ) -> RpcResult<SentTransactionResponse>;

    async fn validate_amount(
        &self,
        request: ValidateAmountRequest,
    ) -> RpcResult<ValidateAmountResponse> {
        self.validate_amount_call(request).await
    }
    async fn validate_amount_call(
        &self,
        request: ValidateAmountRequest,
    ) -> RpcResult<ValidateAmountResponse>;

    async fn validate_address(
        &self,
        request: ValidateAddressRequest,
    ) -> RpcResult<ValidateAddressResponse> {
        self.validate_address_call(request).await
    }
    async fn validate_address_call(
        &self,
        request: ValidateAddressRequest,
    ) -> RpcResult<ValidateAddressResponse>;

    async fn send_tx(&self, request: SendTxRequest) -> RpcResult<SendTxResponse> {
        self.send_tx_call(request).await
    }
    async fn send_tx_call(&self, request: SendTxRequest) -> RpcResult<SendTxResponse>;

    async fn unspent_utxos(&self, request: UnspentUtxosRequest) -> RpcResult<UnspentUtxosResponse> {
        self.unspent_utxos_call(request).await
    }
    async fn unspent_utxos_call(
        &self,
        request: UnspentUtxosRequest,
    ) -> RpcResult<UnspentUtxosResponse>;

    async fn generate_subaddress(&self, payment_id: u64) -> RpcResult<GenerateSubaddressResponse> {
        self.generate_subaddress_call(GenerateSubaddressRequest { payment_id })
            .await
    }
    async fn generate_subaddress_call(
        &self,
        request: GenerateSubaddressRequest,
    ) -> RpcResult<GenerateSubaddressResponse>;

    async fn get_utxos_by_receiver(
        &self,
        request: GetUtxosByReceiverRequest,
    ) -> RpcResult<GetUtxosByReceiverResponse> {
        self.get_utxos_by_receiver_call(request).await
    }
    async fn get_utxos_by_receiver_call(
        &self,
        request: GetUtxosByReceiverRequest,
    ) -> RpcResult<GetUtxosByReceiverResponse>;

    async fn get_aocl_leaf_indices(
        &self,
        request: GetAoclLeafIndicesRequest,
    ) -> RpcResult<GetAoclLeafIndicesResponse> {
        self.get_aocl_leaf_indices_call(request).await
    }
    async fn get_aocl_leaf_indices_call(
        &self,
        request: GetAoclLeafIndicesRequest,
    ) -> RpcResult<GetAoclLeafIndicesResponse>;

    async fn get_spent_status(
        &self,
        request: GetSpentStatusRequest,
    ) -> RpcResult<GetSpentStatusResponse> {
        self.get_spent_status_call(request).await
    }
    async fn get_spent_status_call(
        &self,
        request: GetSpentStatusRequest,
    ) -> RpcResult<GetSpentStatusResponse>;

    async fn get_archival_mutator_set(&self) -> RpcResult<GetArchivalMutatorSetResponse> {
        self.get_archival_mutator_set_call(GetArchivalMutatorSetRequest {})
            .await
    }
    async fn get_archival_mutator_set_call(
        &self,
        request: GetArchivalMutatorSetRequest,
    ) -> RpcResult<GetArchivalMutatorSetResponse>;
}
