use async_trait::async_trait;
use tracing::debug;

use crate::api::export::ReceivingAddress;
use crate::api::export::Timestamp;
use crate::api::export::Transaction;
use crate::api::export::TransactionProof;
use crate::api::export::{BlockHeight, NativeCurrencyAmount, TxInput};
use crate::api::tx_initiation::builder::tx_input_list_builder::SortOrder;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::send::TransactionSender;
use crate::api::wallet::Wallet;
use crate::application::json_rpc::core::api::rpc::*;

use crate::application::json_rpc::core::api::rpc::RpcError;
use crate::application::json_rpc::core::model::json::JsonError;

use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::api::rpc::RpcResult;
use crate::application::json_rpc::core::model::block::RpcBlock;
use crate::application::json_rpc::core::model::message::*;
use crate::application::json_rpc::core::model::mining::template::RpcBlockTemplate;
use crate::application::json_rpc::core::model::mining::template::RpcBlockTemplateMetadata;
use crate::application::json_rpc::core::model::wallet::mutator_set::RpcMsMembershipSnapshot;
use crate::application::json_rpc::server::rpc::RpcServer;
use crate::application::loops::channel::RPCServerToMain;
use crate::protocol::consensus::block::block_selector::BlockSelector;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::FUTUREDATING_LIMIT;

use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::state::wallet::address::KeyType;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
use tasm_lib::prelude::Digest;

#[async_trait]
impl RpcApi for RpcServer {
    async fn network_call(&self, _: NetworkRequest) -> RpcResult<NetworkResponse> {
        Ok(NetworkResponse {
            network: self.state.cli().network.to_string(),
        })
    }

    async fn height_call(&self, _: HeightRequest) -> RpcResult<HeightResponse> {
        let state = self.state.lock_guard().await;

        Ok(HeightResponse {
            height: state.chain.light_state().kernel.header.height,
        })
    }

    async fn tip_digest_call(&self, _: TipDigestRequest) -> RpcResult<TipDigestResponse> {
        let state = self.state.lock_guard().await;
        let block = state.chain.light_state();

        Ok(TipDigestResponse {
            digest: block.hash(),
        })
    }

    async fn tip_call(&self, _: TipRequest) -> RpcResult<TipResponse> {
        let state = self.state.lock_guard().await;
        let block = state.chain.light_state();

        Ok(TipResponse {
            block: block.into(),
        })
    }

    async fn tip_proof_call(&self, _: TipProofRequest) -> RpcResult<TipProofResponse> {
        let state = self.state.lock_guard().await;
        let proof = &state.chain.light_state().proof;

        Ok(TipProofResponse {
            proof: proof.into(),
        })
    }

    async fn tip_kernel_call(&self, _: TipKernelRequest) -> RpcResult<TipKernelResponse> {
        let state = self.state.lock_guard().await;
        let kernel = &state.chain.light_state().kernel;

        Ok(TipKernelResponse {
            kernel: kernel.into(),
        })
    }

    async fn tip_header_call(&self, _: TipHeaderRequest) -> RpcResult<TipHeaderResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipHeaderResponse {
            header: state.chain.light_state().header().into(),
        })
    }

    async fn tip_body_call(&self, _: TipBodyRequest) -> RpcResult<TipBodyResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipBodyResponse {
            body: state.chain.light_state().body().into(),
        })
    }

    async fn tip_transaction_kernel_call(
        &self,
        _: TipTransactionKernelRequest,
    ) -> RpcResult<TipTransactionKernelResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipTransactionKernelResponse {
            kernel: state.chain.light_state().body().transaction_kernel().into(),
        })
    }

    async fn tip_announcements_call(
        &self,
        _: TipAnnouncementsRequest,
    ) -> RpcResult<TipAnnouncementsResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipAnnouncementsResponse {
            announcements: state
                .chain
                .light_state()
                .body()
                .transaction_kernel()
                .announcements
                .iter()
                .map(|a| a.clone().into())
                .collect(),
        })
    }

    async fn get_block_digest_call(
        &self,
        request: GetBlockDigestRequest,
    ) -> RpcResult<GetBlockDigestResponse> {
        let state = self.state.lock_guard().await;
        let digest = request.selector.as_digest(&state).await;

        Ok(GetBlockDigestResponse { digest })
    }

    async fn get_block_digests_call(
        &self,
        request: GetBlockDigestsRequest,
    ) -> RpcResult<GetBlockDigestsResponse> {
        let state = self.state.lock_guard().await;

        Ok(GetBlockDigestsResponse {
            digests: state
                .chain
                .archival_state()
                .block_height_to_block_digests(request.height.into())
                .await,
        })
    }

    async fn get_block_call(&self, request: GetBlockRequest) -> RpcResult<GetBlockResponse> {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let block = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(RpcBlock::from),
            None => None,
        };

        Ok(GetBlockResponse { block })
    }

    async fn get_block_proof_call(
        &self,
        request: GetBlockProofRequest,
    ) -> RpcResult<GetBlockProofResponse> {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let proof = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| (&b.proof).into()),
            None => None,
        };

        Ok(GetBlockProofResponse { proof })
    }

    async fn get_block_kernel_call(
        &self,
        request: GetBlockKernelRequest,
    ) -> RpcResult<GetBlockKernelResponse> {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let kernel = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| (&b.kernel).into()),
            None => None,
        };

        Ok(GetBlockKernelResponse { kernel })
    }

    async fn get_block_header_call(
        &self,
        request: GetBlockHeaderRequest,
    ) -> RpcResult<GetBlockHeaderResponse> {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let header = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| b.header().into()),
            None => None,
        };

        Ok(GetBlockHeaderResponse { header })
    }

    async fn get_block_body_call(
        &self,
        request: GetBlockBodyRequest,
    ) -> RpcResult<GetBlockBodyResponse> {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let body = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| b.body().into()),
            None => None,
        };

        Ok(GetBlockBodyResponse { body })
    }

    async fn get_block_transaction_kernel_call(
        &self,
        request: GetBlockTransactionKernelRequest,
    ) -> RpcResult<GetBlockTransactionKernelResponse> {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let kernel = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| b.body().transaction_kernel().into()),
            None => None,
        };

        Ok(GetBlockTransactionKernelResponse { kernel })
    }

    async fn get_block_announcements_call(
        &self,
        request: GetBlockAnnouncementsRequest,
    ) -> RpcResult<GetBlockAnnouncementsResponse> {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let announcements = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| {
                    b.body()
                        .transaction_kernel()
                        .announcements
                        .iter()
                        .map(|a| a.clone().into())
                        .collect::<Vec<_>>()
                }),
            None => None,
        };

        Ok(GetBlockAnnouncementsResponse { announcements })
    }

    async fn is_block_canonical_call(
        &self,
        request: IsBlockCanonicalRequest,
    ) -> RpcResult<IsBlockCanonicalResponse> {
        let state = self.state.lock_guard().await;

        Ok(IsBlockCanonicalResponse {
            canonical: state
                .chain
                .archival_state()
                .block_belongs_to_canonical_chain(request.digest)
                .await,
        })
    }

    async fn get_utxo_digest_call(
        &self,
        request: GetUtxoDigestRequest,
    ) -> RpcResult<GetUtxoDigestResponse> {
        let state = self.state.lock_guard().await;
        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;

        Ok(GetUtxoDigestResponse {
            digest: aocl.try_get_leaf(request.leaf_index).await,
        })
    }

    async fn find_utxo_origin_call(
        &self,
        request: FindUtxoOriginRequest,
    ) -> RpcResult<FindUtxoOriginResponse> {
        let allowed_search_depth = if self.unrestricted {
            request.search_depth
        } else {
            Some(request.search_depth.unwrap_or(100).min(100))
        };

        let state = self.state.lock_guard().await;
        let block = state
            .chain
            .archival_state()
            .find_canonical_block_with_output(request.addition_record.into(), allowed_search_depth)
            .await;

        Ok(FindUtxoOriginResponse {
            block: block.map(|block| block.hash()),
        })
    }

    async fn get_blocks_call(&self, request: GetBlocksRequest) -> RpcResult<GetBlocksResponse> {
        // Reverse get_blocks is not supported yet.
        // Might be reconsidered after "succinctness" as it might give it a purpose.
        if request.to_height < request.from_height {
            return Ok(GetBlocksResponse { blocks: Vec::new() });
        }

        let max_blocks = if self.unrestricted { usize::MAX } else { 100 };

        let state = self.state.lock_guard().await;
        let mut blocks = Vec::new();
        let mut height = request.from_height;

        while height <= request.to_height && blocks.len() < max_blocks {
            let block_selector = BlockSelector::Height(height);
            let Some(digest) = block_selector.as_digest(&state).await else {
                break;
            };
            let Some(block) = state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
            else {
                break;
            };

            blocks.push((&block).into());
            height = height.next();
        }

        Ok(GetBlocksResponse { blocks })
    }

    async fn restore_membership_proof_call(
        &self,
        request: RestoreMembershipProofRequest,
    ) -> RpcResult<RestoreMembershipProofResponse> {
        if request.absolute_index_sets.len() > 256 && !self.unrestricted {
            return Err(RpcError::RestoreMembershipProof(
                RestoreMembershipProofError::ExceedsAllowed,
            ));
        }

        let state = self.state.lock_guard().await;
        let ams = state.chain.archival_state().archival_mutator_set.ams();
        let mut membership_proofs = Vec::with_capacity(request.absolute_index_sets.len());

        for (index, set) in request.absolute_index_sets.into_iter().enumerate() {
            match ams.restore_membership_proof_privacy_preserving(set).await {
                Ok(msmp) => membership_proofs.push(msmp.into()),
                Err(err) => {
                    debug!("Failed to restore MSMP for {index}: {err}");
                    return Err(RpcError::RestoreMembershipProof(
                        RestoreMembershipProofError::Failed(index),
                    ));
                }
            }
        }

        let current_tip = state.chain.light_state();
        let tip_mutator_set = current_tip
            .mutator_set_accumulator_after()
            .expect("Tip must have valid MSA after");
        let snapshot = RpcMsMembershipSnapshot {
            synced_height: current_tip.header().height.into(),
            synced_hash: current_tip.hash(),
            membership_proofs,
            synced_mutator_set: (&tip_mutator_set).into(),
        };

        Ok(RestoreMembershipProofResponse { snapshot })
    }

    async fn submit_transaction_call(
        &self,
        request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse> {
        let transaction: Transaction = request.transaction.into();
        let network = self.state.cli().network;
        let consensus_rule_set = self.state.lock_guard().await.consensus_rule_set();

        if !transaction.is_valid(network, consensus_rule_set).await {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::InvalidTransaction,
            ));
        }

        if transaction.kernel.coinbase.is_some() {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::CoinbaseTransaction,
            ));
        }

        if transaction.kernel.fee.is_negative() {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::FeeNegative,
            ));
        }

        let timestamp = transaction.kernel.timestamp;
        let now = Timestamp::now();
        if timestamp >= now + FUTUREDATING_LIMIT {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::FutureDated,
            ));
        }

        let msa = self
            .state
            .lock_guard()
            .await
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .expect("Tip block must have mutator set");
        if !transaction.is_confirmable_relative_to(&msa) {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::NotConfirmable,
            ));
        }

        let response = self
            .to_main_tx
            .send(RPCServerToMain::SubmitTx(Box::new(transaction)))
            .await;

        Ok(SubmitTransactionResponse {
            success: response.is_ok(),
        })
    }

    async fn get_block_template_call(
        &self,
        request: GetBlockTemplateRequest,
    ) -> RpcResult<GetBlockTemplateResponse> {
        let (maybe_proposal, tip) = {
            let global_state = self.state.lock_guard().await;
            let proposal = global_state.mining_state.block_proposal.map(|p| p.clone());
            let tip = *global_state.chain.light_state().header();

            (proposal, tip)
        };

        let Some(mut proposal) = maybe_proposal else {
            return Ok(GetBlockTemplateResponse { template: None });
        };

        let address =
            ReceivingAddress::from_bech32m(&request.guesser_address, self.state.cli().network)
                .map_err(|_| RpcError::InvalidAddress)?;
        proposal.set_header_guesser_address(address);

        let template = RpcBlockTemplate {
            block: RpcBlock::from(&proposal),
            metadata: RpcBlockTemplateMetadata::new(&proposal, tip.difficulty),
        };

        Ok(GetBlockTemplateResponse {
            template: Some(template),
        })
    }

    async fn submit_block_call(
        &self,
        request: SubmitBlockRequest,
    ) -> RpcResult<SubmitBlockResponse> {
        let mut template: Block = request.template.into();

        // Since block comes from external source, we need to check validity.
        let tip = self.state.lock_guard().await.chain.light_state().clone();
        if !template
            .is_valid(&tip, Timestamp::now(), self.state.cli().network)
            .await
        {
            return Err(RpcError::SubmitBlock(SubmitBlockError::InvalidBlock));
        }

        template.set_header_pow(request.pow.into());

        if !template.has_proof_of_work(self.state.cli().network, template.header()) {
            return Err(RpcError::SubmitBlock(SubmitBlockError::InsufficientWork));
        }

        // No time to waste! Inform main_loop!
        let solution = Box::new(template);
        let success = self
            .to_main_tx
            .send(RPCServerToMain::ProofOfWorkSolution(solution))
            .await
            .is_ok();

        Ok(SubmitBlockResponse { success })
    }

    async fn transactions_call(&self, _: TransactionsRequest) -> RpcResult<TransactionsResponse> {
        let transactions = self
            .state
            .lock_guard()
            .await
            .mempool
            .fee_density_iter()
            .map(|(txkid, _)| txkid)
            .collect();

        Ok(TransactionsResponse { transactions })
    }

    async fn get_transaction_kernel_call(
        &self,
        request: GetTransactionKernelRequest,
    ) -> RpcResult<GetTransactionKernelResponse> {
        let transaction = self
            .state
            .lock_guard()
            .await
            .mempool
            .get(request.id)
            .cloned();

        Ok(GetTransactionKernelResponse {
            kernel: transaction.map(|t| (&t.kernel).into()),
        })
    }

    async fn get_transaction_proof_call(
        &self,
        request: GetTransactionProofRequest,
    ) -> RpcResult<GetTransactionProofResponse> {
        let transaction = self
            .state
            .lock_guard()
            .await
            .mempool
            .get(request.id)
            .cloned();

        Ok(GetTransactionProofResponse {
            proof: transaction.and_then(|t| match t.proof {
                // Proofs of witness-backed transactions shouldn't be exposed.
                TransactionProof::Witness(_) => None,
                other => Some(other.into()),
            }),
        })
    }
    async fn generate_address_call(
        &self,
        _request: GenerateAddressRequest,
    ) -> RpcResult<GenerateAddressResponse> {
        let network = self.state.cli().network;

        let mut wallet = Wallet::from(self.state.clone());

        let receiving_address = wallet
            .next_receiving_address(KeyType::Generation)
            .await
            .map_err(|e| {
                RpcError::Server(JsonError::Custom {
                    code: -32000,
                    message: format!("Failed to generate address: {}", e),
                    data: None,
                })
            })?;

        let address_string = receiving_address.to_bech32m(network).map_err(|e| {
            RpcError::Server(JsonError::Custom {
                code: -32000,
                message: format!("Failed to encode address: {}", e),
                data: None,
            })
        })?;

        Ok(GenerateAddressResponse {
            address: address_string,
        })
    }

    async fn count_sent_transactions_at_block_call(
        &self,
        request: CountSentTransactionsAtBlockRequest,
    ) -> RpcResult<CountSentTransactionsAtBlockResponse> {
        let state = self.state.lock_guard().await;

        let Some(digest) = request.block.as_digest(&state).await else {
            return Ok(CountSentTransactionsAtBlockResponse { count: 0 });
        };

        let count = state
            .wallet_state
            .count_sent_transactions_at_block(digest)
            .await;

        Ok(CountSentTransactionsAtBlockResponse { count })
    }

    async fn get_balance_call(&self, _request: GetBalanceRequest) -> RpcResult<GetBalanceResponse> {
        let state = self.state.lock_guard().await;
        let wallet_status = state.get_wallet_status_for_tip().await;

        let confirmed_available = wallet_status.available_confirmed(Timestamp::now());

        Ok(GetBalanceResponse {
            balance: confirmed_available.to_string(),
        })
    }

    async fn history_call(&self, request: HistoryRequest) -> RpcResult<HistoryResponse> {
        let state = self.state.lock_guard().await;
        let network = self.state.cli().network;

        let query_lock_script_hash: Option<Digest> =
            if let Some(ref receiving_address_str) = request.receiving_address {
                ReceivingAddress::from_bech32m(receiving_address_str, network)
                    .ok()
                    .map(|addr| addr.lock_script_hash())
            } else {
                None
            };

        let history = state
            .get_balance_history_query(
                request.leaf_index,
                request.utxo_digest,
                query_lock_script_hash,
                request.sender_randomness,
                request.confirmed_height,
                request.spent_height,
            )
            .await;

        let futures = history
            .iter()
            .map(|(i, ud, sr, h, t, bh, sh, utxo)| async {
                let lock_script_hash = utxo.lock_script_hash();

                let address = state
                    .wallet_state
                    .get_all_known_addressable_spending_keys()
                    .find(|k| k.lock_script_hash() == lock_script_hash)
                    .map(|key| key.to_address());

                (*i, *ud, *sr, *h, *bh, *sh, *t, address, utxo.clone())
            })
            .collect::<Vec<_>>();

        let display_history: Vec<(
            u64,
            Option<Digest>,
            Digest,
            Digest,
            BlockHeight,
            Option<BlockHeight>,
            Timestamp,
            Option<ReceivingAddress>,
            Utxo,
        )> = futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Vec<_>>();

        let history_rows = display_history
            .iter()
            .map(
                |(
                    leaf_index,
                    utxo_digest,
                    sender_randomness,
                    digest,
                    confirmed_height,
                    spent_height,
                    timestamp,
                    receiving_address,
                    utxo,
                )| {
                    let receiving_address_str: Option<String>;

                    if let Some(ref receiving_address) = *receiving_address {
                        receiving_address_str = Some(
                            receiving_address
                                .to_bech32m(network)
                                .expect("valid address"),
                        );
                    } else {
                        receiving_address_str = None;
                    }

                    History {
                        leaf_index: *leaf_index,
                        utxo_digest: *utxo_digest,
                        sender_randomness: *sender_randomness,
                        digest: *digest,
                        confirmed_height: *confirmed_height,
                        spent_height: *spent_height,
                        timestamp: *timestamp,
                        receiving_address: receiving_address_str,
                        utxo: ApiUtxo::new(utxo),
                    }
                },
            )
            .collect();

        Ok(history_rows)
    }

    async fn sent_transaction_call(
        &self,
        request: SentTransactionRequest,
    ) -> RpcResult<SentTransactionResponse> {
        let state = self.state.lock_guard().await;

        let sent_transactions = state
            .get_sent_transactions(
                request.sender_randomness,
                request.receiver_digest,
                request.lock_script_hash,
                request.limit,
                request.page,
            )
            .await;

        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;
        let num_leafs = aocl.num_leafs().await;

        let mut sent_txs = Vec::new();
        for tx in sent_transactions {
            let out_utxos = tx.tx_outputs.utxos();
            let out_sender_randomness = tx.tx_outputs.sender_randomnesses();
            let out_receiver_digest = tx.tx_outputs.receiver_digests();

            let mut tx_outputs = Vec::new();
            for (index, utxo) in out_utxos.iter().enumerate() {
                tx_outputs.push(SentTxOutput {
                    utxo: ApiUtxo::new(utxo),
                    sender_randomness: out_sender_randomness[index],
                    receiver_digest: out_receiver_digest[index],
                });
            }

            let mut tx_inputs = Vec::new();
            for (leaf_index, input_utxo) in &tx.tx_inputs {
                let utxo_digest = if *leaf_index > 0 && *leaf_index < num_leafs {
                    Some(aocl.get_leaf_async(*leaf_index).await)
                } else {
                    None
                };

                tx_inputs.push(SentTxInput {
                    leaf_index: *leaf_index,
                    utxo_digest,
                    utxo: ApiUtxo::new(input_utxo),
                });
            }

            sent_txs.push(SentTxToRespResponse {
                tx_inputs,
                tx_outputs,
                fee: tx.fee.to_string(),
                timestamp: tx.timestamp,
                tip_when_sent: tx.tip_when_sent,
            });
        }
        Ok(sent_txs)
    }

    async fn sent_transaction_by_sender_randomness_call(
        &self,
        request: SentTransactionBySenderRandomnessRequest,
    ) -> RpcResult<SentTransactionBySenderRandomnessResponse> {
        let state = self.state.lock_guard().await;

        let sent_transactions = state
            .get_sent_transactions(Some(request.sender_randomness), None, None, None, None)
            .await;

        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;
        let num_leafs = aocl.num_leafs().await;

        for tx in sent_transactions {
            if tx.timestamp != request.timestamp {
                continue;
            }

            let sender_randomnesses = tx.tx_outputs.sender_randomnesses();
            if !sender_randomnesses.contains(&request.sender_randomness) {
                continue;
            }

            let out_utxos = tx.tx_outputs.utxos();
            let out_receiver_digest = tx.tx_outputs.receiver_digests();

            let mut tx_outputs = Vec::new();
            for (index, utxo) in out_utxos.iter().enumerate() {
                tx_outputs.push(SentTxOutput {
                    utxo: ApiUtxo::new(utxo),
                    sender_randomness: sender_randomnesses[index],
                    receiver_digest: out_receiver_digest[index],
                });
            }

            let mut tx_inputs = Vec::new();
            for (index, input_utxo) in &tx.tx_inputs {
                let utxo_digest = if *index > 0 && *index < num_leafs {
                    Some(aocl.get_leaf_async(*index).await)
                } else {
                    None
                };

                tx_inputs.push(SentTxInput {
                    leaf_index: *index,
                    utxo_digest,
                    utxo: ApiUtxo::new(input_utxo),
                });
            }

            return Ok(Some(SentTxToRespResponse {
                tx_inputs,
                tx_outputs,
                fee: tx.fee.to_string(),
                timestamp: tx.timestamp,
                tip_when_sent: tx.tip_when_sent,
            }));
        }

        Ok(None)
    }

    async fn validate_amount_call(
        &self,
        request: ValidateAmountRequest,
    ) -> RpcResult<ValidateAmountResponse> {
        let amount = NativeCurrencyAmount::coins_from_str(&request.amount_string)
            .ok()
            .map(|amt| amt.to_string());

        Ok(ValidateAmountResponse { amount })
    }

    async fn validate_address_call(
        &self,
        request: ValidateAddressRequest,
    ) -> RpcResult<ValidateAddressResponse> {
        let network = self.state.cli().network;

        let ret = ReceivingAddress::from_bech32m(&request.address_string, network).ok();

        let address = ret.and_then(|addr| addr.to_bech32m(network).ok());

        Ok(ValidateAddressResponse { address })
    }

    async fn send_tx_call(&self, request: SendTxRequest) -> RpcResult<SendTxResponse> {
        let Ok(valid_amount) = NativeCurrencyAmount::coins_from_str(&request.amount) else {
            return Err(RpcError::Server(JsonError::Custom {
                code: -32602,
                message: "Invalid amount format".to_string(),
                data: None,
            }));
        };

        let Ok(valid_fee) = NativeCurrencyAmount::coins_from_str(&request.fee) else {
            return Err(RpcError::Server(JsonError::Custom {
                code: -32602,
                message: "Invalid fee format".to_string(),
                data: None,
            }));
        };

        let network = self.state.cli().network;
        let Ok(to_address) = ReceivingAddress::from_bech32m(&request.to_address, network) else {
            return Err(RpcError::Server(JsonError::Custom {
                code: -32602,
                message: "Invalid address format".to_string(),
                data: None,
            }));
        };

        let outputs: Vec<OutputFormat> = vec![OutputFormat::AddressAndAmountAndMedium(
            to_address,
            valid_amount,
            UtxoNotificationMedium::OnChain,
        )];

        let change_policy = ChangePolicy::RecoverToNextUnusedKey {
            key_type: KeyType::Generation,
            medium: UtxoNotificationMedium::OnChain,
        };

        let mut tx_sender = TransactionSender::from(self.state.clone());
        let resp = tx_sender
            .send(
                outputs,
                change_policy,
                valid_fee,
                Timestamp::now(),
                request.exclude_recent_blocks,
            )
            .await
            .map_err(|e| {
                RpcError::Server(JsonError::Custom {
                    code: -32000,
                    message: format!("Failed to send transaction: {}", e),
                    data: None,
                })
            })?;

        let id = resp.transaction().txid();

        let timestamp = resp.details().timestamp;

        let notification_list: Vec<SendTxNotificationData> = resp
            .details()
            .tx_outputs
            .iter()
            .filter(|output| !output.is_change())
            .map(|output| SendTxNotificationData {
                utxo: SendTxNotificationUtxo {
                    lock_script_hash: output.utxo().lock_script_hash(),
                    amount: output.utxo().get_native_currency_amount().to_string(),
                },
                sender_randomness: output.sender_randomness(),
            })
            .collect();

        Ok(SendTxResponse {
            id,
            timestamp,
            notification_data: notification_list,
        })
    }

    async fn unspent_utxos_call(
        &self,
        request: UnspentUtxosRequest,
    ) -> RpcResult<UnspentUtxosResponse> {
        use crate::api::tx_initiation::initiator::TransactionInitiator;

        let tx_initiator = TransactionInitiator::from(self.state.clone());
        let spendable_inputs = tx_initiator
            .spendable_inputs(Timestamp::now(), request.exclude_recent_blocks)
            .await;

        let utxos: Vec<UnspentUtxo> = spendable_inputs
            .iter()
            .map(|input| UnspentUtxo {
                leaf_index: input.mutator_set_mp().aocl_leaf_index,
                lock_script_hash: input.utxo.lock_script_hash(),
                amount: input.native_currency_amount().to_string(),
            })
            .collect();

        Ok(utxos)
    }

    async fn select_spendable_inputs_call(
        &self,
        request: SelectSpendableInputsRequest,
    ) -> RpcResult<SelectSpendableInputsResponse> {
        use crate::api::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
        use crate::api::tx_initiation::initiator::TransactionInitiator;

        let Ok(amount) = NativeCurrencyAmount::coins_from_str(&request.amount) else {
            return Err(RpcError::Server(JsonError::Custom {
                code: -32602,
                message: "Invalid amount format".to_string(),
                data: None,
            }));
        };

        let Ok(fee) = NativeCurrencyAmount::coins_from_str(&request.fee) else {
            return Err(RpcError::Server(JsonError::Custom {
                code: -32602,
                message: "Invalid fee format".to_string(),
                data: None,
            }));
        };

        let target_amount = amount + fee;

        let tx_initiator = TransactionInitiator::from(self.state.clone());
        let selected_inputs: Vec<TxInput> = tx_initiator
            .select_spendable_inputs(
                InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Descending),
                target_amount,
                Timestamp::now(),
                request.exclude_recent_blocks,
            )
            .await
            .into_iter()
            .collect();

        let total_selected_amount: NativeCurrencyAmount = selected_inputs
            .iter()
            .map(|input| input.utxo.get_native_currency_amount())
            .sum();

        let selected_utxos: Vec<UnspentUtxo> = selected_inputs
            .into_iter()
            .map(|input| UnspentUtxo {
                leaf_index: input.mutator_set_mp().aocl_leaf_index,
                lock_script_hash: input.utxo.lock_script_hash(),
                amount: input.utxo.get_native_currency_amount().to_string(),
            })
            .collect();

        Ok(SelectSpendableInputsResponse {
            selected_utxos,
            total_selected_amount: total_selected_amount.to_string(),
        })
    }

    async fn block_api_call(&self, request: BlockApiRequest) -> RpcResult<BlockApiResponse> {
        let state = self.state.lock_guard().await;
        let network = self.state.cli().network;

        let Some(digest) = request.selector.as_digest(&state).await else {
            return Ok(None);
        };

        let archival_state = state.chain.archival_state();

        let Some(block) = archival_state.get_block(digest).await.unwrap() else {
            return Ok(None);
        };

        let header = block.header();
        let body = block.body();
        let digest = block.hash();
        let transaction_kernel = body.transaction_kernel.clone();

        let inputs = state
            .wallet_state
            .scan_for_spent_utxos(&transaction_kernel)
            .await;

        let mut transaction_inputs = Vec::with_capacity(inputs.len());
        for (_, (utxo, _)) in inputs {
            let address = state
                .wallet_state
                .find_spending_key_for_utxo(&utxo)
                .map(|key| key.to_address().to_bech32m(network))
                .and_then(|result| result.ok());

            transaction_inputs.push(InputUtxo {
                utxo: ApiUtxo::new(&utxo),
                receiving_address: address,
            });
        }

        let outputs: Vec<OutputUtxo> = state
            .wallet_state
            .scan_for_utxos_announced_to_known_keys(&transaction_kernel)
            .map(|incoming_utxo| {
                let address = state
                    .wallet_state
                    .find_spending_key_for_utxo(&incoming_utxo.utxo)
                    .map(|key| key.to_address().to_bech32m(network))
                    .and_then(|result| result.ok());

                OutputUtxo {
                    sender_randomness: incoming_utxo.sender_randomness,
                    receiver_preimage: incoming_utxo.receiver_preimage,
                    receiving_address: address,
                    utxo: ApiUtxo::new(&incoming_utxo.utxo),
                }
            })
            .collect();

        Ok(Some(BlockApiData {
            height: header.height,
            digest,
            timestamp: header.timestamp,
            difficulty: header.difficulty,
            size: block.size(),
            fee: transaction_kernel.fee.to_string(),
            transaction_kernel_id: transaction_kernel.txid(),
            inputs: transaction_inputs,
            outputs,
        }))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use std::collections::HashSet;

    use macro_rules_attr::apply;
    use tasm_lib::prelude::Digest;
    use tasm_lib::prelude::Tip5;

    use crate::api::export::Announcement;
    use crate::api::export::KeyType;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::Network;
    use crate::api::export::OutputFormat;
    use crate::api::export::Timestamp;
    use crate::api::export::TxProvingCapability;
    use crate::application::config::cli_args;
    use crate::application::json_rpc::core::api::rpc::RpcApi;
    use crate::application::json_rpc::core::api::rpc::RpcError;
    use crate::application::json_rpc::core::model::common::RpcBlockSelector;
    use crate::application::json_rpc::core::model::mining::template::RpcBlockTemplate;
    use crate::application::json_rpc::server::rpc::RpcServer;
    use crate::protocol::consensus::block::block_height::BlockHeight;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::Transaction;
    use crate::protocol::consensus::transaction::TransactionProof;
    use crate::state::mempool::upgrade_priority::UpgradePriority;
    use crate::state::mining::block_proposal::BlockProposal;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::fake_valid_deterministic_successor;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_tx::testrunning::make_plenty_mock_transaction_supported_by_primitive_witness;
    use crate::tests::shared::strategies::txkernel;
    use crate::tests::shared_tokio_runtime;
    use crate::Block;

    pub async fn test_rpc_server() -> RpcServer {
        let mut cli = cli_args::Args::default_with_network(Network::Main);
        cli.tx_proving_capability = Some(TxProvingCapability::ProofCollection);
        let global_state_lock =
            mock_genesis_global_state(2, WalletEntropy::new_random(), cli).await;

        RpcServer::new(global_state_lock, None)
    }

    #[apply(shared_tokio_runtime)]
    async fn network_is_consistent() {
        let rpc_server = test_rpc_server().await;
        assert_eq!("main", rpc_server.network().await.unwrap().network);
    }

    #[apply(shared_tokio_runtime)]
    async fn height_is_correct() {
        let rpc_server = test_rpc_server().await;
        assert_eq!(
            BlockHeight::genesis(),
            rpc_server.height().await.unwrap().height
        );
    }

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn tip_calls_are_consistent(
        #[strategy(txkernel::with_lengths(0, 2, 2, true))]
        tx_block1: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut rpc_server = test_rpc_server().await;

        let tx_block1 = Transaction {
            kernel: tx_block1,
            proof: TransactionProof::invalid(),
        };
        let block1 = invalid_block_with_transaction(&Block::genesis(Network::Main), tx_block1);
        rpc_server.state.set_new_tip(block1.clone()).await.unwrap();

        let digest = rpc_server.tip_digest().await.unwrap().digest;
        assert_eq!(block1.hash(), digest);

        let block = rpc_server.tip().await.unwrap().block;
        let proof = rpc_server.tip_proof().await.unwrap().proof;
        assert_eq!(block.proof, proof);

        let kernel = rpc_server.tip_kernel().await.unwrap().kernel;
        let header = rpc_server.tip_header().await.unwrap().header;
        assert_eq!(kernel.header, header);

        let body = rpc_server.tip_body().await.unwrap().body;
        let transaction_kernel = rpc_server.tip_transaction_kernel().await.unwrap().kernel;
        assert_eq!(body.transaction_kernel, transaction_kernel);

        let announcements = rpc_server.tip_announcements().await.unwrap().announcements;
        assert_eq!(transaction_kernel.announcements, announcements);
    }

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn get_block_calls_are_consistent(
        #[strategy(0usize..8)] _num_announcements: usize,
        #[strategy(txkernel::with_lengths(0, 2, #_num_announcements, true))]
    tx_block1: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut rpc_server = test_rpc_server().await;

        let tx_block1 = Transaction {
            kernel: tx_block1,
            proof: TransactionProof::invalid(),
        };
        let block1 = invalid_block_with_transaction(&Block::genesis(Network::Main), tx_block1);
        rpc_server.state.set_new_tip(block1.clone()).await.unwrap();

        for height in [BlockHeight::genesis(), BlockHeight::genesis().next()] {
            let height_selector = RpcBlockSelector::Height(height);
            let digest = rpc_server
                .get_block_digest(height_selector)
                .await
                .unwrap()
                .digest
                .expect("digest should be available");
            let selector = RpcBlockSelector::Digest(digest);

            let block = rpc_server
                .get_block(selector)
                .await
                .unwrap()
                .block
                .expect("block should exist");
            let proof = rpc_server
                .get_block_proof(selector)
                .await
                .unwrap()
                .proof
                .expect("proof should exist");
            assert_eq!(block.proof, proof);

            let kernel = rpc_server
                .get_block_kernel(selector)
                .await
                .unwrap()
                .kernel
                .expect("kernel should exist");
            let header = rpc_server
                .get_block_header(selector)
                .await
                .unwrap()
                .header
                .expect("header should exist");
            assert_eq!(kernel.header, header);
            assert_eq!(header.height, height);

            let body = rpc_server
                .get_block_body(selector)
                .await
                .unwrap()
                .body
                .expect("body should exist");
            let transaction_kernel = rpc_server
                .get_block_transaction_kernel(selector)
                .await
                .unwrap()
                .kernel
                .expect("transaction kernel should exist");
            assert_eq!(body.transaction_kernel, transaction_kernel);

            let announcements = rpc_server
                .get_block_announcements(selector)
                .await
                .unwrap()
                .announcements
                .expect("announcements should exist");
            assert_eq!(transaction_kernel.announcements, announcements);
        }
    }

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn get_block_digests_returns_competing_blocks(
        #[strategy(txkernel::with_lengths(0, 2, 2, true))]
    tx_block1: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
        #[strategy(txkernel::with_lengths(0, 2, 2, true))]
    tx_block2: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut rpc_server = test_rpc_server().await;

        let tx_block1 = Transaction {
            kernel: tx_block1,
            proof: TransactionProof::invalid(),
        };
        let tx_block2 = Transaction {
            kernel: tx_block2,
            proof: TransactionProof::invalid(),
        };
        let block1 = invalid_block_with_transaction(&Block::genesis(Network::Main), tx_block1);
        let block2 = invalid_block_with_transaction(&Block::genesis(Network::Main), tx_block2);
        rpc_server.state.set_new_tip(block1.clone()).await.unwrap();
        rpc_server.state.set_new_tip(block2.clone()).await.unwrap();

        let digests = rpc_server
            .get_block_digests(BlockHeight::genesis().next().into())
            .await
            .unwrap()
            .digests;

        let expected: HashSet<_> = [block1.hash(), block2.hash()].into();
        let actual: HashSet<_> = digests.into_iter().collect();

        assert_eq!(expected, actual);
    }

    #[apply(shared_tokio_runtime)]
    async fn is_block_canonical_consistency() {
        let rpc_server = test_rpc_server().await;

        // Test genesis block is canonical
        let genesis_digest = rpc_server.tip_digest().await.unwrap().digest;
        let is_genesis_canonical = rpc_server
            .is_block_canonical(genesis_digest)
            .await
            .unwrap()
            .canonical;
        assert!(is_genesis_canonical, "Genesis block should be canonical");

        // Test non-existent block is not canonical
        let fake_digest = Digest::default();
        let is_fake_canonical = rpc_server
            .is_block_canonical(fake_digest)
            .await
            .unwrap()
            .canonical;
        assert!(
            !is_fake_canonical,
            "Non-existent block should not be canonical"
        );
    }

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn utxo_calls_are_consistent(
        #[strategy(0usize..8)] _num_outputs: usize,
        #[strategy(txkernel::with_lengths(0usize, #_num_outputs, 0usize, true))]
        transaction_kernel: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut rpc_server = test_rpc_server().await;

        // Before new block check size of aocl leaves so we can know exact index of new outputs
        let num_aocl_leaves = rpc_server
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .archival_mutator_set
            .ams()
            .aocl
            .num_leafs()
            .await;

        let transaction = Transaction {
            kernel: transaction_kernel,
            proof: TransactionProof::invalid(),
        };
        let block = invalid_block_with_transaction(&Block::genesis(Network::Main), transaction);
        rpc_server.state.set_new_tip(block.clone()).await.unwrap();

        for (i, output) in block.body().transaction_kernel().outputs.iter().enumerate() {
            let utxo_index = num_aocl_leaves + i as u64;
            let digest_entry = rpc_server
                .get_utxo_digest(utxo_index)
                .await
                .expect("failed to get utxo digest");

            let digest = digest_entry.digest.expect("missing digest for utxo output");

            assert_eq!(
                output.canonical_commitment, digest,
                "canonical commitment mismatch for utxo at index {utxo_index}"
            );

            // Check origin of UTXO
            let origin_response = rpc_server
                .find_utxo_origin((*output).into(), None)
                .await
                .expect("find_utxo_origin RPC failed");

            let origin_block = origin_response.block;
            assert!(
                origin_block.is_some(),
                "expected origin block for utxo {utxo_index}"
            );
            assert_eq!(
                origin_block.unwrap(),
                block.hash(),
                "origin block mismatch for utxo {utxo_index}"
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn remote_wallets_behave_correctly() {
        let mut rpc_server = test_rpc_server().await;
        let network = rpc_server.state.cli().network;

        // Prepare a transaction to our wallet coming from devnet wallet.
        let mut devnet_node = mock_genesis_global_state(
            0,
            WalletEntropy::devnet_wallet(),
            rpc_server.state.cli().clone(),
        )
        .await;

        let rpc_address = rpc_server
            .state
            .api()
            .wallet()
            .next_receiving_address(KeyType::Generation)
            .await
            .unwrap();
        let mock_amount = NativeCurrencyAmount::coins_from_str("1").unwrap();
        let devnet_artifacts = devnet_node
            .api_mut()
            .tx_sender_mut()
            .send(
                vec![OutputFormat::AddressAndAmount(rpc_address, mock_amount)],
                Default::default(),
                mock_amount,
                network.launch_date() + Timestamp::months(3),
                0,
            )
            .await
            .unwrap();

        // Pass transaction into rpc_server network.
        let block_1 = invalid_block_with_transaction(
            &Block::genesis(network),
            devnet_artifacts.transaction().clone(),
        );
        rpc_server.state.set_new_tip(block_1.clone()).await.unwrap();

        // Fetch genesis and tip and ensure announcement (on tip) matches after de/serialization.
        let blocks = rpc_server
            .get_blocks(BlockHeight::genesis(), BlockHeight::genesis().next())
            .await
            .unwrap()
            .blocks;
        assert_eq!(blocks.len(), 2);

        let announcement: Announcement = blocks[1].kernel.body.transaction_kernel.announcements[0]
            .clone()
            .into();
        let expected_announcement = devnet_artifacts.details().announcements()[0].clone();
        assert_eq!(announcement, expected_announcement);

        // Try restoring MSMP thru RPC and ensure it matches the one maintained by our wallet.
        let msa = rpc_server
            .state
            .lock_guard()
            .await
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .unwrap();
        let wallet_status = rpc_server
            .state
            .lock_guard()
            .await
            .wallet_state
            .get_wallet_status(block_1.hash(), &msa)
            .await;

        let (utxo, msmp) = &wallet_status.synced_unspent[0];
        let item = Tip5::hash(&utxo.utxo);

        let msmp_snapshot = rpc_server
            .restore_membership_proof(vec![msmp.compute_indices(item)])
            .await
            .expect("restore to succeed")
            .snapshot;
        let extracted_msmp = msmp_snapshot.membership_proofs[0]
            .clone()
            .extract_ms_membership_proof(
                utxo.aocl_leaf_index,
                msmp.sender_randomness,
                msmp.receiver_preimage,
            )
            .unwrap();
        assert_eq!(msmp, &extracted_msmp);

        // Try submitting a valid transaction (ProofCollection) by RPC.
        let tx_creation_config = TxCreationConfig::default()
            .with_prover_capability(TxProvingCapability::ProofCollection);
        let artifacts = rpc_server
            .state
            .api()
            .tx_initiator_internal()
            .create_transaction(
                Default::default(),
                mock_amount,
                network.launch_date() + Timestamp::months(3) + Timestamp::minutes(3),
                tx_creation_config,
                ConsensusRuleSet::infer_from(network, block_1.header().height),
            )
            .await
            .unwrap();
        let rpc_transaction = artifacts.transaction().clone().into();
        let submit_tx_response = rpc_server
            .submit_transaction(rpc_transaction)
            .await
            .expect("submission to succeed");

        assert!(submit_tx_response.success);
    }

    #[apply(shared_tokio_runtime)]
    async fn mining_scenarios_validated_properly() {
        use crate::application::json_rpc::core::api::rpc::SubmitBlockError;

        let mut rpc_server = test_rpc_server().await;
        let network = rpc_server.state.cli().network;

        let genesis = Block::genesis(network);
        let block1 = fake_valid_deterministic_successor(&genesis, network).await;
        rpc_server
            .state
            .lock_mut(|x| {
                x.mining_state.block_proposal = BlockProposal::ForeignComposition(block1.clone())
            })
            .await;
        let guesser_address = rpc_server
            .state
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Generation)
            .await
            .to_address();

        let RpcBlockTemplate { block, metadata } = rpc_server
            .get_block_template(guesser_address.to_bech32m(network).unwrap())
            .await
            .unwrap()
            .template
            .unwrap();

        assert_eq!(
            rpc_server
                .submit_block(block.clone(), block.kernel.header.pow.clone())
                .await
                .unwrap_err(),
            RpcError::SubmitBlock(SubmitBlockError::InsufficientWork)
        );

        let solution = metadata.solve(ConsensusRuleSet::default());
        assert!(
            rpc_server
                .submit_block(block.clone(), solution.clone())
                .await
                .unwrap()
                .success,
            "Node must accept valid new tip."
        );

        let mut bad_proposal = block;
        bad_proposal.proof = None;
        assert_eq!(
            rpc_server
                .submit_block(bad_proposal.clone(), solution)
                .await
                .unwrap_err(),
            RpcError::SubmitBlock(SubmitBlockError::InvalidBlock)
        );
    }

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn mempool_calls_are_consistent(
        #[strategy(0usize..10)] tx_count: usize,
        #[strategy(0usize..=#tx_count)] sp_count: usize,
    ) {
        let mut rpc_server = test_rpc_server().await;

        // Create some witness txs to be added into mempool.
        let mut txs = make_plenty_mock_transaction_supported_by_primitive_witness(tx_count);
        // Make some of txs SP-backed so we can test proof extraction.
        for index in 0..sp_count {
            txs[index].proof = TransactionProof::invalid();
        }

        // Insert transactions to mempool.
        for tx in &txs {
            rpc_server
                .state
                .lock_guard_mut()
                .await
                .mempool_insert(tx.clone(), UpgradePriority::Irrelevant)
                .await;
        }

        // Test mempool size matches what we are expecting.
        let mempool_txs = rpc_server.transactions().await.unwrap().transactions;
        assert_eq!(mempool_txs.len(), tx_count);

        for tx in txs {
            let id = tx.txid();

            // Test transaction kernel can be extracted and contents match.
            let kernel = rpc_server.get_transaction_kernel(id).await.unwrap().kernel;
            assert!(kernel.is_some());
            assert_eq!(tx.kernel, kernel.unwrap().into());

            // Test transaction proofs can be extracted and contents match.
            let proof = rpc_server.get_transaction_proof(id).await.unwrap().proof;
            match tx.proof {
                // Witness-backed transactions proofs cannot be exposed as it exposes private data.
                TransactionProof::Witness(_) => assert!(proof.is_none()),
                _ => {
                    assert!(proof.is_some());
                    assert_eq!(proof.unwrap(), tx.proof.into());
                }
            }
        }
    }
}
