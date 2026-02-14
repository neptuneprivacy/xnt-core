//! UTXO sync operations
//!
//! Shared sync logic for fetching UTXOs, checking spent status,
//! and managing membership proofs.

use neptune_privacy::prelude::tasm_lib::prelude::Tip5;
use neptune_privacy::util_types::mutator_set::commit;
use neptune_privacy::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use neptune_privacy::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_privacy::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use serde_json::{json, Value};

use super::error::{Result, XntError};
use super::json_rpc::RpcClient;
use super::types::Digest;
use super::utxo::Utxo;
use super::wallet::SpendingKey;

/// Indexed UTXO from sync
pub struct IndexedUtxo {
    pub block_height: u64,
    pub block_digest: Digest,
    pub ciphertext: Vec<u8>,
}

/// Spent status (-1 = not spent, >= 0 = spent at height)
pub type SpentStatus = Vec<i64>;

/// AOCL leaf indices
pub type AoclIndices = Vec<i64>;

/// Mutator set accumulator wrapper
#[derive(Clone)]
pub struct MutatorSet {
    pub(crate) inner: MutatorSetAccumulator,
}

impl MutatorSet {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.inner).map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let inner: MutatorSetAccumulator =
            bincode::deserialize(data).map_err(|e| XntError::EncodingError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Verify membership proof
    pub fn verify(
        &self,
        utxo_hash: &Digest,
        membership_proof: &MembershipProof,
    ) -> bool {
        self.inner.verify(utxo_hash.to_core(), &membership_proof.inner)
    }

    pub(crate) fn from_core(inner: MutatorSetAccumulator) -> Self {
        Self { inner }
    }
}

/// Membership proof wrapper
#[derive(Clone)]
pub struct MembershipProof {
    pub(crate) inner: MsMembershipProof,
}

impl MembershipProof {
    /// Get AOCL leaf index
    pub fn aocl_leaf_index(&self) -> u64 {
        self.inner.aocl_leaf_index
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.inner).map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let inner: MsMembershipProof =
            bincode::deserialize(data).map_err(|e| XntError::EncodingError(e.to_string()))?;
        Ok(Self { inner })
    }

    pub(crate) fn from_core(inner: MsMembershipProof) -> Self {
        Self { inner }
    }
}

/// Spendable input collected from the chain for a specific spending key.
///
/// This struct is SDK-only; it is not serialized on-chain.
#[derive(Clone)]
pub struct SpendableInput {
    /// The decrypted UTXO
    pub utxo: Utxo,
    /// The spending key that can unlock this UTXO (Generation or dCTIDH)
    pub spending_key: SpendingKey,
    /// Membership proof for this UTXO in the mutator set
    pub membership_proof: MembershipProof,
    /// Sender randomness used in the commitment
    pub sender_randomness: Digest,
    /// AOCL leaf index for this UTXO
    pub aocl_index: u64,
    /// Amount in native currency (nau)
    pub amount: i128,
    /// Block height where the UTXO was created
    pub block_height: u64,
    /// Block digest where the UTXO was created
    pub block_digest: Digest,
}


/// Compute canonical commitment for UTXO (using receiver_preimage)
pub fn compute_commitment(
    utxo_hash: &Digest,
    sender_randomness: &Digest,
    receiver_preimage: &Digest,
) -> Digest {
    let addition_record = commit(
        utxo_hash.to_core(),
        sender_randomness.to_core(),
        receiver_preimage.to_core().hash(),
    );
    Digest::from_core(addition_record.canonical_commitment)
}

/// Compute canonical commitment for output (using receiver_postimage/privacy_digest)
pub fn compute_commitment_for_output(
    utxo_hash: &Digest,
    sender_randomness: &Digest,
    receiver_postimage: &Digest,
) -> Digest {
    let addition_record = commit(
        utxo_hash.to_core(),
        sender_randomness.to_core(),
        receiver_postimage.to_core(),
    );
    Digest::from_core(addition_record.canonical_commitment)
}

/// Compute absolute_index_set_hash for spent checking
pub fn compute_absolute_index_set_hash(
    utxo_hash: &Digest,
    sender_randomness: &Digest,
    receiver_preimage: &Digest,
    aocl_leaf_index: u64,
) -> Digest {
    let abs_indices = AbsoluteIndexSet::compute(
        utxo_hash.to_core(),
        sender_randomness.to_core(),
        receiver_preimage.to_core(),
        aocl_leaf_index,
    );
    Digest::from_core(Tip5::hash(&abs_indices))
}

/// Hash an AbsoluteIndexSet from JSON (from RPC mempool response)
/// Used to check if a mempool tx input matches a known UTXO
pub fn hash_absolute_index_set_json(json_str: &str) -> Result<Digest> {
    let abs_indices: AbsoluteIndexSet = serde_json::from_str(json_str)
        .map_err(|e| XntError::InvalidInput(format!("invalid AbsoluteIndexSet JSON: {e}")))?;
    Ok(Digest::from_core(Tip5::hash(&abs_indices)))
}

/// Maximum ciphertext size per UTXO (10KB) - prevents OOM from malicious RPC
const MAX_UTXO_CIPHERTEXT_SIZE: usize = 10_000;
/// Maximum number of UTXOs per response (10,000) - prevents OOM
const MAX_UTXOS_PER_RESPONSE: usize = 10_000;

/// Fetch UTXOs from indexer by receiver_id_hash
pub fn fetch_utxos(
    client: &RpcClient,
    receiver_id_hash: &Digest,
    from_height: u64,
    to_height: u64,
) -> Result<Vec<IndexedUtxo>> {
    let params = json!({
        "receiverIdHash": receiver_id_hash.to_hex(),
        "fromBlockHeight": from_height,
        "toBlockHeight": to_height
    });

    let result = client.call("archival_getUtxosByReceiver", params)?;

    let utxos = result
        .get("utxos")
        .and_then(|v| v.as_array())
        .ok_or_else(|| XntError::RpcError("missing utxos".to_string()))?;

    if utxos.len() > MAX_UTXOS_PER_RESPONSE {
        return Err(XntError::RpcError(format!(
            "too many UTXOs in response: {} > {}",
            utxos.len(),
            MAX_UTXOS_PER_RESPONSE
        )));
    }

    let mut indexed_utxos = Vec::with_capacity(utxos.len());

    for utxo in utxos {
        let block_height = utxo.get("blockHeight").and_then(|v| v.as_u64()).unwrap_or(0);
        let block_digest = utxo
            .get("blockDigest")
            .and_then(|v| v.as_str())
            .and_then(Digest::from_hex)
            .unwrap_or_default();

        let ciphertext_bfes: Vec<u64> = if let Some(Value::Array(arr)) = utxo.get("ciphertext") {
            if arr.len() * 8 > MAX_UTXO_CIPHERTEXT_SIZE {
                return Err(XntError::RpcError(format!(
                    "ciphertext too large: {} bytes > {} max",
                    arr.len() * 8,
                    MAX_UTXO_CIPHERTEXT_SIZE
                )));
            }
            arr.iter()
                .filter_map(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .collect()
        } else {
            Vec::new()
        };

        let ciphertext: Vec<u8> = ciphertext_bfes
            .iter()
            .flat_map(|&v| v.to_le_bytes())
            .collect();

        indexed_utxos.push(IndexedUtxo {
            block_height,
            block_digest,
            ciphertext,
        });
    }

    Ok(indexed_utxos)
}

/// Check spent status of UTXOs
pub fn check_spent(client: &RpcClient, hashes: &[Digest]) -> Result<SpentStatus> {
    let hashes_vec: Vec<String> = hashes.iter().map(|d| d.to_hex()).collect();
    let params = json!({ "absoluteIndexSetHashes": hashes_vec });

    let result = client.call("archival_getSpentStatus", params)?;

    let spent_heights = result
        .get("spentAtHeights")
        .and_then(|v| v.as_array())
        .ok_or_else(|| XntError::RpcError("missing spentAtHeights".to_string()))?;

    Ok(spent_heights
        .iter()
        .map(|v| v.as_i64().unwrap_or(-1))
        .collect())
}

/// Get AOCL leaf indices for commitments
pub fn get_aocl_indices(client: &RpcClient, commitments: &[Digest]) -> Result<AoclIndices> {
    let commitment_vec: Vec<String> = commitments.iter().map(|d| d.to_hex()).collect();
    let params = json!({ "commitments": commitment_vec });

    let result = client.call("archival_getAoclLeafIndices", params)?;

    let indices = result
        .get("indices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| XntError::RpcError("missing indices".to_string()))?;

    Ok(indices.iter().map(|v| v.as_i64().unwrap_or(-1)).collect())
}

/// Collect spendable inputs (UTXOs + membership proofs) for a single spending key.
///
/// This will:
/// - fetch UTXOs by receiver_id_hash
/// - decrypt them using the provided key
/// - compute commitments and AOCL indices
/// - filter out spent UTXOs
/// - restore membership proofs for the remaining ones
pub fn collect_spendable_inputs_for_key(
    client: &RpcClient,
    key: &SpendingKey,
    from_height: u64,
    to_height: u64,
) -> Result<Vec<SpendableInput>> {
    // Derive receiver_id_hash and receiver_preimage from SDK key
    let rid_hash = key.receiver_id_hash();
    let receiver_preimage = key.receiver_preimage();

    // Fetch indexed UTXOs from archival node
    let indexed = fetch_utxos(client, &rid_hash, from_height, to_height)?;
    if indexed.is_empty() {
        return Ok(Vec::new());
    }

    // Decrypt UTXOs using core SpendingKey::decrypt (works for Generation and dCTIDH)
    let mut utxos: Vec<(Utxo, Digest, i128, u64, Digest)> = Vec::new();
    for idx in indexed {
        // ciphertext_bfes are encoded little-endian u64s; convert back to BFieldElements
        let bfe_words = idx
            .ciphertext
            .chunks(8)
            .map(|chunk| {
                let mut arr = [0u8; 8];
                arr[..chunk.len()].copy_from_slice(chunk);
                u64::from_le_bytes(arr)
            })
            .collect::<Vec<u64>>();

        let bfes: Vec<neptune_privacy::prelude::twenty_first::prelude::BFieldElement> =
            bfe_words
                .into_iter()
                .map(|v| neptune_privacy::prelude::twenty_first::prelude::BFieldElement::new(v))
                .collect();

        let (core_utxo, sr, _payment_id) = key
            .inner
            .decrypt(&bfes)
            .map_err(|e| XntError::CryptoError(format!("decryption failed: {e}")))?;
        {
            let amount = core_utxo.get_native_currency_amount().to_nau();
            let utxo = Utxo::from_core(core_utxo);
            utxos.push((utxo, Digest::from_core(sr), amount, idx.block_height, idx.block_digest));
        }
    }

    if utxos.is_empty() {
        return Ok(Vec::new());
    }

    // Compute commitments and fetch AOCL indices
    let commits: Vec<Digest> = utxos
        .iter()
        .map(|(u, sr, _, _, _)| compute_commitment(&u.hash(), sr, &receiver_preimage))
        .collect();

    let aocl = get_aocl_indices(client, &commits)?;
    if aocl.is_empty() {
        return Ok(Vec::new());
    }

    // Build AbsoluteIndexSet hashes and check spent status
    let mut abs_hashes: Vec<Digest> = Vec::new();
    let mut valid_indices: Vec<usize> = Vec::new();
    for (i, &idx) in aocl.iter().enumerate() {
        if idx >= 0 && i < utxos.len() {
            let (ref u, ref sr, _, _, _) = utxos[i];
            let h = compute_absolute_index_set_hash(&u.hash(), sr, &receiver_preimage, idx as u64);
            abs_hashes.push(h);
            valid_indices.push(i);
        }
    }

    if abs_hashes.is_empty() {
        return Ok(Vec::new());
    }

    let spent = check_spent(client, &abs_hashes)?;
    if spent.len() != valid_indices.len() {
        return Err(XntError::RpcError(
            "spent status length mismatch".to_string(),
        ));
    }

    // Filter to unspent
    let mut unspent_indices: Vec<(usize, u64)> = Vec::new();
    for (j, &h) in spent.iter().enumerate() {
        if h < 0 && j < valid_indices.len() {
            let oi = valid_indices[j];
            let aocl_idx = aocl[oi];
            if aocl_idx >= 0 {
                unspent_indices.push((oi, aocl_idx as u64));
            }
        }
    }

    if unspent_indices.is_empty() {
        return Ok(Vec::new());
    }

    // Restore membership proofs for unspent UTXOs
    use neptune_privacy::application::json_rpc::core::model::wallet::mutator_set::RpcMsMembershipProofPrivacyPreserving;

    let absolute_index_sets: Vec<AbsoluteIndexSet> = unspent_indices
        .iter()
        .map(|(oi, idx)| {
            let (ref u, ref sr, _, _, _) = utxos[*oi];
            AbsoluteIndexSet::compute(
                u.hash().to_core(),
                sr.to_core(),
                receiver_preimage.to_core(),
                *idx,
            )
        })
        .collect();

    let params = json!([absolute_index_sets]);
    let result = client.call("archival_restoreMembershipProof", params)?;
    let snapshot = result
        .get("snapshot")
        .ok_or_else(|| XntError::RpcError("missing snapshot".to_string()))?;
    let proofs_arr = snapshot
        .get("membershipProofs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| XntError::RpcError("missing membershipProofs".to_string()))?;

    if proofs_arr.len() != unspent_indices.len() {
        return Err(XntError::RpcError(
            "membershipProofs length mismatch".to_string(),
        ));
    }

    let mut res = Vec::with_capacity(unspent_indices.len());
    for (idx, proof_val) in proofs_arr.iter().enumerate() {
        let rpc_proof: RpcMsMembershipProofPrivacyPreserving =
            serde_json::from_value(proof_val.clone())
                .map_err(|e| XntError::RpcError(format!("parse proof {idx} failed: {e}")))?;

        let (_oi, aocl_idx) = unspent_indices[idx];
        let (ref u, ref sr, amount, bh, bd) = utxos[unspent_indices[idx].0];

        let msmp = rpc_proof
            .extract_ms_membership_proof(aocl_idx, sr.to_core(), receiver_preimage.to_core())
            .ok_or_else(|| {
                XntError::RpcError(format!("extract proof {idx} failed for aocl index {aocl_idx}"))
            })?;

        res.push(SpendableInput {
            utxo: u.clone(),
            spending_key: key.clone(),
            membership_proof: MembershipProof::from_core(msmp),
            sender_randomness: sr.clone(),
            aocl_index: aocl_idx,
            amount,
            block_height: bh,
            block_digest: bd.clone(),
        });
    }

    Ok(res)
}

/// Get current mutator set from archival node
pub fn get_mutator_set(client: &RpcClient) -> Result<MutatorSet> {
    use neptune_privacy::application::json_rpc::core::model::block::body::RpcMutatorSetAccumulator;

    let result = client.call("archival_getArchivalMutatorSet", json!([]))?;

    let msa_obj = result
        .get("archivalMutatorSet")
        .ok_or_else(|| XntError::RpcError("missing archivalMutatorSet".to_string()))?;

    let rpc_msa: RpcMutatorSetAccumulator = serde_json::from_value(msa_obj.clone())
        .map_err(|e| XntError::RpcError(format!("parse mutator set failed: {e}")))?;

    Ok(MutatorSet::from_core(rpc_msa.into()))
}

/// Get membership proofs via wallet RPC
pub fn get_membership_proofs(
    client: &RpcClient,
    utxo_hashes: &[Digest],
    sender_randomnesses: &[Digest],
    receiver_preimage: &Digest,
    aocl_indices: &[u64],
) -> Result<Vec<MembershipProof>> {
    use neptune_privacy::application::json_rpc::core::model::wallet::mutator_set::RpcMsMembershipProofPrivacyPreserving;

    if utxo_hashes.len() != sender_randomnesses.len() || utxo_hashes.len() != aocl_indices.len() {
        return Err(XntError::RpcError("array length mismatch".to_string()));
    }

    // Compute AbsoluteIndexSets for each UTXO
    let absolute_index_sets: Vec<AbsoluteIndexSet> = utxo_hashes
        .iter()
        .zip(sender_randomnesses.iter())
        .zip(aocl_indices.iter())
        .map(|((item, sr), &idx)| {
            AbsoluteIndexSet::compute(
                item.to_core(),
                sr.to_core(),
                receiver_preimage.to_core(),
                idx,
            )
        })
        .collect();

    // Call archival_restoreMembershipProof RPC
    let params = json!([absolute_index_sets]);
    let result = client.call("archival_restoreMembershipProof", params)?;

    // Parse response
    let snapshot = result
        .get("snapshot")
        .ok_or_else(|| XntError::RpcError("missing snapshot".to_string()))?;

    let proofs_arr = snapshot
        .get("membershipProofs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| XntError::RpcError("missing membershipProofs".to_string()))?;

    let mut membership_proofs = Vec::with_capacity(proofs_arr.len());
    for (i, proof_val) in proofs_arr.iter().enumerate() {
        let rpc_proof: RpcMsMembershipProofPrivacyPreserving = serde_json::from_value(proof_val.clone())
            .map_err(|e| XntError::RpcError(format!("parse proof {i} failed: {e}")))?;

        // Extract the actual MsMembershipProof using the AOCL index, sender_randomness, and receiver_preimage
        let aocl_idx = aocl_indices[i];
        let sr = sender_randomnesses[i].to_core();
        let rp = receiver_preimage.to_core();
        let msmp = rpc_proof
            .extract_ms_membership_proof(aocl_idx, sr, rp)
            .ok_or_else(|| XntError::RpcError(format!("extract proof {i} failed")))?;

        membership_proofs.push(MembershipProof::from_core(msmp));
    }

    Ok(membership_proofs)
}

/// Decrypt indexed UTXO ciphertext
pub fn decrypt_indexed_utxo(
    spending_key: &SpendingKey,
    ciphertext_bytes: &[u8],
    block_height: u64,
    block_digest: Digest,
) -> Result<super::utxo::DecryptedUtxo> {
    use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;

    let ciphertext: Vec<BFieldElement> = ciphertext_bytes
        .chunks(8)
        .map(|chunk| {
            let mut arr = [0u8; 8];
            arr[..chunk.len()].copy_from_slice(chunk);
            BFieldElement::new(u64::from_le_bytes(arr))
        })
        .collect();

    let (utxo, sender_randomness, payment_id) = spending_key
        .inner
        .decrypt(&ciphertext)
        .map_err(|e| XntError::CryptoError(format!("decryption failed: {e}")))?;

    Ok(super::utxo::DecryptedUtxo {
        utxo: Utxo::from_core(utxo),
        sender_randomness: Digest::from_core(sender_randomness),
        payment_id: payment_id.value(),
        block_height,
        block_digest,
    })
}


/// Transaction kernel ID from mempool
#[derive(Debug, Clone)]
pub struct MempoolTxId(pub Digest);

/// Removal record from mempool (for pending spent detection)
#[derive(Debug, Clone)]
pub struct MempoolRemovalRecord {
    /// JSON representation of AbsoluteIndexSet for hashing
    pub absolute_indices_json: String,
}

/// Transaction kernel from mempool
#[derive(Debug, Clone)]
pub struct MempoolTxKernel {
    /// Removal records (inputs being spent)
    pub inputs: Vec<MempoolRemovalRecord>,
    /// Announcements (encrypted UTXOs) for pending incoming
    pub announcements: Vec<Vec<u8>>,
    /// Fee amount
    pub fee: i128,
    /// Timestamp
    pub timestamp_ms: u64,
}

/// Get all transaction IDs in mempool
pub fn get_mempool_transactions(client: &RpcClient) -> Result<Vec<MempoolTxId>> {
    let result = client.call("mempool_transactions", json!([]))?;

    let txs = result
        .get("transactions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| XntError::RpcError("missing transactions".to_string()))?;

    let mut ids = Vec::with_capacity(txs.len());
    for tx in txs {
        // Transaction ID is a Digest
        let id: neptune_privacy::api::export::Digest = serde_json::from_value(tx.clone())
            .map_err(|e| XntError::RpcError(format!("parse tx id: {e}")))?;
        ids.push(MempoolTxId(Digest::from_core(id)));
    }

    Ok(ids)
}

/// Get transaction kernel from mempool by ID
pub fn get_mempool_transaction_kernel(client: &RpcClient, id: &MempoolTxId) -> Result<Option<MempoolTxKernel>> {
    let params = json!([id.0.to_core()]);
    let result = client.call("mempool_getTransactionKernel", params)?;

    let kernel = match result.get("kernel") {
        Some(Value::Null) | None => return Ok(None),
        Some(k) => k,
    };

    // Parse inputs (removal records)
    let inputs = kernel
        .get("inputs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|rr| {
                    rr.get("absoluteIndices").map(|ai| MempoolRemovalRecord {
                        absolute_indices_json: ai.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse announcements (hex strings like "0x00010002...")
    let announcements = kernel
        .get("announcements")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|ann| {
                    // Announcement is hex string "0x..." encoding big-endian u64s
                    ann.as_str()
                        .and_then(|s| s.strip_prefix("0x"))
                        .and_then(|hex_str| hex::decode(hex_str).ok())
                        .map(|bytes| {
                            // Convert from big-endian to little-endian per u64
                            bytes
                                .chunks(8)
                                .flat_map(|chunk| {
                                    let mut arr = [0u8; 8];
                                    arr[..chunk.len()].copy_from_slice(chunk);
                                    let be_val = u64::from_be_bytes(arr);
                                    be_val.to_le_bytes()
                                })
                                .collect()
                        })
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse fee
    let fee = kernel
        .get("fee")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i128>().ok())
        .unwrap_or(0);

    // Parse timestamp
    let timestamp_ms = kernel
        .get("timestamp")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Ok(Some(MempoolTxKernel {
        inputs,
        announcements,
        fee,
        timestamp_ms,
    }))
}

/// Check mempool for pending spending (our UTXOs being spent)
/// Returns indices of UTXOs that have pending spends
pub fn mempool_spending(
    client: &RpcClient,
    our_abs_hashes: &[Digest],
) -> Result<Vec<usize>> {
    let tx_ids = get_mempool_transactions(client)?;
    let mut pending_spent_indices = Vec::new();

    for tx_id in tx_ids {
        if let Some(kernel) = get_mempool_transaction_kernel(client, &tx_id)? {
            for input in &kernel.inputs {
                if let Ok(input_hash) = hash_absolute_index_set_json(&input.absolute_indices_json) {
                    for (i, our_hash) in our_abs_hashes.iter().enumerate() {
                        if input_hash == *our_hash && !pending_spent_indices.contains(&i) {
                            pending_spent_indices.push(i);
                        }
                    }
                }
            }
        }
    }

    Ok(pending_spent_indices)
}

/// Decrypt mempool announcement to check for pending incoming.
/// Announcement format: [key_type, receiver_id, ciphertext...]
pub fn decrypt_mempool_announcement(
    spending_key: &SpendingKey,
    announcement_bytes: &[u8],
) -> Result<Option<(Utxo, Digest, u64)>> {
    use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;

    // Convert bytes to BFieldElements (LE per u64)
    let bfes: Vec<BFieldElement> = announcement_bytes
        .chunks(8)
        .map(|chunk| {
            let mut arr = [0u8; 8];
            arr[..chunk.len()].copy_from_slice(chunk);
            BFieldElement::new(u64::from_le_bytes(arr))
        })
        .collect();

    // Need at least: key_type + receiver_id + some ciphertext
    if bfes.len() <= 2 {
        return Ok(None);
    }

    // Check receiver_id (index 1) matches our key
    if bfes[1] != spending_key.inner.receiver_identifier() {
        return Ok(None);
    }

    // Decrypt ciphertext (skip key_type and receiver_id)
    match spending_key.inner.decrypt(&bfes[2..]) {
        Ok((utxo, sender_randomness, payment_id)) => Ok(Some((
            Utxo::from_core(utxo),
            Digest::from_core(sender_randomness),
            payment_id.value(),
        ))),
        Err(_) => Ok(None),
    }
}

/// Check mempool for pending incoming UTXOs
/// Returns list of (utxo, sender_randomness, payment_id) for pending incoming
pub fn mempool_incoming(
    client: &RpcClient,
    spending_key: &SpendingKey,
) -> Result<Vec<(Utxo, Digest, u64)>> {
    let tx_ids = get_mempool_transactions(client)?;
    let mut pending_incoming = Vec::new();

    for tx_id in &tx_ids {
        if let Some(kernel) = get_mempool_transaction_kernel(client, tx_id)? {
            for announcement in &kernel.announcements {
                if let Some(decrypted) = decrypt_mempool_announcement(spending_key, announcement)? {
                    pending_incoming.push(decrypted);
                }
            }
        }
    }

    Ok(pending_incoming)
}
