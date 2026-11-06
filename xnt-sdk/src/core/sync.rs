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
use super::types::{Digest, Network};
use super::utxo::Utxo;
use super::wallet::SpendingKey;

/// Indexed UTXO from sync
pub struct IndexedUtxo {
    pub block_height: u64,
    pub block_digest: Digest,
    pub ciphertext: Vec<u8>,
}

/// Bridge payout from sync: a public UTXO, found by its receiver identifier
/// instead of an encrypted notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIndexedUtxo {
    pub block_height: u64,
    pub block_digest: Digest,
    pub lock_script_hash: Digest,
    pub amount_nau: i128,
    pub sender_randomness: Digest,
}

/// Spent status (-1 = not spent, >= 0 = spent at height)
pub type SpentStatus = Vec<i64>;

/// AOCL leaf indices
pub type AoclIndices = Vec<i64>;

/// Mutator set accumulator wrapper
///
/// Also records the height of the tip whose mutator set it is, if known: a
/// transaction built on it is proven for the consensus rule set of the block
/// after that tip, see [super::transaction::BuiltTransaction::prove].
#[derive(Clone)]
pub struct MutatorSet {
    pub(crate) inner: MutatorSetAccumulator,
    pub(crate) tip_height: Option<u64>,
}

impl MutatorSet {
    /// Serialize to bytes
    ///
    /// The tip height is not serialized; restore it with
    /// [Self::with_tip_height] after [Self::from_bytes].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.inner).map_err(|e| XntError::EncodingError(e.to_string()))
    }

    /// Deserialize from bytes
    ///
    /// The tip height is unknown, see [Self::with_tip_height].
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let inner: MutatorSetAccumulator =
            bincode::deserialize(data).map_err(|e| XntError::EncodingError(e.to_string()))?;
        Ok(Self { inner, tip_height: None })
    }

    /// The same mutator set, as the one of the tip at `tip_height`. For callers
    /// that cache the accumulator, see [Self::to_bytes].
    pub fn with_tip_height(mut self, tip_height: u64) -> Self {
        self.tip_height = Some(tip_height);
        self
    }

    /// The height of the tip whose mutator set this is, if known.
    /// [get_mutator_set] records it.
    pub fn tip_height(&self) -> Option<u64> {
        self.tip_height
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
        Self { inner, tip_height: None }
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
    /// True if the UTXO is locked to a legacy-format (pre-v0.3) dCTIDH lock,
    /// see [SpendingKey::is_legacy]. Such inputs are sweep-only: move them to
    /// a current-format key and never count them towards the available
    /// balance.
    pub is_legacy: bool,
    /// Payment id the UTXO was received with, from its decrypted notification:
    /// 0 for the base address of the key, otherwise the payment id of the
    /// subaddress it was sent to. All payment ids of a key share its lock, so
    /// the payment id is known only from the notification.
    pub payment_id: u64,
}

impl SpendableInput {
    /// Hash of the input's absolute index set, by which [check_spent] tells
    /// whether it is spent.
    pub fn absolute_index_set_hash(&self) -> Digest {
        compute_absolute_index_set_hash(
            &self.utxo.hash(),
            &self.sender_randomness,
            &self.spending_key.receiver_preimage(),
            self.aocl_index,
        )
    }
}

/// Indexed entries a scan skipped instead of failing for the whole range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Entries without a block height, or whose ciphertext is larger than the
    /// size limit or not a list of field elements.
    pub malformed: usize,
    /// Entries this key could not decrypt.
    pub undecryptable: usize,
    /// Decrypted UTXOs locked to a lock script this key cannot satisfy.
    pub foreign_lock: usize,
    /// UTXOs at a legacy-format dCTIDH lock confirmed at or above the legacy
    /// cutoff height, see [super::wallet::legacy_dctidh_cutoff].
    pub legacy_after_cutoff: usize,
}

impl ScanStats {
    /// Total number of skipped entries.
    pub fn total(&self) -> usize {
        self.malformed + self.undecryptable + self.foreign_lock + self.legacy_after_cutoff
    }
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
///
/// Malformed entries are skipped, see [fetch_utxos_with_skipped].
pub fn fetch_utxos(
    client: &RpcClient,
    receiver_id_hash: &Digest,
    from_height: u64,
    to_height: u64,
) -> Result<Vec<IndexedUtxo>> {
    fetch_utxos_with_skipped(client, receiver_id_hash, from_height, to_height)
        .map(|(utxos, _skipped)| utxos)
}

/// Fetch UTXOs from indexer by receiver_id_hash, and count the entries that
/// were skipped instead of failing the whole range: entries without a block
/// height, or whose ciphertext is larger than the size limit or not a list of
/// field elements.
///
/// Both heights are inclusive. A range of more than 10,000 blocks, which the
/// indexer refuses, is fetched in parts.
pub fn fetch_utxos_with_skipped(
    client: &RpcClient,
    receiver_id_hash: &Digest,
    from_height: u64,
    to_height: u64,
) -> Result<(Vec<IndexedUtxo>, usize)> {
    fetch_indexed(client, receiver_id_hash, from_height, to_height)
        .map(|entries| (entries.encrypted, entries.skipped))
}

/// Fetch the bridge payouts of `from_height..=to_height` from the indexer by
/// receiver_id_hash, see [PublicIndexedUtxo].
pub fn fetch_public_utxos(
    client: &RpcClient,
    receiver_id_hash: &Digest,
    from_height: u64,
    to_height: u64,
) -> Result<Vec<PublicIndexedUtxo>> {
    fetch_indexed(client, receiver_id_hash, from_height, to_height).map(|entries| entries.public)
}

fn fetch_indexed(
    client: &RpcClient,
    receiver_id_hash: &Digest,
    from_height: u64,
    to_height: u64,
) -> Result<IndexedEntries> {
    fetch_in_block_ranges(from_height, to_height, |from, to| {
        let params = json!({
            "receiverIdHash": receiver_id_hash.to_hex(),
            "fromBlockHeight": from,
            "toBlockHeight": to
        });

        let result = client.call("archival_getUtxosByReceiver", params)?;
        parse_indexed_utxos(&result)
    })
}

/// Largest block range the indexer serves in one `archival_getUtxosByReceiver`
/// request: `toBlockHeight - fromBlockHeight` must not exceed it, else it
/// answers with the error `{"BlockRangeExceedsLimit":10000}`.
pub(crate) const MAX_BLOCK_RANGE_PER_REQUEST: u64 = 10_000;

/// The inclusive block ranges, each within [MAX_BLOCK_RANGE_PER_REQUEST], that
/// together cover `from_height..=to_height`. A range that ends below its start
/// is passed on as it is.
fn block_ranges(from_height: u64, to_height: u64) -> Vec<(u64, u64)> {
    if to_height <= from_height {
        return vec![(from_height, to_height)];
    }

    let mut ranges = Vec::new();
    let mut from = from_height;
    loop {
        let to = from.saturating_add(MAX_BLOCK_RANGE_PER_REQUEST).min(to_height);
        ranges.push((from, to));
        if to == to_height {
            return ranges;
        }
        from = to + 1;
    }
}

/// Fetch the indexed UTXOs of `from_height..=to_height` with `fetch`, one
/// request per range of [block_ranges], and merge the results and the numbers
/// of skipped entries.
fn fetch_in_block_ranges(
    from_height: u64,
    to_height: u64,
    mut fetch: impl FnMut(u64, u64) -> Result<IndexedEntries>,
) -> Result<IndexedEntries> {
    let mut entries = IndexedEntries::default();
    for (from, to) in block_ranges(from_height, to_height) {
        let range = fetch(from, to)?;
        entries.encrypted.extend(range.encrypted);
        entries.public.extend(range.public);
        entries.skipped += range.skipped;
    }
    Ok(entries)
}

/// The entries of one or more `archival_getUtxosByReceiver` results.
#[derive(Default)]
struct IndexedEntries {
    encrypted: Vec<IndexedUtxo>,
    public: Vec<PublicIndexedUtxo>,
    skipped: usize,
}

/// Parse an `archival_getUtxosByReceiver` result, skipping and counting
/// malformed entries.
fn parse_indexed_utxos(result: &Value) -> Result<IndexedEntries> {
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
    let mut public = Vec::new();
    let mut skipped = 0;

    for utxo in utxos {
        if utxo.get("type").and_then(|v| v.as_str()) == Some("public") {
            match public_utxo_from_json(utxo) {
                Some(payout) => public.push(payout),
                None => skipped += 1,
            }
            continue;
        }

        let Some(block_height) = utxo.get("blockHeight").and_then(|v| v.as_u64()) else {
            skipped += 1;
            continue;
        };
        let block_digest = utxo
            .get("blockDigest")
            .and_then(|v| v.as_str())
            .and_then(Digest::from_hex)
            .unwrap_or_default();

        let Some(ciphertext) = utxo.get("ciphertext").and_then(ciphertext_from_json) else {
            skipped += 1;
            continue;
        };

        indexed_utxos.push(IndexedUtxo {
            block_height,
            block_digest,
            ciphertext,
        });
    }

    Ok(IndexedEntries {
        encrypted: indexed_utxos,
        public,
        skipped,
    })
}

fn public_utxo_from_json(value: &Value) -> Option<PublicIndexedUtxo> {
    use neptune_privacy::application::json_rpc::core::model::message::RpcIndexedUtxo;
    use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

    let RpcIndexedUtxo::Public {
        block_height,
        block_digest,
        lock_script_hash,
        amount_nau,
        sender_randomness,
        ..
    } = serde_json::from_value(value.clone()).ok()?
    else {
        return None;
    };
    Some(PublicIndexedUtxo {
        block_height: block_height.into(),
        block_digest: Digest::from_core(block_digest),
        lock_script_hash: Digest::from_core(lock_script_hash),
        amount_nau: NativeCurrencyAmount::from(amount_nau).to_nau(),
        sender_randomness: Digest::from_core(sender_randomness),
    })
}

/// Ciphertext of an indexed entry as little-endian u64s, or `None` if it is
/// not a list of canonical field elements or larger than
/// [MAX_UTXO_CIPHERTEXT_SIZE].
fn ciphertext_from_json(value: &Value) -> Option<Vec<u8>> {
    use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;

    let arr = value.as_array()?;
    if arr.is_empty() || arr.len() * 8 > MAX_UTXO_CIPHERTEXT_SIZE {
        return None;
    }

    let mut ciphertext = Vec::with_capacity(arr.len() * 8);
    for v in arr {
        let word = v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .filter(|&word| word < BFieldElement::P)?;
        ciphertext.extend_from_slice(&word.to_le_bytes());
    }
    Some(ciphertext)
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

/// One AOCL leaf of a commitment, see [get_aocl_leaves].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AoclLeaf {
    pub aocl_leaf_index: u64,
    pub block_height: u64,
    pub block_digest: Digest,
}

/// Every AOCL leaf of each commitment, in canonical blocks. Identical outputs (same UTXO, sender
/// randomness and receiver) share one commitment; each of its leaves is spendable once.
pub fn get_aocl_leaves(client: &RpcClient, commitments: &[Digest]) -> Result<Vec<Vec<AoclLeaf>>> {
    let commitment_vec: Vec<String> = commitments.iter().map(|d| d.to_hex()).collect();
    let params = json!({ "commitments": commitment_vec });

    let result = client.call("archival_getAoclLeafIndices", params)?;

    let leaves = result
        .get("leaves")
        .and_then(|v| v.as_array())
        .ok_or_else(|| XntError::RpcError("missing leaves: the node predates them".to_string()))?;

    leaves
        .iter()
        .map(|per_commitment| {
            per_commitment
                .as_array()
                .and_then(|leaves| leaves.iter().map(aocl_leaf_from_json).collect())
                .ok_or_else(|| XntError::RpcError("malformed AOCL leaves".to_string()))
        })
        .collect()
}

fn aocl_leaf_from_json(leaf: &Value) -> Option<AoclLeaf> {
    Some(AoclLeaf {
        aocl_leaf_index: leaf.get("aoclLeafIndex")?.as_u64()?,
        block_height: leaf.get("blockHeight")?.as_u64()?,
        block_digest: leaf
            .get("blockDigest")?
            .as_str()
            .and_then(Digest::from_hex)?,
    })
}

/// One entry per AOCL leaf of each distinct commitment. Identical outputs share a commitment and
/// their notifications decrypt alike, so the items of a commitment after the first are dropped.
pub fn expand_per_leaf<T: Clone>(
    items: Vec<T>,
    commitments: &[Digest],
    leaves: Vec<Vec<AoclLeaf>>,
) -> Result<Vec<(T, AoclLeaf)>> {
    if items.len() != commitments.len() || leaves.len() != commitments.len() {
        return Err(XntError::RpcError(
            "AOCL leaves length mismatch".to_string(),
        ));
    }

    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for ((item, commitment), leaves) in items.into_iter().zip(commitments).zip(leaves) {
        if seen.insert(commitment.bytes) {
            entries.extend(leaves.into_iter().map(|leaf| (item.clone(), leaf)));
        }
    }
    Ok(entries)
}

/// Collect spendable inputs (UTXOs + membership proofs) for a single spending key.
///
/// Applies the main-net legacy cutoff, the strictest one; use
/// [collect_spendable_inputs] to apply the rule of another network and to get
/// the number of skipped entries.
pub fn collect_spendable_inputs_for_key(
    client: &RpcClient,
    key: &SpendingKey,
    from_height: u64,
    to_height: u64,
) -> Result<Vec<SpendableInput>> {
    collect_spendable_inputs(client, key, Network::Main, from_height, to_height)
        .map(|(inputs, _skipped)| inputs)
}

/// Collect spendable inputs (UTXOs + membership proofs) for a single spending key.
///
/// This will:
/// - fetch UTXOs by receiver_id_hash
/// - decrypt them using the provided key
/// - compute commitments and AOCL indices
/// - filter out spent UTXOs
/// - restore membership proofs for the remaining ones
///
/// Indexed entries that are malformed, cannot be decrypted, are locked to a
/// foreign lock script, or are at a legacy-format dCTIDH lock confirmed at or
/// above the legacy cutoff of `network` are skipped and counted in the
/// returned [ScanStats] instead of failing the whole range. Inputs at a
/// legacy-format lock below the cutoff are returned with
/// [SpendableInput::is_legacy] set: they are sweep-only.
pub fn collect_spendable_inputs(
    client: &RpcClient,
    key: &SpendingKey,
    network: Network,
    from_height: u64,
    to_height: u64,
) -> Result<(Vec<SpendableInput>, ScanStats)> {
    // Derive receiver_id_hash and receiver_preimage from SDK key
    let rid_hash = key.receiver_id_hash();
    let receiver_preimage = key.receiver_preimage();

    // Fetch indexed UTXOs from archival node
    let entries = fetch_indexed(client, &rid_hash, from_height, to_height)?;
    let mut stats = ScanStats {
        malformed: entries.skipped,
        ..ScanStats::default()
    };

    let mut utxos = decrypt_indexed_utxos(key, network, entries.encrypted, &mut stats);
    utxos.extend(own_public_utxos(key, network, entries.public, &mut stats));
    if utxos.is_empty() {
        return Ok((Vec::new(), stats));
    }

    // Compute commitments and fetch AOCL leaves
    let commits: Vec<Digest> = utxos
        .iter()
        .map(|(u, sr, _, _, _, _)| compute_commitment(&u.hash(), sr, &receiver_preimage))
        .collect();

    // A leaf outside the range is another scan's: each identical payment has its own notification.
    let leaves = get_aocl_leaves(client, &commits)?
        .into_iter()
        .map(|leaves| {
            leaves
                .into_iter()
                .filter(|leaf| (from_height..=to_height).contains(&leaf.block_height))
                .collect()
        })
        .collect();
    let entries = expand_per_leaf(utxos, &commits, leaves)?;
    if entries.is_empty() {
        return Ok((Vec::new(), stats));
    }

    // Build AbsoluteIndexSet hashes and check spent status
    let abs_hashes: Vec<Digest> = entries
        .iter()
        .map(|((u, sr, _, _, _, _), leaf)| {
            compute_absolute_index_set_hash(&u.hash(), sr, &receiver_preimage, leaf.aocl_leaf_index)
        })
        .collect();

    let spent = check_spent(client, &abs_hashes)?;
    if spent.len() != entries.len() {
        return Err(XntError::RpcError(
            "spent status length mismatch".to_string(),
        ));
    }

    // Filter to unspent
    let unspent: Vec<_> = entries
        .into_iter()
        .zip(spent)
        .filter(|(_, spent_at)| *spent_at < 0)
        .map(|(entry, _)| entry)
        .collect();

    if unspent.is_empty() {
        return Ok((Vec::new(), stats));
    }

    // Restore membership proofs for unspent UTXOs
    use neptune_privacy::application::json_rpc::core::model::wallet::mutator_set::RpcMsMembershipProofPrivacyPreserving;

    let absolute_index_sets: Vec<AbsoluteIndexSet> = unspent
        .iter()
        .map(|((u, sr, _, _, _, _), leaf)| {
            AbsoluteIndexSet::compute(
                u.hash().to_core(),
                sr.to_core(),
                receiver_preimage.to_core(),
                leaf.aocl_leaf_index,
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

    if proofs_arr.len() != unspent.len() {
        return Err(XntError::RpcError(
            "membershipProofs length mismatch".to_string(),
        ));
    }

    let mut res = Vec::with_capacity(unspent.len());
    for (idx, (proof_val, ((u, sr, amount, _, _, payment_id), leaf))) in
        proofs_arr.iter().zip(unspent).enumerate()
    {
        let rpc_proof: RpcMsMembershipProofPrivacyPreserving =
            serde_json::from_value(proof_val.clone())
                .map_err(|e| XntError::RpcError(format!("parse proof {idx} failed: {e}")))?;

        let aocl_idx = leaf.aocl_leaf_index;
        let msmp = rpc_proof
            .extract_ms_membership_proof(aocl_idx, sr.to_core(), receiver_preimage.to_core())
            .ok_or_else(|| {
                XntError::RpcError(format!("extract proof {idx} failed for aocl index {aocl_idx}"))
            })?;

        res.push(SpendableInput {
            utxo: u,
            spending_key: key.clone(),
            membership_proof: MembershipProof::from_core(msmp),
            sender_randomness: sr,
            aocl_index: aocl_idx,
            amount,
            block_height: leaf.block_height,
            block_digest: leaf.block_digest,
            is_legacy: key.is_legacy(),
            payment_id,
        });
    }

    Ok((res, stats))
}

/// The bridge payouts this key can spend, as [decrypt_indexed_utxos] returns
/// them, with the same lock-script and legacy-cutoff checks.
fn own_public_utxos(
    key: &SpendingKey,
    network: Network,
    public: Vec<PublicIndexedUtxo>,
    stats: &mut ScanStats,
) -> Vec<(Utxo, Digest, i128, u64, Digest, u64)> {
    use neptune_privacy::protocol::consensus::transaction::utxo::Utxo as CoreUtxo;
    use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

    let own_lock_script_hash = key.lock_script_hash();
    let mut utxos = Vec::new();
    for payout in public {
        if payout.lock_script_hash != own_lock_script_hash {
            stats.foreign_lock += 1;
            continue;
        }
        if !key.recognizes_utxos_at(network, payout.block_height) {
            stats.legacy_after_cutoff += 1;
            continue;
        }
        let utxo = Utxo::from_core(CoreUtxo::new_native_currency(
            payout.lock_script_hash.to_core(),
            NativeCurrencyAmount::from_nau(payout.amount_nau),
        ));
        utxos.push((
            utxo,
            payout.sender_randomness,
            payout.amount_nau,
            payout.block_height,
            payout.block_digest,
            0,
        ));
    }
    utxos
}

/// Decrypt indexed entries with `key`, skipping and counting in `stats` the
/// entries that cannot be decrypted, are locked to a foreign lock script, or
/// are at a legacy-format lock not recognized at their height on `network`.
///
/// Returns (utxo, sender randomness, amount, block height, block digest,
/// payment id).
fn decrypt_indexed_utxos(
    key: &SpendingKey,
    network: Network,
    indexed: Vec<IndexedUtxo>,
    stats: &mut ScanStats,
) -> Vec<(Utxo, Digest, i128, u64, Digest, u64)> {
    use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;

    let own_lock_script_hash = key.lock_script_hash();
    let mut utxos = Vec::new();
    for idx in indexed {
        // ciphertext_bfes are encoded little-endian u64s; convert back to BFieldElements
        let bfes: Vec<BFieldElement> = idx
            .ciphertext
            .chunks(8)
            .map(|chunk| {
                let mut arr = [0u8; 8];
                arr[..chunk.len()].copy_from_slice(chunk);
                BFieldElement::new(u64::from_le_bytes(arr))
            })
            .collect();

        let Ok((core_utxo, sr, payment_id)) = key.inner.decrypt(&bfes) else {
            stats.undecryptable += 1;
            continue;
        };
        let utxo = Utxo::from_core(core_utxo);

        // A third party can craft an announcement that decrypts under
        // this key but whose UTXO is locked by a foreign script; counting
        // it would inflate the balance with unspendable funds.
        if utxo.lock_script_hash() != own_lock_script_hash {
            stats.foreign_lock += 1;
            continue;
        }

        if !key.recognizes_utxos_at(network, idx.block_height) {
            stats.legacy_after_cutoff += 1;
            continue;
        }

        let amount = utxo.amount();
        utxos.push((
            utxo,
            Digest::from_core(sr),
            amount,
            idx.block_height,
            idx.block_digest,
            payment_id.value(),
        ));
    }
    utxos
}

/// Get current mutator set from archival node, with the height of the tip it
/// belongs to, see [MutatorSet::tip_height].
///
/// The node does not report that height with the mutator set, so it is read
/// before and after; if a block arrives in between, the mutator set is
/// fetched again, up to 3 times.
pub fn get_mutator_set(client: &RpcClient) -> Result<MutatorSet> {
    use neptune_privacy::application::json_rpc::core::model::block::body::RpcMutatorSetAccumulator;

    let (inner, tip_height) = fetch_at_one_tip_height(
        || client.chain_height(),
        || {
            let result = client.call("archival_getArchivalMutatorSet", json!([]))?;

            let msa_obj = result
                .get("archivalMutatorSet")
                .ok_or_else(|| XntError::RpcError("missing archivalMutatorSet".to_string()))?;

            let rpc_msa: RpcMutatorSetAccumulator = serde_json::from_value(msa_obj.clone())
                .map_err(|e| XntError::RpcError(format!("parse mutator set failed: {e}")))?;
            Ok(MutatorSetAccumulator::from(rpc_msa))
        },
    )?;

    Ok(MutatorSet::from_core(inner).with_tip_height(tip_height))
}

/// Number of times [get_mutator_set] fetches the mutator set at most, while
/// blocks arrive in between.
pub(crate) const MUTATOR_SET_FETCH_ATTEMPTS: usize = 3;

/// Fetch with `fetch` while the tip height that `tip_height` reads is the same
/// before and after, and return the result with that height. Fails after
/// [MUTATOR_SET_FETCH_ATTEMPTS] attempts at different heights.
fn fetch_at_one_tip_height<T>(
    mut tip_height: impl FnMut() -> Result<u64>,
    mut fetch: impl FnMut() -> Result<T>,
) -> Result<(T, u64)> {
    for _ in 0..MUTATOR_SET_FETCH_ATTEMPTS {
        let before = tip_height()?;
        let fetched = fetch()?;
        let after = tip_height()?;
        if before == after {
            return Ok((fetched, after));
        }
    }

    Err(XntError::RpcError(format!(
        "the tip changed while fetching the mutator set, {MUTATOR_SET_FETCH_ATTEMPTS} times"
    )))
}

/// Get membership proofs via wallet RPC
///
/// `receiver_preimage` is a spending secret for dCTIDH keys, see
/// [SpendingKey::receiver_preimage]. It is used locally and not sent to the
/// node.
pub fn get_membership_proofs(
    client: &RpcClient,
    utxo_hashes: &[Digest],
    sender_randomnesses: &[Digest],
    receiver_preimage: &Digest,
    aocl_indices: &[u64],
) -> Result<Vec<MembershipProof>> {
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

    membership_proofs_from_response(
        &result,
        sender_randomnesses,
        receiver_preimage,
        aocl_indices,
    )
}

/// Parse an `archival_restoreMembershipProof` result for the requested
/// UTXOs. Fails unless it holds exactly one proof per requested UTXO.
fn membership_proofs_from_response(
    result: &Value,
    sender_randomnesses: &[Digest],
    receiver_preimage: &Digest,
    aocl_indices: &[u64],
) -> Result<Vec<MembershipProof>> {
    use neptune_privacy::application::json_rpc::core::model::wallet::mutator_set::RpcMsMembershipProofPrivacyPreserving;

    // Parse response
    let snapshot = result
        .get("snapshot")
        .ok_or_else(|| XntError::RpcError("missing snapshot".to_string()))?;

    let proofs_arr = snapshot
        .get("membershipProofs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| XntError::RpcError("missing membershipProofs".to_string()))?;

    if proofs_arr.len() != aocl_indices.len() || proofs_arr.len() != sender_randomnesses.len() {
        return Err(XntError::RpcError(format!(
            "membershipProofs length mismatch: {} proofs for {} requested",
            proofs_arr.len(),
            aocl_indices.len()
        )));
    }

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
///
/// Applies the main-net legacy cutoff, the strictest one; use
/// [decrypt_indexed_utxo_for_network] to apply the rule of another network.
pub fn decrypt_indexed_utxo(
    spending_key: &SpendingKey,
    ciphertext_bytes: &[u8],
    block_height: u64,
    block_digest: Digest,
) -> Result<super::utxo::DecryptedUtxo> {
    decrypt_indexed_utxo_for_network(
        spending_key,
        ciphertext_bytes,
        block_height,
        block_digest,
        Network::Main,
    )
}

/// Decrypt indexed UTXO ciphertext confirmed in the block at `block_height`.
///
/// Fails for a UTXO at a legacy-format dCTIDH lock confirmed at or above the
/// legacy cutoff of `network` (see [super::wallet::legacy_dctidh_cutoff]).
/// A UTXO at a legacy-format lock below the cutoff is returned with
/// [super::utxo::DecryptedUtxo::is_legacy] set: it is sweep-only.
pub fn decrypt_indexed_utxo_for_network(
    spending_key: &SpendingKey,
    ciphertext_bytes: &[u8],
    block_height: u64,
    block_digest: Digest,
    network: Network,
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

    let utxo = Utxo::from_core(utxo);
    if utxo.lock_script_hash() != spending_key.lock_script_hash() {
        return Err(XntError::CryptoError(
            "announced UTXO is not spendable by this key (foreign lock script)".to_string(),
        ));
    }

    if !spending_key.recognizes_utxos_at(network, block_height) {
        return Err(XntError::CryptoError(format!(
            "UTXO at a legacy-format dCTIDH lock confirmed at height {block_height} is not \
             recognized: such UTXOs are recognized only below the legacy cutoff height"
        )));
    }

    Ok(super::utxo::DecryptedUtxo {
        utxo,
        sender_randomness: Digest::from_core(sender_randomness),
        payment_id: payment_id.value(),
        block_height,
        block_digest,
        is_legacy: spending_key.is_legacy(),
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
        Ok((utxo, sender_randomness, payment_id)) => {
            let utxo = Utxo::from_core(utxo);

            // Ignore announced UTXOs this key cannot spend; they must not
            // show up as pending incoming funds.
            if utxo.lock_script_hash() != spending_key.lock_script_hash() {
                return Ok(None);
            }

            Ok(Some((
                utxo,
                Digest::from_core(sender_randomness),
                payment_id.value(),
            )))
        }
        Err(_) => Ok(None),
    }
}

/// Check mempool for pending incoming UTXOs
/// Returns list of (utxo, sender_randomness, payment_id) for pending incoming
///
/// For a legacy key nothing is returned once the next block is at or above
/// the main-net legacy cutoff, see [super::wallet::legacy_dctidh_cutoff].
pub fn mempool_incoming(
    client: &RpcClient,
    spending_key: &SpendingKey,
) -> Result<Vec<(Utxo, Digest, u64)>> {
    if spending_key.is_legacy() {
        let next_height = client.chain_height()?.saturating_add(1);
        if !spending_key.recognizes_utxos_at(Network::Main, next_height) {
            return Ok(Vec::new());
        }
    }

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

#[cfg(test)]
mod tests {
    use neptune_privacy::api::export::NativeCurrencyAmount;
    use neptune_privacy::api::export::TxOutput;
    use neptune_privacy::prelude::tasm_lib::prelude::Digest as CoreDigest;
    use neptune_privacy::prelude::twenty_first::prelude::BFieldElement;
    use neptune_privacy::state::wallet::address::ciphertext_from_announcement;

    use super::*;
    use crate::core::wallet::WalletEntropy;

    /// Ciphertext of an on-chain notification of `amount` coins to `key`'s
    /// receiving address, as the indexer returns it.
    fn ciphertext_to(key: &SpendingKey, amount: u32) -> Vec<u64> {
        ciphertext_to_address(key.to_address().unwrap().inner, amount)
    }

    /// Ciphertext of an on-chain notification of `amount` coins to `address`,
    /// as the indexer returns it.
    fn ciphertext_to_address(
        address: neptune_privacy::state::wallet::address::ReceivingAddress,
        amount: u32,
    ) -> Vec<u64> {
        let tx_output = TxOutput::onchain_native_currency(
            NativeCurrencyAmount::coins(amount),
            rand::random::<CoreDigest>(),
            address,
            false,
        );
        let announcement = tx_output.announcement().unwrap();
        ciphertext_from_announcement(&announcement)
            .unwrap()
            .iter()
            .map(|bfe| bfe.value())
            .collect()
    }

    fn indexed(block_height: u64, ciphertext: &[u64]) -> IndexedUtxo {
        IndexedUtxo {
            block_height,
            block_digest: Digest::new(),
            ciphertext: ciphertext.iter().flat_map(|w| w.to_le_bytes()).collect(),
        }
    }

    /// Two identical payments decrypt alike and share a commitment with two leaves: one entry per
    /// leaf, not per notification and leaf.
    #[test]
    fn identical_payments_expand_to_one_entry_per_leaf() {
        let digest = |byte: u8| Digest::from_bytes([byte; 40]);
        let leaf = |aocl_leaf_index: u64, block_height: u64| AoclLeaf {
            aocl_leaf_index,
            block_height,
            block_digest: digest(block_height as u8),
        };
        let shared = digest(1);
        let other = digest(2);
        let shared_leaves = vec![leaf(100, 286), leaf(105, 287)];
        let other_leaves = vec![leaf(107, 287)];

        let entries = expand_per_leaf(
            vec!["payment", "payment again", "other"],
            &[shared, shared, other],
            vec![shared_leaves.clone(), shared_leaves, other_leaves.clone()],
        )
        .unwrap();

        assert_eq!(
            vec![
                ("payment", leaf(100, 286)),
                ("payment", leaf(105, 287)),
                ("other", leaf(107, 287)),
            ],
            entries
        );
        assert!(expand_per_leaf(vec!["other"], &[other], vec![]).is_err());
    }

    #[test]
    fn block_ranges_cover_the_range_within_the_indexer_limit() {
        const LIMIT: u64 = MAX_BLOCK_RANGE_PER_REQUEST;
        assert_eq!(10_000, LIMIT);

        // Within the limit, as the indexer takes it: one request.
        assert_eq!(vec![(0, LIMIT)], block_ranges(0, LIMIT));
        assert_eq!(vec![(5, 5)], block_ranges(5, 5));
        assert_eq!(vec![(9, 3)], block_ranges(9, 3));

        assert_eq!(vec![(0, LIMIT), (LIMIT + 1, LIMIT + 1)], block_ranges(0, LIMIT + 1));
        assert_eq!(
            vec![(100, 10_100), (10_101, 20_101), (20_102, 25_000)],
            block_ranges(100, 25_000)
        );
        assert_eq!(vec![(u64::MAX - 1, u64::MAX)], block_ranges(u64::MAX - 1, u64::MAX));

        // Main net from genesis to the tip: contiguous, without overlaps,
        // each part within the limit.
        let ranges = block_ranges(0, 94_072);
        assert_eq!(10, ranges.len());
        assert_eq!(0, ranges[0].0);
        assert_eq!(94_072, ranges.last().unwrap().1);
        for (from, to) in &ranges {
            assert!(to - from <= LIMIT);
        }
        for pair in ranges.windows(2) {
            assert_eq!(pair[0].1 + 1, pair[1].0);
        }
    }

    #[test]
    fn utxos_of_a_long_range_are_fetched_in_parts_and_merged() {
        let mut requests = Vec::new();
        let IndexedEntries {
            encrypted: utxos,
            skipped,
            ..
        } = fetch_in_block_ranges(0, 25_000, |from, to| {
            requests.push((from, to));
            Ok(IndexedEntries {
                encrypted: vec![indexed(from, &[1]), indexed(to, &[2])],
                public: vec![],
                skipped: 1,
            })
        })
        .unwrap();

        assert_eq!(vec![(0, 10_000), (10_001, 20_001), (20_002, 25_000)], requests);
        assert_eq!(
            vec![0, 10_000, 10_001, 20_001, 20_002, 25_000],
            utxos.iter().map(|utxo| utxo.block_height).collect::<Vec<_>>()
        );
        assert_eq!(3, skipped);

        // A failing part fails the whole range.
        let result = fetch_in_block_ranges(0, 25_000, |from, _to| {
            if from > 0 {
                Err(XntError::RpcError("BlockRangeExceedsLimit".to_string()))
            } else {
                Ok(IndexedEntries::default())
            }
        });
        assert!(result.is_err());
    }

    #[test]
    fn the_mutator_set_is_fetched_again_while_the_tip_changes() {
        // The tip moves on between the first two readings, then stays.
        let heights = std::cell::RefCell::new(vec![100, 101, 101, 101].into_iter());
        let mut fetches = 0;
        let (fetched, tip_height) = fetch_at_one_tip_height(
            || Ok(heights.borrow_mut().next().unwrap()),
            || {
                fetches += 1;
                Ok(fetches)
            },
        )
        .unwrap();
        assert_eq!((2, 101), (fetched, tip_height));

        // The tip moves on at every attempt.
        let height = std::cell::Cell::new(0);
        let result = fetch_at_one_tip_height(
            || {
                height.set(height.get() + 1);
                Ok(height.get())
            },
            || Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(2 * MUTATOR_SET_FETCH_ATTEMPTS as u64, height.get());
    }

    #[test]
    fn the_tip_height_is_kept_but_not_serialized() {
        let mutator_set = MutatorSet::from_core(Default::default());
        assert_eq!(None, mutator_set.tip_height());
        let mutator_set = mutator_set.with_tip_height(94_000);
        assert_eq!(Some(94_000), mutator_set.tip_height());

        let bytes = mutator_set.to_bytes().unwrap();
        assert_eq!(bincode::serialize(&mutator_set.inner).unwrap(), bytes);
        let restored = MutatorSet::from_bytes(&bytes).unwrap();
        assert_eq!(None, restored.tip_height());
        assert_eq!(Some(7), restored.with_tip_height(7).tip_height());
    }

    #[test]
    fn malformed_indexed_entries_are_skipped_and_counted() {
        let good = json!({ "blockHeight": 7, "blockDigest": "00", "ciphertext": [1, "2", 3] });
        let oversized = vec![1u64; MAX_UTXO_CIPHERTEXT_SIZE / 8 + 1];
        let result = json!({ "utxos": [
            good,
            { "blockHeight": 8, "ciphertext": oversized },
            { "blockHeight": 9, "ciphertext": [1, BFieldElement::P] },
            { "blockHeight": 10, "ciphertext": [1, "x"] },
            { "blockHeight": 11, "ciphertext": [] },
            { "blockHeight": 12 },
            { "ciphertext": [1, 2] },
            good,
        ]});

        let IndexedEntries {
            encrypted: utxos,
            skipped,
            ..
        } = parse_indexed_utxos(&result).unwrap();
        assert_eq!(6, skipped);
        assert_eq!(2, utxos.len());
        for utxo in utxos {
            assert_eq!(7, utxo.block_height);
            assert_eq!(
                [1u64, 2, 3]
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect::<Vec<_>>(),
                utxo.ciphertext
            );
        }
    }

    #[test]
    fn undecryptable_and_foreign_lock_entries_are_skipped_and_counted() {
        let wallet = WalletEntropy::generate().unwrap();
        let current = wallet.derive_dctidh_spending_key(0);
        let legacy = wallet.derive_legacy_dctidh_spending_key(0);
        let ciphertext = ciphertext_to(&current, 5);
        let entries = || {
            vec![
                indexed(3, &ciphertext),
                indexed(4, &[1, 2, 3, 4, 5]),
                indexed(5, &ciphertext),
            ]
        };

        let mut stats = ScanStats::default();
        let utxos = decrypt_indexed_utxos(&current, Network::Main, entries(), &mut stats);
        assert_eq!(2, utxos.len());
        assert_eq!(
            ScanStats {
                undecryptable: 1,
                ..ScanStats::default()
            },
            stats
        );

        // The legacy key has its own decryption key, so it decrypts none of them
        let mut stats = ScanStats::default();
        let utxos = decrypt_indexed_utxos(&legacy, Network::Main, entries(), &mut stats);
        assert!(utxos.is_empty());
        assert_eq!(
            ScanStats {
                undecryptable: 3,
                ..ScanStats::default()
            },
            stats
        );
        assert_eq!(3, stats.total());
    }

    /// A bridge payout, as the node's indexer serializes it, is parsed apart
    /// from the encrypted entries and credited only to the key it is locked to.
    #[test]
    fn public_payouts_are_parsed_and_credited_to_their_lock() {
        use neptune_privacy::application::json_rpc::core::model::message::RpcIndexedUtxo;

        let wallet = WalletEntropy::generate().unwrap();
        let key = wallet.derive_spending_key(0);
        let other = wallet.derive_spending_key(1);
        let amount = NativeCurrencyAmount::coins(3);
        let payout = |lock: &SpendingKey| {
            serde_json::to_value(RpcIndexedUtxo::Public {
                block_height: 9u64.into(),
                block_digest: CoreDigest::default(),
                receiver_digest: CoreDigest::default(),
                lock_script_hash: lock.lock_script_hash().to_core(),
                amount_nau: amount.into(),
                sender_randomness: CoreDigest::default(),
            })
            .unwrap()
        };
        let result = json!({ "utxos": [payout(&key), payout(&other), { "type": "public" }] });

        let entries = parse_indexed_utxos(&result).unwrap();
        assert!(entries.encrypted.is_empty());
        assert_eq!(1, entries.skipped);
        assert_eq!(2, entries.public.len());
        assert_eq!(amount.to_nau(), entries.public[0].amount_nau);
        assert_eq!(9, entries.public[0].block_height);

        let mut stats = ScanStats::default();
        let utxos = own_public_utxos(&key, Network::Main, entries.public, &mut stats);
        assert_eq!(1, utxos.len());
        assert_eq!(key.lock_script_hash(), utxos[0].0.lock_script_hash());
        assert_eq!(amount.to_nau(), utxos[0].2);
        assert_eq!(
            ScanStats {
                foreign_lock: 1,
                ..ScanStats::default()
            },
            stats
        );
    }

    #[test]
    fn decrypted_entries_carry_the_payment_id_of_their_notification() {
        let wallet = WalletEntropy::generate().unwrap();
        let key = wallet.derive_dctidh_spending_key(0);
        let address = key.to_address().unwrap();
        let entries = vec![
            indexed(3, &ciphertext_to(&key, 1)),
            indexed(4, &ciphertext_to_address(address.dctidh_subaddress(7).unwrap().inner, 2)),
            indexed(5, &ciphertext_to_address(address.dctidh_subaddress(42).unwrap().inner, 3)),
        ];

        let mut stats = ScanStats::default();
        let utxos = decrypt_indexed_utxos(&key, Network::Main, entries, &mut stats);
        assert_eq!(0, stats.total());
        assert_eq!(
            vec![(3, 0), (4, 7), (5, 42)],
            utxos
                .iter()
                .map(|(_, _, _, block_height, _, payment_id)| (*block_height, *payment_id))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![
                NativeCurrencyAmount::coins(1).to_nau(),
                NativeCurrencyAmount::coins(2).to_nau(),
                NativeCurrencyAmount::coins(3).to_nau()
            ],
            utxos.iter().map(|(_, _, amount, _, _, _)| *amount).collect::<Vec<_>>()
        );
    }

    #[test]
    fn decrypted_utxo_reports_its_lock_and_legacy_flag() {
        let wallet = WalletEntropy::generate().unwrap();
        let key = wallet.derive_dctidh_spending_key(0);
        let bytes: Vec<u8> = ciphertext_to(&key, 2)
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();

        let decrypted =
            decrypt_indexed_utxo_for_network(&key, &bytes, u64::MAX, Digest::new(), Network::Main)
                .unwrap();
        assert!(!decrypted.is_legacy);
        assert_eq!(key.lock_script_hash(), decrypted.utxo.lock_script_hash());

        let legacy = wallet.derive_legacy_dctidh_spending_key(0);
        assert!(decrypt_indexed_utxo(&legacy, &bytes, 1, Digest::new()).is_err());
    }

    #[test]
    fn membership_proof_response_must_match_the_request() {
        let response = json!({ "snapshot": { "membershipProofs": [] } });
        let err =
            membership_proofs_from_response(&response, &[Digest::new()], &Digest::new(), &[0])
                .err()
                .unwrap();
        assert!(err.to_string().contains("length mismatch"), "{err}");

        let empty = membership_proofs_from_response(&response, &[], &Digest::new(), &[]);
        assert!(empty.unwrap().is_empty());
    }
}
