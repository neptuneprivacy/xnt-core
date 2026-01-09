//! NAPI bindings for xnt-core (Node.js native module)
//!
//! Automatic memory management via Node.js GC.
//! No manual *_free calls required.
//! Uses shared core module for business logic.

use napi::bindgen_prelude::*;
use napi::bindgen_prelude::BigInt;
use napi_derive::napi;

use crate::core::{
    Address, MembershipProof, MutatorSet, Network, ReceivingAddress, RpcClient, SpendingKey,
    SubAddress, TransactionBuilder, Utxo, WalletEntropy,
};

/// Network type for address encoding
#[napi]
pub enum XntNetwork {
    Main,
    TestnetMock,
    RegTest,
    Testnet,
}

impl From<XntNetwork> for Network {
    fn from(n: XntNetwork) -> Self {
        match n {
            XntNetwork::Main => Network::Main,
            XntNetwork::TestnetMock => Network::TestnetMock,
            XntNetwork::RegTest => Network::RegTest,
            XntNetwork::Testnet => Network::Testnet,
        }
    }
}

impl From<Network> for XntNetwork {
    fn from(n: Network) -> Self {
        match n {
            Network::Main => XntNetwork::Main,
            Network::TestnetMock => XntNetwork::TestnetMock,
            Network::RegTest => XntNetwork::RegTest,
            Network::Testnet => XntNetwork::Testnet,
        }
    }
}

// Wallet & Keys

/// Wallet entropy - root secret for key derivation
#[napi]
pub struct XntWalletEntropy {
    inner: WalletEntropy,
}

#[napi]
impl XntWalletEntropy {
    /// Create from BIP39 mnemonic phrase (space-separated words)
    #[napi(constructor)]
    pub fn new(mnemonic: String) -> Result<Self> {
        let entropy = WalletEntropy::from_mnemonic(&mnemonic)
            .map_err(|e| Error::from_reason(format!("invalid mnemonic: {e}")))?;
        Ok(Self { inner: entropy })
    }

    /// Generate new random mnemonic and wallet
    #[napi(factory)]
    pub fn generate() -> Result<Self> {
        let entropy =
            WalletEntropy::generate().map_err(|e| Error::from_reason(format!("{e}")))?;
        Ok(Self { inner: entropy })
    }

    /// Get devnet test wallet
    #[napi(factory)]
    pub fn devnet() -> Self {
        Self {
            inner: WalletEntropy::devnet(),
        }
    }

    /// Export wallet to mnemonic phrase
    #[napi]
    pub fn to_mnemonic(&self) -> String {
        self.inner.to_mnemonic()
    }

    /// Derive spending key at index
    #[napi]
    pub fn derive_key(&self, index: u32) -> XntSpendingKey {
        XntSpendingKey {
            inner: self.inner.derive_spending_key(index as u64),
        }
    }
}

/// Spending key for signing transactions
#[napi]
pub struct XntSpendingKey {
    inner: SpendingKey,
}

#[napi]
impl XntSpendingKey {
    /// Get receiving address from spending key
    #[napi]
    pub fn to_address(&self) -> XntAddress {
        XntAddress {
            inner: self.inner.to_address(),
        }
    }

    /// Get receiver identifier as u64
    #[napi]
    pub fn receiver_id(&self) -> i64 {
        self.inner.receiver_id() as i64
    }

    /// Get receiver identifier as hex string
    #[napi]
    pub fn receiver_id_hex(&self) -> String {
        self.inner.receiver_id_hex()
    }

    /// Get receiver_id_hash as hex string (for indexer lookups)
    #[napi]
    pub fn receiver_id_hash_hex(&self) -> String {
        hex::encode(self.inner.receiver_id_hash().bytes)
    }

    /// Get receiver_preimage as hex string (for commitment computation)
    #[napi]
    pub fn receiver_preimage_hex(&self) -> String {
        hex::encode(self.inner.receiver_preimage().bytes)
    }

    /// Get inner spending key (for internal use)
    pub(crate) fn inner(&self) -> &SpendingKey {
        &self.inner
    }
}

// Addresses

/// Receiving address for receiving funds
#[napi]
pub struct XntAddress {
    inner: Address,
}

#[napi]
impl XntAddress {
    /// Decode address from bech32m string
    #[napi(factory)]
    pub fn from_bech32(bech32: String, network: XntNetwork) -> Result<Self> {
        let addr = Address::from_bech32(&bech32, network.into())
            .map_err(|e| Error::from_reason(format!("invalid bech32m: {e}")))?;
        Ok(Self { inner: addr })
    }

    /// Encode address to bech32m string
    #[napi]
    pub fn to_bech32(&self, network: XntNetwork) -> Result<String> {
        self.inner
            .to_bech32(network.into())
            .map_err(|e| Error::from_reason(format!("bech32m encoding failed: {e}")))
    }

    /// Get receiver identifier as hex string
    #[napi]
    pub fn receiver_id_hex(&self) -> String {
        self.inner.receiver_id_hex()
    }

    /// Get lock script hash as hex string (40 bytes)
    #[napi]
    pub fn lock_script_hash_hex(&self) -> String {
        hex::encode(self.inner.lock_script_hash().bytes)
    }

    /// Get privacy_digest (receiver_postimage) as hex string for output commitments
    #[napi]
    pub fn privacy_digest_hex(&self) -> String {
        hex::encode(self.inner.privacy_digest().bytes)
    }

    /// Create subaddress with payment_id
    #[napi]
    pub fn with_payment_id(&self, payment_id: i64) -> Result<XntSubAddress> {
        let subaddr = self
            .inner
            .with_payment_id(payment_id as u64)
            .map_err(|e| Error::from_reason(format!("subaddress creation failed: {e}")))?;
        Ok(XntSubAddress { inner: subaddr })
    }

    /// Convert to ReceivingAddress for addOutput
    #[napi]
    pub fn to_receiving_address(&self) -> XntReceivingAddress {
        XntReceivingAddress {
            inner: self.inner.to_receiving_address(),
        }
    }
}

/// Subaddress with payment_id for tracking payments
#[napi]
pub struct XntSubAddress {
    inner: SubAddress,
}

#[napi]
impl XntSubAddress {
    /// Encode subaddress to bech32m string
    #[napi]
    pub fn to_bech32(&self, network: XntNetwork) -> Result<String> {
        self.inner
            .to_bech32(network.into())
            .map_err(|e| Error::from_reason(format!("bech32m encoding failed: {e}")))
    }

    /// Get payment_id
    #[napi]
    pub fn payment_id(&self) -> i64 {
        self.inner.payment_id() as i64
    }

    /// Convert to ReceivingAddress for addOutput
    #[napi]
    pub fn to_receiving_address(&self) -> XntReceivingAddress {
        XntReceivingAddress {
            inner: self.inner.to_receiving_address(),
        }
    }
}

/// Receiving address - can be main address or subaddress (like Neptune's ReceivingAddress enum)
#[napi]
pub struct XntReceivingAddress {
    pub(crate) inner: ReceivingAddress,
}

#[napi]
impl XntReceivingAddress {
    /// Get payment_id if this is a subaddress, null otherwise
    #[napi]
    pub fn payment_id(&self) -> Option<i64> {
        self.inner.payment_id().map(|id| id as i64)
    }

    /// Check if this is a subaddress
    #[napi]
    pub fn is_subaddress(&self) -> bool {
        self.inner.is_subaddress()
    }
}

// RPC Client

/// JSON-RPC client for Neptune node communication
#[napi]
pub struct XntRpcClient {
    inner: RpcClient,
}

#[napi]
impl XntRpcClient {
    /// Create new RPC client
    #[napi(constructor)]
    pub fn new(url: String) -> Result<Self> {
        let client =
            RpcClient::new(&url).map_err(|e| Error::from_reason(format!("RPC error: {e}")))?;
        Ok(Self { inner: client })
    }

    /// Create RPC client with basic auth
    #[napi(factory)]
    pub fn with_auth(url: String, username: String, password: String) -> Result<Self> {
        let client = RpcClient::with_auth(&url, Some((username, password)))
            .map_err(|e| Error::from_reason(format!("RPC error: {e}")))?;
        Ok(Self { inner: client })
    }

    /// Ping the node
    #[napi]
    pub fn ping(&self) -> Result<()> {
        self.inner
            .ping()
            .map_err(|e| Error::from_reason(format!("ping failed: {e}")))
    }

    /// Get current chain height
    #[napi]
    pub fn chain_height(&self) -> Result<i64> {
        self.inner
            .chain_height()
            .map(|h| h as i64)
            .map_err(|e| Error::from_reason(format!("RPC error: {e}")))
    }

    /// Get inner client (for internal use)
    pub(crate) fn inner(&self) -> &RpcClient {
        &self.inner
    }
}

// UTXO

/// Unspent Transaction Output
#[napi]
pub struct XntUtxo {
    inner: Utxo,
}

#[napi]
impl XntUtxo {
    /// Create UTXO for native currency output
    #[napi(factory)]
    pub fn new_native(address: &XntAddress, amount: BigInt) -> Result<Self> {
        let (amt_i128, lossless) = amount.get_i128();
        if !lossless {
            return Err(Error::from_reason("amount overflow: value too large for i128"));
        }
        Ok(Self {
            inner: Utxo::new_native(&address.inner, amt_i128),
        })
    }

    /// Deserialize UTXO from bytes
    #[napi(factory)]
    pub fn from_bytes(data: Buffer) -> Result<Self> {
        let utxo =
            Utxo::from_bytes(&data).map_err(|e| Error::from_reason(format!("deserialize: {e}")))?;
        Ok(Self { inner: utxo })
    }

    /// Serialize UTXO to bytes
    #[napi]
    pub fn to_bytes(&self) -> Result<Buffer> {
        let bytes = self
            .inner
            .to_bytes()
            .map_err(|e| Error::from_reason(format!("serialize: {e}")))?;
        Ok(Buffer::from(bytes))
    }

    /// Get UTXO amount in nau (BigInt for i128 precision)
    #[napi]
    pub fn amount(&self) -> BigInt {
        BigInt::from(self.inner.amount())
    }

    /// Get UTXO hash as hex string (for commitment calculation)
    #[napi]
    pub fn hash_hex(&self) -> String {
        hex::encode(self.inner.hash().bytes)
    }

    /// Get release date if UTXO is timelocked (milliseconds since Unix epoch)
    #[napi]
    pub fn release_date(&self) -> Option<BigInt> {
        self.inner.release_date().map(BigInt::from)
    }

    /// Check if UTXO is timelocked
    #[napi]
    pub fn is_timelocked(&self) -> bool {
        self.inner.is_timelocked()
    }

    /// Check if UTXO can be spent at given timestamp (milliseconds since Unix epoch)
    #[napi]
    pub fn can_spend_at(&self, timestamp_ms: BigInt) -> bool {
        let (_, ts, _) = timestamp_ms.get_u64();
        self.inner.can_spend_at(ts)
    }

    /// Add timelock to UTXO, returns new timelocked UTXO
    #[napi]
    pub fn with_time_lock(&self, release_date_ms: BigInt) -> Self {
        let (_, rd, _) = release_date_ms.get_u64();
        Self {
            inner: self.inner.clone().with_time_lock(rd),
        }
    }

    /// Get inner utxo (for internal use)
    pub(crate) fn inner(&self) -> &Utxo {
        &self.inner
    }
}

// Sync

/// Mutator Set Accumulator
#[napi]
pub struct XntMutatorSet {
    inner: MutatorSet,
}

#[napi]
impl XntMutatorSet {
    /// Deserialize from bytes
    #[napi(factory)]
    pub fn from_bytes(data: Buffer) -> Result<Self> {
        let ms = MutatorSet::from_bytes(&data)
            .map_err(|e| Error::from_reason(format!("deserialize: {e}")))?;
        Ok(Self { inner: ms })
    }

    /// Serialize to bytes
    #[napi]
    pub fn to_bytes(&self) -> Result<Buffer> {
        let bytes = self
            .inner
            .to_bytes()
            .map_err(|e| Error::from_reason(format!("serialize: {e}")))?;
        Ok(Buffer::from(bytes))
    }

    /// Get inner (for internal use)
    pub(crate) fn inner(&self) -> &MutatorSet {
        &self.inner
    }
}

/// Membership Proof for UTXO
#[napi]
pub struct XntMembershipProof {
    inner: MembershipProof,
}

#[napi]
impl XntMembershipProof {
    /// Deserialize from bytes
    #[napi(factory)]
    pub fn from_bytes(data: Buffer) -> Result<Self> {
        let mp = MembershipProof::from_bytes(&data)
            .map_err(|e| Error::from_reason(format!("deserialize: {e}")))?;
        Ok(Self { inner: mp })
    }

    /// Serialize to bytes
    #[napi]
    pub fn to_bytes(&self) -> Result<Buffer> {
        let bytes = self
            .inner
            .to_bytes()
            .map_err(|e| Error::from_reason(format!("serialize: {e}")))?;
        Ok(Buffer::from(bytes))
    }

    /// Get inner (for internal use)
    pub(crate) fn inner(&self) -> &MembershipProof {
        &self.inner
    }
}

/// Fetch UTXOs from indexer
#[napi]
pub fn xnt_fetch_utxos(
    client: &XntRpcClient,
    receiver_id_hash_hex: String,
    from_height: i64,
    to_height: i64,
) -> Result<Vec<XntIndexedUtxo>> {
    let hash_bytes = hex::decode(&receiver_id_hash_hex)
        .map_err(|e| Error::from_reason(format!("invalid hex: {e}")))?;

    if hash_bytes.len() != 40 {
        return Err(Error::from_reason("receiver_id_hash must be 40 bytes"));
    }

    let hash = crate::core::Digest::from_bytes(hash_bytes.try_into().unwrap());

    crate::core::fetch_utxos(client.inner(), &hash, from_height as u64, to_height as u64)
        .map(|utxos| {
            utxos
                .into_iter()
                .map(|u| XntIndexedUtxo {
                    block_height: u.block_height as i64,
                    block_digest_hex: hex::encode(u.block_digest.bytes),
                    ciphertext: Buffer::from(u.ciphertext),
                })
                .collect()
        })
        .map_err(|e| Error::from_reason(format!("fetch_utxos: {e}")))
}

/// Indexed UTXO from sync
#[napi(object)]
pub struct XntIndexedUtxo {
    pub block_height: i64,
    pub block_digest_hex: String,
    pub ciphertext: Buffer,
}

/// Get mutator set from RPC
#[napi]
pub fn xnt_get_mutator_set(client: &XntRpcClient) -> Result<XntMutatorSet> {
    crate::core::get_mutator_set(client.inner())
        .map(|ms| XntMutatorSet { inner: ms })
        .map_err(|e| Error::from_reason(format!("get_mutator_set: {e}")))
}

/// Check if UTXOs are spent by absolute index set hashes
/// Returns Vec<i64> where -1 = not spent, >= 0 = spent at that block height
#[napi]
pub fn xnt_check_spent(
    client: &XntRpcClient,
    absolute_index_set_hashes_hex: Vec<String>,
) -> Result<Vec<i64>> {
    let hashes: std::result::Result<Vec<crate::core::Digest>, _> = absolute_index_set_hashes_hex
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).map_err(|e| format!("invalid hex: {e}"))?;
            if bytes.len() != 40 {
                return Err("hash must be 40 bytes".to_string());
            }
            Ok(crate::core::Digest::from_bytes(bytes.try_into().unwrap()))
        })
        .collect();

    let hashes = hashes.map_err(|e| Error::from_reason(e))?;

    crate::core::check_spent(client.inner(), &hashes)
        .map_err(|e| Error::from_reason(format!("check_spent: {e}")))
}

/// Get AOCL leaf indices for commitments
#[napi]
pub fn xnt_get_aocl_indices(
    client: &XntRpcClient,
    commitment_hashes_hex: Vec<String>,
) -> Result<Vec<i64>> {
    let hashes: std::result::Result<Vec<crate::core::Digest>, _> = commitment_hashes_hex
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).map_err(|e| format!("invalid hex: {e}"))?;
            if bytes.len() != 40 {
                return Err("hash must be 40 bytes".to_string());
            }
            Ok(crate::core::Digest::from_bytes(bytes.try_into().unwrap()))
        })
        .collect();

    let hashes = hashes.map_err(|e| Error::from_reason(e))?;

    crate::core::get_aocl_indices(client.inner(), &hashes)
        .map_err(|e| Error::from_reason(format!("get_aocl_indices: {e}")))
}

/// Decrypted UTXO result
#[napi]
pub struct XntDecryptedUtxo {
    inner: crate::core::DecryptedUtxo,
}

#[napi]
impl XntDecryptedUtxo {
    #[napi(getter)]
    pub fn utxo(&self) -> XntUtxo {
        XntUtxo { inner: self.inner.utxo.clone() }
    }

    #[napi(getter)]
    pub fn sender_randomness_hex(&self) -> String {
        self.inner.sender_randomness.to_hex()
    }

    #[napi(getter)]
    pub fn payment_id(&self) -> i64 {
        self.inner.payment_id as i64
    }

    #[napi(getter)]
    pub fn amount(&self) -> BigInt {
        BigInt::from(self.inner.utxo.amount())
    }

    #[napi(getter)]
    pub fn block_height(&self) -> i64 {
        self.inner.block_height as i64
    }

    #[napi(getter)]
    pub fn block_digest_hex(&self) -> String {
        self.inner.block_digest.to_hex()
    }

    /// Get release date if timelocked (milliseconds since Unix epoch)
    #[napi(getter)]
    pub fn release_date(&self) -> Option<BigInt> {
        self.inner.utxo.release_date().map(BigInt::from)
    }

    /// Check if UTXO is timelocked
    #[napi(getter)]
    pub fn is_timelocked(&self) -> bool {
        self.inner.utxo.is_timelocked()
    }
}

/// Transaction input info
#[napi]
pub struct XntTxInputInfo {
    inner: crate::core::TxInputInfo,
}

#[napi]
impl XntTxInputInfo {
    #[napi(getter)]
    pub fn utxo(&self) -> XntUtxo {
        XntUtxo { inner: self.inner.utxo.clone() }
    }

    #[napi(getter)]
    pub fn sender_randomness_hex(&self) -> String {
        self.inner.sender_randomness.to_hex()
    }

    #[napi(getter)]
    pub fn commitment_hex(&self) -> String {
        self.inner.commitment.to_hex()
    }

    #[napi(getter)]
    pub fn amount(&self) -> BigInt {
        BigInt::from(self.inner.utxo.amount())
    }
}

/// Transaction output info
#[napi]
pub struct XntTxOutputInfo {
    inner: crate::core::TxOutputInfo,
}

#[napi]
impl XntTxOutputInfo {
    #[napi(getter)]
    pub fn utxo(&self) -> XntUtxo {
        XntUtxo { inner: self.inner.utxo.clone() }
    }

    #[napi(getter)]
    pub fn sender_randomness_hex(&self) -> String {
        self.inner.sender_randomness.to_hex()
    }

    #[napi(getter)]
    pub fn receiver_digest_hex(&self) -> String {
        self.inner.receiver_digest.to_hex()
    }

    #[napi(getter)]
    pub fn is_change(&self) -> bool {
        self.inner.is_change
    }

    #[napi(getter)]
    pub fn payment_id(&self) -> Option<i64> {
        self.inner.payment_id.map(|id| id as i64)
    }

    #[napi(getter)]
    pub fn commitment_hex(&self) -> String {
        self.inner.commitment.to_hex()
    }

    #[napi(getter)]
    pub fn amount(&self) -> BigInt {
        BigInt::from(self.inner.utxo.amount())
    }
}

/// Decrypt indexed UTXO ciphertext
#[napi]
pub fn xnt_decrypt_indexed_utxo(
    spending_key: &XntSpendingKey,
    ciphertext: Buffer,
    block_height: i64,
    block_digest_hex: String,
) -> Result<XntDecryptedUtxo> {
    let block_digest = crate::core::Digest::from_hex(&block_digest_hex)
        .ok_or_else(|| Error::from_reason("invalid block_digest_hex"))?;
    let inner = crate::core::decrypt_indexed_utxo(
        spending_key.inner(),
        &ciphertext,
        block_height as u64,
        block_digest,
    )
    .map_err(|e| Error::from_reason(format!("decrypt: {e}")))?;
    Ok(XntDecryptedUtxo { inner })
}

/// Compute commitment hash for UTXO
#[napi]
pub fn xnt_compute_commitment(
    utxo_hash_hex: String,
    sender_randomness_hex: String,
    receiver_preimage_hex: String,
) -> Result<String> {
    let parse = |s: &str, name: &str| -> std::result::Result<crate::core::Digest, Error> {
        let bytes = hex::decode(s).map_err(|e| Error::from_reason(format!("invalid {name} hex: {e}")))?;
        if bytes.len() != 40 {
            return Err(Error::from_reason(format!("{name} must be 40 bytes")));
        }
        Ok(crate::core::Digest::from_bytes(bytes.try_into().unwrap()))
    };

    let utxo_hash = parse(&utxo_hash_hex, "utxo_hash")?;
    let sr = parse(&sender_randomness_hex, "sender_randomness")?;
    let rp = parse(&receiver_preimage_hex, "receiver_preimage")?;

    let commitment = crate::core::compute_commitment(&utxo_hash, &sr, &rp);
    Ok(hex::encode(commitment.bytes))
}

/// Compute commitment hash for output UTXO (using privacy_digest/receiver_postimage)
#[napi]
pub fn xnt_compute_commitment_for_output(
    utxo_hash_hex: String,
    sender_randomness_hex: String,
    privacy_digest_hex: String,
) -> Result<String> {
    let parse = |s: &str, name: &str| -> std::result::Result<crate::core::Digest, Error> {
        let bytes = hex::decode(s).map_err(|e| Error::from_reason(format!("invalid {name} hex: {e}")))?;
        if bytes.len() != 40 {
            return Err(Error::from_reason(format!("{name} must be 40 bytes")));
        }
        Ok(crate::core::Digest::from_bytes(bytes.try_into().unwrap()))
    };

    let utxo_hash = parse(&utxo_hash_hex, "utxo_hash")?;
    let sr = parse(&sender_randomness_hex, "sender_randomness")?;
    let pd = parse(&privacy_digest_hex, "privacy_digest")?;

    let commitment = crate::core::compute_commitment_for_output(&utxo_hash, &sr, &pd);
    Ok(hex::encode(commitment.bytes))
}

/// Compute absolute index set hash for spent checking
#[napi]
pub fn xnt_compute_absolute_index_set_hash(
    utxo_hash_hex: String,
    sender_randomness_hex: String,
    receiver_preimage_hex: String,
    aocl_leaf_index: i64,
) -> Result<String> {
    let parse = |s: &str, name: &str| -> std::result::Result<crate::core::Digest, Error> {
        let bytes = hex::decode(s).map_err(|e| Error::from_reason(format!("invalid {name} hex: {e}")))?;
        if bytes.len() != 40 {
            return Err(Error::from_reason(format!("{name} must be 40 bytes")));
        }
        Ok(crate::core::Digest::from_bytes(bytes.try_into().unwrap()))
    };

    let utxo_hash = parse(&utxo_hash_hex, "utxo_hash")?;
    let sr = parse(&sender_randomness_hex, "sender_randomness")?;
    let rp = parse(&receiver_preimage_hex, "receiver_preimage")?;

    let hash = crate::core::compute_absolute_index_set_hash(&utxo_hash, &sr, &rp, aocl_leaf_index as u64);
    Ok(hex::encode(hash.bytes))
}

/// Hash an AbsoluteIndexSet from JSON (from RPC mempool response)
/// Used to check if a mempool tx input matches a known UTXO
#[napi]
pub fn xnt_hash_absolute_index_set(absolute_index_set_json: String) -> Result<String> {
    let hash = crate::core::hash_absolute_index_set_json(&absolute_index_set_json)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(hex::encode(hash.bytes))
}


/// Pending incoming UTXO from mempool
#[napi]
pub struct XntPendingUtxo {
    utxo: crate::core::Utxo,
    sender_randomness: crate::core::Digest,
    payment_id: u64,
}

#[napi]
impl XntPendingUtxo {
    #[napi(getter)]
    pub fn utxo(&self) -> XntUtxo {
        XntUtxo { inner: self.utxo.clone() }
    }

    #[napi(getter)]
    pub fn sender_randomness_hex(&self) -> String {
        hex::encode(self.sender_randomness.bytes)
    }

    #[napi(getter)]
    pub fn payment_id(&self) -> i64 {
        self.payment_id as i64
    }

    #[napi(getter)]
    pub fn amount(&self) -> BigInt {
        BigInt::from(self.utxo.amount())
    }
}

/// Check mempool for pending spending (our UTXOs being spent)
/// Takes array of absolute_index_set_hash hex strings (from sync)
/// Returns indices of UTXOs with pending spends
#[napi]
pub fn xnt_mempool_spending(
    client: &XntRpcClient,
    abs_hashes_hex: Vec<String>,
) -> Result<Vec<i64>> {
    let hashes: Vec<crate::core::Digest> = abs_hashes_hex
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).map_err(|e| format!("invalid hex: {e}"))?;
            if bytes.len() != 40 {
                return Err("hash must be 40 bytes".to_string());
            }
            Ok(crate::core::Digest::from_bytes(bytes.try_into().unwrap()))
        })
        .collect::<std::result::Result<_, String>>()
        .map_err(Error::from_reason)?;

    let indices = crate::core::mempool_spending(&client.inner, &hashes)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    Ok(indices.into_iter().map(|i| i as i64).collect())
}

/// Check mempool for pending incoming UTXOs
#[napi]
pub fn xnt_mempool_incoming(
    client: &XntRpcClient,
    key: &XntSpendingKey,
) -> Result<Vec<XntPendingUtxo>> {
    let pending = crate::core::mempool_incoming(&client.inner, &key.inner)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    Ok(pending
        .into_iter()
        .map(|(utxo, sr, pid)| XntPendingUtxo {
            utxo,
            sender_randomness: sr,
            payment_id: pid,
        })
        .collect())
}

/// Get membership proofs for UTXOs
#[napi]
pub fn xnt_get_membership_proofs(
    client: &XntRpcClient,
    utxo_hashes_hex: Vec<String>,
    sender_randomnesses_hex: Vec<String>,
    receiver_preimage_hex: String,
    aocl_indices: Vec<i64>,
) -> Result<Vec<Buffer>> {
    let parse = |s: &str, name: &str| -> std::result::Result<crate::core::Digest, String> {
        let bytes = hex::decode(s).map_err(|e| format!("invalid {name} hex: {e}"))?;
        if bytes.len() != 40 {
            return Err(format!("{name} must be 40 bytes"));
        }
        Ok(crate::core::Digest::from_bytes(bytes.try_into().unwrap()))
    };

    let utxo_hashes: Vec<crate::core::Digest> = utxo_hashes_hex
        .iter()
        .map(|h| parse(h, "utxo_hash"))
        .collect::<std::result::Result<_, _>>()
        .map_err(Error::from_reason)?;

    let sender_randomnesses: Vec<crate::core::Digest> = sender_randomnesses_hex
        .iter()
        .map(|h| parse(h, "sender_randomness"))
        .collect::<std::result::Result<_, _>>()
        .map_err(Error::from_reason)?;

    let receiver_preimage = parse(&receiver_preimage_hex, "receiver_preimage")
        .map_err(Error::from_reason)?;

    let aocl_u64: Vec<u64> = aocl_indices.iter().map(|&i| i as u64).collect();

    let proofs = crate::core::get_membership_proofs(
        client.inner(),
        &utxo_hashes,
        &sender_randomnesses,
        &receiver_preimage,
        &aocl_u64,
    )
    .map_err(|e| Error::from_reason(format!("get_membership_proofs: {e}")))?;

    proofs
        .into_iter()
        .map(|p| {
            p.to_bytes()
                .map(Buffer::from)
                .map_err(|e| Error::from_reason(format!("serialize proof: {e}")))
        })
        .collect()
}

// Transaction Building

/// Transaction builder for constructing transactions
#[napi]
pub struct XntTransactionBuilder {
    inner: TransactionBuilder,
}

#[napi]
impl XntTransactionBuilder {
    /// Create new transaction builder
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: TransactionBuilder::new(),
        }
    }

    /// Add input UTXO to spend
    #[napi]
    pub fn add_input(
        &mut self,
        utxo: &XntUtxo,
        spending_key: &XntSpendingKey,
        membership_proof: &XntMembershipProof,
    ) {
        self.inner.add_input(
            utxo.inner.clone(),
            spending_key.inner.clone(),
            membership_proof.inner.clone(),
        );
    }

    /// Add output recipient (takes XntReceivingAddress - use addr.toReceivingAddress() or subaddr.toReceivingAddress())
    #[napi]
    pub fn add_output(
        &mut self,
        receiving_address: &XntReceivingAddress,
        amount: BigInt,
        sender_randomness_hex: String,
    ) -> Result<()> {
        let sr_bytes = hex::decode(&sender_randomness_hex)
            .map_err(|e| Error::from_reason(format!("invalid hex: {e}")))?;
        if sr_bytes.len() != 40 {
            return Err(Error::from_reason("sender_randomness must be 40 bytes"));
        }
        let sr = crate::core::Digest::from_bytes(sr_bytes.try_into().unwrap());
        let (amt_i128, lossless) = amount.get_i128();
        if !lossless {
            return Err(Error::from_reason("amount overflow: value too large for i128"));
        }
        self.inner
            .add_output(receiving_address.inner.clone(), amt_i128, sr);
        Ok(())
    }

    /// Set change address
    #[napi]
    pub fn set_change(&mut self, address: &XntAddress, sender_randomness_hex: String) -> Result<()> {
        let sr_bytes = hex::decode(&sender_randomness_hex)
            .map_err(|e| Error::from_reason(format!("invalid hex: {e}")))?;
        if sr_bytes.len() != 40 {
            return Err(Error::from_reason("sender_randomness must be 40 bytes"));
        }
        let sr = crate::core::Digest::from_bytes(sr_bytes.try_into().unwrap());
        self.inner.set_change(address.inner.clone(), sr);
        Ok(())
    }

    /// Set transaction fee
    #[napi]
    pub fn set_fee(&mut self, fee: BigInt) -> Result<()> {
        let (fee_i128, lossless) = fee.get_i128();
        if !lossless {
            return Err(Error::from_reason("fee overflow: value too large for i128"));
        }
        self.inner.set_fee(fee_i128);
        Ok(())
    }

    /// Get total input amount
    #[napi]
    pub fn input_total(&self) -> BigInt {
        BigInt::from(self.inner.input_total())
    }

    /// Get total output amount
    #[napi]
    pub fn output_total(&self) -> BigInt {
        BigInt::from(self.inner.output_total())
    }

    /// Get calculated change amount
    #[napi]
    pub fn change_amount(&self) -> BigInt {
        BigInt::from(self.inner.change_amount())
    }

    /// Build the transaction
    #[napi]
    pub fn build(
        &self,
        mutator_set: &XntMutatorSet,
        timestamp_ms: i64,
        network: XntNetwork,
    ) -> Result<XntBuiltTransaction> {
        self.inner
            .build(&mutator_set.inner, timestamp_ms as u64, network.into())
            .map(|built| XntBuiltTransaction { inner: built })
            .map_err(|e| Error::from_reason(format!("build failed: {e}")))
    }
}

/// Built transaction ready for submission
#[napi]
pub struct XntBuiltTransaction {
    inner: crate::core::BuiltTransaction,
}

#[napi]
impl XntBuiltTransaction {
    /// Serialize to bytes
    #[napi]
    pub fn to_bytes(&self) -> Result<Buffer> {
        self.inner
            .to_bytes()
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(format!("serialize: {e}")))
    }

    /// Get transaction kernel bytes
    #[napi]
    pub fn kernel_bytes(&self) -> Result<Buffer> {
        self.inner
            .kernel_bytes()
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(format!("kernel: {e}")))
    }

    /// Get witness bytes
    #[napi]
    pub fn witness_bytes(&self) -> Result<Buffer> {
        self.inner
            .witness_bytes()
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(format!("witness: {e}")))
    }

    /// Get all inputs
    #[napi]
    pub fn inputs(&self) -> Vec<XntTxInputInfo> {
        self.inner
            .inputs()
            .into_iter()
            .map(|i| XntTxInputInfo { inner: i })
            .collect()
    }

    /// Get all outputs (including change)
    #[napi]
    pub fn outputs(&self) -> Vec<XntTxOutputInfo> {
        self.inner
            .outputs()
            .into_iter()
            .map(|o| XntTxOutputInfo { inner: o })
            .collect()
    }

    /// Prove the transaction (creates ProofCollection)
    /// WARNING: This is CPU-intensive and requires ~16GB RAM
    #[napi]
    pub fn prove(&self) -> Result<XntTransaction> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| Error::from_reason(format!("runtime: {e}")))?;

        rt.block_on(async {
            self.inner
                .prove()
                .await
                .map(|tx| XntTransaction { inner: tx })
                .map_err(|e| Error::from_reason(format!("prove: {e}")))
        })
    }
}

/// Final transaction
#[napi]
pub struct XntTransaction {
    inner: crate::core::Transaction,
}

#[napi]
impl XntTransaction {
    /// Deserialize from bytes
    #[napi(factory)]
    pub fn from_bytes(data: Buffer) -> Result<Self> {
        crate::core::Transaction::from_bytes(&data)
            .map(|tx| Self { inner: tx })
            .map_err(|e| Error::from_reason(format!("deserialize: {e}")))
    }

    /// Serialize to bytes
    #[napi]
    pub fn to_bytes(&self) -> Result<Buffer> {
        self.inner
            .to_bytes()
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(format!("serialize: {e}")))
    }

    /// Check if has ProofCollection
    #[napi]
    pub fn has_proof_collection(&self) -> bool {
        self.inner.has_proof_collection()
    }

    /// Check if has SingleProof
    #[napi]
    pub fn has_single_proof(&self) -> bool {
        self.inner.has_single_proof()
    }

    /// Submit transaction to node
    #[napi]
    pub fn submit(&self, client: &XntRpcClient) -> Result<()> {
        self.inner
            .submit(client.inner())
            .map_err(|e| Error::from_reason(format!("submit: {e}")))
    }
}

// Utilities

/// Library version
#[napi]
pub fn xnt_version() -> String {
    "0.1.0".to_string()
}

/// Get current timestamp in milliseconds
#[napi]
pub fn xnt_timestamp_now() -> i64 {
    crate::core::timestamp_now() as i64
}

/// Generate random sender randomness (40 bytes hex)
///
/// Uses cryptographically secure OsRng for transaction privacy
#[napi]
pub fn xnt_random_sender_randomness() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 40];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Select UTXOs to cover target amount (smallest-first)
#[napi]
pub fn xnt_select_inputs(amounts: Vec<BigInt>, target: BigInt, limit: u32) -> Result<Vec<u32>> {
    let mut amts = Vec::with_capacity(amounts.len());
    for (i, b) in amounts.iter().enumerate() {
        let (val, lossless) = b.get_i128();
        if !lossless {
            return Err(Error::from_reason(format!("amount[{}] overflow: value too large for i128", i)));
        }
        amts.push(val);
    }
    let (tgt, lossless) = target.get_i128();
    if !lossless {
        return Err(Error::from_reason("target overflow: value too large for i128"));
    }
    crate::core::select_inputs(&amts, tgt, limit as usize)
        .map(|v| v.into_iter().map(|i| i as u32).collect())
        .map_err(|e| Error::from_reason(format!("{e}")))
}
