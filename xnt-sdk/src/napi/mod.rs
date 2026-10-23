//! NAPI bindings for xnt-core (Node.js native module)
//!
//! Automatic memory management via Node.js GC.
//! No manual *_free calls required.
//! Uses shared core module for business logic.

use std::sync::OnceLock;

use napi::bindgen_prelude::*;
use napi::bindgen_prelude::BigInt;
use napi_derive::napi;

use crate::core::{
    Address, MembershipProof, MutatorSet, Network, ReceivingAddress, RpcClient, SpendingKey,
    SubAddress, TransactionBuilder, Utxo, WalletEntropy,
};

/// Persistent tokio runtime shared across all prove() calls.
/// Keeps the TritonVmJobQueue background task alive between calls.
fn global_tokio_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("failed to create global tokio runtime")
    })
}

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
    #[napi(constructor, catch_unwind)]
    pub fn new(mnemonic: String) -> Result<Self> {
        let entropy = WalletEntropy::from_mnemonic(&mnemonic)
            .map_err(|e| Error::from_reason(format!("invalid mnemonic: {e}")))?;
        Ok(Self { inner: entropy })
    }

    /// Generate new random mnemonic and wallet
    #[napi(factory, catch_unwind)]
    pub fn generate() -> Result<Self> {
        let entropy =
            WalletEntropy::generate().map_err(|e| Error::from_reason(format!("{e}")))?;
        Ok(Self { inner: entropy })
    }

    /// Get devnet test wallet
    #[napi(factory, catch_unwind)]
    pub fn devnet() -> Self {
        Self {
            inner: WalletEntropy::devnet(),
        }
    }

    /// Export wallet to mnemonic phrase
    #[napi(catch_unwind)]
    pub fn to_mnemonic(&self) -> String {
        self.inner.to_mnemonic()
    }

    /// Derive spending key at index
    #[napi(catch_unwind)]
    pub fn derive_key(&self, index: u32) -> XntSpendingKey {
        XntSpendingKey {
            inner: self.inner.derive_spending_key(index as u64),
        }
    }

    /// Derive dCTIDH spending key at index (dCTIDH-512)
    #[napi(js_name = "derivedCTIDHKey", catch_unwind)]
    pub fn derive_dctidh_key(&self, index: u32) -> XntSpendingKey {
        XntSpendingKey {
            inner: self.inner.derive_dctidh_spending_key(index as u64),
        }
    }

    /// Derive dCTIDH spending key at index using the legacy (pre-v0.3)
    /// derivation, for recognising and sweeping funds at legacy-format addresses.
    ///
    /// UTXOs of such a key are sweep-only, see `isLegacy`.
    #[napi(js_name = "deriveLegacydCTIDHKey", catch_unwind)]
    pub fn derive_legacy_dctidh_key(&self, index: u32) -> XntSpendingKey {
        XntSpendingKey {
            inner: self.inner.derive_legacy_dctidh_spending_key(index as u64),
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
    /// Get receiving address from spending key. Throws for legacy-derivation
    /// dCTIDH keys, which have no receiving address.
    #[napi(catch_unwind)]
    pub fn to_address(&self) -> Result<XntAddress> {
        let inner = self
            .inner
            .to_address()
            .map_err(|e| Error::from_reason(format!("{e}")))?;
        Ok(XntAddress { inner })
    }

    /// Get receiver identifier as u64
    #[napi(catch_unwind)]
    pub fn receiver_id(&self) -> i64 {
        self.inner.receiver_id() as i64
    }

    /// Get receiver identifier as hex string
    #[napi(catch_unwind)]
    pub fn receiver_id_hex(&self) -> String {
        self.inner.receiver_id_hex()
    }

    /// Get receiver_id_hash as hex string (for indexer lookups)
    #[napi(catch_unwind)]
    pub fn receiver_id_hash_hex(&self) -> String {
        hex::encode(self.inner.receiver_id_hash().bytes)
    }

    /// Get receiver_preimage as hex string (for commitment computation)
    ///
    /// For dCTIDH keys this is also the unlock preimage of the key's lock
    /// script: anyone who knows it can spend the key's UTXOs. Treat it as a
    /// spending secret: keep it in the process that holds the seed, do not
    /// log it, send it to a server or store it unencrypted.
    #[napi(catch_unwind)]
    pub fn receiver_preimage_hex(&self) -> String {
        hex::encode(self.inner.receiver_preimage().bytes)
    }

    /// Get the hash of the lock script this key can satisfy as hex string.
    /// UTXOs with a different lock script hash cannot be spent by this key.
    #[napi(catch_unwind)]
    pub fn lock_script_hash_hex(&self) -> String {
        hex::encode(self.inner.lock_script_hash().bytes)
    }

    /// True for dCTIDH keys derived with the legacy (pre-v0.3) lock
    /// derivation (`deriveLegacydCTIDHKey`). UTXOs of such a key are
    /// sweep-only: move them to a current-format key and never count them
    /// towards the available balance.
    #[napi(catch_unwind)]
    pub fn is_legacy(&self) -> bool {
        self.inner.is_legacy()
    }

    /// Whether UTXOs of this key confirmed in a block of height `block_height`
    /// are recognized on `network`. Always true for keys that are not legacy;
    /// for legacy keys true only below `xntLegacyDctidhCutoff(network)`.
    #[napi(catch_unwind)]
    pub fn recognizes_utxos_at(&self, network: XntNetwork, block_height: i64) -> Result<bool> {
        let height = u64::try_from(block_height)
            .map_err(|_| Error::from_reason("block_height must not be negative"))?;
        Ok(self.inner.recognizes_utxos_at(network.into(), height))
    }

    /// Check if this is a dCTIDH spending key
    #[napi(js_name = "isDCTIDH", catch_unwind)]
    pub fn is_dctidh(&self) -> bool {
        self.inner.is_dctidh()
    }

    /// Check if this is a Generation spending key
    #[napi(catch_unwind)]
    pub fn is_generation(&self) -> bool {
        self.inner.is_generation()
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
    #[napi(factory, catch_unwind)]
    pub fn from_bech32(bech32: String, network: XntNetwork) -> Result<Self> {
        let addr = Address::from_bech32(&bech32, network.into())
            .map_err(|e| Error::from_reason(format!("invalid bech32m: {e}")))?;
        Ok(Self { inner: addr })
    }

    /// Encode address to bech32m string
    #[napi(catch_unwind)]
    pub fn to_bech32(&self, network: XntNetwork) -> Result<String> {
        self.inner
            .to_bech32(network.into())
            .map_err(|e| Error::from_reason(format!("bech32m encoding failed: {e}")))
    }

    /// Get receiver identifier as hex string
    #[napi(catch_unwind)]
    pub fn receiver_id_hex(&self) -> String {
        self.inner.receiver_id_hex()
    }

    /// Get lock script hash as hex string (40 bytes)
    #[napi(catch_unwind)]
    pub fn lock_script_hash_hex(&self) -> String {
        hex::encode(self.inner.lock_script_hash().bytes)
    }

    /// Get privacy_digest (receiver_postimage) as hex string for output commitments
    #[napi(catch_unwind)]
    pub fn privacy_digest_hex(&self) -> String {
        hex::encode(self.inner.privacy_digest().bytes)
    }

    /// Create subaddress with payment_id
    #[napi(catch_unwind)]
    pub fn with_payment_id(&self, payment_id: i64) -> Result<XntSubAddress> {
        let subaddr = self
            .inner
            .with_payment_id(payment_id as u64)
            .map_err(|e| Error::from_reason(format!("subaddress creation failed: {e}")))?;
        Ok(XntSubAddress { inner: subaddr })
    }

    /// Create dCTIDH subaddress with payment_id
    #[napi(js_name = "dCTIDHSubaddress", catch_unwind)]
    pub fn dctidh_subaddress(&self, payment_id: i64) -> Result<XntReceivingAddress> {
        let subaddr = self
            .inner
            .dctidh_subaddress(payment_id as u64)
            .map_err(|e| Error::from_reason(format!("dctidh subaddress creation failed: {e}")))?;
        Ok(XntReceivingAddress { inner: subaddr })
    }

    /// Convert to ReceivingAddress for addOutput
    #[napi(catch_unwind)]
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
    #[napi(catch_unwind)]
    pub fn to_bech32(&self, network: XntNetwork) -> Result<String> {
        self.inner
            .to_bech32(network.into())
            .map_err(|e| Error::from_reason(format!("bech32m encoding failed: {e}")))
    }

    /// Get payment_id
    #[napi(catch_unwind)]
    pub fn payment_id(&self) -> i64 {
        self.inner.payment_id() as i64
    }

    /// Convert to ReceivingAddress for addOutput
    #[napi(catch_unwind)]
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
    /// Encode address to bech32m string
    #[napi(catch_unwind)]
    pub fn to_bech32(&self, network: XntNetwork) -> Result<String> {
        self.inner
            .to_bech32(network.into())
            .map_err(|e| Error::from_reason(format!("bech32m encoding failed: {e}")))
    }
    /// Get payment_id if this is a subaddress, null otherwise
    #[napi(catch_unwind)]
    pub fn payment_id(&self) -> Option<i64> {
        self.inner.payment_id().map(|id| id as i64)
    }

    /// Check if this is a subaddress
    #[napi(catch_unwind)]
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
    #[napi(constructor, catch_unwind)]
    pub fn new(url: String) -> Result<Self> {
        let client =
            RpcClient::new(&url).map_err(|e| Error::from_reason(format!("RPC error: {e}")))?;
        Ok(Self { inner: client })
    }

    /// Create RPC client with basic auth
    #[napi(factory, catch_unwind)]
    pub fn with_auth(url: String, username: String, password: String) -> Result<Self> {
        let client = RpcClient::with_auth(&url, Some((username, password)))
            .map_err(|e| Error::from_reason(format!("RPC error: {e}")))?;
        Ok(Self { inner: client })
    }

    /// Ping the node
    #[napi(catch_unwind)]
    pub fn ping(&self) -> Result<()> {
        self.inner
            .ping()
            .map_err(|e| Error::from_reason(format!("ping failed: {e}")))
    }

    /// Get current chain height
    #[napi(catch_unwind)]
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
    #[napi(factory, catch_unwind)]
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
    #[napi(factory, catch_unwind)]
    pub fn from_bytes(data: Buffer) -> Result<Self> {
        let utxo =
            Utxo::from_bytes(&data).map_err(|e| Error::from_reason(format!("deserialize: {e}")))?;
        Ok(Self { inner: utxo })
    }

    /// Serialize UTXO to bytes
    #[napi(catch_unwind)]
    pub fn to_bytes(&self) -> Result<Buffer> {
        let bytes = self
            .inner
            .to_bytes()
            .map_err(|e| Error::from_reason(format!("serialize: {e}")))?;
        Ok(Buffer::from(bytes))
    }

    /// Get UTXO amount in nau (BigInt for i128 precision)
    #[napi(catch_unwind)]
    pub fn amount(&self) -> BigInt {
        BigInt::from(self.inner.amount())
    }

    /// Get UTXO hash as hex string (for commitment calculation)
    #[napi(catch_unwind)]
    pub fn hash_hex(&self) -> String {
        hex::encode(self.inner.hash().bytes)
    }

    /// Get the hash of the lock script of this UTXO as hex string
    #[napi(catch_unwind)]
    pub fn lock_script_hash_hex(&self) -> String {
        hex::encode(self.inner.lock_script_hash().bytes)
    }

    /// Get release date if UTXO is timelocked (milliseconds since Unix epoch)
    #[napi(catch_unwind)]
    pub fn release_date(&self) -> Option<BigInt> {
        self.inner.release_date().map(BigInt::from)
    }

    /// Check if UTXO is timelocked
    #[napi(catch_unwind)]
    pub fn is_timelocked(&self) -> bool {
        self.inner.is_timelocked()
    }

    /// Check if UTXO can be spent at given timestamp (milliseconds since Unix epoch)
    #[napi(catch_unwind)]
    pub fn can_spend_at(&self, timestamp_ms: BigInt) -> bool {
        let (_, ts, _) = timestamp_ms.get_u64();
        self.inner.can_spend_at(ts)
    }

    /// Add timelock to UTXO, returns new timelocked UTXO
    #[napi(catch_unwind)]
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
    #[napi(factory, catch_unwind)]
    pub fn from_bytes(data: Buffer) -> Result<Self> {
        let ms = MutatorSet::from_bytes(&data)
            .map_err(|e| Error::from_reason(format!("deserialize: {e}")))?;
        Ok(Self { inner: ms })
    }

    /// Serialize to bytes
    ///
    /// The tip height is not serialized, see withTipHeight.
    #[napi(catch_unwind)]
    pub fn to_bytes(&self) -> Result<Buffer> {
        let bytes = self
            .inner
            .to_bytes()
            .map_err(|e| Error::from_reason(format!("serialize: {e}")))?;
        Ok(Buffer::from(bytes))
    }

    /// Height of the tip whose mutator set this is, or null if unknown, as
    /// after fromBytes. A transaction built on it is proven for the block
    /// after that tip, see prove.
    #[napi(catch_unwind)]
    pub fn tip_height(&self) -> Option<i64> {
        self.inner
            .tip_height()
            .and_then(|height| i64::try_from(height).ok())
    }

    /// The same mutator set, as the one of the tip at `tipHeight`: for a
    /// mutator set restored with fromBytes.
    #[napi(catch_unwind)]
    pub fn with_tip_height(&self, tip_height: i64) -> Result<XntMutatorSet> {
        let tip_height = u64::try_from(tip_height)
            .map_err(|_| Error::from_reason("tip height must not be negative"))?;
        Ok(XntMutatorSet {
            inner: self.inner.clone().with_tip_height(tip_height),
        })
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
    #[napi(factory, catch_unwind)]
    pub fn from_bytes(data: Buffer) -> Result<Self> {
        let mp = MembershipProof::from_bytes(&data)
            .map_err(|e| Error::from_reason(format!("deserialize: {e}")))?;
        Ok(Self { inner: mp })
    }

    /// Serialize to bytes
    #[napi(catch_unwind)]
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
///
/// Entries without a block height, or whose ciphertext is oversized or not a
/// list of field elements, are skipped, see `xntFetchUtxosWithSkipped`.
#[napi(catch_unwind)]
pub fn xnt_fetch_utxos(
    client: &XntRpcClient,
    receiver_id_hash_hex: String,
    from_height: i64,
    to_height: i64,
) -> Result<Vec<XntIndexedUtxo>> {
    xnt_fetch_utxos_with_skipped(client, receiver_id_hash_hex, from_height, to_height)
        .map(|fetched| fetched.utxos)
}

/// Fetch UTXOs from indexer, and count the entries skipped instead of failing
/// the whole range: entries without a block height, or whose ciphertext is
/// oversized or not a list of field elements.
#[napi(catch_unwind)]
pub fn xnt_fetch_utxos_with_skipped(
    client: &XntRpcClient,
    receiver_id_hash_hex: String,
    from_height: i64,
    to_height: i64,
) -> Result<XntFetchedUtxos> {
    let hash_bytes = hex::decode(&receiver_id_hash_hex)
        .map_err(|e| Error::from_reason(format!("invalid hex: {e}")))?;

    if hash_bytes.len() != 40 {
        return Err(Error::from_reason("receiver_id_hash must be 40 bytes"));
    }

    let hash = crate::core::Digest::from_bytes(hash_bytes.try_into().unwrap());

    crate::core::fetch_utxos_with_skipped(
        client.inner(),
        &hash,
        from_height as u64,
        to_height as u64,
    )
    .map(|(utxos, skipped)| XntFetchedUtxos {
        utxos: utxos
            .into_iter()
            .map(|u| XntIndexedUtxo {
                block_height: u.block_height as i64,
                block_digest_hex: hex::encode(u.block_digest.bytes),
                ciphertext: Buffer::from(u.ciphertext),
            })
            .collect(),
        skipped: skipped as i64,
    })
    .map_err(|e| Error::from_reason(format!("fetch_utxos: {e}")))
}

/// Indexed UTXOs of one range, see `xntFetchUtxosWithSkipped`
#[napi(object)]
pub struct XntFetchedUtxos {
    pub utxos: Vec<XntIndexedUtxo>,
    /// Number of malformed entries that were skipped
    pub skipped: i64,
}

/// The block height from which UTXOs at legacy-format (pre-v0.3) dCTIDH locks
/// are no longer recognized on `network`, or null if there is no cutoff.
#[napi(catch_unwind)]
pub fn xnt_legacy_dctidh_cutoff(network: XntNetwork) -> Option<i64> {
    crate::core::legacy_dctidh_cutoff(network.into()).map(|height| height as i64)
}

/// Indexed UTXO from sync
#[napi(object)]
pub struct XntIndexedUtxo {
    pub block_height: i64,
    pub block_digest_hex: String,
    pub ciphertext: Buffer,
}

/// Get mutator set from RPC
#[napi(catch_unwind)]
pub fn xnt_get_mutator_set(client: &XntRpcClient) -> Result<XntMutatorSet> {
    crate::core::get_mutator_set(client.inner())
        .map(|ms| XntMutatorSet { inner: ms })
        .map_err(|e| Error::from_reason(format!("get_mutator_set: {e}")))
}

/// Check if UTXOs are spent by absolute index set hashes
/// Returns Vec<i64> where -1 = not spent, >= 0 = spent at that block height
#[napi(catch_unwind)]
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
#[napi(catch_unwind)]
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
    #[napi(getter, catch_unwind)]
    pub fn utxo(&self) -> XntUtxo {
        XntUtxo { inner: self.inner.utxo.clone() }
    }

    #[napi(getter, catch_unwind)]
    pub fn sender_randomness_hex(&self) -> String {
        self.inner.sender_randomness.to_hex()
    }

    #[napi(getter, catch_unwind)]
    pub fn payment_id(&self) -> i64 {
        self.inner.payment_id as i64
    }

    #[napi(getter, catch_unwind)]
    pub fn amount(&self) -> BigInt {
        BigInt::from(self.inner.utxo.amount())
    }

    #[napi(getter, catch_unwind)]
    pub fn block_height(&self) -> i64 {
        self.inner.block_height as i64
    }

    #[napi(getter, catch_unwind)]
    pub fn block_digest_hex(&self) -> String {
        self.inner.block_digest.to_hex()
    }

    /// Lock script hash of the UTXO as hex string
    #[napi(getter, catch_unwind)]
    pub fn lock_script_hash_hex(&self) -> String {
        hex::encode(self.inner.utxo.lock_script_hash().bytes)
    }

    /// True if the UTXO is at a legacy-format (pre-v0.3) dCTIDH lock. Such
    /// UTXOs are sweep-only: move them to a current-format key and never
    /// count them towards the available balance.
    #[napi(getter, catch_unwind)]
    pub fn is_legacy(&self) -> bool {
        self.inner.is_legacy
    }

    /// Get release date if timelocked (milliseconds since Unix epoch)
    #[napi(getter, catch_unwind)]
    pub fn release_date(&self) -> Option<BigInt> {
        self.inner.utxo.release_date().map(BigInt::from)
    }

    /// Check if UTXO is timelocked
    #[napi(getter, catch_unwind)]
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
    #[napi(getter, catch_unwind)]
    pub fn utxo(&self) -> XntUtxo {
        XntUtxo { inner: self.inner.utxo.clone() }
    }

    #[napi(getter, catch_unwind)]
    pub fn sender_randomness_hex(&self) -> String {
        self.inner.sender_randomness.to_hex()
    }

    #[napi(getter, catch_unwind)]
    pub fn commitment_hex(&self) -> String {
        self.inner.commitment.to_hex()
    }

    #[napi(getter, catch_unwind)]
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
    #[napi(getter, catch_unwind)]
    pub fn utxo(&self) -> XntUtxo {
        XntUtxo { inner: self.inner.utxo.clone() }
    }

    #[napi(getter, catch_unwind)]
    pub fn sender_randomness_hex(&self) -> String {
        self.inner.sender_randomness.to_hex()
    }

    #[napi(getter, catch_unwind)]
    pub fn receiver_digest_hex(&self) -> String {
        self.inner.receiver_digest.to_hex()
    }

    #[napi(getter, catch_unwind)]
    pub fn is_change(&self) -> bool {
        self.inner.is_change
    }

    #[napi(getter, catch_unwind)]
    pub fn payment_id(&self) -> Option<i64> {
        self.inner.payment_id.map(|id| id as i64)
    }

    #[napi(getter, catch_unwind)]
    pub fn commitment_hex(&self) -> String {
        self.inner.commitment.to_hex()
    }

    #[napi(getter, catch_unwind)]
    pub fn amount(&self) -> BigInt {
        BigInt::from(self.inner.utxo.amount())
    }
}

/// Decrypt indexed UTXO ciphertext
///
/// Applies the main-net legacy cutoff, the strictest one; see
/// `xntDecryptIndexedUtxoForNetwork`.
#[napi(catch_unwind)]
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

/// Decrypt indexed UTXO ciphertext, applying the legacy cutoff of `network`.
///
/// Throws for a UTXO at a legacy-format dCTIDH lock confirmed at or above
/// `xntLegacyDctidhCutoff(network)`. Legacy UTXOs below the cutoff have
/// `isLegacy` set: they are sweep-only.
#[napi(catch_unwind)]
pub fn xnt_decrypt_indexed_utxo_for_network(
    spending_key: &XntSpendingKey,
    ciphertext: Buffer,
    block_height: i64,
    block_digest_hex: String,
    network: XntNetwork,
) -> Result<XntDecryptedUtxo> {
    let block_digest = crate::core::Digest::from_hex(&block_digest_hex)
        .ok_or_else(|| Error::from_reason("invalid block_digest_hex"))?;
    let inner = crate::core::decrypt_indexed_utxo_for_network(
        spending_key.inner(),
        &ciphertext,
        block_height as u64,
        block_digest,
        network.into(),
    )
    .map_err(|e| Error::from_reason(format!("decrypt: {e}")))?;
    Ok(XntDecryptedUtxo { inner })
}

/// Compute commitment hash for UTXO
///
/// `receiver_preimage_hex` is a spending secret for dCTIDH keys, see
/// `XntSpendingKey.receiverPreimageHex`.
#[napi(catch_unwind)]
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
#[napi(catch_unwind)]
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
///
/// `receiver_preimage_hex` is a spending secret for dCTIDH keys, see
/// `XntSpendingKey.receiverPreimageHex`.
#[napi(catch_unwind)]
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
#[napi(catch_unwind)]
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
    is_legacy: bool,
}

#[napi]
impl XntPendingUtxo {
    #[napi(getter, catch_unwind)]
    pub fn utxo(&self) -> XntUtxo {
        XntUtxo { inner: self.utxo.clone() }
    }

    #[napi(getter, catch_unwind)]
    pub fn sender_randomness_hex(&self) -> String {
        hex::encode(self.sender_randomness.bytes)
    }

    #[napi(getter, catch_unwind)]
    pub fn payment_id(&self) -> i64 {
        self.payment_id as i64
    }

    #[napi(getter, catch_unwind)]
    pub fn amount(&self) -> BigInt {
        BigInt::from(self.utxo.amount())
    }

    /// True if the UTXO is at a legacy-format (pre-v0.3) dCTIDH lock, see
    /// `XntDecryptedUtxo.isLegacy`
    #[napi(getter, catch_unwind)]
    pub fn is_legacy(&self) -> bool {
        self.is_legacy
    }
}

/// Check mempool for pending spending (our UTXOs being spent)
/// Takes array of absolute_index_set_hash hex strings (from sync)
/// Returns indices of UTXOs with pending spends
#[napi(catch_unwind)]
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
///
/// For a legacy key nothing is returned once the next block is at or above
/// the main-net legacy cutoff.
#[napi(catch_unwind)]
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
            is_legacy: key.inner.is_legacy(),
        })
        .collect())
}

/// Get membership proofs for UTXOs
///
/// `receiver_preimage_hex` is a spending secret for dCTIDH keys (see
/// `XntSpendingKey.receiverPreimageHex`); it is used locally and not sent to
/// the node. Throws unless the node returns one proof per requested UTXO.
#[napi(catch_unwind)]
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
    #[napi(constructor, catch_unwind)]
    pub fn new() -> Self {
        Self {
            inner: TransactionBuilder::new(),
        }
    }

    /// Add input UTXO to spend
    #[napi(catch_unwind)]
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
    #[napi(catch_unwind)]
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
    #[napi(catch_unwind)]
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
    ///
    /// `build()` throws for a fee below 0.0005 coins per input, including a
    /// zero fee, unless `setAllowLowFee(true)` was called.
    #[napi(catch_unwind)]
    pub fn set_fee(&mut self, fee: BigInt) -> Result<()> {
        let (fee_i128, lossless) = fee.get_i128();
        if !lossless {
            return Err(Error::from_reason("fee overflow: value too large for i128"));
        }
        self.inner.set_fee(fee_i128);
        Ok(())
    }

    /// Allow a fee below the default minimum relay fee (0.0005 coins per
    /// input), including a zero fee. Nodes with the default
    /// `--min-relay-pctx-fee-per-input` neither keep nor relay such a
    /// transaction; use this only with a node configured to accept it.
    #[napi(catch_unwind)]
    pub fn set_allow_low_fee(&mut self, allow: bool) {
        self.inner.set_allow_low_fee(allow);
    }

    /// Get total input amount
    #[napi(catch_unwind)]
    pub fn input_total(&self) -> BigInt {
        BigInt::from(self.inner.input_total())
    }

    /// Get total output amount
    #[napi(catch_unwind)]
    pub fn output_total(&self) -> BigInt {
        BigInt::from(self.inner.output_total())
    }

    /// Get calculated change amount
    #[napi(catch_unwind)]
    pub fn change_amount(&self) -> BigInt {
        BigInt::from(self.inner.change_amount())
    }

    /// Build the transaction
    ///
    /// Throws for more than 200 inputs, for a fee below the minimum relay fee
    /// (see `setFee`), and for a recipient that cannot receive a UTXO
    /// notification (legacy-format dCTIDH lock or invalid dCTIDH public key).
    #[napi(catch_unwind)]
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
    ///
    /// Contains the primitive witness, see `witnessBytes`: keep it in the
    /// process that holds the seed.
    #[napi(catch_unwind)]
    pub fn to_bytes(&self) -> Result<Buffer> {
        self.inner
            .to_bytes()
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(format!("serialize: {e}")))
    }

    /// Get transaction kernel bytes
    #[napi(catch_unwind)]
    pub fn kernel_bytes(&self) -> Result<Buffer> {
        self.inner
            .kernel_bytes()
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(format!("kernel: {e}")))
    }

    /// Get witness bytes
    ///
    /// The witness holds the unlock data of every input, which for dCTIDH
    /// inputs is the key's spending secret (see
    /// `XntSpendingKey.receiverPreimageHex`). Keep it in the process that
    /// holds the seed.
    #[napi(catch_unwind)]
    pub fn witness_bytes(&self) -> Result<Buffer> {
        self.inner
            .witness_bytes()
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(format!("witness: {e}")))
    }

    /// Get all inputs
    #[napi(catch_unwind)]
    pub fn inputs(&self) -> Vec<XntTxInputInfo> {
        self.inner
            .inputs()
            .into_iter()
            .map(|i| XntTxInputInfo { inner: i })
            .collect()
    }

    /// Get all outputs (including change)
    #[napi(catch_unwind)]
    pub fn outputs(&self) -> Vec<XntTxOutputInfo> {
        self.inner
            .outputs()
            .into_iter()
            .map(|o| XntTxOutputInfo { inner: o })
            .collect()
    }

    /// Check the (unproven) transaction is still confirmable against `mutator_set`.
    /// Fetch the current tip via getMutatorSet and call this BEFORE prove() to
    /// avoid proving a stale snapshot.
    #[napi(catch_unwind)]
    pub fn is_confirmable(&self, mutator_set: &XntMutatorSet) -> bool {
        self.inner.is_confirmable(mutator_set.inner())
    }

    /// Prove the transaction (creates ProofCollection) for the consensus rule set
    /// of the block that follows the tip whose mutator set it was built on, as
    /// proveForTip does with that tip's height: before the UpgradeVMv8 hard fork
    /// at main-net block 97000, a v7 proof collection. Fails if that height is
    /// unknown (see XntMutatorSet.tipHeight); then use withTipHeight before
    /// building, or proveForTip.
    /// WARNING: CPU-intensive, requires ~16 GB RAM.
    #[napi(catch_unwind)]
    pub fn prove(&self) -> Result<XntTransaction> {
        let rt = global_tokio_runtime();

        rt.block_on(async {
            self.inner
                .prove()
                .await
                .map(|tx| XntTransaction { inner: tx })
                .map_err(|e| Error::from_reason(format!("prove: {e}")))
        })
    }

    /// Prove the transaction (creates ProofCollection) for the consensus rule set
    /// of the block that follows a tip at `tipHeight`: before the UpgradeVMv8
    /// hard fork on main net, a v7 proof collection. Fails if the transaction
    /// does not meet the terms of that era, or if the fork is too close.
    /// WARNING: CPU-intensive, requires ~16 GB RAM.
    #[napi(catch_unwind)]
    pub fn prove_for_tip(&self, tip_height: i64) -> Result<XntTransaction> {
        let tip_height = u64::try_from(tip_height)
            .map_err(|_| Error::from_reason("prove: tip height must not be negative"))?;
        let rt = global_tokio_runtime();

        rt.block_on(async {
            self.inner
                .prove_for_tip(tip_height)
                .await
                .map(|tx| XntTransaction { inner: tx })
                .map_err(|e| Error::from_reason(format!("prove: {e}")))
        })
    }
}

// Migration of legacy-format dCTIDH funds

/// An input of a migration transaction, or one left out of the
/// transactions, with the legacy key and the payment id it was received with.
/// A migration transaction merges the UTXOs of many payment ids into one
/// output; record what it moves per payment id from these.
#[napi(object)]
#[derive(Clone, Debug)]
pub struct XntMigrationInput {
    /// Index of the legacy key the UTXO is locked to
    /// (wallet.deriveLegacydCTIDHKey)
    pub key_index: i64,
    /// Payment id the UTXO was received with, 0 for the base address, as
    /// XntDecryptedUtxo.paymentId reports it
    pub payment_id: i64,
    /// Amount in nau, before fees
    pub amount: BigInt,
    /// Height of the block the UTXO was confirmed in
    pub block_height: i64,
    pub aocl_index: i64,
    /// Absolute index set hash, for xntCheckSpent: the UTXO is spent once
    /// the transaction spending it is confirmed
    pub absolute_index_set_hash_hex: String,
}

impl XntMigrationInput {
    fn from_core(input: &crate::core::MigrationInput) -> Self {
        Self {
            key_index: input.key_index as i64,
            payment_id: input.payment_id as i64,
            amount: BigInt::from(input.amount),
            block_height: input.block_height as i64,
            aocl_index: input.aocl_index as i64,
            absolute_index_set_hash_hex: input.absolute_index_set_hash.to_hex(),
        }
    }
}

/// What the transactions of a migration spend for one legacy key index and
/// payment id
#[napi(object)]
#[derive(Clone, Debug)]
pub struct XntMigrationPaymentIdTotal {
    pub key_index: i64,
    /// As XntDecryptedUtxo.paymentId reports it, 0 for the base address
    pub payment_id: i64,
    /// In nau, before fees
    pub amount: BigInt,
}

/// Transactions that move funds from legacy-format dCTIDH locks, see
/// xntBuildMigration
#[napi]
pub struct XntMigrationPlan {
    transactions: Vec<Option<crate::core::BuiltTransaction>>,
    input_hashes: Vec<Vec<String>>,
    swept_inputs: Vec<Vec<crate::core::MigrationInput>>,
    dust_input_info: Vec<crate::core::MigrationInput>,
    time_locked_info: Vec<crate::core::MigrationInput>,
    totals_by_payment_id: Vec<(u64, u64, i128)>,
    total: i128,
    fees: i128,
    dust_inputs: usize,
    time_locked: usize,
    skipped: usize,
    tip_height: u64,
}

impl XntMigrationPlan {
    fn from_core(plan: crate::core::MigrationPlan) -> Self {
        let input_hashes = plan
            .swept
            .iter()
            .map(|inputs| {
                inputs
                    .iter()
                    .map(|input| input.absolute_index_set_hash().to_hex())
                    .collect()
            })
            .collect();
        Self {
            dust_inputs: plan.dust.iter().map(Vec::len).sum(),
            time_locked: plan.time_locked.len(),
            skipped: plan.skipped.total(),
            total: plan.total,
            fees: plan.fees,
            tip_height: plan.tip_height,
            input_hashes,
            totals_by_payment_id: plan.totals_by_payment_id(),
            swept_inputs: plan.swept_inputs,
            dust_input_info: plan.dust_inputs.into_iter().flatten().collect(),
            time_locked_info: plan.time_locked_inputs,
            transactions: plan.transactions.into_iter().map(Some).collect(),
        }
    }
}

#[napi]
impl XntMigrationPlan {
    /// Number of transactions
    #[napi(catch_unwind)]
    pub fn num_transactions(&self) -> u32 {
        self.transactions.len() as u32
    }

    /// Take all transactions not taken yet, the largest amounts first. Each
    /// has one output, to the destination, and no change.
    #[napi(catch_unwind)]
    pub fn take_transactions(&mut self) -> Vec<XntBuiltTransaction> {
        self.transactions
            .iter_mut()
            .filter_map(Option::take)
            .map(|inner| XntBuiltTransaction { inner })
            .collect()
    }

    /// Hex absolute index set hashes of the inputs of the transaction at
    /// `index`, for xntCheckSpent: the transaction is confirmed once its inputs
    /// are spent.
    #[napi(catch_unwind)]
    pub fn input_hashes(&self, index: u32) -> Result<Vec<String>> {
        self.input_hashes
            .get(index as usize)
            .cloned()
            .ok_or_else(|| Error::from_reason("no transaction at this index"))
    }

    /// Inputs of the transaction at `index` with their legacy key index,
    /// payment id, amount, block height, AOCL index and absolute index set
    /// hash, in the order of inputHashes
    #[napi(catch_unwind)]
    pub fn inputs(&self, index: u32) -> Result<Vec<XntMigrationInput>> {
        self.swept_inputs
            .get(index as usize)
            .map(|inputs| inputs.iter().map(XntMigrationInput::from_core).collect())
            .ok_or_else(|| Error::from_reason("no transaction at this index"))
    }

    /// What the transactions spend per legacy key index and payment id, in
    /// nau, before fees, sorted by key index and payment id. Covers the
    /// inputs of the transactions, not those left out (dustInputInfo,
    /// timeLockedInfo).
    #[napi(catch_unwind)]
    pub fn totals_by_payment_id(&self) -> Vec<XntMigrationPaymentIdTotal> {
        self.totals_by_payment_id
            .iter()
            .map(|&(key_index, payment_id, amount)| XntMigrationPaymentIdTotal {
                key_index: key_index as i64,
                payment_id: payment_id as i64,
                amount: BigInt::from(amount),
            })
            .collect()
    }

    /// The inputs left out because their batch holds no more than its fee,
    /// see inputs()
    #[napi(catch_unwind)]
    pub fn dust_input_info(&self) -> Vec<XntMigrationInput> {
        self.dust_input_info.iter().map(XntMigrationInput::from_core).collect()
    }

    /// The UTXOs at legacy-format locks left out because their time lock is
    /// not released yet, see inputs()
    #[napi(catch_unwind)]
    pub fn time_locked_info(&self) -> Vec<XntMigrationInput> {
        self.time_locked_info.iter().map(XntMigrationInput::from_core).collect()
    }

    /// Total moved to the destination, after fees, in nau
    #[napi(catch_unwind)]
    pub fn total(&self) -> BigInt {
        BigInt::from(self.total)
    }

    /// Total of the fees in nau
    #[napi(catch_unwind)]
    pub fn fees(&self) -> BigInt {
        BigInt::from(self.fees)
    }

    /// Height of the tip whose mutator set and membership proofs the
    /// transactions were built on
    #[napi(catch_unwind)]
    pub fn tip_height(&self) -> i64 {
        i64::try_from(self.tip_height).unwrap_or(i64::MAX)
    }

    /// Number of inputs left out because their batch holds no more than its
    /// fee
    #[napi(catch_unwind)]
    pub fn dust_inputs(&self) -> u32 {
        self.dust_inputs as u32
    }

    /// Number of UTXOs at legacy-format locks left out because their time
    /// lock is not released yet
    #[napi(catch_unwind)]
    pub fn time_locked(&self) -> u32 {
        self.time_locked as u32
    }

    /// Number of indexed entries the scans skipped
    #[napi(catch_unwind)]
    pub fn skipped(&self) -> u32 {
        self.skipped as u32
    }
}

/// Build the transactions that move every UTXO at the legacy-format dCTIDH
/// locks of the given key indices of `wallet` that can be spent now to the
/// bech32m address `destination` (a Generation or current-format dCTIDH
/// address of `network`), ready for prove(). Nothing is proven or submitted.
///
/// At most 10 inputs per transaction, the largest first, and the fee the node
/// uses for its own migration (0.1 coins for a proof collection); see
/// xntBuildMigrationWith. A proof collection is valid only for the mutator set
/// it was built on: prove, check and submit each transaction right away, and
/// build the remaining ones again after a new block.
#[napi(catch_unwind)]
pub fn xnt_build_migration(
    client: &XntRpcClient,
    wallet: &XntWalletEntropy,
    legacy_indices: Vec<i64>,
    destination: String,
    network: XntNetwork,
) -> Result<XntMigrationPlan> {
    xnt_build_migration_with(client, wallet, legacy_indices, destination, network, None, None, None, None)
}

/// xntBuildMigration with options: `fee` the fee of each transaction in nau,
/// `maxInputs` the most inputs per transaction (default 10; before the
/// UpgradeVMv8 fork capped at 10 with time locks, 11 without), and the heights
/// scanned from `fromHeight` (default 0) to `toHeight` (default the tip).
#[napi(catch_unwind)]
#[allow(clippy::too_many_arguments)]
pub fn xnt_build_migration_with(
    client: &XntRpcClient,
    wallet: &XntWalletEntropy,
    legacy_indices: Vec<i64>,
    destination: String,
    network: XntNetwork,
    fee: Option<BigInt>,
    max_inputs: Option<u32>,
    from_height: Option<i64>,
    to_height: Option<i64>,
) -> Result<XntMigrationPlan> {
    let indices = legacy_indices
        .iter()
        .map(|&index| u64::try_from(index))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::from_reason("key indices must not be negative"))?;
    let mut options = crate::core::MigrationOptions::default();
    if let Some(fee) = fee {
        let (fee, lossless) = fee.get_i128();
        if !lossless {
            return Err(Error::from_reason("fee overflow: value too large for i128"));
        }
        options.fee = Some(fee);
    }
    if let Some(max_inputs) = max_inputs {
        options.max_inputs = max_inputs as usize;
    }
    if let Some(from_height) = from_height {
        options.from_height = u64::try_from(from_height)
            .map_err(|_| Error::from_reason("heights must not be negative"))?;
    }
    if let Some(to_height) = to_height {
        options.to_height = Some(
            u64::try_from(to_height)
                .map_err(|_| Error::from_reason("heights must not be negative"))?,
        );
    }

    crate::core::build_migration_with(
        client.inner(),
        &wallet.inner,
        &indices,
        &destination,
        network.into(),
        &options,
    )
    .map(XntMigrationPlan::from_core)
    .map_err(|e| Error::from_reason(format!("build migration: {e}")))
}

/// Final transaction
#[napi]
pub struct XntTransaction {
    inner: crate::core::Transaction,
}

#[napi]
impl XntTransaction {
    /// Deserialize from bytes
    #[napi(factory, catch_unwind)]
    pub fn from_bytes(data: Buffer) -> Result<Self> {
        crate::core::Transaction::from_bytes(&data)
            .map(|tx| Self { inner: tx })
            .map_err(|e| Error::from_reason(format!("deserialize: {e}")))
    }

    /// Serialize to bytes
    #[napi(catch_unwind)]
    pub fn to_bytes(&self) -> Result<Buffer> {
        self.inner
            .to_bytes()
            .map(Buffer::from)
            .map_err(|e| Error::from_reason(format!("serialize: {e}")))
    }

    /// Check if has ProofCollection
    #[napi(catch_unwind)]
    pub fn has_proof_collection(&self) -> bool {
        self.inner.has_proof_collection()
    }

    /// Check if has SingleProof
    #[napi(catch_unwind)]
    pub fn has_single_proof(&self) -> bool {
        self.inner.has_single_proof()
    }

    /// Check the transaction is confirmable against `mutator_set` (mirrors the
    /// node submit gate). Fetch the current tip via getMutatorSet and call this
    /// before submit() to detect a transaction that went stale while proving.
    #[napi(catch_unwind)]
    pub fn is_confirmable(&self, mutator_set: &XntMutatorSet) -> bool {
        self.inner.is_confirmable(mutator_set.inner())
    }

    /// Submit transaction to node. Returns the node's `success` field. `true`
    /// only means the node passed its validity and confirmability checks and
    /// queued the transaction for its mempool: the node can still drop it,
    /// for example if the fee is below its relay minimum. Confirm by looking
    /// the transaction up in the mempool or waiting for its outputs on chain.
    /// `false` means the node did not queue it. Throws for rejections the node
    /// reports as errors (for example `NotConfirmable`) and on RPC/transport
    /// errors.
    #[napi(catch_unwind)]
    pub fn submit(&self, client: &XntRpcClient) -> Result<bool> {
        self.inner
            .submit(client.inner())
            .map_err(|e| Error::from_reason(format!("submit: {e}")))
    }
}

// Utilities

/// Library version
#[napi(catch_unwind)]
pub fn xnt_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get current timestamp in milliseconds
#[napi(catch_unwind)]
pub fn xnt_timestamp_now() -> i64 {
    crate::core::timestamp_now() as i64
}

/// Generate random sender randomness (40 bytes hex)
///
/// Uses cryptographically secure OsRng for transaction privacy
#[napi(catch_unwind)]
pub fn xnt_random_sender_randomness() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 40];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Select UTXOs to cover target amount (smallest-first)
///
/// At most 200 inputs are selected, whatever `limit` is.
#[napi(catch_unwind)]
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
