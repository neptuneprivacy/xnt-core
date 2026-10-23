//! Moving funds from legacy-format dCTIDH locks to a current-format address
//!
//! [build_migration] scans the given legacy-derivation dCTIDH keys of a wallet
//! (see [WalletEntropy::derive_legacy_dctidh_spending_key]) and builds the
//! transactions that move every UTXO they can spend now to one destination, a
//! Generation or current-format dCTIDH address. The transactions are ready for
//! [BuiltTransaction::prove], which proves each for the consensus rule set of
//! the block after the tip it was built on. Nothing is proven or submitted
//! here.
//!
//! A proof collection is valid only against the mutator set it was built on.
//! Prove, check ([crate::core::Transaction::is_confirmable]) and submit each
//! transaction right away, one after the other, and build the remaining ones
//! again after a new block.
//!
//! The transactions merge the UTXOs of all payment ids of a key into one
//! output. [MigrationPlan::swept_inputs] and [MigrationPlan::totals_by_payment_id]
//! tell, per input and per payment id, what they move.

use std::collections::BTreeMap;
use std::collections::HashMap;

use neptune_privacy::api::export::BlockHeight;
use neptune_privacy::api::export::ConsensusRuleSet;
use neptune_privacy::api::export::NativeCurrencyAmount;
use neptune_privacy::api::export::TxProvingCapability;
use neptune_privacy::api::tx_initiation::legacy_era;
use neptune_privacy::api::tx_initiation::migrate_dctidh::migration_fee;
use neptune_privacy::prelude::tasm_lib::prelude::Digest as CoreDigest;
use neptune_privacy::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use neptune_privacy::protocol::consensus::type_scripts::time_lock::TimeLock;
use neptune_privacy::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;
use neptune_privacy::protocol::proof_abstractions::tasm::program::ConsensusProgram;

use super::address::Address;
use super::error::{Result, XntError};
use super::json_rpc::RpcClient;
use super::sync::{
    collect_spendable_inputs, get_mutator_set, MutatorSet, ScanStats, SpendableInput,
};
use super::transaction::{
    timestamp_now, BuiltTransaction, TransactionBuilder, MAX_INPUTS, MIN_RELAY_FEE_PER_INPUT_NAU,
};
use super::types::{Digest, Network};
use super::wallet::WalletEntropy;

/// Most inputs of a migration transaction, unless configured otherwise: the
/// limit of the era before the UpgradeVMv8 fork for transactions with time
/// locks, see [MigrationOptions::max_inputs].
pub const DEFAULT_MIGRATION_MAX_INPUTS: usize = 10;

/// Number of times [build_migration_with] scans at most, while blocks arrive
/// during a scan.
const MIGRATION_SCAN_ATTEMPTS: usize = 3;

/// Options of [build_migration_with]
#[derive(Clone, Copy, Debug)]
pub struct MigrationOptions {
    /// Fee of each transaction in nau, or `None` for the fee the node uses for
    /// its own migration transactions (`migrate_dctidh::migration_fee`):
    /// 0.1 coins for a proof collection, and no less than 0.0005 coins per
    /// input. Before the fork it must be at least 0.017 coins.
    pub fee: Option<i128>,
    /// Most inputs per transaction. Before the UpgradeVMv8 fork it is capped
    /// at the limit of that era: 10 if an input carries a time lock, 11
    /// otherwise; after it at [MAX_INPUTS].
    pub max_inputs: usize,
    /// Lowest block height scanned.
    pub from_height: u64,
    /// Highest block height scanned, or `None` for the tip.
    pub to_height: Option<u64>,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            fee: None,
            max_inputs: DEFAULT_MIGRATION_MAX_INPUTS,
            from_height: 0,
            to_height: None,
        }
    }
}

/// An input of a migration transaction, or one left out of the
/// transactions, with the legacy key and the payment id it was received with.
///
/// A migration transaction merges the UTXOs of many payment ids into one
/// output; these tell which deposits it moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationInput {
    /// Index of the legacy key the UTXO is locked to, see
    /// [WalletEntropy::derive_legacy_dctidh_spending_key].
    pub key_index: u64,
    /// Payment id the UTXO was received with, 0 for the base address, see
    /// [SpendableInput::payment_id].
    pub payment_id: u64,
    /// Amount of the UTXO in nau, before fees.
    pub amount: i128,
    /// Height of the block the UTXO was confirmed in.
    pub block_height: u64,
    /// AOCL leaf index of the UTXO.
    pub aocl_index: u64,
    /// Hash of the absolute index set of the UTXO, for
    /// [crate::core::check_spent]: it is spent once the transaction spending
    /// it is confirmed.
    pub absolute_index_set_hash: Digest,
}

/// Transactions that move the funds at legacy-format dCTIDH locks, see
/// [build_migration]
pub struct MigrationPlan {
    /// The transactions, ready for proving, the largest amounts first. Each
    /// has one output, to the destination, and no change.
    pub transactions: Vec<BuiltTransaction>,
    /// The inputs each transaction spends, by position: watch them to see
    /// the transaction confirmed.
    pub swept: Vec<Vec<SpendableInput>>,
    /// [MigrationPlan::swept] with the legacy key index and payment id of
    /// each input, in the same order.
    pub swept_inputs: Vec<Vec<MigrationInput>>,
    /// Total moved to the destination, after fees, in nau.
    pub total: i128,
    /// Total of the fees, in nau.
    pub fees: i128,
    /// Batches of inputs for which no transaction was built, as they hold no
    /// more than the fee.
    pub dust: Vec<Vec<SpendableInput>>,
    /// [MigrationPlan::dust] with the legacy key index and payment id of each
    /// input, in the same order.
    pub dust_inputs: Vec<Vec<MigrationInput>>,
    /// UTXOs at legacy-format locks that cannot be spent yet, as their time
    /// lock is not released.
    pub time_locked: Vec<SpendableInput>,
    /// [MigrationPlan::time_locked] with the legacy key index and payment id
    /// of each UTXO, in the same order.
    pub time_locked_inputs: Vec<MigrationInput>,
    /// Indexed entries the scans of all keys skipped.
    pub skipped: ScanStats,
    /// Height of the tip whose mutator set and membership proofs the
    /// transactions were built on.
    pub tip_height: u64,
}

impl MigrationPlan {
    /// What the transactions spend per legacy key index and payment id, in
    /// nau, before fees: (key index, payment id, amount), sorted by key index
    /// and payment id.
    ///
    /// Covers the inputs of the transactions, [MigrationPlan::swept_inputs],
    /// not those left out ([MigrationPlan::dust_inputs],
    /// [MigrationPlan::time_locked_inputs]).
    pub fn totals_by_payment_id(&self) -> Vec<(u64, u64, i128)> {
        let mut totals: BTreeMap<(u64, u64), i128> = BTreeMap::new();
        for input in self.swept_inputs.iter().flatten() {
            let total = totals
                .entry((input.key_index, input.payment_id))
                .or_default();
            *total = total.saturating_add(input.amount);
        }
        totals
            .into_iter()
            .map(|((key_index, payment_id), amount)| (key_index, payment_id, amount))
            .collect()
    }
}

/// Build the transactions that move every UTXO at the legacy-format dCTIDH
/// locks of the given key indices of `wallet` that can be spent now to the
/// bech32m address `destination`, with the default [MigrationOptions].
///
/// See [build_migration_with].
pub fn build_migration(
    client: &RpcClient,
    wallet: &WalletEntropy,
    legacy_indices: &[u64],
    destination: &str,
    network: Network,
) -> Result<MigrationPlan> {
    build_migration_with(
        client,
        wallet,
        legacy_indices,
        destination,
        network,
        &MigrationOptions::default(),
    )
}

/// Build the transactions that move every UTXO at the legacy-format dCTIDH
/// locks of the given key indices of `wallet` that can be spent now to the
/// bech32m address `destination`.
///
/// `destination` is decoded for `network`, which refuses an address of
/// another network and a legacy-format dCTIDH address, and must be able to
/// receive a UTXO notification. Each key is scanned with
/// [collect_spendable_inputs], which also applies the legacy cutoff of
/// `network`. The scans and the mutator set the transactions are built on
/// belong to the same tip: if a block arrives during the scans, they are
/// repeated, up to 3 times.
///
/// The inputs are batched largest first, at most [MigrationOptions::max_inputs]
/// per transaction, each input unlocked with the key it belongs to. Each
/// transaction pays the fee and moves the rest of its inputs to the
/// destination; a batch that holds no more than the fee is reported in
/// [MigrationPlan::dust] instead. Fails within the cutoff margin before the
/// UpgradeVMv8 fork (10 blocks), when no new transaction is made.
///
/// Each input, also those left out, is reported with the index of the legacy
/// key it was found with and its payment id in [MigrationPlan::swept_inputs],
/// [MigrationPlan::dust_inputs] and [MigrationPlan::time_locked_inputs].
pub fn build_migration_with(
    client: &RpcClient,
    wallet: &WalletEntropy,
    legacy_indices: &[u64],
    destination: &str,
    network: Network,
    options: &MigrationOptions,
) -> Result<MigrationPlan> {
    let destination = Address::from_bech32(destination, network)?;
    if legacy_indices.is_empty() {
        return Err(XntError::InvalidInput("no legacy key indices".to_string()));
    }
    let mut indices = legacy_indices.to_vec();
    indices.sort_unstable();
    indices.dedup();
    let keys: Vec<_> = indices
        .iter()
        .map(|&index| wallet.derive_legacy_dctidh_spending_key(index))
        .collect();

    for _ in 0..MIGRATION_SCAN_ATTEMPTS {
        let tip_height = client.chain_height()?;
        let to_height = options
            .to_height
            .map_or(tip_height, |height| height.min(tip_height));
        let mut inputs = Vec::new();
        let mut key_indices = HashMap::new();
        let mut skipped = ScanStats::default();
        for (&key_index, key) in indices.iter().zip(&keys) {
            let (key_inputs, stats) =
                collect_spendable_inputs(client, key, network, options.from_height, to_height)?;
            key_indices.extend(key_inputs.iter().map(|input| (input.aocl_index, key_index)));
            inputs.extend(key_inputs);
            add_scan_stats(&mut skipped, &stats);
        }

        // The membership proofs must be of the tip whose mutator set the
        // transactions are built on.
        let mutator_set = get_mutator_set(client)?;
        let same_tip = mutator_set.tip_height() == Some(tip_height)
            && inputs
                .iter()
                .all(|input| mutator_set.verify(&input.utxo.hash(), &input.membership_proof));
        if !same_tip {
            continue;
        }

        return build_migration_from_inputs(
            inputs,
            &key_indices,
            skipped,
            &destination,
            &mutator_set,
            network,
            options,
            timestamp_now(),
        );
    }

    Err(XntError::RpcError(format!(
        "the tip changed while scanning the legacy keys, {MIGRATION_SCAN_ATTEMPTS} times"
    )))
}

fn add_scan_stats(total: &mut ScanStats, stats: &ScanStats) {
    total.malformed += stats.malformed;
    total.undecryptable += stats.undecryptable;
    total.foreign_lock += stats.foreign_lock;
    total.legacy_after_cutoff += stats.legacy_after_cutoff;
}

/// The fee of a migration transaction with `num_inputs` inputs, as the node
/// uses it for its own migration: see [MigrationOptions::fee].
fn default_migration_fee(num_inputs: usize) -> i128 {
    migration_fee(
        TxProvingCapability::ProofCollection,
        NativeCurrencyAmount::from_nau(MIN_RELAY_FEE_PER_INPUT_NAU),
        num_inputs,
    )
    .to_nau()
}

/// The most inputs of a migration transaction under `consensus_rule_set`:
/// before the fork the limit of that era (`legacy_era::legacy_era_max_num_inputs`)
/// for the distinct type scripts of all `inputs` and of the output (the native
/// currency), with the legacy time lock counted as `TimeLockV2`, as the proof
/// collection proves them; after it [MAX_INPUTS].
fn max_num_inputs(inputs: &[SpendableInput], consensus_rule_set: ConsensusRuleSet) -> usize {
    if consensus_rule_set != ConsensusRuleSet::UpgradeVMv7 {
        return MAX_INPUTS;
    }

    let time_lock_hash = TimeLock.hash();
    let time_lock_v2_hash = TimeLockV2.hash();
    let mut type_script_hashes: Vec<CoreDigest> = vec![NativeCurrency.hash()];
    for input in inputs {
        for coin in input.utxo.inner.coins() {
            let hash = if coin.type_script_hash == time_lock_hash {
                time_lock_v2_hash
            } else {
                coin.type_script_hash
            };
            if !type_script_hashes.contains(&hash) {
                type_script_hashes.push(hash);
            }
        }
    }

    legacy_era::legacy_era_max_num_inputs(type_script_hashes.len())
}

/// The inputs in batches of at most `max_inputs`, the largest amounts first.
fn migration_batches(
    mut inputs: Vec<SpendableInput>,
    max_inputs: usize,
) -> Vec<Vec<SpendableInput>> {
    inputs.sort_by(|left, right| {
        right
            .amount
            .cmp(&left.amount)
            .then(left.aocl_index.cmp(&right.aocl_index))
    });
    inputs
        .chunks(max_inputs)
        .map(|batch| batch.to_vec())
        .collect()
}

/// The [MigrationInput] of each of `inputs`, with the legacy key index
/// `key_indices` maps its AOCL index to.
fn migration_inputs(
    inputs: &[SpendableInput],
    key_indices: &HashMap<u64, u64>,
) -> Result<Vec<MigrationInput>> {
    inputs
        .iter()
        .map(|input| {
            let key_index = *key_indices.get(&input.aocl_index).ok_or_else(|| {
                XntError::InvalidInput(format!(
                    "no legacy key index for the input at AOCL index {}",
                    input.aocl_index
                ))
            })?;
            Ok(MigrationInput {
                key_index,
                payment_id: input.payment_id,
                amount: input.amount,
                block_height: input.block_height,
                aocl_index: input.aocl_index,
                absolute_index_set_hash: input.absolute_index_set_hash(),
            })
        })
        .collect()
}

/// [build_migration_with] for inputs and a mutator set of the same tip, the
/// one [MutatorSet::tip_height] names, at the time `now_ms`. `key_indices`
/// maps the AOCL index of each input to the index of the legacy key it was
/// found with.
fn build_migration_from_inputs(
    inputs: Vec<SpendableInput>,
    key_indices: &HashMap<u64, u64>,
    skipped: ScanStats,
    destination: &Address,
    mutator_set: &MutatorSet,
    network: Network,
    options: &MigrationOptions,
    now_ms: u64,
) -> Result<MigrationPlan> {
    let tip_height = mutator_set.tip_height().ok_or_else(|| {
        XntError::InvalidInput("the tip height of the mutator set is unknown".to_string())
    })?;
    let consensus_rule_set = legacy_era::rule_set_for_new_transaction(
        network.into(),
        BlockHeight::from(tip_height),
        legacy_era::DEFAULT_FORK_TX_CUTOFF_MARGIN,
    )
    .map_err(|e| XntError::TransactionError(e.to_string()))?;
    if options.max_inputs == 0 {
        return Err(XntError::InvalidInput(
            "max_inputs must be positive".to_string(),
        ));
    }

    // Each UTXO once, also if it was found twice.
    let mut inputs = inputs;
    inputs.sort_by_key(|input| input.aocl_index);
    inputs.dedup_by_key(|input| input.aocl_index);
    let (spendable, time_locked): (Vec<_>, Vec<_>) = inputs
        .into_iter()
        .filter(|input| input.is_legacy)
        .partition(|input| input.utxo.can_spend_at(now_ms));
    let max_inputs = options
        .max_inputs
        .min(max_num_inputs(&spendable, consensus_rule_set));

    let mut plan = MigrationPlan {
        transactions: Vec::new(),
        swept: Vec::new(),
        swept_inputs: Vec::new(),
        total: 0,
        fees: 0,
        dust: Vec::new(),
        dust_inputs: Vec::new(),
        time_locked_inputs: migration_inputs(&time_locked, key_indices)?,
        time_locked,
        skipped,
        tip_height,
    };
    for batch in migration_batches(spendable, max_inputs) {
        let amount = batch
            .iter()
            .try_fold(0i128, |sum, input| sum.checked_add(input.amount))
            .ok_or_else(|| XntError::TransactionError("input total overflow".into()))?;
        let fee = options
            .fee
            .unwrap_or_else(|| default_migration_fee(batch.len()));
        if amount <= fee {
            plan.dust_inputs
                .push(migration_inputs(&batch, key_indices)?);
            plan.dust.push(batch);
            continue;
        }

        let mut builder = TransactionBuilder::new();
        for input in &batch {
            builder.add_input(
                input.utxo.clone(),
                input.spending_key.clone(),
                input.membership_proof.clone(),
            );
        }
        builder.add_output(
            destination.to_receiving_address(),
            amount - fee,
            Digest::from_core(rand::random::<CoreDigest>()),
        );
        builder.set_fee(fee);
        let built = builder.build(mutator_set, now_ms, network)?;

        // Before the fork, the terms of that era apply, which prove() checks
        // again.
        if consensus_rule_set == ConsensusRuleSet::UpgradeVMv7 {
            legacy_era::check_proof_collection_terms(built.witness())
                .map_err(|e| XntError::TransactionError(e.to_string()))?;
        }

        plan.total += amount - fee;
        plan.fees += fee;
        plan.transactions.push(built);
        plan.swept_inputs
            .push(migration_inputs(&batch, key_indices)?);
        plan.swept.push(batch);
    }

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::sync::MembershipProof;
    use crate::core::utxo::Utxo;
    use crate::core::wallet::SpendingKey;

    fn coins(amount: &str) -> i128 {
        NativeCurrencyAmount::coins_from_str(amount)
            .unwrap()
            .to_nau()
    }

    /// Membership proof with the given AOCL leaf index and no authentication
    /// data, as in the transaction builder tests.
    fn dummy_membership_proof(aocl_leaf_index: u64) -> MembershipProof {
        let mut bytes = vec![0u8; 40 + 40 + 8];
        bytes.extend_from_slice(&aocl_leaf_index.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        MembershipProof::from_bytes(&bytes).unwrap()
    }

    /// An input at the legacy-format lock of `key` holding `amount`, received
    /// at the base address.
    fn input(key: &SpendingKey, aocl_index: u64, amount: i128) -> SpendableInput {
        input_with_payment_id(key, aocl_index, amount, 0)
    }

    /// An input at the legacy-format lock of `key` holding `amount`, received
    /// with `payment_id`.
    fn input_with_payment_id(
        key: &SpendingKey,
        aocl_index: u64,
        amount: i128,
        payment_id: u64,
    ) -> SpendableInput {
        let utxo = Utxo::from_core(neptune_privacy::api::export::Utxo::new_native_currency(
            key.lock_script_hash().to_core(),
            NativeCurrencyAmount::from_nau(amount),
        ));
        SpendableInput {
            utxo,
            spending_key: key.clone(),
            membership_proof: dummy_membership_proof(aocl_index),
            sender_randomness: Digest::new(),
            aocl_index,
            amount,
            block_height: 1,
            block_digest: Digest::new(),
            is_legacy: key.is_legacy(),
            payment_id,
        }
    }

    fn mutator_set(tip_height: u64) -> MutatorSet {
        MutatorSet::from_core(Default::default()).with_tip_height(tip_height)
    }

    fn destination() -> Address {
        WalletEntropy::devnet()
            .derive_dctidh_spending_key(0)
            .to_address()
            .unwrap()
    }

    /// The AOCL index of each input mapped to the index of the devnet legacy
    /// key it is locked to, as the scans of [build_migration_with] record it.
    fn key_indices(inputs: &[SpendableInput]) -> HashMap<u64, u64> {
        let wallet = WalletEntropy::devnet();
        let locks: Vec<_> = (0..2)
            .map(|index| {
                wallet
                    .derive_legacy_dctidh_spending_key(index)
                    .lock_script_hash()
            })
            .collect();
        inputs
            .iter()
            .filter_map(|input| {
                let lock = input.spending_key.lock_script_hash();
                let index = locks.iter().position(|own| *own == lock)?;
                Some((input.aocl_index, index as u64))
            })
            .collect()
    }

    fn plan(
        inputs: Vec<SpendableInput>,
        tip_height: u64,
        options: &MigrationOptions,
    ) -> Result<MigrationPlan> {
        let key_indices = key_indices(&inputs);
        build_migration_from_inputs(
            inputs,
            &key_indices,
            ScanStats::default(),
            &destination(),
            &mutator_set(tip_height),
            Network::Main,
            options,
            timestamp_now(),
        )
    }

    fn amounts(batch: &[SpendableInput]) -> Vec<i128> {
        batch.iter().map(|input| input.amount).collect()
    }

    #[test]
    fn inputs_are_batched_largest_first_within_the_cap() {
        let wallet = WalletEntropy::devnet();
        let key = wallet.derive_legacy_dctidh_spending_key(0);
        let inputs: Vec<_> = (1..=25)
            .map(|i| input(&key, i, coins("1") * i as i128))
            .collect();

        let batches = migration_batches(inputs, 10);
        assert_eq!(
            vec![10, 10, 5],
            batches.iter().map(Vec::len).collect::<Vec<_>>()
        );
        assert_eq!(coins("25"), batches[0][0].amount);
        assert_eq!(coins("1"), batches[2][4].amount);
        for batch in &batches {
            assert!(amounts(batch).windows(2).all(|pair| pair[0] >= pair[1]));
        }
    }

    #[test]
    fn the_cap_is_that_of_the_era_before_the_fork() {
        let wallet = WalletEntropy::devnet();
        let key = wallet.derive_legacy_dctidh_spending_key(0);
        let plain: Vec<_> = (0..3).map(|i| input(&key, i, coins("1"))).collect();
        assert_eq!(11, max_num_inputs(&plain, ConsensusRuleSet::UpgradeVMv7));
        assert_eq!(
            MAX_INPUTS,
            max_num_inputs(&plain, ConsensusRuleSet::UpgradeVMv8)
        );

        let mut time_locked = input(&key, 3, coins("1"));
        time_locked.utxo = time_locked.utxo.with_time_lock(1);
        let with_time_lock = [plain, vec![time_locked]].concat();
        assert_eq!(
            10,
            max_num_inputs(&with_time_lock, ConsensusRuleSet::UpgradeVMv7)
        );

        // Configured higher, the cap of the era holds: 12 inputs before the
        // fork make two transactions of 11 and 1.
        let many: Vec<_> = (0..12).map(|i| input(&key, i, coins("1"))).collect();
        let options = MigrationOptions {
            max_inputs: 50,
            ..MigrationOptions::default()
        };
        let before = plan(many.clone(), 94_000, &options).unwrap();
        assert_eq!(
            vec![11, 1],
            before.swept.iter().map(Vec::len).collect::<Vec<_>>()
        );
        let after = plan(many, 97_000, &options).unwrap();
        assert_eq!(
            vec![12],
            after.swept.iter().map(Vec::len).collect::<Vec<_>>()
        );
    }

    #[test]
    fn each_transaction_moves_its_inputs_less_the_fee_to_the_destination() {
        let wallet = WalletEntropy::devnet();
        let first = wallet.derive_legacy_dctidh_spending_key(0);
        let second = wallet.derive_legacy_dctidh_spending_key(1);

        // Two indices in one batch, each input with its own key.
        let inputs = vec![
            input(&first, 0, coins("5")),
            input(&second, 1, coins("3")),
            input(&first, 2, coins("2")),
        ];
        let plan = plan(inputs, 94_000, &MigrationOptions::default()).unwrap();
        assert_eq!(1, plan.transactions.len());
        assert_eq!(coins("0.1"), plan.fees);
        assert_eq!(coins("9.9"), plan.total);
        assert_eq!(94_000, plan.tip_height);

        let transaction = &plan.transactions[0];
        let outputs = transaction.outputs();
        assert_eq!(1, outputs.len(), "one output, no change");
        assert_eq!(coins("9.9"), outputs[0].utxo.amount());
        assert_eq!(
            destination().lock_script_hash(),
            outputs[0].utxo.lock_script_hash()
        );
        assert!(!outputs[0].is_change);
        assert_eq!(Some(94_000), transaction.tip_height());

        let swept_locks: Vec<_> = plan.swept[0]
            .iter()
            .map(|input| input.spending_key.lock_script_hash())
            .collect();
        assert_eq!(
            vec![
                first.lock_script_hash(),
                second.lock_script_hash(),
                first.lock_script_hash()
            ],
            swept_locks
        );

        // A given fee.
        let options = MigrationOptions {
            fee: Some(coins("0.5")),
            ..MigrationOptions::default()
        };
        let inputs = vec![input(&first, 0, coins("5"))];
        let plan = plan_with(inputs, &options);
        assert_eq!(coins("4.5"), plan.total);
        assert_eq!(coins("0.5"), plan.fees);
    }

    fn plan_with(inputs: Vec<SpendableInput>, options: &MigrationOptions) -> MigrationPlan {
        plan(inputs, 94_000, options).unwrap()
    }

    #[test]
    fn each_utxo_is_spent_once() {
        let wallet = WalletEntropy::devnet();
        let key = wallet.derive_legacy_dctidh_spending_key(0);
        let inputs = vec![
            input(&key, 0, coins("1")),
            input(&key, 1, coins("2")),
            input(&key, 0, coins("1")),
        ];
        let plan = plan_with(inputs, &MigrationOptions::default());
        assert_eq!(1, plan.transactions.len());
        assert_eq!(vec![coins("2"), coins("1")], amounts(&plan.swept[0]));
        assert_eq!(coins("2.9"), plan.total);
    }

    #[test]
    fn batches_holding_no_more_than_the_fee_are_reported_not_built() {
        let wallet = WalletEntropy::devnet();
        let key = wallet.derive_legacy_dctidh_spending_key(0);
        let options = MigrationOptions {
            max_inputs: 2,
            ..MigrationOptions::default()
        };
        let inputs = vec![
            input(&key, 0, coins("1")),
            input(&key, 1, coins("1")),
            input(&key, 2, coins("0.05")),
            input(&key, 3, coins("0.05")),
        ];
        let plan = plan_with(inputs, &options);
        assert_eq!(1, plan.transactions.len());
        assert_eq!(1, plan.dust.len());
        assert_eq!(vec![coins("0.05"), coins("0.05")], amounts(&plan.dust[0]));
        assert_eq!(coins("1.9"), plan.total);
    }

    #[test]
    fn inputs_that_cannot_be_spent_yet_or_are_not_legacy_are_left_out() {
        let wallet = WalletEntropy::devnet();
        let legacy = wallet.derive_legacy_dctidh_spending_key(0);
        let current = wallet.derive_dctidh_spending_key(0);
        let mut locked = input(&legacy, 1, coins("2"));
        locked.utxo = locked.utxo.with_time_lock(u64::MAX / 2);
        let inputs = vec![
            input(&legacy, 0, coins("1")),
            locked,
            input(&current, 2, coins("3")),
        ];
        let plan = plan_with(inputs, &MigrationOptions::default());
        assert_eq!(1, plan.transactions.len());
        assert_eq!(vec![coins("1")], amounts(&plan.swept[0]));
        assert_eq!(vec![coins("2")], amounts(&plan.time_locked));
    }

    #[test]
    fn each_input_is_reported_with_its_key_index_and_payment_id() {
        let wallet = WalletEntropy::devnet();
        let first = wallet.derive_legacy_dctidh_spending_key(0);
        let second = wallet.derive_legacy_dctidh_spending_key(1);
        let options = MigrationOptions {
            max_inputs: 3,
            ..MigrationOptions::default()
        };
        let inputs = vec![
            input_with_payment_id(&first, 0, coins("5"), 0),
            input_with_payment_id(&first, 1, coins("3"), 7),
            input_with_payment_id(&second, 2, coins("2"), 7),
            input_with_payment_id(&second, 3, coins("1.5"), 0),
            input_with_payment_id(&first, 4, coins("1"), 7),
            input_with_payment_id(&second, 5, coins("0.5"), 9),
        ];
        let plan = plan_with(inputs, &options);
        assert_eq!(2, plan.transactions.len());

        // Parallel to the swept inputs, each with the key it was found with.
        assert_eq!(plan.swept.len(), plan.swept_inputs.len());
        for (swept, details) in plan.swept.iter().zip(&plan.swept_inputs) {
            assert_eq!(swept.len(), details.len());
            for (input, detail) in swept.iter().zip(details) {
                assert_eq!(input.aocl_index, detail.aocl_index);
                assert_eq!(input.amount, detail.amount);
                assert_eq!(input.payment_id, detail.payment_id);
                assert_eq!(input.block_height, detail.block_height);
                assert_eq!(
                    input.absolute_index_set_hash(),
                    detail.absolute_index_set_hash
                );
                let key = if detail.key_index == 0 {
                    &first
                } else {
                    &second
                };
                assert_eq!(
                    key.lock_script_hash(),
                    input.spending_key.lock_script_hash()
                );
            }
        }
        let keys_and_payment_ids: Vec<_> = plan
            .swept_inputs
            .iter()
            .flatten()
            .map(|input| (input.aocl_index, input.key_index, input.payment_id))
            .collect();
        assert_eq!(
            vec![
                (0, 0, 0),
                (1, 0, 7),
                (2, 1, 7),
                (3, 1, 0),
                (4, 0, 7),
                (5, 1, 9)
            ],
            keys_and_payment_ids
        );

        // Per key and payment id, before fees, adding up to what the
        // transactions spend.
        let totals = plan.totals_by_payment_id();
        assert_eq!(
            vec![
                (0, 0, coins("5")),
                (0, 7, coins("4")),
                (1, 0, coins("1.5")),
                (1, 7, coins("2")),
                (1, 9, coins("0.5"))
            ],
            totals
        );
        assert_eq!(
            plan.total + plan.fees,
            totals.iter().map(|(_, _, amount)| amount).sum::<i128>()
        );
    }

    #[test]
    fn inputs_left_out_are_reported_with_their_key_index_and_payment_id() {
        let wallet = WalletEntropy::devnet();
        let first = wallet.derive_legacy_dctidh_spending_key(0);
        let second = wallet.derive_legacy_dctidh_spending_key(1);
        let options = MigrationOptions {
            max_inputs: 2,
            ..MigrationOptions::default()
        };
        let mut locked = input_with_payment_id(&second, 4, coins("2"), 11);
        locked.utxo = locked.utxo.with_time_lock(u64::MAX / 2);
        let inputs = vec![
            input_with_payment_id(&first, 0, coins("1"), 3),
            input_with_payment_id(&first, 1, coins("1"), 0),
            input_with_payment_id(&second, 2, coins("0.05"), 5),
            input_with_payment_id(&first, 3, coins("0.04"), 3),
            locked,
        ];
        let plan = plan_with(inputs, &options);
        assert_eq!(1, plan.transactions.len());

        let dust: Vec<_> = plan.dust_inputs[0]
            .iter()
            .map(|input| (input.key_index, input.payment_id, input.amount))
            .collect();
        assert_eq!(vec![(1, 5, coins("0.05")), (0, 3, coins("0.04"))], dust);
        assert_eq!(plan.dust.len(), plan.dust_inputs.len());
        assert_eq!(
            vec![(1, 11, coins("2"))],
            plan.time_locked_inputs
                .iter()
                .map(|input| (input.key_index, input.payment_id, input.amount))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            plan.time_locked[0].absolute_index_set_hash(),
            plan.time_locked_inputs[0].absolute_index_set_hash
        );

        // The totals cover the transactions only.
        assert_eq!(
            vec![(0, 0, coins("1")), (0, 3, coins("1"))],
            plan.totals_by_payment_id()
        );
    }

    #[test]
    fn an_input_without_a_key_index_is_refused() {
        let wallet = WalletEntropy::devnet();
        let key = wallet.derive_legacy_dctidh_spending_key(0);
        let result = build_migration_from_inputs(
            vec![input(&key, 0, coins("5"))],
            &HashMap::new(),
            ScanStats::default(),
            &destination(),
            &mutator_set(94_000),
            Network::Main,
            &MigrationOptions::default(),
            timestamp_now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn no_migration_within_the_margin_before_the_fork_or_below_its_fee() {
        let wallet = WalletEntropy::devnet();
        let key = wallet.derive_legacy_dctidh_spending_key(0);
        let inputs = vec![input(&key, 0, coins("5"))];
        for tip_height in [96_990, 96_998] {
            assert!(plan(inputs.clone(), tip_height, &MigrationOptions::default()).is_err());
        }
        assert!(plan(inputs.clone(), 96_999, &MigrationOptions::default()).is_ok());

        // Before the fork, at least 0.017 coins; after it, the relay minimum.
        let low_fee = MigrationOptions {
            fee: Some(coins("0.01")),
            ..MigrationOptions::default()
        };
        assert!(plan(inputs.clone(), 94_000, &low_fee).is_err());
        assert!(plan(inputs, 97_000, &low_fee).is_ok());
    }

    #[test]
    fn the_destination_must_be_a_current_address_of_the_network() {
        let wallet = WalletEntropy::devnet();
        let current = wallet.derive_dctidh_spending_key(0).to_address().unwrap();
        let generation = wallet.derive_spending_key(0).to_address().unwrap();
        for address in [current, generation] {
            let main_net = address.to_bech32(Network::Main).unwrap();
            assert!(Address::from_bech32(&main_net, Network::Main).is_ok());
            assert!(Address::from_bech32(&main_net, Network::Testnet).is_err());
        }

        // Legacy keys have no address to move funds to.
        assert!(wallet
            .derive_legacy_dctidh_spending_key(0)
            .to_address()
            .is_err());
    }
}
