//! Transactions for the era before the next hard fork.
//!
//! Main net follows the `UpgradeVMv7` consensus rule set until the
//! `UpgradeVMv8` hard fork at
//! [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET`](crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET).
//! While the next block belongs to that era, this version creates transactions
//! with v7 proofs: a v7 proof collection, raised to a v7 single proof where the
//! node proves single proofs and the machine can hold one (see
//! [`check_v7_single_proof_capability`](crate::protocol::consensus::transaction::validity::legacy_v7::check_v7_single_proof_capability)).
//!
//! The nodes that compose blocks of that era run the previous release. They
//! mine single-proof-backed transactions only, and their proof upgraders raise
//! a proof collection to a single proof only if it has at most
//! [`LEGACY_ERA_MAX_NUM_PROOFS`] proofs and pays a fee whose upgrader share
//! covers their minimum gobbling fee. Their peers relay it only if the fee
//! covers [`LEGACY_ERA_MIN_FEE_PER_INPUT`] per input. A transaction for this
//! era must therefore meet these terms (see [`check_proof_collection_terms`]),
//! since it may end up with its proof collection.
//!
//! A transaction of this era must be mined before the fork, and this version
//! can neither update nor merge its proof. New ones are refused once the tip is
//! within a margin of the fork (see [`rule_set_for_new_transaction`]).

use std::sync::Arc;

use tasm_lib::prelude::Digest;
use tracing::info;

use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::error::CreateProofError;
use crate::api::tx_initiation::error::CreateTxError;
use crate::application::config::network::Network;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::consensus_rule_set::leviathan_settlement_activation_height;
use crate::protocol::consensus::consensus_rule_set::upgrade_vm_v8_activation_height;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::transaction::validity::legacy_v7::check_v7_single_proof_capability_blocking;
use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::AnyProofCollection;
use crate::protocol::consensus::transaction::validity::leviathan_proof_collection::VerifyOptions;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::legacy_v7;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;

/// The number of blocks before the fork from which no new transaction for the
/// era before it is created, unless configured otherwise.
pub const DEFAULT_FORK_TX_CUTOFF_MARGIN: u64 = 10;

/// The largest number of proofs in a proof collection that the proof upgraders
/// of the era before the fork raise to a single proof, by default.
pub const LEGACY_ERA_MAX_NUM_PROOFS: usize = 16;

/// The number of proofs in a proof collection besides those of the lock and
/// type scripts: removal records integrity, kernel to outputs, and the
/// collection of lock and type scripts.
const NUM_FIXED_PROOFS: usize = 4;

/// The least fee per input at which the nodes of the era before the fork
/// relay a proof-collection-backed transaction, by default.
pub const LEGACY_ERA_MIN_FEE_PER_INPUT: NativeCurrencyAmount =
    NativeCurrencyAmount::from_nau(NativeCurrencyAmount::coin_as_nau() / 2000);

/// The least fee at which the proof upgraders of the era before the fork raise
/// a proof collection to a single proof, by default: they take 0.6 of the fee
/// and need at least 0.01 coins of it. 0.017 is the smallest round amount above
/// 0.01 / 0.6.
pub const LEGACY_ERA_MIN_FEE: NativeCurrencyAmount =
    NativeCurrencyAmount::from_nau(NativeCurrencyAmount::coin_as_nau() / 1000 * 17);

/// The least fee of a transaction for the era before the fork with this many
/// inputs: [`LEGACY_ERA_MIN_FEE`], or [`LEGACY_ERA_MIN_FEE_PER_INPUT`] per
/// input if that is more.
pub fn legacy_era_min_fee(num_inputs: usize) -> NativeCurrencyAmount {
    let relay_minimum = u32::try_from(num_inputs)
        .ok()
        .and_then(|num_inputs| LEGACY_ERA_MIN_FEE_PER_INPUT.checked_scalar_mul(num_inputs));
    match relay_minimum {
        Some(relay_minimum) if relay_minimum > LEGACY_ERA_MIN_FEE => relay_minimum,
        Some(_) => LEGACY_ERA_MIN_FEE,
        None => NativeCurrencyAmount::from_nau(i128::MAX),
    }
}

/// The largest number of inputs of a transaction for the era before the fork
/// whose proof collection, with this many type-script proofs, stays within
/// [`LEGACY_ERA_MAX_NUM_PROOFS`]: one lock-script proof per input. With only
/// the native currency that is 11 inputs, with a time lock as well 10.
pub fn legacy_era_max_num_inputs(num_type_script_proofs: usize) -> usize {
    LEGACY_ERA_MAX_NUM_PROOFS.saturating_sub(NUM_FIXED_PROOFS + num_type_script_proofs)
}

/// The number of type-script proofs in the proof collection of this witness:
/// one per distinct type script, after the legacy `TimeLock` is remapped to
/// `TimeLockV2`, as [`ProofCollection::produce_v2`] proves them.
///
/// [`ProofCollection::produce_v2`]: crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection::produce_v2
pub(crate) fn num_type_script_proofs(primitive_witness: &PrimitiveWitness) -> usize {
    let time_lock_hash = TimeLock.hash();
    let time_lock_v2_hash = TimeLockV2.hash();
    let mut hashes: Vec<Digest> = vec![];
    for type_script_and_witness in &primitive_witness.type_scripts_and_witnesses {
        let hash = type_script_and_witness.program.hash();
        let hash = if hash == time_lock_hash {
            time_lock_v2_hash
        } else {
            hash
        };
        if !hashes.contains(&hash) {
            hashes.push(hash);
        }
    }

    hashes.len()
}

/// The consensus rule set of a transaction created now, after a tip at
/// `tip_height`: that of the next block.
///
/// Fails with [`CreateProofError::LegacyEra`] if the tip is within `margin`
/// blocks of the fork that ends the next block's era: a transaction created
/// then may not be mined before the fork, and this version cannot carry it
/// over.
pub fn rule_set_for_new_transaction(
    network: Network,
    tip_height: BlockHeight,
    margin: u64,
) -> Result<ConsensusRuleSet, CreateProofError> {
    let consensus_rule_set = ConsensusRuleSet::infer_for_next_block(network, tip_height);
    if let Some(fork_height) = era_end(consensus_rule_set, network) {
        if tip_height.value().saturating_add(margin) >= fork_height.value() {
            info!(
                "Not creating a transaction for consensus rule set {consensus_rule_set}: the tip \
                 at height {tip_height} is within {margin} blocks of the hard fork at height \
                 {fork_height}."
            );
            return Err(CreateProofError::LegacyEra(consensus_rule_set));
        }
    }

    Ok(consensus_rule_set)
}

/// The height of the hard fork that ends this rule set's era, if this version cannot carry the
/// era's transactions across it: their proofs are not valid under the next era's programs.
fn era_end(consensus_rule_set: ConsensusRuleSet, network: Network) -> Option<BlockHeight> {
    match consensus_rule_set {
        ConsensusRuleSet::UpgradeVMv7 => Some(upgrade_vm_v8_activation_height(network)),
        ConsensusRuleSet::UpgradeVMv8 => Some(leviathan_settlement_activation_height(network)),
        ConsensusRuleSet::Reboot
        | ConsensusRuleSet::HardforkAlpha
        | ConsensusRuleSet::Xnt
        | ConsensusRuleSet::TimelockExtension
        | ConsensusRuleSet::UpgradeVM
        | ConsensusRuleSet::UpgradeVMv4
        | ConsensusRuleSet::UpgradeVMv5
        | ConsensusRuleSet::LeviathanSettlement => None,
    }
}

/// Whether a transaction with this witness meets the terms on which the nodes
/// of the era before the fork relay its proof collection and raise it to a
/// single proof: a fee of at least [`legacy_era_min_fee`], and at most
/// [`legacy_era_max_num_inputs`] inputs. Its outputs must also carry only
/// type scripts that both eras know under their current hashes, so that they
/// stay spendable after the fork.
pub fn check_proof_collection_terms(
    primitive_witness: &PrimitiveWitness,
) -> Result<(), CreateTxError> {
    let num_inputs = primitive_witness.kernel.inputs.len();
    let max_num_inputs = legacy_era_max_num_inputs(num_type_script_proofs(primitive_witness));
    if num_inputs > max_num_inputs {
        return Err(CreateTxError::LegacyEraTooManyInputs {
            num_inputs,
            max_num_inputs,
        });
    }

    let fee = primitive_witness.kernel.fee;
    let min_fee = legacy_era_min_fee(num_inputs);
    if fee < min_fee {
        return Err(CreateTxError::LegacyEraFeeTooLow {
            fee,
            min_fee,
            num_inputs,
        });
    }

    let current_type_script_hashes = [NativeCurrency.hash(), TimeLock.hash(), TimeLockV2.hash()];
    if let Some(coin) = primitive_witness
        .output_utxos
        .utxos
        .iter()
        .flat_map(|utxo| utxo.coins())
        .find(|coin| !current_type_script_hashes.contains(&coin.type_script_hash))
    {
        return Err(CreateTxError::LegacyEraTypeScript(coin.type_script_hash));
    }

    Ok(())
}

/// Whether a transaction submitted to this node, to be held for the era before
/// the fork, meets the terms of that era that its kernel and proof show: it is
/// not submitted within `margin` blocks of the fork, see
/// [`rule_set_for_new_transaction`], and if it is backed by a proof collection,
/// that pays at least [`legacy_era_min_fee`] and has at most
/// [`LEGACY_ERA_MAX_NUM_PROOFS`] proofs, see [`check_proof_collection_terms`].
/// Its outputs are commitments, so their type scripts are not checked.
///
/// In any other era only the margin before the fork that ends it applies.
///
/// The same for every way of submitting a transaction to this node.
pub(crate) fn submitted_transaction_meets_terms(
    transaction: &Transaction,
    network: Network,
    tip_height: BlockHeight,
    margin: u64,
) -> bool {
    let Ok(consensus_rule_set) = rule_set_for_new_transaction(network, tip_height, margin) else {
        return false;
    };
    if !consensus_rule_set.is_legacy_era() {
        return true;
    }

    match &transaction.proof {
        TransactionProof::ProofCollection(proof_collection) => {
            let num_inputs = transaction.kernel.inputs.len();
            transaction.kernel.fee >= legacy_era_min_fee(num_inputs)
                && proof_collection.num_proofs() <= LEGACY_ERA_MAX_NUM_PROOFS
        }
        TransactionProof::SingleProof(_) | TransactionProof::Witness(_) => true,
    }
}

/// Prove a transaction for the era before the fork from its primitive witness.
///
/// Makes the v7 proof collection, and if `attempt_single_proof`, raises it to
/// a v7 single proof where
/// [`check_v7_single_proof_capability`](crate::protocol::consensus::transaction::validity::legacy_v7::check_v7_single_proof_capability)
/// allows it, see [`prove_legacy_era_single_proof`]. The transaction keeps its
/// proof collection if the single proof is not made or fails. The result is
/// verified under `UpgradeVMv7` before it is returned.
pub(crate) async fn prove_legacy_era_transaction(
    primitive_witness: &PrimitiveWitness,
    job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: &TritonVmProofJobOptions,
    attempt_single_proof: bool,
) -> Result<Transaction, CreateProofError> {
    let transaction =
        prove_legacy_era_proof_collection(primitive_witness, job_queue.clone(), proof_job_options)
            .await?;
    if !attempt_single_proof {
        return Ok(transaction);
    }

    match prove_legacy_era_single_proof(&transaction, job_queue, proof_job_options).await {
        Ok(Some(single_proof)) => Ok(single_proof),
        Ok(None) => Ok(transaction),
        Err(error) => {
            info!(
                "Transaction {} keeps its v7 proof collection: the v7 single proof failed: \
                 {error}",
                transaction.kernel.txid()
            );
            Ok(transaction)
        }
    }
}

/// The transaction with the v7 proof collection of this primitive witness,
/// verified under `UpgradeVMv7`.
pub(crate) async fn prove_legacy_era_proof_collection(
    primitive_witness: &PrimitiveWitness,
    job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: &TritonVmProofJobOptions,
) -> Result<Transaction, CreateProofError> {
    let collection_options = TritonVmProofJobOptionsBuilder::new()
        .template(proof_job_options)
        .proof_type(TransactionProofType::ProofCollection)
        .build();
    let proof = TransactionProofBuilder::new()
        .consensus_rule_set(ConsensusRuleSet::UpgradeVMv7)
        .primitive_witness_ref(primitive_witness)
        .job_queue(job_queue)
        .proof_job_options(collection_options)
        .build()
        .await?;

    verified_legacy_era_transaction(
        Transaction {
            kernel: primitive_witness.kernel.clone(),
            proof,
        },
        proof_job_options.job_settings.network,
    )
    .await
}

/// The transaction with the v7 single proof raised from its v7 proof
/// collection, verified under `UpgradeVMv7`, or `None` where
/// [`check_v7_single_proof_capability`](crate::protocol::consensus::transaction::validity::legacy_v7::check_v7_single_proof_capability)
/// does not allow it, as for a transaction too large for this machine.
pub(crate) async fn prove_legacy_era_single_proof(
    transaction: &Transaction,
    job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: &TritonVmProofJobOptions,
) -> Result<Option<Transaction>, CreateProofError> {
    let TransactionProof::ProofCollection(AnyProofCollection::Upstream(proof_collection)) =
        &transaction.proof
    else {
        return Ok(None);
    };
    let network = proof_job_options.job_settings.network;
    let txid = transaction.kernel.txid();

    let capability = if network.use_mock_proof() {
        Ok(())
    } else {
        check_v7_single_proof_capability_blocking(
            proof_collection.clone(),
            proof_job_options.job_settings.clone(),
            legacy_v7::available_memory(),
        )
        .await
        .map(|_| ())
    };
    if let Err(reason) = capability {
        info!("Transaction {txid} keeps its v7 proof collection: {reason}");
        return Ok(None);
    }

    let single_proof_options = TritonVmProofJobOptionsBuilder::new()
        .template(proof_job_options)
        .proof_type(TransactionProofType::SingleProof)
        .build();
    let proof = TransactionProofBuilder::new()
        .consensus_rule_set(ConsensusRuleSet::UpgradeVMv7)
        .proof_collection(proof_collection.clone())
        .job_queue(job_queue)
        .proof_job_options(single_proof_options)
        .build()
        .await?;

    verified_legacy_era_transaction(
        Transaction {
            kernel: transaction.kernel.clone(),
            proof,
        },
        network,
    )
    .await
    .map(Some)
}

/// The transaction, if its proof verifies under `UpgradeVMv7`: no v7 proof
/// leaves this node unless it does.
async fn verified_legacy_era_transaction(
    transaction: Transaction,
    network: Network,
) -> Result<Transaction, CreateProofError> {
    if !verify_legacy_era_transaction(&transaction, network).await {
        return Err(CreateProofError::ProducedProofDoesNotVerify(
            transaction.kernel.mast_hash(),
        ));
    }

    Ok(transaction)
}

/// Whether the transaction's proof is valid under `UpgradeVMv7`, the rule set
/// of the era before the fork.
pub(crate) async fn verify_legacy_era_transaction(
    transaction: &Transaction,
    network: Network,
) -> bool {
    transaction
        .proof
        .verify(
            transaction.kernel.mast_hash(),
            network,
            ConsensusRuleSet::UpgradeVMv7,
            VerifyOptions::default(),
        )
        .await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use macro_rules_attr::apply;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::tx_initiation::error::SendError;
    use crate::api::tx_initiation::migrate_dctidh::tests::main_net_placeholder_block;
    use crate::api::tx_initiation::migrate_dctidh::tests::main_net_wallet_with_legacy_indices;
    use crate::api::tx_initiation::migrate_dctidh::tests::receive_at_dctidh_locks;
    use crate::api::tx_initiation::migrate_dctidh::tests::tip;
    use crate::application::config::cli_args;
    use crate::application::loops::channel::MainToPeerTask;
    use crate::application::loops::main_loop::proof_upgrader::PrimitiveWitnessToProofCollection;
    use crate::application::loops::main_loop::proof_upgrader::UpgradeJob;
    use crate::application::triton_vm_job_queue::vm_job_queue;
    use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::utxo::Coin;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::address::KeyType;
    use crate::state::wallet::address::ReceivingAddress;
    use crate::state::wallet::change_policy::ChangePolicy;
    use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::tests::shared_tokio_runtime;

    fn coins(amount: &str) -> NativeCurrencyAmount {
        NativeCurrencyAmount::coins_from_str(amount).unwrap()
    }

    fn primitive_witness(num_inputs: usize) -> PrimitiveWitness {
        PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), 2, 0)
            .new_tree(&mut TestRunner::deterministic())
            .unwrap()
            .current()
    }

    fn with_fee(mut primitive_witness: PrimitiveWitness, fee: &str) -> PrimitiveWitness {
        primitive_witness.kernel = TransactionKernelModifier::default()
            .fee(coins(fee))
            .modify(primitive_witness.kernel);
        primitive_witness
    }

    #[test]
    fn terms_are_as_specified() {
        assert_eq!(coins("0.017"), LEGACY_ERA_MIN_FEE);
        assert_eq!(coins("0.0005"), LEGACY_ERA_MIN_FEE_PER_INPUT);
        assert_eq!(16, LEGACY_ERA_MAX_NUM_PROOFS);
        assert_eq!(
            DEFAULT_FORK_TX_CUTOFF_MARGIN,
            cli_args::Args::default().fork_tx_cutoff_margin
        );

        // The upgraders of that era take 0.6 of the fee and need 0.01 of it.
        assert!(LEGACY_ERA_MIN_FEE.lossy_f64_fraction_mul(0.6) >= coins("0.01"));
        assert!(coins("0.016").lossy_f64_fraction_mul(0.6) < coins("0.01"));

        // The relay minimum per input matters from 35 inputs on.
        assert_eq!(LEGACY_ERA_MIN_FEE, legacy_era_min_fee(0));
        assert_eq!(LEGACY_ERA_MIN_FEE, legacy_era_min_fee(11));
        assert_eq!(LEGACY_ERA_MIN_FEE, legacy_era_min_fee(34));
        assert_eq!(coins("0.0175"), legacy_era_min_fee(35));
        assert_eq!(coins("0.1"), legacy_era_min_fee(200));

        // With the native currency alone 11 inputs, with a time lock 10.
        assert_eq!(11, legacy_era_max_num_inputs(1));
        assert_eq!(10, legacy_era_max_num_inputs(2));
        assert_eq!(0, legacy_era_max_num_inputs(20));
    }

    /// New transactions are made up to, but not within, the margin before the
    /// fork; once the next block belongs to the era after it, again for that
    /// era. Test networks are never in the legacy era.
    #[test]
    fn new_transactions_stop_within_the_margin_of_the_fork() {
        let network = Network::Main;
        let fork = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET.value();
        let margin = DEFAULT_FORK_TX_CUTOFF_MARGIN;
        let rule_set = |tip: u64, cutoff_margin: u64| {
            rule_set_for_new_transaction(network, BlockHeight::from(tip), cutoff_margin)
        };

        assert_eq!(
            ConsensusRuleSet::UpgradeVMv7,
            rule_set(fork - margin - 1, margin).unwrap()
        );
        for tip in [fork - margin, fork - 2] {
            assert!(
                matches!(
                    rule_set(tip, margin),
                    Err(CreateProofError::LegacyEra(ConsensusRuleSet::UpgradeVMv7))
                ),
                "tip {tip}"
            );
        }
        for tip in [fork - 1, fork, fork + 1] {
            assert_eq!(
                ConsensusRuleSet::UpgradeVMv8,
                rule_set(tip, margin).unwrap(),
                "tip {tip}"
            );
        }

        // Without a margin, up to the last block before the fork.
        assert_eq!(
            ConsensusRuleSet::UpgradeVMv7,
            rule_set(fork - 2, 0).unwrap()
        );

        for test_network in [Network::Testnet(0), Network::RegTest] {
            assert_eq!(
                ConsensusRuleSet::LeviathanSettlement,
                rule_set_for_new_transaction(test_network, BlockHeight::genesis(), margin).unwrap()
            );
        }
    }

    /// Likewise before the bridge era: no v8 proof is valid under its programs.
    #[test]
    fn new_transactions_stop_within_the_margin_of_the_bridge_era() {
        use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_LEVIATHAN_SETTLEMENT_MAIN_NET;

        let fork = BLOCK_HEIGHT_LEVIATHAN_SETTLEMENT_MAIN_NET.value();
        let margin = DEFAULT_FORK_TX_CUTOFF_MARGIN;
        let rule_set =
            |tip: u64| rule_set_for_new_transaction(Network::Main, BlockHeight::from(tip), margin);

        assert_eq!(
            ConsensusRuleSet::UpgradeVMv8,
            rule_set(fork - margin - 1).unwrap()
        );
        for tip in [fork - margin, fork - 2] {
            assert!(
                matches!(
                    rule_set(tip),
                    Err(CreateProofError::LegacyEra(ConsensusRuleSet::UpgradeVMv8))
                ),
                "tip {tip}"
            );
        }
        for tip in [fork - 1, fork, fork + 1] {
            assert_eq!(
                ConsensusRuleSet::LeviathanSettlement,
                rule_set(tip).unwrap(),
                "tip {tip}"
            );
        }
    }

    /// The same terms for every way of submitting a transaction: none within
    /// the margin of the fork, and a proof collection with the fee and at most
    /// the number of proofs of the era.
    #[test]
    fn submitted_transactions_meet_the_terms_of_the_era() {
        use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;

        let network = Network::Main;
        let fork = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET.value();
        let margin = DEFAULT_FORK_TX_CUTOFF_MARGIN;
        let backed_by = |primitive_witness: &PrimitiveWitness, single_proof: bool| Transaction {
            kernel: primitive_witness.kernel.clone(),
            proof: if single_proof {
                TransactionProof::invalid()
            } else {
                TransactionProof::ProofCollection(
                    ProofCollection::produce_mock(primitive_witness, true).into(),
                )
            },
        };
        let meets = |transaction: &Transaction, tip: u64| {
            submitted_transaction_meets_terms(transaction, network, BlockHeight::from(tip), margin)
        };

        let paying = with_fee(primitive_witness(2), "0.017");
        let below = with_fee(primitive_witness(2), "0.0169");
        let too_many_proofs = with_fee(primitive_witness(legacy_era_max_num_inputs(1) + 1), "1");
        let tip = fork - margin - 1;
        assert!(meets(&backed_by(&paying, false), tip));
        assert!(!meets(&backed_by(&below, false), tip));
        assert!(!meets(&backed_by(&too_many_proofs, false), tip));

        // A single proof is relayed and mined whatever its fee.
        assert!(meets(&backed_by(&below, true), tip));

        // None within the margin of the fork.
        for transaction in [backed_by(&paying, false), backed_by(&paying, true)] {
            assert!(!meets(&transaction, fork - margin));
        }
    }

    #[test]
    fn proof_collection_terms_are_checked() {
        let witness = primitive_witness(2);
        assert_eq!(1, num_type_script_proofs(&witness));
        assert!(check_proof_collection_terms(&with_fee(witness.clone(), "0.017")).is_ok());
        assert!(matches!(
            check_proof_collection_terms(&with_fee(witness.clone(), "0.0169")),
            Err(CreateTxError::LegacyEraFeeTooLow { num_inputs: 2, .. })
        ));

        let max_num_inputs = legacy_era_max_num_inputs(1);
        let at_the_limit = with_fee(primitive_witness(max_num_inputs), "0.1");
        assert!(check_proof_collection_terms(&at_the_limit).is_ok());
        let above_the_limit = with_fee(primitive_witness(max_num_inputs + 1), "0.1");
        assert!(matches!(
            check_proof_collection_terms(&above_the_limit),
            Err(CreateTxError::LegacyEraTooManyInputs {
                num_inputs: 12,
                max_num_inputs: 11,
            })
        ));

        // An output may carry the native currency and time locks, and nothing
        // else.
        let mut unknown_type_script = with_fee(witness.clone(), "0.1");
        let unknown_hash = Digest::default();
        unknown_type_script.output_utxos.utxos[0] = Utxo::new(
            unknown_type_script.output_utxos.utxos[0].lock_script_hash(),
            vec![Coin {
                type_script_hash: unknown_hash,
                state: vec![],
            }],
        );
        assert!(matches!(
            check_proof_collection_terms(&unknown_type_script),
            Err(CreateTxError::LegacyEraTypeScript(hash)) if hash == unknown_hash
        ));
    }

    /// Before the fork, the initiator spends the largest inputs first, so that
    /// a wallet holding many small UTXOs next to a large one stays within the
    /// input cap of the era.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn send_before_the_fork_spends_the_largest_inputs_first() {
        let mut alice = main_net_wallet_with_legacy_indices(1).await;
        let mut payments = vec![(0, coins("5"), false)];
        payments.extend((0..25).map(|_| (0, coins("0.05"), false)));
        receive_at_dctidh_locks(&mut alice, &payments).await;
        let pre_fork = main_net_placeholder_block(&tip(&alice).await, 94_000u64.into());
        alice.set_new_tip(pre_fork.clone()).await.unwrap();

        let recipient: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(rand::random()).into();
        let artifacts = alice
            .api()
            .tx_initiator()
            .send(
                vec![(recipient, coins("1"))],
                ChangePolicy::RecoverToNextUnusedKey {
                    key_type: KeyType::Generation,
                    medium: UtxoNotificationMedium::OnChain,
                },
                coins("0.02"),
                pre_fork.header().timestamp + Timestamp::minutes(1),
                0,
                None,
            )
            .await
            .unwrap();
        assert_eq!(1, artifacts.transaction().kernel.inputs.len());
    }

    /// A transaction recorded and broadcast through the initiator, as the RPC
    /// server's `record_and_broadcast_transaction` does for a caller's
    /// transaction, meets the terms of every submission: none within the
    /// cutoff margin of the fork.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn recording_within_the_margin_of_the_fork_is_refused() {
        let mut alice = main_net_wallet_with_legacy_indices(1).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("3"), false)]).await;
        let pre_fork = main_net_placeholder_block(&tip(&alice).await, 94_000u64.into());
        alice.set_new_tip(pre_fork.clone()).await.unwrap();

        let recipient: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(rand::random()).into();
        let artifacts = alice
            .api()
            .tx_initiator()
            .send(
                vec![(recipient, coins("1"))],
                ChangePolicy::default(),
                coins("0.02"),
                pre_fork.header().timestamp + Timestamp::minutes(1),
                0,
                None,
            )
            .await
            .unwrap();

        let margin = alice.cli().fork_tx_cutoff_margin;
        let close = main_net_placeholder_block(
            &pre_fork,
            (BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET.value() - margin).into(),
        );
        alice.set_new_tip(close).await.unwrap();
        let refused = alice
            .api()
            .tx_initiator()
            .record_and_broadcast_transaction(&artifacts)
            .await;
        assert!(matches!(refused, Err(SendError::BelowLegacyEraTerms)));
    }

    /// Through the initiator, before the fork: a payment is made for the
    /// legacy era, held in the legacy relay pool, and proven as the main loop
    /// does into a v7 proof collection that verifies under `UpgradeVMv7` and
    /// not under `UpgradeVMv8`. Its outputs carry only the native currency
    /// under standard hash locks of a Generation address, so they stay
    /// spendable after the fork. Too low a fee, and the margin of the fork,
    /// are refused.
    ///
    /// Produces one real v7 proof collection.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn send_before_the_fork_makes_a_v7_proof_collection() {
        let mut alice = main_net_wallet_with_legacy_indices(1).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("3"), false)]).await;
        let pre_fork = main_net_placeholder_block(&tip(&alice).await, 94_000u64.into());
        alice.set_new_tip(pre_fork.clone()).await.unwrap();

        let recipient: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(rand::random()).into();
        let change_policy = ChangePolicy::RecoverToNextUnusedKey {
            key_type: KeyType::Generation,
            medium: UtxoNotificationMedium::OnChain,
        };
        let timestamp = pre_fork.header().timestamp + Timestamp::minutes(1);
        let outputs = vec![(recipient.clone(), coins("1"))];

        // Below the fee the upgraders of the legacy era take.
        let refused = alice
            .api()
            .tx_initiator()
            .send(
                outputs.clone(),
                change_policy.clone(),
                coins("0.01"),
                timestamp,
                0,
                None,
            )
            .await;
        assert!(matches!(
            refused,
            Err(SendError::Tx(CreateTxError::LegacyEraFeeTooLow { .. }))
        ));

        let artifacts = alice
            .api()
            .tx_initiator()
            .send(outputs, change_policy, coins("0.02"), timestamp, 0, None)
            .await
            .unwrap();
        let txid = artifacts.transaction().txid();
        let proof = {
            let state = alice.lock_guard().await;
            assert!(state.mempool.is_empty(), "no v7 transaction in the mempool");
            state.legacy_relay_pool.get(txid).unwrap().proof.clone()
        };
        let TransactionProof::Witness(primitive_witness) = proof else {
            panic!("an own transaction starts out with its primitive witness");
        };

        // The outputs stay spendable under v8: native currency only, at the
        // recipient's lock and at that of a Generation key of the wallet.
        let mut locks: Vec<Digest> = alice
            .lock_guard()
            .await
            .wallet_state
            .get_known_spending_keys(KeyType::Generation)
            .map(|key| key.lock_script_hash())
            .collect();
        locks.push(recipient.lock_script_hash());
        for utxo in &primitive_witness.output_utxos.utxos {
            assert!(utxo
                .coins()
                .iter()
                .all(|coin| coin.type_script_hash == NativeCurrency.hash()));
            assert!(
                locks.contains(&utxo.lock_script_hash()),
                "output to an unexpected lock"
            );
        }

        // As the main loop does for a transaction this node initiates.
        let (main_to_peer_tx, mut main_to_peer_rx) =
            tokio::sync::broadcast::channel::<MainToPeerTask>(10);
        UpgradeJob::PrimitiveWitnessToProofCollection(PrimitiveWitnessToProofCollection {
            primitive_witness,
        })
        .handle_upgrade(vm_job_queue(), alice.clone(), main_to_peer_tx)
        .await;

        let transaction = {
            let state = alice.lock_guard().await;
            assert!(state.mempool.is_empty(), "no v7 transaction in the mempool");
            assert!(
                state.legacy_relay_pool.primitive_witness(txid).is_some(),
                "the pool keeps the primitive witness to prove again"
            );
            state.legacy_relay_pool.get(txid).unwrap().clone()
        };
        assert!(transaction.proof.is_proof_collection());
        let kernel_mast_hash = transaction.kernel.mast_hash();
        let network = Network::Main;
        assert!(
            transaction
                .proof
                .verify(
                    kernel_mast_hash,
                    network,
                    ConsensusRuleSet::UpgradeVMv7,
                    VerifyOptions::default()
                )
                .await
        );
        assert!(
            !transaction
                .proof
                .verify(
                    kernel_mast_hash,
                    network,
                    ConsensusRuleSet::UpgradeVMv8,
                    VerifyOptions::default()
                )
                .await
        );
        let Ok(MainToPeerTask::TransactionNotification(notification)) = main_to_peer_rx.try_recv()
        else {
            panic!("the proven transaction must be announced");
        };
        assert_eq!(txid, notification.txid);

        // Within the margin of the fork, no new transaction.
        let margin = alice.cli().fork_tx_cutoff_margin;
        let close = main_net_placeholder_block(
            &pre_fork,
            (BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET.value() - margin).into(),
        );
        alice.set_new_tip(close.clone()).await.unwrap();
        let refused_close_to_the_fork = alice
            .api()
            .tx_initiator()
            .send(
                vec![(recipient, coins("1"))],
                ChangePolicy::default(),
                coins("0.02"),
                close.header().timestamp + Timestamp::minutes(1),
                0,
                None,
            )
            .await;
        assert!(matches!(
            refused_close_to_the_fork,
            Err(SendError::Proof(CreateProofError::LegacyEra(
                ConsensusRuleSet::UpgradeVMv7
            )))
        ));
    }
}
