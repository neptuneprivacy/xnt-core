//! A transaction of this node across the `UpgradeVMv8` fork, on a mock-proof
//! test network whose activation height is set, as by
//! `--v8-activation-height`: made for the era before the fork, held in the
//! legacy relay pool and proven again on every block, parked once the next
//! block belongs to the era after the fork, and proven for that era by the
//! main loop's update of transactions once the tip belongs to it.

use macro_rules_attr::apply;
use tracing_test::traced_test;

use super::*;
use crate::api::export::NativeCurrencyAmount;
use crate::api::tx_initiation::error::CreateProofError;
use crate::api::tx_initiation::error::SendError;
use crate::application::config::cli_args;
use crate::application::config::network::Network;
use crate::application::loops::main_loop::proof_upgrader::PrimitiveWitnessToSingleProof;
use crate::protocol::consensus::consensus_rule_set::tests::V8ActivationHeightForTests;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
use crate::state::wallet::address::KeyType;
use crate::state::wallet::address::ReceivingAddress;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::state::MAX_PARKED_WITNESS_ATTEMPTS;
use crate::tests::shared::blocks::invalid_block_with_transaction;
use crate::tests::shared::blocks::invalid_empty_block;
use crate::tests::shared::blocks::invalid_empty_block_with_timestamp;
use crate::tests::shared::blocks::make_mock_block;
use crate::tests::shared::globalstate::get_test_genesis_setup;
use crate::tests::shared_tokio_runtime;

const NETWORK: Network = Network::RegTest;

/// The height of the first block of the era after the fork.
const ACTIVATION_HEIGHT: u64 = 6;

/// The number of blocks before the fork from which no new transaction is made
/// for the era before it.
const CUTOFF_MARGIN: u64 = 2;

fn coins(amount: &str) -> NativeCurrencyAmount {
    NativeCurrencyAmount::coins_from_str(amount).unwrap()
}

/// Where the node holds a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Holding {
    legacy_pool: bool,
    mempool: bool,

    /// The number of blocks on which the parked transaction was handed to
    /// the updater, if it is parked.
    parked: Option<usize>,
}

const IN_LEGACY_POOL: Holding = Holding {
    legacy_pool: true,
    mempool: false,
    parked: None,
};

const fn parked(attempts: usize) -> Holding {
    Holding {
        legacy_pool: false,
        mempool: false,
        parked: Some(attempts),
    }
}

const NOWHERE: Holding = Holding {
    legacy_pool: false,
    mempool: false,
    parked: None,
};

struct Node {
    main_loop_handler: MainLoopHandler,
    main_to_peer_rx: broadcast::Receiver<MainToPeerTask>,
    _main_to_miner_rx: mpsc::Receiver<MainToMiner>,
}

/// A node of the test network at its genesis block, whose wallet holds the
/// network's premine for the devnet wallet.
async fn node() -> Node {
    node_with(TxProvingCapability::ProofCollection).await
}

/// [`node`], proving with the given capability.
async fn node_with(tx_proving_capability: TxProvingCapability) -> Node {
    let cli = cli_args::Args {
        network: NETWORK,
        fork_tx_cutoff_margin: CUTOFF_MARGIN,
        tx_proving_capability: Some(tx_proving_capability),
        ..Default::default()
    };
    let (main_to_peer_tx, main_to_peer_rx, peer_to_main_tx, peer_to_main_rx, state, _) =
        get_test_genesis_setup(NETWORK, 0, cli).await.unwrap();
    let (main_to_miner_tx, main_to_miner_rx) = mpsc::channel::<MainToMiner>(10);
    let (_miner_to_main_tx, miner_to_main_rx) = mpsc::channel::<MinerToMain>(10);
    let (_rpc_server_to_main_tx, rpc_server_to_main_rx) = mpsc::channel::<RPCServerToMain>(10);
    let main_loop_handler = MainLoopHandler::new(
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        state,
        main_to_peer_tx,
        peer_to_main_tx,
        main_to_miner_tx,
        peer_to_main_rx,
        miner_to_main_rx,
        rpc_server_to_main_rx,
        vec![],
        None,
    );

    Node {
        main_loop_handler,
        main_to_peer_rx,
        _main_to_miner_rx: main_to_miner_rx,
    }
}

impl Node {
    fn state(&self) -> &GlobalStateLock {
        &self.main_loop_handler.global_state_lock
    }

    async fn tip(&self) -> Block {
        self.state().lock_guard().await.chain.light_state().clone()
    }

    async fn next_block_rule_set(&self) -> ConsensusRuleSet {
        self.state()
            .lock_guard()
            .await
            .next_block_consensus_rule_set()
    }

    async fn holding(&self, txid: TransactionKernelId) -> Holding {
        let state = self.state().lock_guard().await;
        let parked = state
            .parked_own_transactions()
            .into_iter()
            .find(|(parked_txid, _)| *parked_txid == txid)
            .map(|(_, attempts)| attempts);

        Holding {
            legacy_pool: state.legacy_relay_pool.contains(txid),
            mempool: state.mempool.contains(txid),
            parked,
        }
    }

    /// The transaction with this id in the mempool or the legacy relay pool.
    async fn held_transaction(&self, txid: TransactionKernelId) -> Transaction {
        self.state()
            .lock_guard()
            .await
            .mempool_or_legacy_pool_get(txid)
            .unwrap()
            .clone()
    }

    /// Pay one coin to a stranger, with the change back to this wallet.
    async fn send(&self, fee: &str) -> Result<TransactionKernelId, SendError> {
        let recipient: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(rand::random()).into();
        let change_policy = ChangePolicy::RecoverToNextUnusedKey {
            key_type: KeyType::Generation,
            medium: UtxoNotificationMedium::OnChain,
        };
        self.state()
            .api()
            .tx_initiator()
            .send(
                vec![(recipient, coins("1"))],
                change_policy,
                coins(fee),
                Timestamp::now(),
                0,
                None,
            )
            .await
            .map(|artifacts| artifacts.transaction().txid())
    }

    /// Prove a transaction this node initiated, as the main loop does.
    async fn prove_initiated(&self, txid: TransactionKernelId) {
        let primitive_witness = self
            .state()
            .lock_guard()
            .await
            .legacy_relay_pool
            .primitive_witness(txid)
            .unwrap()
            .clone();
        UpgradeJob::PrimitiveWitnessToProofCollection(PrimitiveWitnessToProofCollection {
            primitive_witness,
        })
        .handle_upgrade(
            vm_job_queue(),
            self.state().clone(),
            self.main_loop_handler.main_to_peer_broadcast_tx.clone(),
        )
        .await;
    }

    /// Upgrade this node's transaction of this witness as the main loop does
    /// after it was initiated, to a single proof if so asked.
    async fn upgrade(&self, primitive_witness: PrimitiveWitness, single_proof: bool) {
        let job = if single_proof {
            UpgradeJob::PrimitiveWitnessToSingleProof(PrimitiveWitnessToSingleProof {
                primitive_witness,
            })
        } else {
            UpgradeJob::PrimitiveWitnessToProofCollection(PrimitiveWitnessToProofCollection {
                primitive_witness,
            })
        };
        job.handle_upgrade(
            vm_job_queue(),
            self.state().clone(),
            self.main_loop_handler.main_to_peer_broadcast_tx.clone(),
        )
        .await;
    }

    async fn set_tip(&mut self, block: &Block) -> Vec<MempoolUpdateJob> {
        self.main_loop_handler
            .global_state_lock
            .set_new_tip(block.clone())
            .await
            .unwrap()
    }

    /// Extend the tip by an empty block.
    async fn extend(&mut self) -> (Block, Vec<MempoolUpdateJob>) {
        let block = invalid_empty_block(&self.tip().await, NETWORK);
        let jobs = self.set_tip(&block).await;

        (block, jobs)
    }

    /// Run update jobs as the main loop does after a block, and return their
    /// results, to be handled by [`Self::handle`].
    async fn run_update_jobs(&self, jobs: Vec<MempoolUpdateJob>) -> Vec<MempoolUpdateJobResult> {
        let (update_sender, mut update_receiver) =
            mpsc::channel::<Vec<MempoolUpdateJobResult>>(TX_UPDATER_CHANNEL_CAPACITY);
        let proof_job_options = self
            .state()
            .cli()
            .proof_job_options(TritonVmJobPriority::Highest);
        MainLoopHandler::update_mempool_jobs(
            self.state().clone(),
            jobs,
            vm_job_queue(),
            update_sender,
            proof_job_options,
        )
        .await;

        update_receiver.recv().await.unwrap()
    }

    /// Handle the results of update jobs as the main loop does, and return
    /// the transactions proven, with the rule set each was proven for.
    async fn handle(
        &mut self,
        results: Vec<MempoolUpdateJobResult>,
    ) -> Vec<(TransactionKernelId, ConsensusRuleSet)> {
        let proven = results
            .iter()
            .filter_map(|result| match result {
                MempoolUpdateJobResult::Success {
                    new_transaction,
                    consensus_rule_set,
                    ..
                } => Some((new_transaction.txid(), *consensus_rule_set)),
                _ => None,
            })
            .collect();
        self.main_loop_handler
            .handle_updated_mempool_txs(results)
            .await;

        proven
    }

    /// Run update jobs and handle their results, as the main loop does after
    /// a block.
    async fn update(
        &mut self,
        jobs: Vec<MempoolUpdateJob>,
    ) -> Vec<(TransactionKernelId, ConsensusRuleSet)> {
        let results = self.run_update_jobs(jobs).await;
        self.handle(results).await
    }

    /// Extend the tip by a block whose coinbase goes to this wallet, so that
    /// it can make a second transaction.
    async fn fund(&mut self) {
        let composer_key = self
            .state()
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);
        let (block, expected_utxos) = make_mock_block(
            &self.tip().await,
            None,
            composer_key,
            rand::random(),
            NETWORK,
        )
        .await;
        self.main_loop_handler
            .global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos)
            .await;
        self.set_tip(&block).await;
    }

    /// A block on the tip that spends the inputs of this node's transaction,
    /// whose primitive witness is given, as the transaction would.
    async fn block_spending(&self, primitive_witness: PrimitiveWitness) -> Block {
        let mutator_set_update = self
            .state()
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_mutator_set_update_to_tip(
                &primitive_witness.mutator_set_accumulator,
                SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE,
            )
            .await
            .unwrap();
        let primitive_witness = primitive_witness.update_with_new_ms_data(mutator_set_update);

        invalid_block_with_transaction(&self.tip().await, primitive_witness.into())
    }

    /// The primitive witness of this node's transaction in the legacy relay
    /// pool.
    async fn own_witness(&self, txid: TransactionKernelId) -> PrimitiveWitness {
        self.state()
            .lock_guard()
            .await
            .legacy_relay_pool
            .primitive_witness(txid)
            .unwrap()
            .clone()
    }

    /// The ids of the transactions announced to peers since the last call.
    fn announced(&mut self) -> Vec<TransactionKernelId> {
        let mut txids = vec![];
        while let Ok(message) = self.main_to_peer_rx.try_recv() {
            if let MainToPeerTask::TransactionNotification(notification) = message {
                txids.push(notification.txid);
            }
        }

        txids
    }
}

fn jobs_for(jobs: &[MempoolUpdateJob], txid: TransactionKernelId) -> usize {
    jobs.iter().filter(|job| job.txid() == txid).count()
}

/// A transaction of this node from before the fork to after it: made while
/// the next block belongs to the era before the fork, held in the legacy relay
/// pool and proven again for that era on every block; none made within the
/// cutoff margin. When the next block is the fork block, it is parked: held in
/// the mempool backed by its primitive witness, so that the wallet keeps its
/// inputs reserved, and handed to the updater to be proven for the era after
/// the fork, also on the fork block when the jobs of the block before are
/// skipped, as while the update queue is busy. Once proven, the mempool
/// updates it, and a reorganization at the fork block that clears the mempool
/// does not lose it.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn own_transaction_is_carried_across_the_fork() {
    let _activation_height = V8ActivationHeightForTests::set(NETWORK, ACTIVATION_HEIGHT.into());
    let mut node = node().await;
    assert_eq!(
        ConsensusRuleSet::UpgradeVMv7,
        node.next_block_rule_set().await
    );

    let txid = node.send("0.02").await.unwrap();
    assert_eq!(IN_LEGACY_POOL, node.holding(txid).await);
    assert!(node.held_transaction(txid).await.proof.is_witness());
    node.prove_initiated(txid).await;
    assert!(node
        .held_transaction(txid)
        .await
        .proof
        .is_proof_collection());
    assert_eq!(vec![txid], node.announced());

    // Blocks 1 to 4: the next block belongs to the era before the fork, for
    // which the transaction is proven again on every block.
    let mut blocks = vec![node.tip().await];
    for height in 1..=4 {
        let (block, jobs) = node.extend().await;
        assert_eq!(height, block.header().height.value());
        assert_eq!(1, jobs_for(&jobs, txid), "block {height}");
        assert_eq!(
            vec![(txid, ConsensusRuleSet::UpgradeVMv7)],
            node.update(jobs).await,
            "block {height}"
        );

        assert_eq!(IN_LEGACY_POOL, node.holding(txid).await, "block {height}");
        let transaction = node.held_transaction(txid).await;
        assert!(transaction.proof.is_proof_collection());
        assert_eq!(
            block.mutator_set_accumulator_after().unwrap().hash(),
            transaction.kernel.mutator_set_hash,
            "block {height}"
        );
        assert_eq!(vec![txid], node.announced(), "block {height}");
        blocks.push(block);
    }

    // The tip is within the cutoff margin of the fork: no new transaction.
    assert!(matches!(
        node.send("0.02").await,
        Err(SendError::Proof(CreateProofError::LegacyEra(
            ConsensusRuleSet::UpgradeVMv7
        )))
    ));

    // Block 5: the next block is the fork block. The legacy relay pool is
    // cleared, and the transaction is parked, held in the mempool backed by
    // its witness, and handed to the updater. Its jobs are skipped, as by a
    // busy update queue.
    let (block, switch_jobs) = node.extend().await;
    blocks.push(block);
    assert_eq!(
        ConsensusRuleSet::UpgradeVMv8,
        node.next_block_rule_set().await
    );
    assert_eq!(1, jobs_for(&switch_jobs, txid));
    assert_eq!(
        Holding {
            mempool: true,
            ..parked(1)
        },
        node.holding(txid).await
    );
    assert!(node.held_transaction(txid).await.proof.is_witness());
    assert!(node.state().lock_guard().await.legacy_relay_pool.is_empty());
    assert!(node.announced().is_empty(), "a witness is never announced");
    assert!(
        node.state()
            .lock_guard()
            .await
            .wallet_state
            .mempool_spent_utxos_iter()
            .count()
            > 0,
        "the wallet keeps the inputs reserved"
    );
    drop(switch_jobs);

    // Block 6, the fork block: handed over again, proven for the era after the
    // fork, and held in the mempool.
    let (fork_block, fork_block_jobs) = node.extend().await;
    assert_eq!(ACTIVATION_HEIGHT, fork_block.header().height.value());
    assert_eq!(1, jobs_for(&fork_block_jobs, txid));
    assert_eq!(
        vec![(txid, ConsensusRuleSet::UpgradeVMv8)],
        node.update(fork_block_jobs).await
    );
    let proven = Holding {
        mempool: true,
        ..parked(2)
    };
    assert_eq!(proven, node.holding(txid).await);
    let transaction = node.held_transaction(txid).await;
    assert!(transaction.proof.is_proof_collection());
    assert_eq!(
        fork_block.mutator_set_accumulator_after().unwrap().hash(),
        transaction.kernel.mutator_set_hash
    );
    assert_eq!(vec![txid], node.announced());

    // A sibling of the fork block: the reorganization clears the mempool, and
    // the transaction is put back and proven again.
    let block_5 = &blocks[5];
    let sibling = invalid_empty_block_with_timestamp(
        block_5,
        block_5.header().timestamp + Timestamp::hours(2),
        NETWORK,
    );
    assert_ne!(fork_block.hash(), sibling.hash());
    let sibling_jobs = node.set_tip(&sibling).await;
    assert_eq!(1, jobs_for(&sibling_jobs, txid));
    assert_eq!(
        Holding {
            mempool: true,
            ..parked(3)
        },
        node.holding(txid).await
    );
    assert_eq!(
        vec![(txid, ConsensusRuleSet::UpgradeVMv8)],
        node.update(sibling_jobs).await
    );
    assert_eq!(
        Holding {
            mempool: true,
            ..parked(3)
        },
        node.holding(txid).await
    );
    assert!(node
        .held_transaction(txid)
        .await
        .proof
        .is_proof_collection());

    // The next block: the mempool updates it, as any of its own transactions,
    // with no further job for the parked transaction.
    let (_, next_jobs) = node.extend().await;
    assert_eq!(1, jobs_for(&next_jobs, txid));
    assert_eq!(
        vec![(txid, ConsensusRuleSet::UpgradeVMv8)],
        node.update(next_jobs).await
    );
    assert_eq!(
        Holding {
            mempool: true,
            ..parked(3)
        },
        node.holding(txid).await
    );

    // The block that mines it: parked no longer.
    let primitive_witness = node
        .state()
        .lock_guard()
        .await
        .mempool
        .primitive_witness(txid)
        .unwrap()
        .clone();
    let mining_block = node.block_spending(primitive_witness).await;
    let mining_jobs = node.set_tip(&mining_block).await;
    assert_eq!(0, jobs_for(&mining_jobs, txid));
    assert_eq!(NOWHERE, node.holding(txid).await);
}

/// A reorganization back across the fork, to a chain whose next block belongs
/// to the era before it: the mempool is cleared, the parked transaction stays
/// parked, and no new transaction is made for that era this close to the
/// fork. Once the next block of the new chain belongs to the era after the
/// fork, the transaction is held in the mempool and proven again.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn a_parked_transaction_stays_parked_across_a_reorganization_back_across_the_fork() {
    let _activation_height = V8ActivationHeightForTests::set(NETWORK, ACTIVATION_HEIGHT.into());
    let mut node = node().await;
    let txid = node.send("0.02").await.unwrap();
    node.prove_initiated(txid).await;

    let mut blocks = vec![node.tip().await];
    for height in 1..=3 {
        let (block, jobs) = node.extend().await;
        assert_eq!(
            vec![(txid, ConsensusRuleSet::UpgradeVMv7)],
            node.update(jobs).await,
            "block {height}"
        );
        blocks.push(block);
    }
    for _ in 4..=ACTIVATION_HEIGHT {
        let (block, _) = node.extend().await;
        blocks.push(block);
    }
    assert_eq!(
        Holding {
            mempool: true,
            ..parked(2)
        },
        node.holding(txid).await
    );

    // A sibling of block 4: the next block belongs to the era before the
    // fork again.
    let block_3 = &blocks[3];
    let sibling = invalid_empty_block_with_timestamp(
        block_3,
        block_3.header().timestamp + Timestamp::hours(2),
        NETWORK,
    );
    assert_eq!(4, sibling.header().height.value());
    assert_ne!(blocks[4].hash(), sibling.hash());
    let sibling_jobs = node.set_tip(&sibling).await;
    assert_eq!(
        ConsensusRuleSet::UpgradeVMv7,
        node.next_block_rule_set().await
    );
    assert_eq!(0, jobs_for(&sibling_jobs, txid));
    assert_eq!(parked(2), node.holding(txid).await);
    assert!(matches!(
        node.send("0.02").await,
        Err(SendError::Proof(CreateProofError::LegacyEra(
            ConsensusRuleSet::UpgradeVMv7
        )))
    ));

    // Block 5 of the new chain: the next block is the fork block. The
    // transaction is held in the mempool again, and proven for it.
    let (_, next_jobs) = node.extend().await;
    assert_eq!(1, jobs_for(&next_jobs, txid));
    assert_eq!(
        Holding {
            mempool: true,
            ..parked(3)
        },
        node.holding(txid).await
    );
    assert_eq!(
        vec![(txid, ConsensusRuleSet::UpgradeVMv8)],
        node.update(next_jobs).await
    );
    assert!(node
        .held_transaction(txid)
        .await
        .proof
        .is_proof_collection());
}

/// A parked transaction is dropped once a block spends one of its inputs.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn a_parked_transaction_is_dropped_when_a_block_spends_an_input() {
    let _activation_height = V8ActivationHeightForTests::set(NETWORK, ACTIVATION_HEIGHT.into());
    let mut node = node().await;
    let txid = node.send("0.02").await.unwrap();
    node.prove_initiated(txid).await;
    for _ in 1..ACTIVATION_HEIGHT - 1 {
        node.extend().await;
    }
    let primitive_witness = node.own_witness(txid).await;
    node.extend().await;
    assert_eq!(
        Holding {
            mempool: true,
            ..parked(1)
        },
        node.holding(txid).await
    );

    // The fork block spends the transaction's inputs, as another transaction
    // spending them would.
    let fork_block = node.block_spending(primitive_witness).await;
    assert_eq!(ACTIVATION_HEIGHT, fork_block.header().height.value());
    let jobs = node.set_tip(&fork_block).await;
    assert_eq!(0, jobs_for(&jobs, txid));
    assert_eq!(NOWHERE, node.holding(txid).await);
    assert!(logs_contain("spends one of its inputs"));
}

/// A parked transaction that is not proven is handed to the updater on
/// [`MAX_PARKED_WITNESS_ATTEMPTS`] blocks, and dropped then, also from the
/// mempool.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn a_parked_transaction_not_proven_is_dropped_after_the_attempt_limit() {
    let _activation_height = V8ActivationHeightForTests::set(NETWORK, ACTIVATION_HEIGHT.into());
    let mut node = node().await;
    let txid = node.send("0.02").await.unwrap();
    node.prove_initiated(txid).await;
    for _ in 1..ACTIVATION_HEIGHT - 1 {
        node.extend().await;
    }

    for attempt in 1..=MAX_PARKED_WITNESS_ATTEMPTS {
        let (_, jobs) = node.extend().await;
        assert_eq!(1, jobs_for(&jobs, txid), "attempt {attempt}");
        assert_eq!(
            Holding {
                mempool: true,
                ..parked(attempt)
            },
            node.holding(txid).await
        );
    }
    assert!(!logs_contain("was not proven for"));

    let (_, jobs) = node.extend().await;
    assert_eq!(0, jobs_for(&jobs, txid));
    assert_eq!(NOWHERE, node.holding(txid).await);
    assert!(logs_contain("was not proven for"));
}

/// Two transactions of this node in flight across a block: the first proof
/// of one completes, the other's is interrupted by the block. The interrupted
/// proof, stale once it completes, is dropped and not made again; the block's
/// update jobs prove both, also the one still backed by its witness, and both
/// stay this node's and are proven again on the next block.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn two_own_transactions_in_flight_across_a_block_stay_own_and_are_proven() {
    let _activation_height = V8ActivationHeightForTests::set(NETWORK, 100u64.into());
    let mut node = node().await;
    node.fund().await;
    let first = node.send("0.02").await.unwrap();
    let second = node.send("0.02").await.unwrap();
    assert_ne!(first, second);
    node.prove_initiated(first).await;
    assert!(node
        .held_transaction(first)
        .await
        .proof
        .is_proof_collection());
    assert!(node.held_transaction(second).await.proof.is_witness());
    assert_eq!(vec![first], node.announced());

    let (block, block_jobs) = node.extend().await;
    for txid in [first, second] {
        assert_eq!(
            1,
            block_jobs
                .iter()
                .filter(
                    |job| job.txid() == txid && matches!(job, MempoolUpdateJob::ProofCollection(_))
                )
                .count()
        );
    }

    // The interrupted first proof of the second transaction completes,
    // stale, before the block's jobs report.
    node.prove_initiated(second).await;
    assert!(node.announced().is_empty());
    {
        let state = node.state().lock_guard().await;
        assert!(state.legacy_relay_pool.is_own(second));
        assert!(state
            .legacy_relay_pool
            .get(second)
            .unwrap()
            .proof
            .is_witness());
    }

    let mut proven = node.update(block_jobs).await;
    proven.sort_by_key(|(txid, _)| *txid == second);
    assert_eq!(
        vec![
            (first, ConsensusRuleSet::UpgradeVMv7),
            (second, ConsensusRuleSet::UpgradeVMv7)
        ],
        proven
    );
    let tip_mutator_set_hash = block.mutator_set_accumulator_after().unwrap().hash();
    for txid in [first, second] {
        let state = node.state().lock_guard().await;
        assert!(state.legacy_relay_pool.is_own(txid));
        let transaction = state.legacy_relay_pool.get(txid).unwrap();
        assert!(transaction.proof.is_proof_collection());
        assert_eq!(tip_mutator_set_hash, transaction.kernel.mutator_set_hash);
    }

    let (_, next_jobs) = node.extend().await;
    for txid in [first, second] {
        assert_eq!(1, jobs_for(&next_jobs, txid));
    }
}

/// The update of a transaction of this node that reports after a block mined
/// the transaction is discarded: the transaction does not come back.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn a_late_update_does_not_bring_back_a_mined_transaction() {
    let _activation_height = V8ActivationHeightForTests::set(NETWORK, 100u64.into());
    let mut node = node().await;
    let txid = node.send("0.02").await.unwrap();
    node.prove_initiated(txid).await;

    // The jobs of block 1 run, and report only after block 2, which mines
    // the transaction.
    let (_, block_1_jobs) = node.extend().await;
    let results = node.run_update_jobs(block_1_jobs).await;
    let mining_block = node.block_spending(node.own_witness(txid).await).await;
    let mining_jobs = node.set_tip(&mining_block).await;
    assert_eq!(0, jobs_for(&mining_jobs, txid));
    assert_eq!(NOWHERE, node.holding(txid).await);

    assert!(node
        .handle(results)
        .await
        .contains(&(txid, ConsensusRuleSet::UpgradeVMv7)));
    assert_eq!(NOWHERE, node.holding(txid).await);
    assert!(logs_contain("no longer holds it"));

    let (_, next_jobs) = node.extend().await;
    assert_eq!(0, jobs_for(&next_jobs, txid));
}

/// Before the fork, the upgrade of this node's transaction takes its v7 proof
/// collection as soon as that exists, and its v7 single proof after; a proof
/// that a block made stale is dropped and not made again: the update jobs of
/// that block prove the transaction.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn own_upgrade_takes_the_collection_first_and_drops_a_stale_proof() {
    let _activation_height = V8ActivationHeightForTests::set(NETWORK, 100u64.into());
    let mut node = node_with(TxProvingCapability::SingleProof).await;
    let txid = node.send("0.02").await.unwrap();
    let primitive_witness = node.own_witness(txid).await;

    node.upgrade(primitive_witness.clone(), true).await;
    assert_eq!(
        vec![txid, txid],
        node.announced(),
        "the collection, then the single proof"
    );
    assert!(node.held_transaction(txid).await.proof.is_single_proof());
    assert!(node
        .state()
        .lock_guard()
        .await
        .legacy_relay_pool
        .is_own(txid));

    // A block arrives: an upgrade from the witness of before it makes a
    // stale proof, which is dropped, without a second attempt.
    let (_, jobs) = node.extend().await;
    node.upgrade(primitive_witness, true).await;
    assert!(node.announced().is_empty());
    assert!(logs_contain("a block arrived while proving"));
    assert!(node.held_transaction(txid).await.proof.is_single_proof());
    assert!(jobs
        .iter()
        .any(|job| job.txid() == txid && matches!(job, MempoolUpdateJob::PrimitiveWitness(_))));
}

/// A parked transaction that is removed explicitly, as after failed proofs or
/// when an input is spent, is parked no longer: its inputs can be spent again,
/// and a new payment spending them stays.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn a_removed_parked_transaction_is_not_put_back() {
    let _activation_height = V8ActivationHeightForTests::set(NETWORK, ACTIVATION_HEIGHT.into());
    let mut node = node().await;
    let txid = node.send("0.02").await.unwrap();
    node.prove_initiated(txid).await;
    for _ in 1..ACTIVATION_HEIGHT {
        node.extend().await;
    }
    assert_eq!(
        Holding {
            mempool: true,
            ..parked(1)
        },
        node.holding(txid).await
    );

    node.main_loop_handler
        .global_state_lock
        .lock_guard_mut()
        .await
        .mempool_remove(txid)
        .await;
    assert_eq!(NOWHERE, node.holding(txid).await);

    // A new payment spends the inputs again, for the era after the fork.
    let second = node.send("0.02").await.unwrap();
    assert_ne!(txid, second);
    assert!(node.holding(second).await.mempool);

    let (_, jobs) = node.extend().await;
    assert_eq!(0, jobs_for(&jobs, txid));
    assert_eq!(NOWHERE, node.holding(txid).await);
    assert!(node.holding(second).await.mempool);
}

/// A parked transaction of which a block spends an input is dropped also when
/// the next block belongs to the era before the fork, as after a
/// reorganization back across it.
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn a_parked_transaction_spent_before_the_fork_is_dropped() {
    let _activation_height = V8ActivationHeightForTests::set(NETWORK, ACTIVATION_HEIGHT.into());
    let mut node = node().await;
    let txid = node.send("0.02").await.unwrap();
    node.prove_initiated(txid).await;

    let mut blocks = vec![node.tip().await];
    for _ in 1..=3 {
        let (block, jobs) = node.extend().await;
        node.update(jobs).await;
        blocks.push(block);
    }
    let primitive_witness = node.own_witness(txid).await;
    for _ in 4..=ACTIVATION_HEIGHT {
        node.extend().await;
    }
    assert_eq!(
        Holding {
            mempool: true,
            ..parked(2)
        },
        node.holding(txid).await
    );

    // A sibling of block 4 that spends the transaction's inputs: the next
    // block belongs to the era before the fork.
    let sibling = invalid_block_with_transaction(&blocks[3], primitive_witness.into());
    assert_eq!(4, sibling.header().height.value());
    let jobs = node.set_tip(&sibling).await;
    assert_eq!(
        ConsensusRuleSet::UpgradeVMv7,
        node.next_block_rule_set().await
    );
    assert_eq!(0, jobs_for(&jobs, txid));
    assert_eq!(NOWHERE, node.holding(txid).await);
    assert!(logs_contain("spends one of its inputs"));

    let (_, jobs) = node.extend().await;
    assert_eq!(0, jobs_for(&jobs, txid));
    assert_eq!(NOWHERE, node.holding(txid).await);
}
