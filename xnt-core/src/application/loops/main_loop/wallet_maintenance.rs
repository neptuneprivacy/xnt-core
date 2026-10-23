//! Wallet maintenance for a new tip: moving funds held at legacy-format
//! dCTIDH locks, and consolidating UTXOs, as configured.

use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::api::export::Timestamp;
use crate::api::tx_initiation::consolidate::NUM_RECENT_BLOCKS_EXCLUDED;
use crate::api::tx_initiation::error::CreateProofError;
use crate::api::tx_initiation::error::SendError;
use crate::api::tx_initiation::initiator::TransactionInitiator;
use crate::api::tx_initiation::migrate_dctidh::DctidhMigrationReport;
use crate::application::config::dctidh_migration::DctidhMigrationSettings;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::wallet::address::ReceivingAddress;
use crate::GlobalStateLock;

/// What the wallet maintenance remembers from one tip to the next.
#[derive(Debug, Default)]
pub(super) struct WalletMaintenance {
    /// Whether it was logged that moving funds held at legacy-format dCTIDH
    /// locks waits for the `UpgradeVMv8` hard fork.
    fork_wait_logged: bool,

    /// The funds held at legacy-format dCTIDH locks that were last reported,
    /// as number of UTXOs and amount.
    reported_legacy_funds: Option<(usize, NativeCurrencyAmount)>,
}

impl WalletMaintenance {
    /// Move a batch of funds held at legacy-format dCTIDH locks if
    /// `migration` is set, or else report such funds, and then consolidate a
    /// batch of UTXOs if `consolidation` is set.
    ///
    /// Both run one after the other, so that the consolidation does not select
    /// inputs the migration spends.
    pub(super) async fn run(
        &mut self,
        global_state_lock: GlobalStateLock,
        migration: Option<DctidhMigrationSettings>,
        consolidation: Option<(usize, Option<ReceivingAddress>)>,
    ) {
        let mut tx_initiator = global_state_lock.api().tx_initiator();
        let timestamp = Timestamp::now();

        match migration {
            Some(settings) => self.migrate(&mut tx_initiator, settings, timestamp).await,
            None => self.report_unmoved_legacy_funds(&global_state_lock).await,
        }

        if let Some((num_inputs, address)) = consolidation {
            match tx_initiator
                .consolidate(num_inputs, address, timestamp)
                .await
            {
                Ok(_) => {}
                Err(e) if e.is_nothing_to_do() => debug!("auto-consolidation: {e}"),
                Err(e) => warn!("auto-consolidation: {e}"),
            }
        }
    }

    async fn migrate(
        &mut self,
        tx_initiator: &mut TransactionInitiator,
        settings: DctidhMigrationSettings,
        timestamp: Timestamp,
    ) {
        let result = tx_initiator
            .migrate_dctidh_utxos(
                settings.destination,
                settings.fee,
                timestamp,
                NUM_RECENT_BLOCKS_EXCLUDED,
                settings.batch,
            )
            .await;
        match result {
            Ok(report) => self.report_waiting_legacy_funds(&report),
            Err(SendError::Proof(CreateProofError::LegacyEra(_))) => {
                if !self.fork_wait_logged {
                    info!(
                        "Moving funds held at legacy-format dCTIDH locks (--migrate-dctidh) \
                         pauses while the UpgradeVMv8 hard fork is close, and resumes with it."
                    );
                    self.fork_wait_logged = true;
                }
            }
            Err(e) => warn!("dCTIDH migration: {e}"),
        }
    }

    /// Log the funds held at legacy-format dCTIDH locks that wait to be moved,
    /// if they changed since the last report.
    fn report_waiting_legacy_funds(&mut self, report: &DctidhMigrationReport) {
        let waiting = (report.num_waiting, report.amount_waiting);
        let previous = self.reported_legacy_funds.replace(waiting);
        if previous == Some(waiting) {
            return;
        }

        if report.num_waiting == 0 {
            if previous.is_some_and(|(num_utxos, _)| num_utxos > 0) {
                info!("No more funds held at legacy-format dCTIDH locks wait to be moved.");
            }
            return;
        }

        let dust = if report.num_dust > 0 {
            format!(
                "; {} of them, worth {}, are not worth more than their share of the fee and are \
                 not moved",
                report.num_dust, report.amount_dust
            )
        } else {
            String::new()
        };
        info!(
            "{} UTXOs worth {} held at legacy-format dCTIDH locks wait to be moved{dust}.",
            report.num_waiting, report.amount_waiting
        );
    }

    /// Warn if the wallet holds funds at legacy-format dCTIDH locks, which are
    /// not moved since `--migrate-dctidh` is not set. Repeated only when these
    /// funds change.
    pub(super) async fn report_unmoved_legacy_funds(
        &mut self,
        global_state_lock: &GlobalStateLock,
    ) {
        let legacy_funds = {
            let state = global_state_lock.lock_guard().await;
            if state
                .wallet_state
                .get_known_legacy_dctidh_keys()
                .next()
                .is_none()
            {
                return;
            }

            let wallet_status = state.get_wallet_status_for_tip().await;
            let legacy_utxos = wallet_status
                .synced_unspent
                .iter()
                .filter(|(element, _)| element.is_legacy)
                .count();
            (legacy_utxos, wallet_status.legacy_confirmed())
        };

        let previous = self.reported_legacy_funds.replace(legacy_funds);
        let (num_utxos, amount) = legacy_funds;
        if previous == Some(legacy_funds) || num_utxos == 0 {
            return;
        }

        warn!(
            "{num_utxos} UTXOs worth {amount} are held at legacy-format dCTIDH locks. They are not \
             part of the available balance. Move them to a current-format address with \
             --migrate-dctidh, or with the xnt-cli command migrate-dctidh."
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::tx_initiation::migrate_dctidh::tests::coins;
    use crate::api::tx_initiation::migrate_dctidh::tests::receive_at_dctidh_locks;
    use crate::api::tx_initiation::migrate_dctidh::tests::wallet_with_legacy_indices;
    use crate::api::tx_initiation::migrate_dctidh::MigrationDestination;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::BlockProof;
    use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET;
    use crate::state::transaction::tx_proving_capability::TxProvingCapability;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::invalid_empty_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;

    fn settings() -> DctidhMigrationSettings {
        DctidhMigrationSettings {
            destination: MigrationDestination::Generation { index: None },
            fee: None,
            batch: 10,
            allow_foreign: false,
        }
    }

    fn count_lines_containing(lines: &[&str], needle: &str) -> usize {
        lines.iter().filter(|line| line.contains(needle)).count()
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn pause_close_to_the_v8_fork_is_logged_once() {
        let network = Network::Main;
        let cli = cli_args::Args {
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            rate_limit_until_height: 0,
            ..cli_args::Args::default_with_network(network)
        };
        let mut alice = mock_genesis_global_state(0, WalletEntropy::new_random(), cli).await;

        // A placeholder for the first block within the margin before the fork,
        // from which no new transaction for the legacy era is made.
        let tip = alice.lock_guard().await.chain.light_state().clone();
        let successor = invalid_empty_block(&tip, network);
        let mut header = *successor.header();
        let margin = alice.cli().fork_tx_cutoff_margin;
        header.height = (BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET.value() - margin).into();
        let last_pre_fork_block = Block::new(
            header,
            successor.body().clone(),
            successor.appendix().clone(),
            BlockProof::Invalid,
        );
        alice.set_new_tip(last_pre_fork_block).await.unwrap();

        let mut maintenance = WalletMaintenance::default();
        for _ in 0..3 {
            maintenance.run(alice.clone(), Some(settings()), None).await;
        }

        logs_assert(|lines: &[&str]| {
            match count_lines_containing(lines, "pauses while the UpgradeVMv8 hard fork is close") {
                1 => Ok(()),
                n => Err(format!("logged {n} times")),
            }
        });
        assert!(!logs_contain("dCTIDH migration:"));
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn waiting_legacy_funds_are_logged_when_they_change() {
        let mut alice = wallet_with_legacy_indices(1, TxProvingCapability::SingleProof).await;
        receive_at_dctidh_locks(
            &mut alice,
            &[
                (0, coins("3"), true),
                (0, coins("2"), true),
                (0, coins("1"), true),
            ],
        )
        .await;

        // Each pass moves one UTXO, until none is left.
        let mut maintenance = WalletMaintenance::default();
        let one_at_a_time = DctidhMigrationSettings {
            batch: 1,
            ..settings()
        };
        for _ in 0..4 {
            maintenance
                .run(alice.clone(), Some(one_at_a_time.clone()), None)
                .await;
        }

        for (num_utxos, amount) in [(2, "3"), (1, "1")] {
            let amount = coins(amount);
            assert!(logs_contain(&format!(
                "{num_utxos} UTXOs worth {amount} held at legacy-format dCTIDH locks wait to be \
                 moved."
            )));
        }
        logs_assert(|lines: &[&str]| {
            match count_lines_containing(lines, "No more funds held at legacy-format dCTIDH locks")
            {
                1 => Ok(()),
                n => Err(format!("logged {n} times")),
            }
        });
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn unmoved_legacy_funds_are_reported_when_they_change() {
        let mut alice = wallet_with_legacy_indices(1, TxProvingCapability::SingleProof).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("3"), true)]).await;

        let mut maintenance = WalletMaintenance::default();
        maintenance.run(alice.clone(), None, None).await;
        maintenance.run(alice.clone(), None, None).await;
        receive_at_dctidh_locks(&mut alice, &[(0, coins("2"), true)]).await;
        maintenance.run(alice.clone(), None, None).await;

        let warning = "held at legacy-format dCTIDH locks. They are not part of the available";
        logs_assert(
            |lines: &[&str]| match count_lines_containing(lines, warning) {
                2 => Ok(()),
                n => Err(format!("warned {n} times")),
            },
        );
        for (num_utxos, amount) in [(1, "3"), (2, "5")] {
            let amount = coins(amount);
            assert!(logs_contain(&format!(
                "{num_utxos} UTXOs worth {amount} are held"
            )));
        }
    }
}
