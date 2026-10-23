//! Settings for moving funds held at legacy-format dCTIDH locks after each
//! block, see `--migrate-dctidh`.

use anyhow::ensure;
use tracing::info;
use tracing::warn;

use crate::api::tx_initiation::migrate_dctidh::is_own_address;
use crate::api::tx_initiation::migrate_dctidh::MigrationDestination;
use crate::application::config::auto_consolidation::MAX_NUM_CONSOLIDATION_INPUTS;
use crate::application::config::cli_args::Args;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;
use crate::state::wallet::address::KeyType;
use crate::state::GlobalState;

/// Largest number of inputs of a migration transaction. Peers do not relay
/// proof-collection-backed transactions with more inputs.
pub(crate) const MAX_NUM_MIGRATION_INPUTS: usize = MAX_NUM_CONSOLIDATION_INPUTS as usize;

/// The settings given with `--migrate-dctidh` and the flags that go with it.
#[derive(Debug, Clone)]
pub struct DctidhMigrationSettings {
    pub(crate) destination: MigrationDestination,

    /// The fee per transaction, or `None` to choose it from the proving
    /// capability and the number of inputs.
    pub(crate) fee: Option<NativeCurrencyAmount>,

    /// The maximum number of inputs per transaction.
    pub(crate) batch: usize,

    /// Whether an explicit destination address may be one not owned by this
    /// wallet.
    pub(crate) allow_foreign: bool,
}

impl DctidhMigrationSettings {
    /// The settings given on the command line, or `None` if `--migrate-dctidh`
    /// is not set.
    ///
    /// Checks the flags among themselves; the destination address is checked
    /// by [`Self::validate_destination`] and against the wallet by
    /// [`Self::prepare_wallet`].
    pub(crate) fn parse(args: &Args) -> anyhow::Result<Option<Self>> {
        let Some(spec) = &args.migrate_dctidh else {
            return Ok(None);
        };

        let destination =
            MigrationDestination::parse(spec, args.migrate_dctidh_index, args.network)
                .map_err(|err| anyhow::anyhow!("invalid --migrate-dctidh destination: {err}"))?;

        let batch = args.migrate_dctidh_batch;
        ensure!(
            (1..=MAX_NUM_MIGRATION_INPUTS).contains(&batch),
            "--migrate-dctidh-batch must be between 1 and {MAX_NUM_MIGRATION_INPUTS}, got {batch}"
        );

        if let Some(fee) = args.migrate_dctidh_fee {
            let per_input = args.min_relay_pctx_fee_per_input;
            let relay_minimum = u32::try_from(batch)
                .ok()
                .and_then(|batch| per_input.checked_scalar_mul(batch));
            ensure!(
                relay_minimum.is_some_and(|relay_minimum| fee >= relay_minimum),
                "--migrate-dctidh-fee {fee} is below the minimum at which peers relay a \
                 transaction with {batch} inputs ({per_input} per input, see \
                 --min-relay-pctx-fee-per-input); raise the fee or lower --migrate-dctidh-batch"
            );
        }

        ensure!(
            !args.no_transaction_initiation,
            "--migrate-dctidh cannot be combined with --no-transaction-initiation"
        );
        ensure!(
            !matches!(
                args.tx_proving_capability,
                Some(TxProvingCapability::LockScript | TxProvingCapability::PrimitiveWitness)
            ),
            "--migrate-dctidh requires a proving capability of at least proof collection"
        );

        Ok(Some(Self {
            destination,
            fee: args.migrate_dctidh_fee,
            batch,
            allow_foreign: args.migrate_dctidh_allow_foreign,
        }))
    }

    /// Check that an explicit destination address can receive funds, see
    /// [`ReceivingAddress::validate_as_recipient`](crate::state::wallet::address::ReceivingAddress::validate_as_recipient).
    /// Costs one dCTIDH key derivation for a dCTIDH address.
    pub(crate) fn validate_destination(&self) -> anyhow::Result<()> {
        if let MigrationDestination::Address(address) = &self.destination {
            address
                .validate_as_recipient()
                .map_err(|err| anyhow::anyhow!("invalid --migrate-dctidh destination: {err}"))?;
        }
        Ok(())
    }

    /// Check the destination against the wallet, before the first migration.
    ///
    /// An explicit destination address must be owned by this wallet, unless
    /// `--migrate-dctidh-allow-foreign` is set. A derivation index at or above
    /// the wallet's counter for its key type raises the counter, so that the
    /// wallet watches the destination.
    pub(crate) async fn prepare_wallet(&self, state: &mut GlobalState) -> anyhow::Result<()> {
        let (key_type, index) = match &self.destination {
            MigrationDestination::Address(address) => {
                if !is_own_address(&state.wallet_state, address) {
                    ensure!(
                        self.allow_foreign,
                        "the --migrate-dctidh destination address is not owned by this wallet; \
                         set --migrate-dctidh-allow-foreign to move the funds there anyway"
                    );
                    let network = state.cli().network;
                    let address = address.to_display_bech32m_abbreviated(network)?;
                    warn!(
                        "Funds held at legacy-format dCTIDH locks are moved to {address}, an \
                         address not owned by this wallet."
                    );
                }
                return Ok(());
            }
            MigrationDestination::Generation { index } => (KeyType::Generation, *index),
            MigrationDestination::Dctidh { index } => (KeyType::dCTIDH, *index),
        };

        if let Some(index) = index {
            let counter = state.wallet_state.spending_key_counter(key_type);
            if index >= counter {
                info!(
                    "Raising the {key_type} key derivation counter from {counter} to {}, so that \
                     the wallet watches the --migrate-dctidh destination.",
                    index + 1
                );
                state
                    .wallet_state
                    .bump_derivation_counter(key_type, index)
                    .await;
                state.persist_wallet().await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use clap::Parser;
    use macro_rules_attr::apply;
    use rand::random;

    use super::*;
    use crate::application::config::network::Network;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::address::ReceivingAddress;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;

    const NETWORK: Network = Network::Testnet(0);

    fn args(spec: &str) -> Args {
        Args {
            migrate_dctidh: Some(spec.to_string()),
            ..Args::default_with_network(NETWORK)
        }
    }

    fn coins(amount: &str) -> NativeCurrencyAmount {
        NativeCurrencyAmount::coins_from_str(amount).unwrap()
    }

    fn foreign_address() -> ReceivingAddress {
        GenerationReceivingAddress::derive_from_seed(random()).into()
    }

    #[test]
    fn absent_flag_turns_the_migration_off() {
        let args = Args::default_with_network(NETWORK);
        assert!(DctidhMigrationSettings::parse(&args).unwrap().is_none());
        args.validate_dctidh_migration().unwrap();
        assert!(args.dctidh_migration().is_none());
    }

    #[test]
    fn command_line_flags_are_parsed() {
        let args = Args::try_parse_from([
            "xnt-core",
            "--migrate-dctidh",
            "dctidh",
            "--migrate-dctidh-index",
            "4",
            "--migrate-dctidh-fee",
            "0.02",
            "--migrate-dctidh-batch",
            "20",
        ])
        .unwrap();
        args.validate_dctidh_migration().unwrap();
        let settings = args.dctidh_migration().unwrap();
        assert_eq!(
            MigrationDestination::Dctidh { index: Some(4) },
            settings.destination
        );
        assert_eq!(Some(coins("0.02")), settings.fee);
        assert_eq!(20, settings.batch);
        assert!(!settings.allow_foreign);

        let defaults =
            Args::try_parse_from(["xnt-core", "--migrate-dctidh", "generation"]).unwrap();
        let default_settings = DctidhMigrationSettings::parse(&defaults).unwrap().unwrap();
        assert_eq!(
            MigrationDestination::Generation { index: None },
            default_settings.destination
        );
        assert_eq!(None, default_settings.fee);
        assert_eq!(10, default_settings.batch);
    }

    #[test]
    fn batch_size_must_be_in_range() {
        for (batch, is_valid) in [(0, false), (1, true), (200, true), (201, false)] {
            let args = Args {
                migrate_dctidh_batch: batch,
                ..args("generation")
            };
            assert_eq!(
                is_valid,
                DctidhMigrationSettings::parse(&args).is_ok(),
                "{batch}"
            );
        }
    }

    #[test]
    fn fee_must_cover_the_relay_minimum_of_a_full_batch() {
        // 10 inputs at 0.0005 each
        for (fee, is_valid) in [("0.0049", false), ("0.005", true), ("1", true)] {
            let args = Args {
                migrate_dctidh_fee: Some(coins(fee)),
                ..args("generation")
            };
            assert_eq!(
                is_valid,
                DctidhMigrationSettings::parse(&args).is_ok(),
                "{fee}"
            );
        }
    }

    #[test]
    fn incompatible_flags_are_refused() {
        let no_initiation = Args {
            no_transaction_initiation: true,
            ..args("generation")
        };
        assert!(DctidhMigrationSettings::parse(&no_initiation).is_err());

        let witness_only = Args {
            tx_proving_capability: Some(TxProvingCapability::PrimitiveWitness),
            ..args("generation")
        };
        assert!(DctidhMigrationSettings::parse(&witness_only).is_err());

        let encoded = foreign_address().to_bech32m(NETWORK).unwrap();
        let index_with_address = Args {
            migrate_dctidh_index: Some(0),
            ..args(&encoded)
        };
        assert!(DctidhMigrationSettings::parse(&index_with_address).is_err());

        let other_network = foreign_address().to_bech32m(Network::Main).unwrap();
        assert!(DctidhMigrationSettings::parse(&args(&other_network)).is_err());
        assert!(args(&other_network).validate_dctidh_migration().is_err());
    }

    #[apply(shared_tokio_runtime)]
    async fn foreign_destination_requires_the_opt_in_flag() {
        let encoded = foreign_address().to_bech32m(NETWORK).unwrap();
        for allow_foreign in [false, true] {
            let args = Args {
                migrate_dctidh_allow_foreign: allow_foreign,
                ..args(&encoded)
            };
            let settings = DctidhMigrationSettings::parse(&args).unwrap().unwrap();
            settings.validate_destination().unwrap();
            let mut alice = mock_genesis_global_state(0, WalletEntropy::new_random(), args).await;
            let result = settings
                .prepare_wallet(&mut *alice.lock_guard_mut().await)
                .await;
            assert_eq!(allow_foreign, result.is_ok());
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn own_destination_needs_no_opt_in_flag() {
        let wallet = WalletEntropy::new_random();
        let own_address: ReceivingAddress =
            wallet.nth_generation_spending_key(0).to_address().into();
        let encoded = own_address.to_bech32m(NETWORK).unwrap();
        let args = args(&encoded);
        let settings = DctidhMigrationSettings::parse(&args).unwrap().unwrap();
        let mut alice = mock_genesis_global_state(0, wallet, args).await;
        settings
            .prepare_wallet(&mut *alice.lock_guard_mut().await)
            .await
            .unwrap();
    }

    #[apply(shared_tokio_runtime)]
    async fn derivation_index_beyond_the_counter_raises_it() {
        let mut alice =
            mock_genesis_global_state(0, WalletEntropy::new_random(), args("generation")).await;
        let counter = alice
            .lock_guard()
            .await
            .wallet_state
            .spending_key_counter(KeyType::Generation);

        let index = counter + 3;
        let args = Args {
            migrate_dctidh_index: Some(index),
            ..args("generation")
        };
        let settings = DctidhMigrationSettings::parse(&args).unwrap().unwrap();
        settings
            .prepare_wallet(&mut *alice.lock_guard_mut().await)
            .await
            .unwrap();

        assert_eq!(
            index + 1,
            alice
                .lock_guard()
                .await
                .wallet_state
                .spending_key_counter(KeyType::Generation)
        );
    }
}
