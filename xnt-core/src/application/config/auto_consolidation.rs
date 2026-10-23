use crate::application::config::network::Network;
use crate::state::wallet::address::ReceivingAddress;

/// Smallest number of inputs a consolidation transaction may have. Spending a
/// single UTXO to one output does not reduce the number of UTXOs.
pub(crate) const MIN_NUM_CONSOLIDATION_INPUTS: u8 = 2;

/// Largest number of inputs a consolidation transaction may have. Peers do not
/// relay proof-collection-backed transactions with more inputs, and the fee
/// for such a consolidation covers the relay minimum up to this many.
pub(crate) const MAX_NUM_CONSOLIDATION_INPUTS: u8 = 200;

#[derive(Debug, Clone, Default)]
pub struct AutoConsolidationSettings {
    /// The number of inputs used in each consolidation transaction. Will never
    /// consolidate with another number of inputs than this.
    pub(crate) num_inputs: u8,

    /// Where the consolidated outputs should be sent.
    pub(crate) policy: ConsolidationTarget,
}

#[derive(Debug, Clone, Default)]
pub enum ConsolidationTarget {
    #[default]
    Inactive,

    /// Send each consolidated output to this wallet's Generation key at
    /// [`CONSOLIDATION_KEY_INDEX`](crate::api::tx_initiation::consolidate::CONSOLIDATION_KEY_INDEX).
    ActiveDynamic,

    /// Send each consolidated output to a fixed address.
    ActiveFixed { address: Box<ReceivingAddress> },
}

impl AutoConsolidationSettings {
    // OK to suppress this linter rule because we are parsing and the nested
    // type tells clap how to parse.
    #[expect(clippy::option_option)]
    pub(crate) fn parse(
        auto_consolidate_cli: &Option<Option<String>>,
        num_consolidation_inputs_cli: u8,
        network: Network,
    ) -> Result<Self, String> {
        let policy = match auto_consolidate_cli {
            Some(None) => ConsolidationTarget::ActiveDynamic,
            Some(Some(address)) => {
                let address = ReceivingAddress::from_bech32m(address, network)
                    .map_err(|inner_err| format!("invalid consolidation address: {inner_err}"))?;
                ConsolidationTarget::ActiveFixed {
                    address: Box::new(address),
                }
            }
            None => ConsolidationTarget::Inactive,
        };

        if !(MIN_NUM_CONSOLIDATION_INPUTS..=MAX_NUM_CONSOLIDATION_INPUTS)
            .contains(&num_consolidation_inputs_cli)
        {
            return Err(format!(
                "--num-consolidation-inputs must be between {MIN_NUM_CONSOLIDATION_INPUTS} and \
                 {MAX_NUM_CONSOLIDATION_INPUTS}, got {num_consolidation_inputs_cli}"
            ));
        }

        Ok(AutoConsolidationSettings {
            num_inputs: num_consolidation_inputs_cli,
            policy,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;

    #[test]
    fn parse_flag_without_address_is_dynamic() {
        let settings = AutoConsolidationSettings::parse(&Some(None), 8, Network::Main).unwrap();
        assert_eq!(8, settings.num_inputs);
        assert!(matches!(
            settings.policy,
            ConsolidationTarget::ActiveDynamic
        ));
    }

    #[test]
    fn parse_absent_flag_is_inactive() {
        let settings = AutoConsolidationSettings::parse(&None, 8, Network::Main).unwrap();
        assert!(matches!(settings.policy, ConsolidationTarget::Inactive));
    }

    #[test]
    fn parse_flag_with_address_is_fixed() {
        let network = Network::Main;
        let address: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(rand::random()).into();
        let encoded = address.to_bech32m(network).unwrap();
        let settings = AutoConsolidationSettings::parse(&Some(Some(encoded)), 8, network).unwrap();
        let ConsolidationTarget::ActiveFixed { address: parsed } = settings.policy else {
            panic!("expected a fixed consolidation target");
        };
        assert_eq!(address, *parsed);
    }

    #[test]
    fn parse_rejects_invalid_address() {
        let result =
            AutoConsolidationSettings::parse(&Some(Some("foo".to_string())), 8, Network::Main);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_number_of_inputs_out_of_range() {
        assert!(AutoConsolidationSettings::parse(&Some(None), 1, Network::Main).is_err());
        assert!(AutoConsolidationSettings::parse(&Some(None), 0, Network::Main).is_err());
        assert!(AutoConsolidationSettings::parse(&Some(None), 2, Network::Main).is_ok());
        assert!(AutoConsolidationSettings::parse(&Some(None), 200, Network::Main).is_ok());
        assert!(AutoConsolidationSettings::parse(&Some(None), 201, Network::Main).is_err());
    }

    #[test]
    fn command_line_flags_are_parsed() {
        use clap::Parser;

        use crate::application::config::cli_args::Args;

        let defaults = Args::try_parse_from(["xnt-core"]).unwrap();
        assert!(matches!(
            defaults.auto_consolidate().policy,
            ConsolidationTarget::Inactive
        ));
        assert_eq!(8, defaults.auto_consolidate().num_inputs);

        let dynamic = Args::try_parse_from(["xnt-core", "--auto-consolidate"]).unwrap();
        dynamic.validate_auto_consolidation().unwrap();
        assert!(matches!(
            dynamic.auto_consolidate().policy,
            ConsolidationTarget::ActiveDynamic
        ));

        let address: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(rand::random()).into();
        let encoded = address.to_bech32m(Network::Main).unwrap();
        let fixed = Args::try_parse_from([
            "xnt-core",
            "--network",
            "main",
            "--auto-consolidate",
            &encoded,
            "--num-consolidation-inputs",
            "4",
        ])
        .unwrap();
        fixed.validate_auto_consolidation().unwrap();
        let settings = fixed.auto_consolidate();
        assert_eq!(4, settings.num_inputs);
        assert!(matches!(
            settings.policy,
            ConsolidationTarget::ActiveFixed { address: parsed } if *parsed == address
        ));

        let invalid = Args::try_parse_from(["xnt-core", "--auto-consolidate", "foo"]).unwrap();
        assert!(invalid.validate_auto_consolidation().is_err());
    }

    #[test]
    fn rejects_auto_consolidation_on_nodes_that_do_not_initiate_transactions() {
        use clap::Parser;

        use crate::application::config::cli_args::Args;

        let notx = Args::try_parse_from([
            "xnt-core",
            "--auto-consolidate",
            "--no-transaction-initiation",
        ])
        .unwrap();
        assert!(notx.validate_auto_consolidation().is_err());

        let weak = Args::try_parse_from([
            "xnt-core",
            "--auto-consolidate",
            "--tx-proving-capability",
            "lockscript",
        ])
        .unwrap();
        assert!(weak.validate_auto_consolidation().is_err());

        let capable = Args::try_parse_from([
            "xnt-core",
            "--auto-consolidate",
            "--tx-proving-capability",
            "proofcollection",
        ])
        .unwrap();
        assert!(capable.validate_auto_consolidation().is_ok());

        let inactive = Args::try_parse_from(["xnt-core", "--no-transaction-initiation"]).unwrap();
        assert!(inactive.validate_auto_consolidation().is_ok());
    }
}
