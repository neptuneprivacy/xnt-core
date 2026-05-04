//! provides a builder and related types for selecting which inputs to use in a
//! transaction in order to cover the target spend amount.
//!
//! all spendable inputs may be obtained via
//! [TransactionInitiator::spendable_inputs()](super::super::initiator::TransactionInitiator::spendable_inputs()).
//!
//! The `InputSelectionPolicy` enum provides a set of policies for selecting
//! inputs.
//!
//! If one wishes to use custom logic for selecting and ordering inputs
//! that can be done by manipulating the spendable inputs directly, and then
//! pass `InputSelectionPolicy::ByProvidedOrder` to the builder.
//!
//! see [builder](super) for examples of using the builders together.
use get_size2::GetSize;
use num_traits::Zero;
use rand::rng;
use rand::seq::SliceRandom;
use serde::Deserialize;
use serde::Serialize;

use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::wallet::transaction_input::TxInput;

/// defines sort ordering: ascending or descending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortOrder {
    /// ascending order
    Ascending,
    /// descending order
    Descending,
}

// ##multicoin## :
//  1. how do we select inputs if spending a token?
//  2. how do we select inputs if input or output utxo represent
//     a smart contract?
//  3. what if input or output utxo(s) contain more than one Coin?

/// defines a policy for selecting from available transaction inputs in order
/// to cover the target spend amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum InputSelectionPolicy {
    /// choose inputs at random
    #[default]
    Random,

    /// use the natural order of the provided inputs.
    ByProvidedOrder,

    /// choose inputs by native currency amount in specified sort order.
    ByNativeCoinAmount(SortOrder),

    /// choose inputs by utxo size (bytes) in specified sort order
    ByUtxoSize(SortOrder),
    // ##multicoin## : is something like this possible?
    // eg, so we can order by a particular token amount, like USDT.
    // ByCoinAmount(Coin, SortOrder)

    // I'm unsure how/if this is possible (to lookup block-height of input confirmation)
    // ByBlockHeight(SortOrder)
}

/// a builder to select transaction inputs from all available inputs based on an
/// [InputSelectionPolicy].
#[derive(Debug, Default)]
pub struct TxInputListBuilder {
    // note: all fields intentionally private
    spendable_inputs: Vec<TxInput>,
    policy: InputSelectionPolicy,

    // ##multicoin## : maybe this should be Coin or Vec<Coin> instead of NativeCurrencyAmount?
    spend_amount: NativeCurrencyAmount,

    /// Maximum number of inputs to select. `None` means no limit.
    max_inputs: Option<usize>,
}

impl TxInputListBuilder {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// set available spendable inputs.  These may be obtained via
    /// [spendable_inputs()](super::super::initiator::TransactionInitiator::spendable_inputs())
    pub fn spendable_inputs(mut self, inputs: Vec<TxInput>) -> Self {
        self.spendable_inputs = inputs;
        self
    }

    /// set an input selection policy
    pub fn policy(mut self, policy: InputSelectionPolicy) -> Self {
        self.policy = policy;
        self
    }

    // ##multicoin## : maybe this should be Coin or Vec<Coin> instead of NativeCurrencyAmount?

    /// set the target spend amount
    pub fn spend_amount(mut self, spend_amount: NativeCurrencyAmount) -> Self {
        self.spend_amount = spend_amount;
        self
    }

    /// set optional max number of inputs to select
    pub fn max_inputs(mut self, max_inputs: Option<usize>) -> Self {
        self.max_inputs = max_inputs;
        self
    }

    /// Build the list of transaction inputs.
    pub fn build(self) -> Vec<TxInput> {
        let Self {
            mut spendable_inputs,
            policy,
            spend_amount,
            max_inputs,
        } = self;

        // apply ordering
        match policy {
            InputSelectionPolicy::Random => {
                spendable_inputs.shuffle(&mut rng());
            }
            InputSelectionPolicy::ByProvidedOrder => {}
            InputSelectionPolicy::ByNativeCoinAmount(order) => {
                spendable_inputs.sort_by(|a, b| {
                    sort(
                        order,
                        &a.utxo.get_native_currency_amount(),
                        &b.utxo.get_native_currency_amount(),
                    )
                });
            }
            InputSelectionPolicy::ByUtxoSize(order) => {
                spendable_inputs
                    .sort_by(|a, b| sort(order, &a.utxo.get_heap_size(), &b.utxo.get_heap_size()));
            }
        }

        match max_inputs {
            Some(limit) => Self::select_with_consolidation(spendable_inputs, spend_amount, limit),
            None => Self::select_without_consolidation(spendable_inputs, spend_amount),
        }
    }

    /// Select up to `limit` inputs, maximizing small-value consolidation.
    /// Fills all slots with the smallest inputs, then swaps in large ones
    /// from the end only as needed to cover the spend amount.
    fn select_with_consolidation(
        spendable_inputs: Vec<TxInput>,
        spend_amount: NativeCurrencyAmount,
        limit: usize,
    ) -> Vec<TxInput> {
        let n = spendable_inputs.len();
        let limit = limit.min(n);
        if limit == 0 {
            return Vec::new();
        }

        let mut small_end = limit;
        let mut big_start = n;

        let selected_sum = |se: usize, bs: usize| -> NativeCurrencyAmount {
            spendable_inputs[..se]
                .iter()
                .chain(spendable_inputs[bs..].iter())
                .fold(NativeCurrencyAmount::zero(), |acc, input| {
                    acc + input.utxo.get_native_currency_amount()
                })
        };

        while selected_sum(small_end, big_start) < spend_amount
            && small_end > 0
            && big_start > small_end
        {
            small_end -= 1;
            big_start -= 1;
        }

        if selected_sum(small_end, big_start) >= spend_amount {
            let mut result = spendable_inputs[..small_end].to_vec();
            result.extend_from_slice(&spendable_inputs[big_start..]);
            result
        } else {
            Vec::new()
        }
    }

    /// Collect inputs in policy order until the spend target is met.
    fn select_without_consolidation(
        spendable_inputs: Vec<TxInput>,
        spend_amount: NativeCurrencyAmount,
    ) -> Vec<TxInput> {
        let mut collected = Vec::new();
        let mut current = NativeCurrencyAmount::zero();
        for input in spendable_inputs {
            if current >= spend_amount {
                break;
            }
            current += input.utxo.get_native_currency_amount();
            collected.push(input);
        }
        collected
    }
}

fn sort<O: Ord>(order: SortOrder, a: &O, b: &O) -> std::cmp::Ordering {
    match order {
        SortOrder::Ascending => Ord::cmp(a, b),
        SortOrder::Descending => Ord::cmp(b, a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::state::wallet::unlocked_utxo::UnlockedUtxo;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use tasm_lib::prelude::Digest;
    use tasm_lib::triton_vm::prelude::triton_program;
    use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

    fn make_input(amount: u32) -> TxInput {
        let coins = NativeCurrencyAmount::coins(amount).to_native_coins();
        let lock_script = LockScriptAndWitness::new(triton_program!(halt));
        let utxo = Utxo::new(Digest::default(), coins);
        let mp = MsMembershipProof {
            sender_randomness: Digest::default(),
            receiver_preimage: Digest::default(),
            auth_path_aocl: MmrMembershipProof::new(vec![]),
            aocl_leaf_index: 0,
            target_chunks: ChunkDictionary::empty(),
        };
        UnlockedUtxo::unlock(utxo, lock_script, mp).into()
    }

    fn coins(n: u32) -> NativeCurrencyAmount {
        NativeCurrencyAmount::coins(n)
    }

    fn amounts(inputs: &[TxInput]) -> Vec<NativeCurrencyAmount> {
        inputs
            .iter()
            .map(|i| i.utxo.get_native_currency_amount())
            .collect()
    }

    #[test]
    fn consolidation_takes_smalls_and_swaps_in_bigs() {
        let inputs: Vec<TxInput> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 50, 200]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(60))
            .max_inputs(Some(10))
            .build();

        let amts = amounts(&result);
        assert_eq!(result.len(), 10);
        assert!(amts.contains(&coins(1)));
        assert!(amts.contains(&coins(2)));
        assert!(amts.contains(&coins(200)));
    }

    #[test]
    fn consolidation_all_smalls_sufficient() {
        let inputs: Vec<TxInput> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(20))
            .max_inputs(Some(10))
            .build();

        assert_eq!(result.len(), 10);
        let expected: Vec<NativeCurrencyAmount> = (1..=10).map(coins).collect();
        assert_eq!(amounts(&result), expected);
    }

    #[test]
    fn consolidation_single_big_enough() {
        let inputs: Vec<TxInput> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40, 50, 200]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(250))
            .max_inputs(Some(10))
            .build();

        let amts = amounts(&result);
        assert_eq!(result.len(), 10);
        assert!(amts.contains(&coins(200)));
        assert!(amts.contains(&coins(1)));
    }

    #[test]
    fn consolidation_impossible_returns_empty() {
        let inputs: Vec<TxInput> = [1, 1, 1, 1].into_iter().map(make_input).collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(10))
            .max_inputs(Some(4))
            .build();

        assert!(result.is_empty());
    }

    #[test]
    fn consolidation_limit_larger_than_inputs() {
        let inputs: Vec<TxInput> = [10, 20, 30].into_iter().map(make_input).collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(50))
            .max_inputs(Some(10))
            .build();

        assert_eq!(result.len(), 3);
        assert_eq!(amounts(&result), vec![coins(10), coins(20), coins(30)]);
    }

    #[test]
    fn consolidation_empty_inputs() {
        let result = TxInputListBuilder::new()
            .spendable_inputs(vec![])
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(10))
            .max_inputs(Some(10))
            .build();

        assert!(result.is_empty());
    }

    #[test]
    fn consolidation_many_dust_utxos() {
        // 100 incremental inputs [1..=100] + 1 big one.
        let mut inputs: Vec<TxInput> = (1..=100).map(make_input).collect();
        inputs.push(make_input(5000));

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(5010))
            .max_inputs(Some(10))
            .build();

        let amts = amounts(&result);
        assert_eq!(result.len(), 10);
        let mut expected: Vec<NativeCurrencyAmount> = (1..=9).map(coins).collect();
        expected.push(coins(5000));
        assert_eq!(amts, expected);
    }

    #[test]
    fn without_consolidation_greedy_scan() {
        let inputs: Vec<TxInput> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(10))
            .max_inputs(None)
            .build();

        // greedy: takes 1+2+3+4 = 10, stops
        assert_eq!(amounts(&result), vec![coins(1), coins(2), coins(3), coins(4)]);
    }
}
