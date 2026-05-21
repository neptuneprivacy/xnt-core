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
    ///
    /// When `max_inputs` is set, automatically chooses a strategy based on the
    /// number of spendable inputs:
    /// - **≥ 50 inputs** — consolidation: fills slots with the smallest UTXOs
    ///   and swaps in large ones from the tail as needed to cover the amount.
    /// - **< 50 inputs** — sliding window: finds the best contiguous window of
    ///   up to `limit` inputs that covers the spend amount.
    ///
    /// When `max_inputs` is `None`, uses a greedy scan with no input cap.
    pub fn build(self) -> Vec<TxInput> {
        let Self {
            mut spendable_inputs,
            policy,
            spend_amount,
            max_inputs,
        } = self;

        if spend_amount.is_zero() {
            return Vec::new();
        }

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
            Some(limit) => {
                if spendable_inputs.len() >= 50 {
                    Self::select_with_consolidation(spendable_inputs, spend_amount, limit)
                } else {
                    Self::select_best_window(spendable_inputs, spend_amount, limit)
                }
            }
            None => Self::select_greedy(spendable_inputs, spend_amount),
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

    /// Find the fewest inputs (up to `limit`) that cover the spend amount,
    /// preferring the tightest fit. Tries sizes 1, 2, 3, ... and for each
    /// size slides from the small end to find the first (smallest-valued)
    /// window that covers the target.
    fn select_best_window(
        spendable_inputs: Vec<TxInput>,
        spend_amount: NativeCurrencyAmount,
        limit: usize,
    ) -> Vec<TxInput> {
        let n = spendable_inputs.len();
        let max_window = limit.min(n);

        for size in 1..=max_window {
            for start in 0..=(n - size) {
                let window = &spendable_inputs[start..start + size];
                let sum = window
                    .iter()
                    .fold(NativeCurrencyAmount::zero(), |acc, input| {
                        acc + input.utxo.get_native_currency_amount()
                    });
                if sum >= spend_amount {
                    return window.to_vec();
                }
            }
        }

        Vec::new()
    }

    /// Greedy scan: collect inputs in policy order until the target is met.
    /// No input count limit.
    fn select_greedy(
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

    // --- best_window tests (< 50 inputs, limit=10) ---

    #[test]
    fn best_window_tightest_single_fit() {
        // target=25, picks [35] (smallest single ≥ 25), not [300]
        let inputs: Vec<TxInput> = [1, 2, 3, 5, 8, 12, 20, 35, 50, 80, 150, 300]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(25))
            .max_inputs(Some(10))
            .build();

        // size=1: scans 1,2,3,5,8,12,20 all < 25, then [35] ≥ 25 ✓
        assert_eq!(result.len(), 1);
        assert_eq!(amounts(&result), vec![coins(35)]);
    }

    #[test]
    fn best_window_tightest_single_large_target() {
        // target=140, picks [150] not [300]
        let inputs: Vec<TxInput> = [1, 2, 3, 5, 8, 12, 20, 35, 50, 80, 150, 300]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(140))
            .max_inputs(Some(10))
            .build();

        // size=1: scans... [150] ≥ 140 ✓
        assert_eq!(result.len(), 1);
        assert_eq!(amounts(&result), vec![coins(150)]);
    }

    #[test]
    fn best_window_two_inputs_needed() {
        // target=350, no single input covers, need 2
        let inputs: Vec<TxInput> = [1, 2, 3, 5, 8, 12, 20, 35, 50, 80, 150, 300]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(350))
            .max_inputs(Some(10))
            .build();

        // size=1: max is 300 < 350
        // size=2: slides... [150,300]=450 ≥ 350 ✓
        assert_eq!(result.len(), 2);
        assert_eq!(amounts(&result), vec![coins(150), coins(300)]);
    }

    #[test]
    fn best_window_three_inputs_needed() {
        // target=500, need 3
        let inputs: Vec<TxInput> = [1, 2, 3, 5, 8, 12, 20, 35, 50, 80, 150, 300]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(500))
            .max_inputs(Some(10))
            .build();

        // size=2: max pair [150,300]=450 < 500
        // size=3: slides... [80,150,300]=530 ≥ 500 ✓
        assert_eq!(result.len(), 3);
        assert_eq!(amounts(&result), vec![coins(80), coins(150), coins(300)]);
    }

    #[test]
    fn best_window_five_inputs_needed() {
        // target=600, need 5
        let inputs: Vec<TxInput> = [1, 2, 3, 5, 8, 12, 20, 35, 50, 80, 150, 300]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(600))
            .max_inputs(Some(10))
            .build();

        // size=4: [50,80,150,300]=580 < 600
        // size=5: slides... [35,50,80,150,300]=615 ≥ 600 ✓
        assert_eq!(result.len(), 5);
        assert_eq!(
            amounts(&result),
            vec![coins(35), coins(50), coins(80), coins(150), coins(300)]
        );
    }

    #[test]
    fn best_window_nine_inputs_exact_fit() {
        // target=660, needs 9 to exactly hit
        let inputs: Vec<TxInput> = [1, 2, 3, 5, 8, 12, 20, 35, 50, 80, 150, 300]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(660))
            .max_inputs(Some(10))
            .build();

        // size=9: slides... [5,8,12,20,35,50,80,150,300]=660 ≥ 660 ✓
        assert_eq!(result.len(), 9);
        assert_eq!(
            amounts(&result),
            vec![
                coins(5),
                coins(8),
                coins(12),
                coins(20),
                coins(35),
                coins(50),
                coins(80),
                coins(150),
                coins(300)
            ]
        );
    }

    #[test]
    fn best_window_impossible_total_insufficient() {
        // target=670, total of all 12 = 666 < 670
        let inputs: Vec<TxInput> = [1, 2, 3, 5, 8, 12, 20, 35, 50, 80, 150, 300]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(670))
            .max_inputs(Some(10))
            .build();

        assert!(result.is_empty());
    }

    #[test]
    fn best_window_impossible_limit_too_tight() {
        // target=640, top 3 = 530 < 640, limit=3
        let inputs: Vec<TxInput> = [1, 2, 3, 5, 8, 12, 20, 35, 50, 80, 150, 300]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(640))
            .max_inputs(Some(3))
            .build();

        assert!(result.is_empty());
    }

    #[test]
    fn best_window_limit_larger_than_inputs() {
        let inputs: Vec<TxInput> = [10, 20, 30].into_iter().map(make_input).collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(50))
            .max_inputs(Some(10))
            .build();

        // size=1: 30 < 50
        // size=2: slides... [10,20]=30 < 50, [20,30]=50 ≥ 50 ✓
        assert_eq!(result.len(), 2);
        assert_eq!(amounts(&result), vec![coins(20), coins(30)]);
    }

    #[test]
    fn best_window_empty_inputs() {
        let result = TxInputListBuilder::new()
            .spendable_inputs(vec![])
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(10))
            .max_inputs(Some(10))
            .build();

        assert!(result.is_empty());
    }

    #[test]
    fn best_window_exact_match_prefers_tight() {
        // target=50, picks [50] exactly, not [80] or [300]
        let inputs: Vec<TxInput> = [5, 10, 25, 50, 80].into_iter().map(make_input).collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(50))
            .max_inputs(Some(10))
            .build();

        assert_eq!(result.len(), 1);
        assert_eq!(amounts(&result), vec![coins(50)]);
    }

    #[test]
    fn best_window_all_equal_values() {
        let inputs: Vec<TxInput> = [10, 10, 10, 10, 10].into_iter().map(make_input).collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(25))
            .max_inputs(Some(10))
            .build();

        // size=1: 10 < 25
        // size=2: 20 < 25
        // size=3: [10,10,10]=30 ≥ 25 ✓
        assert_eq!(result.len(), 3);
        assert_eq!(amounts(&result), vec![coins(10), coins(10), coins(10)]);
    }

    #[test]
    fn best_window_tightest_pair() {
        // target=90, could use [80,150]=230 or just [150]=150
        // size=1 finds [150] first since it's the smallest single ≥ 90
        let inputs: Vec<TxInput> = [5, 10, 20, 50, 80, 150, 300]
            .into_iter()
            .map(make_input)
            .collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(90))
            .max_inputs(Some(10))
            .build();

        assert_eq!(result.len(), 1);
        assert_eq!(amounts(&result), vec![coins(150)]);
    }

    // --- consolidation tests (>= 50 inputs) ---

    #[test]
    fn consolidation_many_dust_utxos() {
        // 101 inputs >= 50 → consolidation (small front + big tail)
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
    fn consolidation_swaps_in_bigs_as_needed() {
        // 60 inputs >= 50 → consolidation
        let mut inputs: Vec<TxInput> = (1..=58).map(make_input).collect();
        inputs.push(make_input(500));
        inputs.push(make_input(1000));

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(520))
            .max_inputs(Some(10))
            .build();

        let amts = amounts(&result);
        assert_eq!(result.len(), 10);
        // keeps smallest dust [1..=9] and swaps in 1000
        assert!(amts.contains(&coins(1)));
        assert!(amts.contains(&coins(9)));
        assert!(amts.contains(&coins(1000)));
    }

    #[test]
    fn consolidation_all_smalls_sufficient() {
        // 50 inputs >= 50 → consolidation, but all smalls cover it
        let inputs: Vec<TxInput> = (1..=50).map(make_input).collect();

        let result = TxInputListBuilder::new()
            .spendable_inputs(inputs)
            .policy(InputSelectionPolicy::ByNativeCoinAmount(SortOrder::Ascending))
            .spend_amount(coins(10))
            .max_inputs(Some(10))
            .build();

        assert_eq!(result.len(), 10);
        let expected: Vec<NativeCurrencyAmount> = (1..=10).map(coins).collect();
        assert_eq!(amounts(&result), expected);
    }

    // --- greedy tests (no limit) ---

    #[test]
    fn greedy_scan_no_limit() {
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
