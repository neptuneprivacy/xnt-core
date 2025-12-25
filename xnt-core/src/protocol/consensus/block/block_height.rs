use std::cmp::min;
use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::Add;
use std::ops::Sub;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use num_traits::ConstZero;
use num_traits::One;
use num_traits::Zero;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

/// The distance, in number of blocks, to the genesis block.
///
/// This struct wraps around a [`BFieldElement`], so the maximum block height
/// is P-1 = 2^64 - 2^32. With an average block time of 588 seconds, this
/// maximum will be reached roughly 344 trillion years after launch. Not urgent.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Hash,
    BFieldCodec,
    TasmObject,
    GetSize,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct BlockHeight(BFieldElement);

// Assuming a block time of 300 seconds
// the number of blocks per reduction cycle is 8640.
pub const BLOCKS_PER_GENERATION: u64 = 8640;

impl BlockHeight {
    pub const MAX: u64 = BFieldElement::MAX;

    pub const fn new(value: BFieldElement) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0.value()
    }

    pub fn get_generation(&self) -> u64 {
        self.0.value() / BLOCKS_PER_GENERATION
    }

    pub fn next(&self) -> Self {
        Self(self.0 + BFieldElement::one())
    }

    pub fn previous(&self) -> Option<Self> {
        if self.is_genesis() {
            None
        } else {
            Some(Self(self.0 - BFieldElement::one()))
        }
    }

    pub const fn genesis() -> Self {
        Self(BFieldElement::ZERO)
    }

    pub fn is_genesis(&self) -> bool {
        self.0.is_zero()
    }

    pub(crate) fn arithmetic_mean(left: Self, right: Self) -> Self {
        // Calculate arithmetic mean, without risk of overflow.
        let left = left.0.value();
        let right = right.0.value();
        let ret = (left / 2) + (right / 2) + (left % 2 + right % 2) / 2;

        Self(BFieldElement::new(ret))
    }

    /// Subtract a number from a block height.
    //
    // *NOT* implemented as trait `CheckedSub` because of type mismatch.
    pub(crate) fn checked_sub(&self, v: u64) -> Option<Self> {
        self.0.value().checked_sub(v).map(|x| x.into())
    }
}

impl From<BFieldElement> for BlockHeight {
    fn from(item: BFieldElement) -> Self {
        BlockHeight(item)
    }
}

impl From<BlockHeight> for BFieldElement {
    fn from(item: BlockHeight) -> BFieldElement {
        item.0
    }
}

impl From<u64> for BlockHeight {
    fn from(val: u64) -> Self {
        BlockHeight(BFieldElement::new(min(BFieldElement::MAX, val)))
    }
}

impl From<BlockHeight> for u64 {
    fn from(bh: BlockHeight) -> Self {
        bh.0.value()
    }
}

impl Ord for BlockHeight {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0.value()).cmp(&(other.0.value()))
    }
}

impl Add<usize> for BlockHeight {
    type Output = BlockHeight;

    fn add(self, rhs: usize) -> Self::Output {
        Self(BFieldElement::new(self.0.value() + rhs as u64))
    }
}

impl Sub for BlockHeight {
    type Output = i128;

    fn sub(self, rhs: Self) -> Self::Output {
        i128::from(self.0.value()) - i128::from(rhs.0.value())
    }
}

impl PartialOrd for BlockHeight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u64::from(self.0))
    }
}

impl Distribution<BlockHeight> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BlockHeight {
        let height = rng.random::<BFieldElement>();
        BlockHeight::new(height)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use num_traits::CheckedAdd;
    use num_traits::CheckedSub;
    use proptest::prop_assert;
    use proptest::prop_assume;
    use test_strategy::proptest;
    use tracing_test::traced_test;

    use super::*;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::Network;
    use crate::protocol::consensus::block::PREMINE_MAX_SIZE;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::tests::shared_tokio_runtime;

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn genesis_test() {
        assert!(BlockHeight::genesis().is_genesis());
        assert!(!BlockHeight::genesis().next().is_genesis());
    }

    #[test]
    fn block_interval_times_generation_count_is_30_days() {
        let network = Network::Main;
        let calculated_halving_time =
            network.target_block_interval() * (BLOCKS_PER_GENERATION as usize);
        let calculated_halving_time = calculated_halving_time.to_millis();
        let thirty_days = Timestamp::days(30);
        let thirty_days = thirty_days.to_millis();
        assert!(
            (calculated_halving_time as f64) * 1.01 > thirty_days as f64
                && (calculated_halving_time as f64) * 0.99 < thirty_days as f64,
            "target halving time must be within 1 % of 30 days. Got:\n\
            thirty days = {thirty_days}ms\n calculated_halving_time = {calculated_halving_time}ms"
        );
    }

    #[proptest]
    fn arithmetic_mean_of_block_heights_is_always_in_between_arguments(low: u64, up: u64) {
        prop_assume!(low <= up);
        let lower = BlockHeight::from(low);
        let upper = BlockHeight::from(up);
        let mean = BlockHeight::arithmetic_mean(lower, upper);
        prop_assert!(low <= mean.value());
        prop_assert!(mean.value() <= up);
    }
}
