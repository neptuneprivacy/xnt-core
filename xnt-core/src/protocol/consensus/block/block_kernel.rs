use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::block_appendix::BlockAppendix;
use super::block_body::BlockBody;
use super::block_header::BlockHeader;
use crate::api::export::AdditionRecord;
use crate::api::export::Utxo;
use crate::protocol::consensus::block::block_validation_error::BlockValidationError;
use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET;
use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::proof_abstractions::mast_hash::HasDiscriminant;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::util_types::mutator_set::commit;

/// The kernel of a block contains all data that is not proof data
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct BlockKernel {
    pub header: BlockHeader,
    pub body: BlockBody,

    pub(crate) appendix: BlockAppendix,
}

impl BlockKernel {
    pub(crate) fn new(header: BlockHeader, body: BlockBody, appendix: BlockAppendix) -> Self {
        Self {
            header,
            body,
            appendix,
        }
    }

    /// Get the block's guesser fee UTXOs.
    ///
    /// The amounts in the UTXOs are taken from the transaction fee.
    ///
    /// The genesis block does not have a guesser reward.
    pub fn guesser_fee_utxos(&self) -> Result<Vec<Utxo>, BlockValidationError> {
        if self.header.height.is_genesis() {
            return Ok(vec![]);
        }

        // Without locking for miners

        let total_guesser_reward = self.body.total_guesser_reward()?;

        // The guesser-fee UTXO is *re-derived* (not read back as a stored
        // addition record) every time the mutator set is advanced past this
        // block, so its native-currency `type_script_hash` must match what was
        // committed when the block was produced. Each VM upgrade re-hashed
        // `NativeCurrency`, so the embedded hash is era-specific and reproducing a
        // block with the wrong-era hash would make that parent's
        // `mutator_set_accumulator_after` diverge from the child's stored
        // `mutator_set_hash`. Three eras:
        //   pre-UpgradeVM (pre-v3) -> legacy hash,
        //   UpgradeVM (v3)         -> v3 hash,
        //   UpgradeVMv4 (current)  -> current hash.
        let nc_type_script_hash = if self.header.height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET {
            NativeCurrency::legacy_type_script_hash()
        } else if self.header.height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET {
            NativeCurrency::v3_type_script_hash()
        } else {
            NativeCurrency.hash()
        };
        let coins_unlocked =
            total_guesser_reward.to_native_coins_with_type_script_hash(nc_type_script_hash);
        let lock_script_hash = self.header.guesser_receiver_data.lock_script_hash;
        let unlocked_utxo = Utxo::new(lock_script_hash, coins_unlocked);

        Ok(vec![unlocked_utxo])
    }

    /// Compute the addition records that correspond to the UTXOs generated for
    /// the block's guesser
    ///
    /// The genesis block does not have this addition record.
    pub(crate) fn guesser_fee_addition_records(
        &self,
        block_hash: Digest,
    ) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        Ok(self
            .guesser_fee_utxos()?
            .into_iter()
            .map(|utxo| {
                let item = Tip5::hash(&utxo);

                // Adding the block hash to the mutator set here means that no
                // composer can start proving before solving the PoW-race;
                // production of future proofs is impossible as they depend on
                // inputs hidden behind the veil of future PoW.
                let sender_randomness = block_hash;
                let receiver_digest = self.header.guesser_receiver_data.receiver_digest;

                commit(item, sender_randomness, receiver_digest)
            })
            .collect_vec())
    }

    /// Guesser-fee UTXOs computed with an explicit `NativeCurrency`
    /// `type_script_hash` instead of the height-derived era hash. Used by
    /// rollback to tolerate blocks committed under a different fork
    /// configuration than the one this binary currently derives.
    fn guesser_fee_utxos_with_nc_hash(
        &self,
        nc_type_script_hash: Digest,
    ) -> Result<Vec<Utxo>, BlockValidationError> {
        if self.header.height.is_genesis() {
            return Ok(vec![]);
        }
        let total_guesser_reward = self.body.total_guesser_reward()?;
        let coins_unlocked =
            total_guesser_reward.to_native_coins_with_type_script_hash(nc_type_script_hash);
        let lock_script_hash = self.header.guesser_receiver_data.lock_script_hash;
        Ok(vec![Utxo::new(lock_script_hash, coins_unlocked)])
    }

    /// [`Self::guesser_fee_addition_records`] for an explicit `NativeCurrency`
    /// `type_script_hash`.
    fn guesser_fee_addition_records_with_nc_hash(
        &self,
        block_hash: Digest,
        nc_type_script_hash: Digest,
    ) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        Ok(self
            .guesser_fee_utxos_with_nc_hash(nc_type_script_hash)?
            .into_iter()
            .map(|utxo| {
                let item = Tip5::hash(&utxo);
                let sender_randomness = block_hash;
                let receiver_digest = self.header.guesser_receiver_data.receiver_digest;
                commit(item, sender_randomness, receiver_digest)
            })
            .collect_vec())
    }

    /// Candidate guesser-fee addition records computed for EVERY historical
    /// `NativeCurrency` era hash (legacy / v3 / current).
    ///
    /// The guesser-fee record is re-derived (not stored), so a chain whose
    /// blocks were committed under a different fork configuration may carry a
    /// different era's hash in the mutator set. Rollback reverts whichever of
    /// these candidates is actually present in the append-only commitment list.
    pub(crate) fn guesser_fee_addition_records_all_eras(
        &self,
        block_hash: Digest,
    ) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        let mut out = vec![];
        for nc_hash in [
            NativeCurrency::legacy_type_script_hash(),
            NativeCurrency::v3_type_script_hash(),
            NativeCurrency.hash(),
        ] {
            out.extend(self.guesser_fee_addition_records_with_nc_hash(block_hash, nc_hash)?);
        }
        Ok(out)
    }
}

#[derive(Debug, Copy, Clone, EnumCount)]
pub enum BlockKernelField {
    Header,
    Body,
    Appendix,
}

impl HasDiscriminant for BlockKernelField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

impl MastHash for BlockKernel {
    type FieldEnum = BlockKernelField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        let sequences = vec![
            self.header.mast_hash().encode(),
            self.body.mast_hash().encode(),
            self.appendix.encode(),
        ];
        sequences
    }
}
