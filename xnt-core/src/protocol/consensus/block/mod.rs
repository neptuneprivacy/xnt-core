pub mod block_appendix;
pub mod block_body;
pub mod block_header;
pub mod block_height;
pub mod block_info;
pub mod block_kernel;
pub mod block_selector;
pub(crate) mod block_transaction;
mod block_validation_error;
pub mod difficulty_control;
pub(crate) mod guesser_receiver_data;
pub mod mock_block_generator;
pub mod mutator_set_update;
pub mod pow;
pub mod validity;

use std::sync::Arc;
use std::sync::OnceLock;

use block_appendix::BlockAppendix;
use block_appendix::MAX_NUM_CLAIMS;
use block_body::BlockBody;
use block_header::BlockHeader;
use block_height::BlockHeight;
use block_kernel::BlockKernel;
use block_validation_error::BlockValidationError;
use difficulty_control::Difficulty;
use get_size2::GetSize;
use itertools::Itertools;
use mutator_set_update::MutatorSetUpdate;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use rayon::ThreadPoolBuilder;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tracing::warn;
use validity::block_primitive_witness::BlockPrimitiveWitness;
use validity::block_program::BlockProgram;
use validity::block_proof_witness::BlockProofWitness;

use super::transaction::transaction_kernel::TransactionKernelProxy;
use super::transaction::utxo::Utxo;
use super::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::api::tx_initiation::builder::proof_builder::ProofBuilder;
use crate::application::config::network::Network;
use crate::application::loops::channel::Cancelable;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::block::block_header::BlockHeaderField;
use crate::protocol::consensus::block::block_header::BlockPow;
use crate::protocol::consensus::block::block_kernel::BlockKernelField;
use crate::protocol::consensus::block::block_transaction::BlockTransaction;
use crate::protocol::consensus::block::difficulty_control::difficulty_control;
use crate::protocol::consensus::block::pow::GuesserBuffer;
use crate::protocol::consensus::block::pow::Pow;
use crate::protocol::consensus::block::pow::PowMastPaths;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::utxo::Coin;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::proof_abstractions::mast_hash::HasDiscriminant;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::protocol::proof_abstractions::verifier::verify;
use crate::protocol::proof_abstractions::SecretWitness;
use crate::state::wallet::address::ReceivingAddress;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordList;

/// With removal records only represented by their absolute index set, the block
/// size limit of 1.000.000 `BFieldElement`s allows for a "balanced" block
/// (equal number of inputs and outputs, no announcements) of ~10.000
/// input and outputs. To prevent an attacker from making it costly to run an
/// archival node, the number of outputs is restricted. For simplicity though
/// this limit is enforced for inputs, outputs, and announcements. This
/// restriction on the number of announcements also makes it feasible for
/// wallets to scan through all.
pub(crate) const MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS: usize = 1 << 14;

/// Duration of timelock for half of all mining rewards.
pub(crate) const MINING_REWARD_TIME_LOCK_PERIOD: Timestamp = Timestamp::years(0);

pub(crate) const GENERATION_FOR_TAIL_EMISSION_START: i32 = 72;
pub(crate) const BLOCK_SUBSIDY_SCALED: [u64; GENERATION_FOR_TAIL_EMISSION_START as usize] = [
    6800000, 6655636, 6511273, 6366909, 6222545, 6078182, 5933818, 5789455, 5645091, 5500727,
    5356364, 5212000, 5168444, 5124889, 5081333, 5037778, 4994222, 4950667, 4907111, 4863556,
    4820000, 4776444, 4732889, 4689333, 4645778, 4602222, 4558667, 4515111, 4471556, 4428000,
    4384444, 4340889, 4297333, 4253778, 4210222, 4166667, 4123110, 4079556, 4035999, 3992444,
    3948889, 3905333, 3861778, 3818222, 3774667, 3731111, 3687556, 3644000, 3533833, 3423667,
    3313500, 3203333, 3093167, 2983000, 2872833, 2762667, 2652500, 2542333, 2432167, 2322000,
    2211833, 2101667, 1991500, 1881333, 1771167, 1661000, 1550833, 1440667, 1330500, 1220333,
    1110167, 1000000,
];
pub(crate) const TAIL_EMISSION_BLOCK_SUBSIDY: NativeCurrencyAmount = NativeCurrencyAmount::coins(1);

/*
pub(crate) const CURVE_DECAY_DENOMINATOR: i32 = 36;
pub(crate) const CURVE_EXPONENT: u32 = 2;
*/
/// Blocks with timestamps too far into the future are invalid. Reject blocks
/// whose timestamp exceeds now with this value or more.
pub(crate) const FUTUREDATING_LIMIT: Timestamp = Timestamp::minutes(5);

/// The size of the premine.
pub const PREMINE_MAX_SIZE: NativeCurrencyAmount = NativeCurrencyAmount::coins(1942384);

/// All blocks have proofs except the genesis block
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize, Default)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub enum BlockProof {
    Genesis,
    #[default]
    Invalid,
    SingleProof(Proof),
}

/// Public fields of `Block` are read-only, enforced by #[readonly::make].
/// Modifications are possible only through `Block` methods.
///
/// Example:
///
/// test: verify that compile fails on an attempt to mutate block
/// internals directly (bypassing encapsulation)
///
/// ```compile_fail,E0594
/// use neptune_privacy::protocol::consensus::block::Block;
/// use neptune_privacy::application::config::network::Network;
/// use neptune_privacy::prelude::twenty_first::math::b_field_element::BFieldElement;
/// use tasm_lib::prelude::Digest;
///
/// let mut block = Block::genesis(Network::RegTest);
///
/// let height = block.kernel.header.height;
///
/// let nonce = Digest::default();
///
/// // this line fails to compile because we try to
/// // mutate an internal field.
/// block.kernel.header.pow.nonce = nonce;
/// ```
// ## About the private `digest` field:
//
// The `digest` field represents the `Block` hash.  It is an optimization so
// that the hash can be lazily computed at most once (per modification).
//
// It is wrapped in `OnceLock<_>` for interior mutability because (a) the hash()
// method is used in many methods that are `&self` and (b) because `Block` is
// passed between tasks/threads, and thus `Rc<RefCell<_>>` is not an option.
//
// The field must be reset whenever the Block is modified.  As such, we should
// not permit direct modification of internal fields, particularly `kernel`
//
// Therefore `[readonly::make]` is used to make public `Block` fields read-only
// (not mutable) outside of this module.  All methods that modify Block also
// reset the `digest` field.
//
// We manually implement `PartialEq` and `Eq` so that digest field will not be
// compared.  Otherwise, we could have identical blocks except one has
// initialized digest field and the other has not.
//
// The field should not be serialized, so it has the `#[serde(skip)]` attribute.
// Upon deserialization, the field will have Digest::default() which is desired
// so that the digest will be recomputed if/when hash() is called.
//
// We likewise skip the field for `BFieldCodec`, and `GetSize` because there
// exist no impls for `OnceLock<_>` so derive fails.
//
// A unit test-suite exists in module tests::digest_encapsulation.
#[readonly::make]
#[derive(Debug, Clone, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct Block {
    /// Everything but the proof
    pub kernel: BlockKernel,

    pub proof: BlockProof,

    // this is only here as an optimization for Block::hash()
    // so that we lazily compute the hash at most once.
    #[serde(skip)]
    #[bfield_codec(ignore)]
    #[get_size(ignore)]
    digest: OnceLock<Digest>,
}

impl MastHash for Block {
    type FieldEnum = BlockField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        vec![self.kernel.mast_hash().encode(), self.proof.encode()]
    }
}

#[derive(Debug, Copy, Clone, EnumCount)]
pub enum BlockField {
    Kernel,
    Proof,
}

impl HasDiscriminant for BlockField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        // TBD: is it faster overall to compare hashes or equality
        // of kernel and blocktype fields?
        // In the (common?) case where hash has already been
        // computed for both `Block` comparing hash equality
        // should be faster.
        self.hash() == other.hash()
    }
}
impl Eq for Block {}

impl Block {
    pub(crate) async fn block_template_from_block_primitive_witness(
        primitive_witness: BlockPrimitiveWitness,
        timestamp: Timestamp,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        let network = proof_job_options.job_settings.network;
        let body = primitive_witness.body().to_owned();
        let header = primitive_witness.header(timestamp, network.target_block_interval());
        let (appendix, proof) = {
            let block_proof_witness = BlockProofWitness::produce(primitive_witness);
            let appendix = block_proof_witness.appendix();
            let claim = BlockProgram::claim(&body, &appendix);

            let proof = ProofBuilder::new()
                .program(BlockProgram.program())
                .claim(claim)
                .nondeterminism(|| block_proof_witness.nondeterminism())
                .job_queue(triton_vm_job_queue)
                .proof_job_options(proof_job_options)
                .build()
                .await?;

            (appendix, BlockProof::SingleProof(proof))
        };

        Ok(Block::new(header, body, appendix, proof))
    }

    async fn make_block_template_with_valid_proof(
        predecessor: &Block,
        transaction: BlockTransaction,
        block_timestamp: Timestamp,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        let next_block_height = predecessor.header().height.next();
        let network = proof_job_options.job_settings.network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, next_block_height);
        let tx_claim = BlockAppendix::transaction_validity_claim(
            transaction.kernel.mast_hash(),
            consensus_rule_set,
        );
        assert!(
            verify(
                tx_claim.clone(),
                transaction.proof.clone().into_single_proof(),
                network
            )
            .await,
            "Transaction proof must be valid to generate a block"
        );

        assert!(
            transaction.kernel.merge_bit,
            "Merge-bit must be set in transactions before they can be included in blocks."
        );
        let primitive_witness =
            BlockPrimitiveWitness::new(predecessor.to_owned(), transaction, network);
        Self::block_template_from_block_primitive_witness(
            primitive_witness,
            block_timestamp,
            triton_vm_job_queue,
            proof_job_options,
        )
        .await
    }

    /// Compose a block.
    ///
    /// Create a block with valid block proof, but without proof-of-work.
    pub(crate) async fn compose(
        predecessor: &Block,
        transaction: BlockTransaction,
        block_timestamp: Timestamp,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        Self::make_block_template_with_valid_proof(
            predecessor,
            transaction,
            block_timestamp,
            triton_vm_job_queue,
            proof_job_options,
        )
        .await
    }

    /// Returns the block Digest
    ///
    /// performance note:
    ///
    /// The digest is never computed until hash() is called.  Subsequent calls
    /// will not recompute it unless the Block was modified since the last call.
    #[inline]
    pub fn hash(&self) -> Digest {
        *self.digest.get_or_init(|| self.mast_hash())
    }

    #[inline]
    fn unset_digest(&mut self) {
        // note: this replaces the OnceLock so the digest will be calc'd in hash()
        self.digest = Default::default();
    }

    /// Set the guesser digest in the block's header.
    ///
    /// Note: this causes the block digest to change.
    #[inline]
    pub fn set_header_guesser_address(&mut self, address: ReceivingAddress) {
        self.kernel.header.guesser_receiver_data.receiver_digest = address.privacy_digest();
        self.kernel.header.guesser_receiver_data.lock_script_hash = address.lock_script_hash();
        self.unset_digest();
    }

    /// sets header timestamp and difficulty.
    ///
    /// These must be set as a pair because the difficulty depends
    /// on the timestamp, and may change with it.
    ///
    /// note: this causes block digest to change.
    #[inline]
    pub(crate) fn set_header_timestamp_and_difficulty(
        &mut self,
        timestamp: Timestamp,
        difficulty: Difficulty,
    ) {
        self.kernel.header.timestamp = timestamp;
        self.kernel.header.difficulty = difficulty;

        self.unset_digest();
    }

    #[inline]
    pub fn header(&self) -> &BlockHeader {
        &self.kernel.header
    }

    #[inline]
    pub fn body(&self) -> &BlockBody {
        &self.kernel.body
    }

    /// Return the mutator set as it looks after the application of this block.
    ///
    /// Includes the guesser-fee UTXOs which are not included by the
    /// `mutator_set_accumulator` field on the block body.
    pub fn mutator_set_accumulator_after(
        &self,
    ) -> Result<MutatorSetAccumulator, BlockValidationError> {
        let guesser_fee_addition_records = self.guesser_fee_addition_records()?;
        let msa = self
            .body()
            .mutator_set_accumulator_after(guesser_fee_addition_records);

        Ok(msa)
    }

    #[inline]
    pub(crate) fn appendix(&self) -> &BlockAppendix {
        &self.kernel.appendix
    }

    /// note: this causes block digest to change to that of the new block.
    #[inline]
    pub fn set_block(&mut self, block: Block) {
        *self = block;
    }

    /// The number of coins that can be printed into existence with the mining
    /// a block with this height.
    pub fn block_subsidy(block_height: BlockHeight) -> NativeCurrencyAmount {
        let generation = block_height.get_generation();

        if generation >= GENERATION_FOR_TAIL_EMISSION_START as u64 {
            return TAIL_EMISSION_BLOCK_SUBSIDY;
        }

        let one_coin = NativeCurrencyAmount::coins(1);
        let units_one_coin = one_coin.to_nau();
        let scaled_subsidy = BLOCK_SUBSIDY_SCALED[generation as usize];
        // Safe from overflow, max subsidy is 6.8
        let (units_scaled, overflow) = units_one_coin.overflowing_mul(scaled_subsidy as i128);
        assert!(!overflow, "Block subsidy calculation overflowed");
        let units_divided = units_scaled / 1_000_000;
        let final_nau_i128 = units_divided;
        return NativeCurrencyAmount::from_nau(final_nau_i128);
    }

    /// returns coinbase reward amount for this block.
    ///
    /// note that this amount may differ from self::block_subsidy(self.height)
    /// because a miner can choose to accept less than the calculated reward amount.
    pub fn coinbase_amount(&self) -> NativeCurrencyAmount {
        // A block must always have a Coinbase.
        // we impl this method in part to cement that guarantee.
        self.body()
            .transaction_kernel
            .coinbase
            .unwrap_or_else(NativeCurrencyAmount::zero)
    }

    pub fn genesis(network: Network) -> Self {
        let premine_distribution = Self::premine_distribution();
        let total_premine_amount = premine_distribution
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum();

        let mut ms_update = MutatorSetUpdate::default();
        let mut genesis_mutator_set = MutatorSetAccumulator::default();
        let mut genesis_tx_outputs = vec![];
        for ((receiving_address, _amount), utxo) in
            premine_distribution.iter().zip(Self::premine_utxos())
        {
            let utxo_digest = Tip5::hash(&utxo);
            // generate randomness for mutator set commitment
            // Sender randomness cannot be random because there is no sender.
            let bad_randomness = Self::premine_sender_randomness(network);

            let receiver_digest = receiving_address.privacy_digest();

            // Add pre-mine UTXO to MutatorSet
            let addition_record = commit(utxo_digest, bad_randomness, receiver_digest);
            ms_update.additions.push(addition_record);
            genesis_mutator_set.add(&addition_record);

            // Add pre-mine UTXO + commitment to coinbase transaction
            genesis_tx_outputs.push(addition_record)
        }

        let genesis_txk = TransactionKernelProxy {
            inputs: vec![],
            outputs: genesis_tx_outputs,
            fee: NativeCurrencyAmount::coins(0),
            timestamp: network.launch_date(),
            announcements: vec![],
            coinbase: Some(total_premine_amount),
            mutator_set_hash: MutatorSetAccumulator::default().hash(),
            merge_bit: false,
        }
        .into_kernel();

        let body: BlockBody = BlockBody::new(
            genesis_txk,
            genesis_mutator_set.clone(),
            MmrAccumulator::new_from_leafs(vec![]),
            MmrAccumulator::new_from_leafs(vec![]),
        );

        let header = BlockHeader::genesis(network);

        let appendix = BlockAppendix::default();

        Self::new(header, body, appendix, BlockProof::Genesis)
    }

    /// sender randomness is tailored to the network. This change
    /// percolates into the mutator set hash and eventually into all transaction
    /// kernels. The net result is that broadcasting transaction on other
    /// networks invalidates the lock script proofs.
    pub(crate) fn premine_sender_randomness(network: Network) -> Digest {
        Digest::new(bfe_array![u64::from(network.id()), 0, 0, 0, 0])
    }

    fn original_premine_distribution() -> Vec<(ReceivingAddress, NativeCurrencyAmount)> {
        // The premine UTXOs can be hardcoded here.
        vec![
            (ReceivingAddress::from_bech32m("xntnwm19tgyejh6wxmjqn09shm044d2kfrr3vygk2hzpey739qw4uw6npsgwlagxanu4ndp94x9y6vcnfz8tcwrhcgk0sfxr7z8g78w47lv758edaxa80pjj8sgshdtjgp8jtp5rpxy0ds3c23h2xvecst4e8yevr7cx6t9llczdudwqejwjklpjqy8369v0eydxzh6awmxw2t6clrvtck0guzgjfz8ata54l3zhfrkqrncmynz856tugjkau6f6jh5wxu783vn8wzl0jv5v5s5vecuengvq0hsprj2cp4j323wxxdl95l5x88g0ww5mzjf3tlxdr2md5jvqncxyu3gj5ezvyd6dqex6g45fz7znfgz0kjdtxdsyzkernax5de5v0uhe97dydktttvwymy7kehznzzutv3gdtxmk805kqlthy42hgcnsfxxpktujqlkeftsvht24uuhjqgv45khpuwt0p26rkg30sd2dvgd4k2mu05rzjnathyqw748qm792gtd39vupxe4h3wdzap4rhkdescvjhsh3k6rpcp49vkhpk5722vwadg39844609ku79s4j25uqyr99fk4zf3u4uffm6hk5pgqax903gm0pn5utgngr90ef9kzzpdp6acwv574t8hyf9sdt6de8vlx8t3hu3e0yzvy6hrsxwrpjr296z4wtpulgazxsphw4hn6k7zhu9ehmdknhudl0xf6dzj0uz8yaxw4sju9sthmsc2uju07ua0amu0jvpfqqtsqkeyrjj8vgxssaqk35w40ze7dhpvgcqxehm8xccfxn6m9j707kcwfr5quyze2ntxmqfdw4n5yg93rzdrmskh9hsdut9s9u3d4zm2dk8pfl85394twy9g89c8ncarcealz4dhjc6vdw0gmm9rfce0t959e8fx2hczzhhpp6trufk8vm3r2ck3e6dyuuzgqh0jzfd9r9l2zyaf7mnz4cqyer34zgfpufg4683pgw9h4vr3f825m6gled0g5nz92u7eaelgdm5wkpg4dzmrqhl8hszelq4h2aglcgynn3y6xfrsyplfvfhmd9s68rdagqaa20gh2tnc4hpev9uuqvz99vcfahelyraz9xq9gucpkgv99w2wrca066p8j7qcdlljd5nq8yau76man3989c0kq0ulzs7e2079w8v3q6dnaynr8y286kfmm85z6sg2n0eqm7dlep3ml38pemyh9n40zydk98dlmz9f8c5ppsxeglvy4davsqfu5ll7q7ufzhy7xfvgcz7sm9akkl7gkcsad08w48el8keusussuk8upnc0gs7aq9kz2znl7uyc77wupyry9zwne86pnnsp8v496kfdx3nwkkpc89md5eh9ph55xvs6gnz05wqkvlkc4ztpqcc37d4nee5fhpuwxkvlvyq29u0lqe9j3dfhtdru9k0l7vm56wq4ed27w80puylx4w5agnf54v8hnv5vs36dxjw8xklsvsqsk4dlv3un9dn2sr6tj7aknuvhd8et6anhfvxjmfjqzth53gvt6hvys5gu8hhaqzavyta475yzflx882zqqadm3htl07qawfwylkf8apju9cc8xd9uzcfzs0mhhfw4qhn9qhrv09clgn6rl8l4rr5cemtmvsy9gsel9qvpa4ysd5upe3kas2vu5fk0fgw5wzjs0u27yexe2m6e8ysn426vl0v4ejclryse2u2dupzp73kzmz42pqa49xxgukzr4mw7e9rkqtulgzw47l44zspw453hd0q7dllach6ws0ym4j4qs7yexn05xpfe8nz0e29xe2ra93dyn2q8ca49mezgdmh9cd8k0shg4ztwxcu6pmkaxrf7kfmzn8wrfmxthnz9t6gn6e2ym58fdyu9ln4qfl7me2vtg465c94sgrgehc8qhrmqr7x7vjrfe2s648kuhulhhhsvf5plqmff8evj3y3g33ds4klzd42y02v53r2cfkqnjkrwrme8w27svzkwg4lpt7r0jvcn7klwmpstufgkf5c9pdhewyuvxuhjfsvp6n62vnxkup3t8m0z94twyprxp5sd3pla02j0kj76pu6928st26vp06kqv7assrugejn8jn9lt3eemapqmrunsfyy0yhh42tgmrlfht63vys0vzjg97jau7truzuycct2rtx7a8zqjuwyu82v3qmz99ddcucg0zxckpslaayknwpplyz9yma8pzk8dsx70qj0s3q5waj8whxxctsf7gh5z07sadhh042yeuz4qrpmmpcnafnvlcnv0sswq66a97gaqxtm4wuxsvl082dltvwtqsrzw285vfc97aewvg8pkh26u40cuxm7qxvg7c5anzhwhphl5m28jul3clvgzl5cth8awccmcyfl0ze9lzykcwpuasmcf080ynp437h57gtajwawayaclnmgjc7fp5477mzctm4m8d2ay2t3r4jzgmpf97dlckhfjlsrxfpr7ckv7kt3j4w4rmv3z9p2tdcs6slq6nrx543g6eqd3afyk4cu74xfjklnj0ny968v4zegprw7ncrmut0jzcvmknwtfxl9fmpwhnzdn4059r29zlaqwhrwfwzx3e4envdl8zer6zsh6qkejj3445pycsg95a7t5vh0t498q5zcdxvuzyk3xzs3y5upnxyc53k962pk4cfur5cn4f8varemgny86qpknhvkdjxwafxjwvue2mgu8zymv7x99e9wqqcq23tzm8n3skv9a4k9rpw0r27fevs4tqku7q3uh77g7yw206tugdavd327t9wk2zytw9prfdzeuf6dkvywcg9pmkchrf6azwhc3483f5z03pjy2rglhy7w2z0tuc4jr9njzk28hq8rkrggd8uc6whry8am30j2yt4ez4e8z8amcm2pyvcxd7g5acq63dlk4s465ug28ryvfvagjxaxvjc77fgkl5mseg0y68mmf7vpmlysjp5d3qgpjfcpy7dgws2gjvct9qflqw5ms36czcv7ls3c32jmpnn9mrev4h2k89k2qctr4ye599a5s76z0utup69zsxcqklr5jn6pp5uf39r3w75danrvdc2mrmxncykm9y8ka57yzkyfyrvft4mvtzr86eys0qnrwegs2st2u8gjextz4kvk66whp2ncytm5t2ftnq20a7vu222k93r6n82lt2lrp6akrxknc2a66tg5pycu9rck3v8h5jfm4xul0wa4htzjxehtder9c4usudechyqx4qv3r4tj7cl3sczja6l63uh7j4nvzselnspc9udjf3dh5ljld9m60lem3fyrvt7dnew0va7g9tgg4544g2yfpmnxrqztm8632vayv674c8yxn2yhvlsm043d5nyvk99fpht5yr6y8nw9qs5y7hxtnnrasy7chtuwqu5shd3qgjc2hpgvjm6kdzkxxpsfdlypw4tldu5", Network::Main).unwrap(), NativeCurrencyAmount::coins(1942384))
        ]
    }

    /// All premine allocations, including claims fund and claims
    fn premine_distribution() -> Vec<(ReceivingAddress, NativeCurrencyAmount)> {
        [Self::original_premine_distribution()].concat()
    }

    pub fn premine_utxos() -> Vec<Utxo> {
        // Premine will be unlocked at genesis

        let mut utxos = vec![];
        for (receiving_address, amount) in Self::premine_distribution() {
            let coins = vec![
                Coin::new_native_currency(amount),
                //TimeLock::until(premine_release_date),
            ];
            let utxo = Utxo::new(receiving_address.lock_script_hash(), coins);
            utxos.push(utxo);
        }

        utxos
    }

    pub(crate) fn new(
        header: BlockHeader,
        body: BlockBody,
        appendix: BlockAppendix,
        block_proof: BlockProof,
    ) -> Self {
        let kernel = BlockKernel::new(header, body, appendix);
        Self {
            digest: OnceLock::default(), // calc'd in hash()
            kernel,
            proof: block_proof,
        }
    }

    /// Verify a block. It is assumed that `previous_block` is valid.
    /// Note that this function does **not** check that the block has enough
    /// proof of work; that must be done separately by the caller, for instance
    /// by calling [`Self::has_proof_of_work`].
    pub async fn is_valid(&self, previous_block: &Block, now: Timestamp, network: Network) -> bool {
        match self.validate(previous_block, now, network).await {
            Ok(_) => true,
            Err(e) => {
                warn!("{e}");
                false
            }
        }
    }

    /// Verify a block against previous block and return detailed error
    ///
    /// This method assumes that the previous block is valid.
    ///
    /// Note that this function does **not** check that the block has enough
    /// proof of work; that must be done separately by the caller, for instance
    /// by calling [`Self::has_proof_of_work`].
    pub async fn validate(
        &self,
        previous_block: &Block,
        now: Timestamp,
        network: Network,
    ) -> Result<(), BlockValidationError> {
        // Note that there is a correspondence between the logic here and the
        // error types in `BlockValidationError`.

        let consensus_rule_set = ConsensusRuleSet::infer_from(network, self.header().height);

        // 0.a)
        if previous_block.kernel.header.height.next() != self.kernel.header.height {
            return Err(BlockValidationError::BlockHeight);
        }

        // 0.b)
        if previous_block.hash() != self.kernel.header.prev_block_digest {
            return Err(BlockValidationError::PrevBlockDigest);
        }

        // 0.c)
        let mut mmra = previous_block.kernel.body.block_mmr_accumulator.clone();
        mmra.append(previous_block.hash());
        if mmra != self.kernel.body.block_mmr_accumulator {
            return Err(BlockValidationError::BlockMmrUpdate);
        }

        // 0.d)
        if previous_block.kernel.header.timestamp + network.minimum_block_time()
            > self.kernel.header.timestamp
        {
            return Err(BlockValidationError::MinimumBlockTime);
        }

        // 0.e)
        let expected_difficulty = if Self::should_reset_difficulty(
            network,
            self.header().timestamp,
            previous_block.header().timestamp,
        ) {
            network.genesis_difficulty()
        } else {
            difficulty_control(
                self.header().timestamp,
                previous_block.header().timestamp,
                previous_block.header().difficulty,
                network.target_block_interval(),
                previous_block.header().height,
            )
        };

        if self.kernel.header.difficulty != expected_difficulty {
            return Err(BlockValidationError::Difficulty);
        }

        // 0.f)
        let expected_cumulative_proof_of_work =
            previous_block.header().cumulative_proof_of_work + previous_block.header().difficulty;
        if self.header().cumulative_proof_of_work != expected_cumulative_proof_of_work {
            return Err(BlockValidationError::CumulativeProofOfWork);
        }

        // 0.g)
        let future_limit = now + FUTUREDATING_LIMIT;
        if self.kernel.header.timestamp >= future_limit {
            return Err(BlockValidationError::FutureDating);
        }

        // 1.a)
        for required_claim in BlockAppendix::consensus_claims(self.body(), consensus_rule_set) {
            if !self.appendix().contains(&required_claim) {
                return Err(BlockValidationError::AppendixMissingClaim);
            }
        }

        // 1.b)
        if self.appendix().len() > MAX_NUM_CLAIMS {
            return Err(BlockValidationError::AppendixTooLarge);
        }

        // 1.c)
        let BlockProof::SingleProof(block_proof) = &self.proof else {
            return Err(BlockValidationError::ProofQuality);
        };

        // 1.d)
        if !BlockProgram::verify(self.body(), self.appendix(), block_proof, network).await {
            return Err(BlockValidationError::ProofValidity);
        }

        // 1.e)
        if self.size() > consensus_rule_set.max_block_size() {
            return Err(BlockValidationError::MaxSize);
        }

        // 2.a)
        let inputs = RemovalRecordList::try_unpack(self.body().transaction_kernel.inputs.clone())
            .map_err(BlockValidationError::from)?;

        // 2.b)
        let msa_before = previous_block.mutator_set_accumulator_after()?;
        for removal_record in &inputs {
            if !msa_before.can_remove(removal_record) {
                return Err(BlockValidationError::RemovalRecordsValidity);
            }
        }

        // 2.c)
        let mut absolute_index_sets = inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices.to_vec())
            .collect_vec();
        absolute_index_sets.sort();
        absolute_index_sets.dedup();
        if absolute_index_sets.len() != inputs.len() {
            return Err(BlockValidationError::RemovalRecordsUniqueness);
        }

        let mutator_set_update = MutatorSetUpdate::new(
            inputs.clone(),
            self.body().transaction_kernel.outputs.clone(),
        );
        let mut msa = msa_before;
        let ms_update_result = mutator_set_update.apply_to_accumulator(&mut msa);

        // 2.d)
        if ms_update_result.is_err() {
            return Err(BlockValidationError::MutatorSetUpdateImpossible);
        };

        // 2.e)
        if msa.hash() != self.body().mutator_set_accumulator.hash() {
            return Err(BlockValidationError::MutatorSetUpdateIntegrity);
        }

        // 2.f)
        if self.kernel.body.transaction_kernel.timestamp > self.kernel.header.timestamp {
            return Err(BlockValidationError::TransactionTimestamp);
        }

        let block_subsidy = Self::block_subsidy(self.kernel.header.height);
        let coinbase = self.kernel.body.transaction_kernel.coinbase;
        if let Some(coinbase) = coinbase {
            // 2.g)
            if coinbase > block_subsidy {
                return Err(BlockValidationError::CoinbaseTooBig);
            }

            // 2.h)
            if coinbase.is_negative() {
                return Err(BlockValidationError::NegativeCoinbase);
            }
        }

        // 2.i)
        let fee = self.kernel.body.transaction_kernel.fee;
        if fee.is_negative() {
            return Err(BlockValidationError::NegativeFee);
        }

        // 2.j)
        if inputs.len() > consensus_rule_set.max_num_inputs() {
            return Err(BlockValidationError::TooManyInputs);
        }

        // 2.k)
        if self.body().transaction_kernel.outputs.len() > consensus_rule_set.max_num_outputs() {
            return Err(BlockValidationError::TooManyOutputs);
        }

        // 2.l)
        if self.body().transaction_kernel.announcements.len()
            > consensus_rule_set.max_num_announcements()
        {
            return Err(BlockValidationError::TooManyAnnouncements);
        }

        Ok(())
    }

    /// indicates if a difficulty reset should be performed.
    ///
    /// Reset only occurs for network(s) that define a difficulty-reset-interval,
    /// typically testnet(s).
    ///
    /// A reset should be performed any time the interval between a block
    /// and its parent block is >= the network's reset interval.
    pub(crate) fn should_reset_difficulty(
        network: Network,
        current_block_timestamp: Timestamp,
        previous_block_timestamp: Timestamp,
    ) -> bool {
        let Some(reset_interval) = network.difficulty_reset_interval() else {
            return false;
        };
        let elapsed_interval = current_block_timestamp - previous_block_timestamp;
        elapsed_interval >= reset_interval
    }

    /// Determine whether the proof-of-work puzzle was solved correctly.
    ///
    /// Specifically, compare the hash of the current block against the
    /// target corresponding to the previous block's difficulty and return true
    /// if the former is smaller.
    pub fn has_proof_of_work(&self, network: Network, previous_block_header: &BlockHeader) -> bool {
        // enforce network difficulty-reset-interval if present. Note that *no*
        // pow checks are enforced in this case, not even Merkle authentication
        // path checks. Consequently, very little memory is required to produce
        // blocks on networks that reset difficulty.
        if Self::should_reset_difficulty(
            network,
            self.header().timestamp,
            previous_block_header.timestamp,
        ) && self.header().difficulty == network.genesis_difficulty()
        {
            return true;
        }

        let threshold = previous_block_header.difficulty.target();
        if network.allows_mock_pow() && self.is_valid_mock_pow(threshold) {
            return true;
        }

        let consensus_rule_set =
            ConsensusRuleSet::infer_from(network, previous_block_header.height.next());
        self.pow_verify(threshold, consensus_rule_set)
    }

    /// Produce the MAST authentication paths for the `pow` field on
    /// [`BlockHeader`], against the block MAST hash.
    pub(crate) fn pow_mast_paths(&self) -> PowMastPaths {
        let pow = BlockHeader::mast_path(self.header(), BlockHeaderField::Pow)
            .try_into()
            .unwrap();
        let header = BlockKernel::mast_path(&self.kernel, BlockKernelField::Header)
            .try_into()
            .unwrap();
        let kernel = Block::mast_path(self, BlockField::Kernel)
            .try_into()
            .unwrap();

        PowMastPaths {
            pow,
            header,
            kernel,
        }
    }

    /// Preprocess block for PoW guessing
    pub fn guess_preprocess(
        &self,
        maybe_cancel_channel: Option<&dyn Cancelable>,
        num_guesser_threads: Option<usize>,
        consensus_rule_set: ConsensusRuleSet,
    ) -> GuesserBuffer<{ BlockPow::MERKLE_TREE_HEIGHT }> {
        // build a rayon thread pool that respects the limitation on the number
        // of threads
        let num_threads = num_guesser_threads.unwrap_or_else(rayon::current_num_threads);
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap();

        let auth_paths = self.pow_mast_paths();
        let prev_block_digest = self.header().prev_block_digest;
        thread_pool.install(|| {
            Pow::<{ BlockPow::MERKLE_TREE_HEIGHT }>::preprocess(
                auth_paths,
                maybe_cancel_channel,
                consensus_rule_set,
                prev_block_digest,
            )
        })
    }

    /// Mock verification of Pow. Use only on networks that allow for PoW
    /// mocking. Only checks that block hash is less than target. Does not
    /// verify other aspects of PoW.
    pub(crate) fn is_valid_mock_pow(&self, target: Digest) -> bool {
        self.hash() <= target
    }

    /// Satisfy mock-PoW, meaning that only the hash needs to be lower than the
    /// threshold, does not set valid root/authentication paths of the PoW
    /// field.
    pub fn satisfy_mock_pow(&mut self, difficulty: Difficulty, seed: [u8; 32]) {
        let mut rng = StdRng::from_seed(seed);

        // Guessing loop.
        let threshold = difficulty.target();
        while !self.is_valid_mock_pow(threshold) {
            let pow = rng.random();
            self.set_header_pow(pow);
        }
    }

    /// Verify that block digest is less than threshold and integral.
    pub(crate) fn pow_verify(&self, target: Digest, consensus_rule_set: ConsensusRuleSet) -> bool {
        let auth_paths = self.pow_mast_paths();
        self.header()
            .pow
            .validate(
                auth_paths,
                target,
                consensus_rule_set,
                self.header().prev_block_digest,
            )
            .is_ok()
    }

    pub fn set_header_pow(&mut self, pow: BlockPow) {
        self.kernel.header.pow = pow;
        self.unset_digest();
    }

    /// Evaluate the fork choice rule.
    ///
    /// Given two blocks, determine which one is more canonical. This function
    /// evaluates the following logic:
    ///  - if the height is different, prefer the block with more accumulated
    ///    proof-of-work;
    ///  - otherwise, if exactly one of the blocks' transactions has no inputs,
    ///    reject that one;
    ///  - otherwise, prefer the current tip.
    ///
    /// This function assumes the blocks are valid and have the self-declared
    /// accumulated proof-of-work.
    ///
    /// This function is called exclusively in
    /// [`GlobalState::incoming_block_is_more_canonical`][1], which is in turn
    /// called in two places:
    ///  1. In `peer_loop`, when a peer sends a block. The `peer_loop` task only
    ///     sends the incoming block to the `main_loop` if it is more canonical.
    ///  2. In `main_loop`, when it receives a block from a `peer_loop` or from
    ///     the `mine_loop`. It is possible that despite (1), race conditions
    ///     arise, and they must be solved here.
    ///
    /// [1]: crate::state::GlobalState::incoming_block_is_more_canonical
    pub(crate) fn fork_choice_rule<'a>(
        current_tip: &'a Self,
        incoming_block: &'a Self,
    ) -> &'a Self {
        if current_tip.header().height != incoming_block.header().height {
            if current_tip.header().cumulative_proof_of_work
                >= incoming_block.header().cumulative_proof_of_work
            {
                current_tip
            } else {
                incoming_block
            }
        } else if current_tip.body().transaction_kernel.inputs.is_empty() {
            incoming_block
        } else {
            current_tip
        }
    }

    /// Size in number of BFieldElements of the block
    // Why defined in terms of BFieldElements and not bytes? Anticipates
    // recursive block validation, where we need to test a block's size against
    // the limit. The size is easier to calculate if it relates to a block's
    // encoding on the VM, rather than its serialization as a vector of bytes.
    pub(crate) fn size(&self) -> usize {
        self.encode().len()
    }

    /// A number showing how big the guesser reward is relative to the block
    /// subsidy.  Notice that this number can exceed 1 because of transaction
    /// fees.
    ///
    /// May not be used in any consensus-related setting, as precision is lost
    /// because of the use of floats.
    pub(crate) fn relative_guesser_reward(&self) -> Result<f64, BlockValidationError> {
        let guesser_reward = self.body().total_guesser_reward()?;
        let block_subsidy = Self::block_subsidy(self.header().height);

        Ok(guesser_reward.to_nau_f64() / block_subsidy.to_nau_f64())
    }

    /// Compute the addition records that correspond to the UTXOs generated for
    /// the block's guesser
    ///
    /// The genesis block does not have this addition record.
    pub(crate) fn guesser_fee_addition_records(
        &self,
    ) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        let block_hash = self.hash();
        self.kernel.guesser_fee_addition_records(block_hash)
    }

    /// Return the mutator set update corresponding to this block, which sends
    /// the mutator set accumulator after the predecessor to the mutator set
    /// accumulator after self.
    pub(crate) fn mutator_set_update(&self) -> Result<MutatorSetUpdate, BlockValidationError> {
        let inputs = RemovalRecordList::try_unpack(self.body().transaction_kernel.inputs.clone())
            .map_err(BlockValidationError::from)?;

        let mut mutator_set_update =
            MutatorSetUpdate::new(inputs, self.body().transaction_kernel.outputs.clone());

        let guesser_addition_records = self.guesser_fee_addition_records()?;
        mutator_set_update
            .additions
            .extend(guesser_addition_records);

        Ok(mutator_set_update)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use macro_rules_attr::apply;
    use proptest::collection;
    use proptest::prop_compose;
    use proptest_arbitrary_interop::arb;
    use rand::random;
    use rand::rng;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
    use tracing_test::traced_test;

    use super::super::transaction::transaction_kernel::TransactionKernelModifier;
    use super::super::transaction::Transaction;
    use super::block_transaction::BlockOrRegularTransaction;
    use super::*;
    use crate::application::config::cli_args;
    use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
    use crate::application::config::network::Network;
    use crate::application::database::storage::storage_schema::SimpleRustyStorage;
    use crate::application::database::NeptuneLevelDb;
    use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;
    use crate::application::loops::mine_loop::composer_parameters::ComposerParameters;
    use crate::application::loops::mine_loop::prepare_coinbase_transaction_stateless;
    use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state;
    use crate::application::rpc::server::proof_of_work_puzzle::ProofOfWorkPuzzle;
    use crate::application::triton_vm_job_queue::vm_job_queue;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::protocol::consensus::block::block_height::BLOCKS_PER_GENERATION;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::transaction::TransactionProof;
    use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
    use crate::protocol::consensus::type_scripts::TypeScript;
    use crate::state::mempool::upgrade_priority::UpgradePriority;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::transaction::tx_proving_capability::TxProvingCapability;
    use crate::state::wallet::address::KeyType;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::fake_valid_successor_for_tests;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::blocks::invalid_empty_block;
    use crate::tests::shared::blocks::invalid_empty_block1_with_guesser_fraction;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_tx::make_mock_transaction;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::archival_mmr::ArchivalMmr;

    pub(crate) const DIFFICULTY_LIMIT_FOR_TESTS: u32 = 20_000;

    impl Block {
        pub(crate) fn set_proof(&mut self, proof: BlockProof) {
            self.proof = proof;
            self.unset_digest();
        }

        /// Create a block template with an invalid block proof.
        ///
        /// To be used in tests where you don't care about block validity.
        pub(crate) fn block_template_invalid_proof(
            predecessor: &Block,
            block_transaction: BlockTransaction,
            block_timestamp: Timestamp,
            override_target_block_interval: Option<Timestamp>,
            network: Network,
        ) -> Block {
            let primitive_witness =
                BlockPrimitiveWitness::new(predecessor.to_owned(), block_transaction, network);
            let target_block_interval =
                override_target_block_interval.unwrap_or(network.target_block_interval());
            Self::block_template_invalid_proof_from_witness(
                primitive_witness,
                block_timestamp,
                target_block_interval,
            )
        }

        /// Create a block template with an invalid block proof, from a block
        /// primitive witness.
        pub(crate) fn block_template_invalid_proof_from_witness(
            primitive_witness: BlockPrimitiveWitness,
            block_timestamp: Timestamp,
            target_block_interval: Timestamp,
        ) -> Block {
            let body = primitive_witness.body().to_owned();
            let header = primitive_witness.header(block_timestamp, target_block_interval);
            let proof = BlockProof::Invalid;
            let appendix = BlockAppendix::default();

            Block::new(header, body, appendix, proof)
        }

        /// Produce two fake blocks, parent and child.
        pub(crate) async fn fake_block_pair_genesis_and_child_from_witness(
            primitive_witness: BlockPrimitiveWitness,
        ) -> (Block, Block) {
            let mut fake_genesis = primitive_witness.predecessor_block().to_owned();
            fake_genesis.proof = BlockProof::Genesis;
            let block_timestamp = primitive_witness.transaction().kernel.timestamp;
            let fake_child = Self::block_template_from_block_primitive_witness(
                primitive_witness,
                block_timestamp,
                vm_job_queue(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();

            (fake_genesis, fake_child)
        }

        /// Satisfy PoW for this block. Only to be used for tests since this
        /// function cannot be cancelled. Deterministic, will always return the
        /// same solution for the same input.
        pub(crate) fn satisfy_pow(
            &mut self,
            parent_difficulty: Difficulty,
            consensus_rule_set: ConsensusRuleSet,
        ) {
            println!("Trying to guess for difficulty: {parent_difficulty}");
            assert!(
                parent_difficulty < Difficulty::from(DIFFICULTY_LIMIT_FOR_TESTS),
                "Don't use high difficulty in test"
            );

            let puzzle = ProofOfWorkPuzzle::new(self.clone(), parent_difficulty);
            let valid_pow = puzzle.solve(consensus_rule_set);

            self.set_header_pow(valid_pow);
        }
    }

    prop_compose! {
        /// Relies on the private fields hence is here for re-export via `tests::shared::strategies`.
        pub fn arbitrary_kernel() (
            header in arb::<BlockHeader>(),
            transaction_kernel in crate::tests::shared::strategies::txkernel::default(true),
            lock_free_mmr_accumulator in arb::<MmrAccumulator>(),
            block_mmr_accumulator in arb::<MmrAccumulator>(),
            appendix in arb::<BlockAppendix>(),
            mutator_set_accumulator in arb::<MutatorSetAccumulator>(),
        ) -> Block {Block{
            kernel: BlockKernel{ header, body: BlockBody::new(
                transaction_kernel, mutator_set_accumulator, lock_free_mmr_accumulator, block_mmr_accumulator
            ), appendix },
            proof: Default::default(),
            digest: Default::default()
        }}
    }

    #[test]
    fn all_genesis_blocks_have_unique_sender_randomnesses() {
        assert!(
            Network::all_networks()
                .map(Block::premine_sender_randomness)
                .all_unique(),
            "All genesis blocks must have unique sender randomness for the premine UTXOs",
        );
    }

    #[test]
    fn all_genesis_blocks_have_unique_mutator_set_hashes() {
        let mutator_set_hash = |network| {
            Block::genesis(network)
                .body()
                .mutator_set_accumulator
                .hash()
        };

        assert!(
            Network::all_networks().map(mutator_set_hash).all_unique(),
            "All genesis blocks must have unique MSA digests, else replay attacks are possible",
        );
    }

    #[test]
    fn guess_nonce_happy_path() {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let mut invalid_block = invalid_empty_block(&genesis, network);
        let mast_auth_paths = invalid_block.pow_mast_paths();

        for consensus_rule_set in ConsensusRuleSet::iter() {
            let guesser_buffer = invalid_block.guess_preprocess(None, None, consensus_rule_set);
            let target = Difficulty::from(2u32).target();
            let mut rng = rng();
            let index_picker_preimage = guesser_buffer.index_picker_preimage(&mast_auth_paths);

            let valid_pow = loop {
                if let Some(valid_pow) = Pow::guess(
                    &guesser_buffer,
                    &mast_auth_paths,
                    index_picker_preimage,
                    rng.random(),
                    target,
                ) {
                    break valid_pow;
                }
            };

            assert!(
                !invalid_block.pow_verify(target, consensus_rule_set),
                "Pow verification must fail prior to setting PoW"
            );
            invalid_block.set_header_pow(valid_pow);
            assert!(invalid_block.pow_verify(target, consensus_rule_set));
        }
    }

    #[test]
    fn print_block_subsidy_per_generation() {
        let mut block_height = 0;
        for generation in 0..100 {
            let subsidy = Block::block_subsidy(block_height.into());
            println!(
                "Generation {generation}: Block height {block_height}, Subsidy: {}",
                subsidy.to_coins_f64_lossy()
            );
            block_height += BLOCKS_PER_GENERATION;
        }
    }
    //Generation 72: Block start height 622080, Subsidy: 1, Supply so far: 2463281.26272
    //
    #[test]
    fn print_block_subsidy_per_generation_and_total_supply_mined() {
        let mut block_height = 0;
        let mut total_supply_mined = NativeCurrencyAmount::zero();
        for generation in 0..100 {
            let subsidy = Block::block_subsidy(block_height.into());
            println!("Generation {generation}: Block start height {block_height}, Subsidy: {}, Supply so far: {}", subsidy.to_coins_f64_lossy(), total_supply_mined.to_coins_f64_lossy());
            total_supply_mined += subsidy.scalar_mul(BLOCKS_PER_GENERATION as u32);
            block_height += BLOCKS_PER_GENERATION;
        }
    }

    #[test]
    fn block_subsidy_generation_0() {
        let block_height_generation_0 = 199u64.into();
        assert_eq!(
            NativeCurrencyAmount::coins(8),
            Block::block_subsidy(block_height_generation_0)
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn relative_guesser_reward() {
        let network = Network::Main;
        for fraction in [0.01, 0.1, 0.5, 0.6, 0.7, 0.8, 0.9, 0.99, 1.0] {
            let block = invalid_empty_block1_with_guesser_fraction(network, fraction).await;
            assert_eq!(fraction, block.relative_guesser_reward().unwrap());
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn total_block_subsidy_is_128_coins_regardless_of_guesser_fraction() {
        let network = Network::Main;
        let a_wallet_secret = WalletEntropy::new_random();
        let a_key = a_wallet_secret.nth_generation_spending_key_for_tests(0);
        let coinbase_distribution = CoinbaseDistribution::solo(a_key.to_address().into());
        let genesis = Block::genesis(network);
        let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);
        let now = genesis.header().timestamp + Timestamp::days(1);

        let mut guesser_fraction = 0f64;
        let step = 0.05;
        while guesser_fraction + step <= 1f64 {
            let composer_parameters = ComposerParameters::new(
                coinbase_distribution.clone(),
                rng.random(),
                None,
                guesser_fraction,
                FeeNotificationPolicy::OffChain,
            );
            let (composer_txos, transaction_details) =
                prepare_coinbase_transaction_stateless(&genesis, composer_parameters, now, network);
            let coinbase_kernel =
                PrimitiveWitness::from_transaction_details(&transaction_details).kernel;
            let coinbase_kernel = TransactionKernelModifier::default()
                .merge_bit(true)
                .modify(coinbase_kernel); // ok: proof is invalid anyway
            let coinbase_transaction = Transaction {
                kernel: coinbase_kernel,
                proof: TransactionProof::invalid(),
            };
            let coinbase_transaction =
                BlockTransaction::try_from(coinbase_transaction).expect("merge bit was set");
            let total_composer_reward: NativeCurrencyAmount = composer_txos
                .iter()
                .map(|tx_output| tx_output.utxo().get_native_currency_amount())
                .sum();
            let block_primitive_witness =
                BlockPrimitiveWitness::new(genesis.clone(), coinbase_transaction, network);
            let block_proof_witness = BlockProofWitness::produce(block_primitive_witness.clone());
            let block1 = Block::new(
                block_primitive_witness.header(now, network.target_block_interval()),
                block_primitive_witness.body().to_owned(),
                block_proof_witness.appendix(),
                BlockProof::Invalid,
            );
            let total_guesser_reward = block1.body().total_guesser_reward().unwrap();
            let total_miner_reward = total_composer_reward + total_guesser_reward;
            assert_eq!(NativeCurrencyAmount::coins(128), total_miner_reward);

            println!("guesser_fraction: {guesser_fraction}");
            println!(
                "total_composer_reward: {total_guesser_reward}, as nau: {}",
                total_composer_reward.to_nau()
            );
            println!(
                "total_guesser_reward: {total_guesser_reward}, as nau {}",
                total_guesser_reward.to_nau()
            );
            println!(
                "total_miner_reward: {total_miner_reward}, as nau {}\n\n",
                total_miner_reward.to_nau()
            );

            guesser_fraction += step;
        }
    }

    #[test]
    fn observed_total_mining_reward_matches_block_subsidy() {
        // Data read from a node composing and guessing on test net. It
        // composed and guessed block number #115 and got four UTXOs, where the
        // native currency type script recorded these states. Those states must
        // sum to the total block subsidy for generation 0, 128 coins. This
        // were the recorded states for block
        // a1cd0ea9103c19444dd0342e7c772b0a02ed610b71a73ea37e4fe48357c619bb4fa0c3e866000000
        let state0 = [0u64, 980281920, 2521720867, 1615].map(BFieldElement::new);
        let state1 = [0u64, 980281920, 2521720867, 1615].map(BFieldElement::new);
        let state2 = [0u64, 981467136, 2521720867, 1615].map(BFieldElement::new);
        let state3 = [0u64, 981467136, 2521720867, 1615].map(BFieldElement::new);

        let mut total_amount = NativeCurrencyAmount::zero();
        for state in [state0, state1, state2, state3] {
            total_amount += *NativeCurrency.try_decode_state(&state).unwrap();
        }

        assert_eq!(NativeCurrencyAmount::coins(128), total_amount);
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn test_difficulty_control_matches() {
        let network = Network::Main;

        let a_wallet_secret = WalletEntropy::new_random();
        let a_key = a_wallet_secret.nth_generation_spending_key_for_tests(0);

        // TODO: Can this outer-loop be parallelized?
        for multiplier in [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000] {
            let mut block_prev = Block::genesis(network);
            let mut now = block_prev.kernel.header.timestamp;
            let mut rng = rand::rng();

            for i in (0..30).step_by(1) {
                let duration = i as u64 * multiplier;
                now += Timestamp::millis(duration);

                let (block, _) =
                    make_mock_block(&block_prev, Some(now), a_key, rng.random(), network).await;

                let control = difficulty_control(
                    block.kernel.header.timestamp,
                    block_prev.header().timestamp,
                    block_prev.header().difficulty,
                    network.target_block_interval(),
                    block_prev.header().height,
                );
                assert_eq!(block.kernel.header.difficulty, control);

                block_prev = block;
            }
        }
    }

    #[test]
    fn difficulty_to_threshold_test() {
        // Verify that a difficulty of 2 accepts half of the digests
        let difficulty: u32 = 2;
        let difficulty_u32s = Difficulty::from(difficulty);
        let threshold_for_difficulty_two: Digest = difficulty_u32s.target();

        for elem in threshold_for_difficulty_two.values() {
            assert_eq!(BFieldElement::MAX / u64::from(difficulty), elem.value());
        }

        // Verify that a difficulty of BFieldElement::MAX accepts all digests where the
        // last BFieldElement is zero
        let some_difficulty = Difficulty::new([1, u32::MAX, 0, 0, 0]);
        let some_threshold_actual: Digest = some_difficulty.target();

        let bfe_max_elem = BFieldElement::new(BFieldElement::MAX);
        let some_threshold_expected = Digest::new([
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            BFieldElement::zero(),
        ]);

        assert_eq!(0u64, some_threshold_actual.values()[4].value());
        assert_eq!(some_threshold_actual, some_threshold_expected);
        assert_eq!(bfe_max_elem, some_threshold_actual.values()[3]);
    }

    #[apply(shared_tokio_runtime)]
    async fn block_with_wrong_mmra_is_invalid() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let now = genesis_block.kernel.header.timestamp + Timestamp::hours(2);
        let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);

        let mut block1 =
            fake_valid_successor_for_tests(&genesis_block, now, rng.random(), network).await;

        let timestamp = block1.kernel.header.timestamp;
        assert!(block1.is_valid(&genesis_block, timestamp, network).await);

        let mut mutated_leaf = genesis_block.body().block_mmr_accumulator.clone();
        let mp = mutated_leaf.append(genesis_block.hash());
        mutated_leaf.mutate_leaf(LeafMutation::new(0, random(), mp));

        let mut extra_leaf = block1.body().block_mmr_accumulator.clone();
        extra_leaf.append(block1.hash());

        let bad_new_mmrs = [
            MmrAccumulator::new_from_leafs(vec![]),
            mutated_leaf,
            extra_leaf,
        ];

        for bad_new_mmr in bad_new_mmrs {
            block1.kernel.body.block_mmr_accumulator = bad_new_mmr;
            assert!(!block1.is_valid(&genesis_block, timestamp, network).await);
        }
    }

    #[test_strategy::proptest(async = "tokio", cases = 1)]
    async fn can_prove_block_ancestry(
        #[strategy(collection::vec(arb::<Digest>(), 55))] mut sender_randomness_vec: Vec<Digest>,
        #[strategy(0..54usize)] index: usize,
        #[strategy(collection::vec(arb::<WalletEntropy>(), 55))] mut wallet_secret_vec: Vec<
            WalletEntropy,
        >,
    ) {
        let network = Network::RegTest;
        let genesis_block = Block::genesis(network);
        let mut blocks = vec![];
        blocks.push(genesis_block.clone());
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();
        let mut storage = SimpleRustyStorage::new(db);
        let ammr_storage = storage.schema.new_vec::<Digest>("ammr-blocks-0").await;
        let mut ammr = ArchivalMmr::new(ammr_storage).await;
        ammr.append(genesis_block.hash()).await;
        let mut mmra = MmrAccumulator::new_from_leafs(vec![genesis_block.hash()]);

        for i in 0..55 {
            let wallet_secret = wallet_secret_vec.pop().unwrap();
            let key = wallet_secret.nth_generation_spending_key_for_tests(0);
            let (new_block, _) = make_mock_block(
                blocks.last().unwrap(),
                None,
                key,
                sender_randomness_vec.pop().unwrap(),
                network,
            )
            .await;
            if i != 54 {
                ammr.append(new_block.hash()).await;
                mmra.append(new_block.hash());
                assert_eq!(
                    ammr.to_accumulator_async().await.bag_peaks(),
                    mmra.bag_peaks()
                );
            }
            blocks.push(new_block);
        }

        let last_block_mmra = blocks.last().unwrap().body().block_mmr_accumulator.clone();
        assert_eq!(mmra, last_block_mmra);

        let block_digest = blocks[index].hash();

        let leaf_index = index as u64;
        let membership_proof = ammr.prove_membership_async(leaf_index).await;
        let v = membership_proof.verify(
            leaf_index,
            block_digest,
            &last_block_mmra.peaks(),
            last_block_mmra.num_leafs(),
        );
        assert!(
            v,
            "peaks: {} ({}) leaf count: {} index: {} path: {} number of blocks: {}",
            last_block_mmra.peaks().iter().join(","),
            last_block_mmra.peaks().len(),
            last_block_mmra.num_leafs(),
            leaf_index,
            membership_proof.authentication_path.iter().join(","),
            blocks.len(),
        );
        assert_eq!(last_block_mmra.num_leafs(), blocks.len() as u64 - 1);
    }

    mod block_is_valid {
        use rand::rng;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        use super::*;
        use crate::application::loops::mine_loop::create_block_transaction_from;
        use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state;
        use crate::application::loops::mine_loop::TxMergeOrigin;
        use crate::application::triton_vm_job_queue::vm_job_queue;
        use crate::state::transaction::tx_creation_config::TxCreationConfig;
        use crate::state::wallet::address::KeyType;
        use crate::tests::shared::blocks::fake_valid_successor_for_tests;

        async fn deterministic_empty_block1_proposal() -> (Block, Timestamp, Network, Block) {
            let network = Network::Main;
            let genesis = Block::genesis(network);
            let plus_one_hour = genesis.kernel.header.timestamp + Timestamp::hours(1);

            // wallet must be deterministic for block 1 to be deterministic, for
            // block proof to be reusable over test runs.
            let alice_wallet = WalletEntropy::devnet_wallet();
            let alice = mock_genesis_global_state(
                3,
                alice_wallet.clone(),
                cli_args::Args {
                    guesser_fraction: 0.5,
                    network,
                    ..Default::default()
                },
            )
            .await;

            let job_options = TritonVmProofJobOptions::default();
            let (transaction, _) = create_block_transaction_from(
                &genesis,
                alice.clone(),
                plus_one_hour,
                job_options.clone(),
                TxMergeOrigin::ExplicitList(vec![]),
            )
            .await
            .unwrap();
            let block1_proposal = Block::compose(
                &genesis,
                transaction,
                plus_one_hour,
                vm_job_queue(),
                job_options,
            )
            .await
            .unwrap();
            (genesis, plus_one_hour, network, block1_proposal)
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn block_with_valid_proof_passes() {
            let (predecesor, time, network, block) = deterministic_empty_block1_proposal().await;
            assert!(block.validate(&predecesor, time, network).await.is_ok());
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn block_with_invalid_proof_fails() {
            let (predecesor, time, network, mut block) =
                deterministic_empty_block1_proposal().await;

            // Block validation fails on manipulated proof
            let BlockProof::SingleProof(block_proof) = &mut block.proof else {
                panic!("Single proof expected");
            };
            let proof_length = block_proof.0.len();

            let mut rng = rng();
            let index = rng.random_range(0..proof_length);
            block_proof.0.get_mut(index).unwrap().increment();

            assert_eq!(
                BlockValidationError::ProofValidity,
                block
                    .validate(&predecesor, time, network)
                    .await
                    .unwrap_err()
            );
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn block_with_empty_proof_fails() {
            let (predecesor, time, network, mut block) =
                deterministic_empty_block1_proposal().await;

            // Block validation fails on empty proof
            block.set_proof(BlockProof::SingleProof(Proof(vec![]).into()));
            assert_eq!(
                BlockValidationError::ProofValidity,
                block
                    .validate(&predecesor, time, network)
                    .await
                    .unwrap_err()
            );
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn blocks_with_0_to_10_inputs_and_successors_are_valid() {
            // Scenario: Build different blocks of height 2, with varying number
            // of inputs. Verify all are valid. The build a block of height 3
            // with non-zero inputs and verify validity. This should ensure that
            // at least one of block 2's guesser fee UTXOs shift the active
            // window of the mutator set's Bloom filter, ensuring that the
            // validity-check of a block handles guesser fee UTXOs correctly
            // when calculating the expected state of the new mutator set.
            // Cf., the bug fixed in 4d6b7013624e593c40e76ce93cb6b288b6b3f48b.

            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let plus_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
            let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);
            let block1 = fake_valid_successor_for_tests(
                &genesis_block,
                plus_seven_months,
                rng.random(),
                network,
            )
            .await;

            let alice_wallet = WalletEntropy::devnet_wallet();
            let mut alice = mock_genesis_global_state(
                3,
                alice_wallet.clone(),
                cli_args::Args {
                    guesser_fraction: 0.5,
                    network,
                    ..Default::default()
                },
            )
            .await;
            alice.set_new_tip(block1.clone()).await.unwrap();
            let alice_key = alice
                .lock_guard()
                .await
                .wallet_state
                .nth_spending_key(KeyType::Generation, 0);
            let output_to_self = TxOutput::onchain_native_currency(
                NativeCurrencyAmount::coins(1),
                rng.random(),
                alice_key.to_address(),
                true,
            );

            let plus_eight_months = plus_seven_months + Timestamp::months(1);
            let (coinbase_for_block2, _) = make_coinbase_transaction_from_state(
                &block1,
                &alice,
                plus_eight_months,
                TritonVmProofJobOptions::default_with_network(network),
            )
            .await
            .unwrap();
            let block_height = block1.header().height;
            let consensus_rule_set_1 = ConsensusRuleSet::infer_from(network, block_height);
            let fee = NativeCurrencyAmount::coins(1);
            let plus_nine_months = plus_eight_months + Timestamp::months(1);
            for i in 0..10 {
                println!("i: {i}");
                alice = mock_genesis_global_state(
                    3,
                    alice_wallet.clone(),
                    cli_args::Args::default_with_network(network),
                )
                .await;
                alice.set_new_tip(block1.clone()).await.unwrap();
                let outputs = vec![output_to_self.clone(); i];
                let config2 = TxCreationConfig::default()
                    .recover_change_on_chain(alice_key)
                    .with_prover_capability(TxProvingCapability::SingleProof);
                let tx2 = alice
                    .api()
                    .tx_initiator_internal()
                    .create_transaction(
                        outputs.into(),
                        fee,
                        plus_eight_months,
                        config2,
                        consensus_rule_set_1,
                    )
                    .await
                    .unwrap()
                    .transaction;
                let block2_tx = BlockTransaction::merge(
                    coinbase_for_block2.clone().into(),
                    (*tx2).clone(),
                    rng.random(),
                    TritonVmJobQueue::get_instance(),
                    TritonVmProofJobOptions::default_with_network(network),
                    consensus_rule_set_1,
                )
                .await
                .unwrap();
                let block2_without_valid_pow = Block::compose(
                    &block1,
                    block2_tx,
                    plus_eight_months,
                    TritonVmJobQueue::get_instance(),
                    TritonVmProofJobOptions::default_with_network(network),
                )
                .await
                .unwrap();

                assert!(
                    block2_without_valid_pow
                        .is_valid(&block1, plus_eight_months, network)
                        .await,
                    "Block with {i} inputs must be valid"
                );

                alice
                    .set_new_tip(block2_without_valid_pow.clone())
                    .await
                    .unwrap();
                let (coinbase_for_block3, _) = make_coinbase_transaction_from_state(
                    &block2_without_valid_pow,
                    &alice,
                    plus_nine_months,
                    TritonVmProofJobOptions::default_with_network(network),
                )
                .await
                .unwrap();

                let block_height2 = block2_without_valid_pow.header().height;
                let consensus_rule_set_2 = ConsensusRuleSet::infer_from(network, block_height2);
                let config3 = TxCreationConfig::default()
                    .recover_change_on_chain(alice_key)
                    .with_prover_capability(TxProvingCapability::SingleProof);
                let tx3 = alice
                    .api()
                    .tx_initiator_internal()
                    .create_transaction(
                        vec![output_to_self.clone()].into(),
                        fee,
                        plus_nine_months,
                        config3,
                        consensus_rule_set_2,
                    )
                    .await
                    .unwrap()
                    .transaction;
                let block3_tx = BlockTransaction::merge(
                    coinbase_for_block3.clone().into(),
                    (*tx3).clone(),
                    rng.random(),
                    TritonVmJobQueue::get_instance(),
                    TritonVmProofJobOptions::default_with_network(network),
                    consensus_rule_set_2,
                )
                .await
                .unwrap();
                assert!(
                    !block3_tx.kernel.inputs.len().is_zero(),
                    "block transaction 3 must have inputs"
                );
                let block3_without_valid_pow = Block::compose(
                    &block2_without_valid_pow,
                    block3_tx,
                    plus_nine_months,
                    TritonVmJobQueue::get_instance(),
                    TritonVmProofJobOptions::default_with_network(network),
                )
                .await
                .unwrap();

                assert!(
                    block3_without_valid_pow
                        .is_valid(&block2_without_valid_pow, plus_nine_months, network)
                        .await,
                    "Block of height 3 after block 2 with {i} inputs must be valid"
                );
            }
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn block_with_far_future_timestamp_is_invalid() {
            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let mut now = genesis_block.kernel.header.timestamp + Timestamp::hours(2);
            let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);

            let mut block1 =
                fake_valid_successor_for_tests(&genesis_block, now, rng.random(), network).await;

            // Set block timestamp 4 minutes in the future.  (is valid)
            let future_time1 = now + Timestamp::minutes(4);
            block1.kernel.header.timestamp = future_time1;
            assert!(block1.is_valid(&genesis_block, now, network).await);

            now = block1.kernel.header.timestamp;

            // Set block timestamp 5 minutes - 1 sec in the future.  (is valid)
            let future_time2 = now + Timestamp::minutes(5) - Timestamp::seconds(1);
            block1.kernel.header.timestamp = future_time2;
            assert!(block1.is_valid(&genesis_block, now, network).await);

            // Set block timestamp 5 minutes in the future. (not valid)
            let future_time3 = now + Timestamp::minutes(5);
            block1.kernel.header.timestamp = future_time3;
            assert!(!block1.is_valid(&genesis_block, now, network).await);

            // Set block timestamp 5 minutes + 1 sec in the future. (not valid)
            let future_time4 = now + Timestamp::minutes(5) + Timestamp::seconds(1);
            block1.kernel.header.timestamp = future_time4;
            assert!(!block1.is_valid(&genesis_block, now, network).await);

            // Set block timestamp 2 days in the future. (not valid)
            let future_time5 = now + Timestamp::seconds(86400 * 2);
            block1.kernel.header.timestamp = future_time5;
            assert!(!block1.is_valid(&genesis_block, now, network).await);
        }
    }

    /// This module has tests that verify a block's digest
    /// is always in a correct state.
    ///
    /// All operations that create or modify a Block should
    /// have a test here.
    mod digest_encapsulation {

        use super::*;
        use crate::api::export::NeptuneProof;

        // test: verify clone + modify does not change original.
        //
        // note: a naive impl that derives `Clone` on `Block` containing
        //       `Arc<Mutex<Option<Digest>>>` would link the digest in the clone
        #[test]
        fn clone_and_modify() {
            let gblock = Block::genesis(Network::RegTest);
            let g_hash = gblock.hash();

            let mut g2 = gblock.clone();
            assert_eq!(gblock.hash(), g_hash);
            assert_eq!(gblock.hash(), g2.hash());

            g2.set_header_pow(Default::default());
            assert_ne!(gblock.hash(), g2.hash());
            assert_eq!(gblock.hash(), g_hash);
        }

        // test: verify digest is correct after Block::new().
        #[test]
        fn new() {
            let gblock = Block::genesis(Network::RegTest);
            let g2 = gblock.clone();

            let block = Block::new(
                g2.kernel.header,
                g2.kernel.body,
                g2.kernel.appendix,
                g2.proof,
            );
            assert_eq!(gblock.hash(), block.hash());
        }

        #[test]
        fn hash_depends_on_proof() {
            let network = Network::Main;
            let mut block = invalid_empty_block(&Block::genesis(network), network);
            let original_hash = block.hash();
            block.set_proof(BlockProof::SingleProof(NeptuneProof::invalid_with_size(65)));
            assert_ne!(original_hash, block.hash());
        }

        // test: verify digest changes after pow is updated.
        #[test]
        fn set_header_pow() {
            let gblock = Block::genesis(Network::RegTest);
            let mut rng = rand::rng();

            let mut new_block = gblock.clone();
            new_block.set_header_pow(rng.random());
            assert_ne!(gblock.hash(), new_block.hash());
        }

        // test: verify set_block() copies source digest
        #[test]
        fn set_block() {
            let gblock = Block::genesis(Network::RegTest);
            let mut rng = rand::rng();

            let mut unique_block = gblock.clone();
            unique_block.set_header_pow(rng.random());

            let mut block = gblock.clone();
            block.set_block(unique_block.clone());

            assert_eq!(unique_block.hash(), block.hash());
            assert_ne!(unique_block.hash(), gblock.hash());
        }

        // test: verify digest is correct after deserializing
        #[test]
        fn deserialize() {
            let gblock = Block::genesis(Network::RegTest);

            let bytes = bincode::serialize(&gblock).unwrap();
            let block: Block = bincode::deserialize(&bytes).unwrap();

            assert_eq!(gblock.hash(), block.hash());
        }

        // test: verify block digest matches after BFieldCodec encode+decode
        //       round trip.
        #[test]
        fn bfieldcodec_encode_and_decode() {
            let gblock = Block::genesis(Network::RegTest);

            let encoded: Vec<BFieldElement> = gblock.encode();
            let decoded: Block = *Block::decode(&encoded).unwrap();

            assert_eq!(gblock, decoded);
            assert_eq!(gblock.hash(), decoded.hash());
        }
    }

    mod guesser_fee_utxos {
        use super::*;
        use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;
        use crate::state::transaction::tx_creation_config::TxCreationConfig;
        use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
        use crate::state::wallet::address::generation_address::GenerationSpendingKey;
        use crate::tests::shared::blocks::make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction;

        #[apply(shared_tokio_runtime)]
        async fn guesser_fee_addition_records_are_consistent() {
            // Ensure that multiple ways of deriving guesser-fee addition
            // records are consistent.

            let network = Network::Main;
            let mut rng = rand::rng();
            let genesis_block = Block::genesis(network);
            let a_key = GenerationSpendingKey::derive_from_seed(rng.random());
            let guesser_address = GenerationReceivingAddress::derive_from_seed(rng.random());
            let (block1, _) = make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
                &genesis_block,
                vec![],
                vec![],
                None,
                a_key,
                rng.random(),
                (0.4, guesser_address.into()),
                network,
            )
            .await;
            let ars = block1.guesser_fee_addition_records().unwrap();
            let ars_from_wallet = block1
                .kernel
                .guesser_fee_utxos()
                .unwrap()
                .iter()
                .map(|utxo| {
                    UtxoTriple {
                        utxo: utxo.clone(),
                        sender_randomness: block1.hash(),
                        receiver_digest: guesser_address.receiver_postimage(),
                    }
                    .addition_record()
                })
                .collect_vec();
            assert_eq!(ars, ars_from_wallet);

            let MutatorSetUpdate {
                removals: _,
                additions,
            } = block1.mutator_set_update().unwrap();
            assert!(
                ars.iter().all(|ar| additions.contains(ar)),
                "All addition records must be present in block's mutator set update"
            );
        }

        #[test]
        fn guesser_can_unlock_guesser_fee_utxo() {
            let genesis_block = Block::genesis(Network::Main);
            let mut transaction = make_mock_transaction(vec![], vec![]);

            transaction.kernel = TransactionKernelModifier::default()
                .fee(NativeCurrencyAmount::from_nau(1337.into()))
                .modify(transaction.kernel);

            let mut block = invalid_block_with_transaction(&genesis_block, transaction);

            let guesser_key = GenerationSpendingKey::derive_from_seed(rand::rng().random());
            let guesser_address = guesser_key.to_address();
            block.set_header_guesser_address(guesser_address.into());

            let guesser_fee_utxos = block.kernel.guesser_fee_utxos().unwrap();

            let lock_script_and_witness = guesser_key.lock_script_and_witness();
            assert!(guesser_fee_utxos
                .iter()
                .all(|guesser_fee_utxo| lock_script_and_witness.can_unlock(guesser_fee_utxo)));
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn guesser_fees_are_added_to_mutator_set() {
            // Mine two blocks on top of the genesis block. Verify that the guesser
            // fee for the 1st block was added to the mutator set. The genesis
            // block awards no guesser fee.

            // This test must live in block/mod.rs because it relies on access to
            // private fields on `BlockBody`.

            let mut rng = rand::rng();
            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            assert!(
                genesis_block.kernel.guesser_fee_utxos().unwrap().is_empty(),
                "Genesis block has no guesser fee UTXOs"
            );

            let launch_date = genesis_block.header().timestamp;
            let in_seven_months = launch_date + Timestamp::months(7);
            let in_eight_months = launch_date + Timestamp::months(8);
            let alice_wallet = WalletEntropy::devnet_wallet();
            let alice_key = alice_wallet.nth_generation_spending_key(0);
            let alice_address = alice_key.to_address();
            let mut alice = mock_genesis_global_state(
                0,
                alice_wallet,
                cli_args::Args::default_with_network(network),
            )
            .await;

            let output = TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(4),
                rng.random(),
                alice_address.into(),
                true,
            );
            let fee = NativeCurrencyAmount::coins(1);
            let config1 = TxCreationConfig::default()
                .recover_change_on_chain(alice_key.into())
                .with_prover_capability(TxProvingCapability::PrimitiveWitness);
            let consensus_rule_set_0 =
                ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
            let tx1 = alice
                .api()
                .tx_initiator_internal()
                .create_transaction(
                    vec![output.clone()].into(),
                    fee,
                    in_seven_months,
                    config1,
                    consensus_rule_set_0,
                )
                .await
                .unwrap()
                .transaction;

            let tx1 = BlockTransaction::upgrade((*tx1).clone());
            let block1 = Block::block_template_invalid_proof(
                &genesis_block,
                tx1,
                in_seven_months,
                None,
                network,
            );
            alice.set_new_tip(block1.clone()).await.unwrap();

            let config2 = TxCreationConfig::default()
                .recover_change_on_chain(alice_key.into())
                .with_prover_capability(TxProvingCapability::PrimitiveWitness);
            let block_height1 = BlockHeight::genesis().next();
            let consensus_rule_set_1 = ConsensusRuleSet::infer_from(network, block_height1);
            let tx2 = alice
                .api()
                .tx_initiator_internal()
                .create_transaction(
                    vec![output].into(),
                    fee,
                    in_eight_months,
                    config2,
                    consensus_rule_set_1,
                )
                .await
                .unwrap()
                .transaction;

            let tx2 = BlockTransaction::upgrade((*tx2).clone());
            let block2 =
                Block::block_template_invalid_proof(&block1, tx2, in_eight_months, None, network);

            let mut ms = block1.body().mutator_set_accumulator.clone();

            // Assumes no packing of mutator set happens on block level.
            let mutator_set_update_guesser_fees =
                MutatorSetUpdate::new(vec![], block1.guesser_fee_addition_records().unwrap());
            let mut mutator_set_update_tx = MutatorSetUpdate::new(
                block2.body().transaction_kernel.inputs.clone(),
                block2.body().transaction_kernel.outputs.clone(),
            );

            let reason = "applying mutator set update derived from block 2 \
                          to mutator set from block 1 should work";
            mutator_set_update_guesser_fees
                .apply_to_accumulator_and_records(
                    &mut ms,
                    &mut mutator_set_update_tx.removals.iter_mut().collect_vec(),
                    &mut [],
                )
                .expect(reason);
            mutator_set_update_tx
                .apply_to_accumulator(&mut ms)
                .expect(reason);

            assert_eq!(ms.hash(), block2.body().mutator_set_accumulator.hash());
        }
    }

    #[test]
    fn premine_distribution_does_not_crash() {
        Block::premine_distribution();
    }

    /// Exhibits a strategy for creating one transaction by merging in many
    /// small ones that spend from one's own wallet. The difficulty you run into
    /// when you do this naïvely is that you end up merging in transactions that
    /// spend the same UTXOs over and over. To avoid doing this, you insert the
    /// transaction into the mempool thus making the wallet aware of this
    /// transaction and avoiding a double-spend of a UTXO.
    #[apply(shared_tokio_runtime)]
    async fn avoid_reselecting_same_input_utxos() {
        let mut rng = StdRng::seed_from_u64(893423984854);
        let network = Network::Main;
        let devnet_wallet = WalletEntropy::devnet_wallet();
        let mut alice = mock_genesis_global_state(
            0,
            devnet_wallet,
            cli_args::Args::default_with_network(network),
        )
        .await;

        let job_queue = TritonVmJobQueue::get_instance();

        let genesis_block = Block::genesis(network);

        let mut blocks = vec![genesis_block];

        // Spend i inputs in block i, for i in {1,2}. The first expenditure and
        // block is guaranteed to succeed. Prior to the second block, Alice owns
        // two inputs and creates a big transaction by merging in smaller ones.
        // She needs to ensure the two transactions she merges in do not spend
        // the same UTXO.
        let launch_date = network.launch_date();
        let mut now = launch_date + Timestamp::months(6);
        for i in 1..3 {
            now += network.target_block_interval();

            // create coinbase transaction
            let (transaction, _) = make_coinbase_transaction_from_state(
                &blocks[i - 1],
                &alice,
                launch_date,
                TritonVmProofJobOptions::from((TritonVmJobPriority::Normal, None)),
            )
            .await
            .unwrap();
            let mut transaction = BlockOrRegularTransaction::from(transaction);

            let block_height = blocks.last().unwrap().header().height;
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);

            // for all own UTXOs, spend to self
            for _ in 0..i {
                // create a transaction spending it to self
                let change_key = alice
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .next_unused_symmetric_key()
                    .await;
                let receiving_address = alice
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .next_unused_spending_key(KeyType::Generation)
                    .await
                    .to_address();
                let send_amount = NativeCurrencyAmount::coins(1);
                let tx_outputs = vec![TxOutput::onchain_native_currency(
                    send_amount,
                    rng.random(),
                    receiving_address,
                    true,
                )]
                .into();
                let config = TxCreationConfig::default()
                    .recover_change_on_chain(change_key.into())
                    .with_prover_capability(TxProvingCapability::SingleProof)
                    .use_job_queue(job_queue.clone());
                let transaction_creation_artifacts = alice
                    .api()
                    .tx_initiator_internal()
                    .create_transaction(
                        tx_outputs,
                        NativeCurrencyAmount::coins(0),
                        now,
                        config,
                        consensus_rule_set,
                    )
                    .await
                    .unwrap();
                let self_spending_transaction = transaction_creation_artifacts.transaction;

                // merge that transaction in
                transaction = BlockTransaction::merge(
                    transaction,
                    (*self_spending_transaction).clone(),
                    rng.random(),
                    job_queue.clone(),
                    TritonVmProofJobOptions::default_with_network(network),
                    consensus_rule_set,
                )
                .await
                .unwrap()
                .into();

                alice
                    .lock_guard_mut()
                    .await
                    .mempool_insert(transaction.clone().into(), UpgradePriority::Critical)
                    .await;
            }

            // compose block
            let block = Block::compose(
                blocks.last().unwrap(),
                transaction.try_into().expect(
                    "went through at least one iteration of above loop, so merge bit must be set",
                ),
                now,
                job_queue.clone(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();

            let block_is_valid = block.validate(blocks.last().unwrap(), now, network).await;
            println!("block is valid? {:?}", block_is_valid.map(|_| "yes"));
            println!();
            assert!(block_is_valid.is_ok());

            // update state with new block
            alice.set_new_tip(block.clone()).await.unwrap();

            blocks.push(block);
        }
    }
}
