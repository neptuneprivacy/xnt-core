use strum_macros::EnumIter;

use crate::api::export::BlockHeight;
use crate::api::export::Network;
use crate::protocol::consensus::block::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;
use crate::BFieldElement;

/// Height of 1st block that follows the Xnt consensus ruleset (with Triton VM v1).
pub const BLOCK_HEIGHT_HARDFORK_XNT_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(15256u64));

/// Height of the 1st block that follows the `TimelockExtension` consensus
/// ruleset on mainnet.
pub const BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(52540u64));

/// Height of the 1st block that follows the `UpgradeVM` consensus ruleset on
/// mainnet. UpgradeVM is the triton-vm v3 / tasm-lib upgrade: it changes the
/// bytecode (hence program digest) of every consensus program. Pre-upgrade history
/// stays verifiable under the single v3 verifier via hardcoded per-era program
/// digests; UpgradeVM blocks use the recomputed v3 digests.
pub const BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(55800u64));

/// Height of the 1st block that follows the `UpgradeVMv4` consensus ruleset on
/// mainnet. UpgradeVMv4 is the triton-vm v4 upgrade: it re-hashes every consensus
/// program again (the proof format version bumps 1 -> 2, and the leaf type-script
/// length-bound is lifted for single-word coin state). Pre-v4 history stays
/// verifiable via the hardcoded UpgradeVM (v3) program digests; UpgradeVMv4 blocks
/// use the recomputed v4 digests.
///
/// Mainnet v4 activation height.
pub const BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(56700u64));

/// Height of the 1st block that follows the `UpgradeVMv5` consensus ruleset on
/// mainnet. UpgradeVMv5 is the triton-vm v5 upgrade: triton-vm's ISA and proof
/// format changed (proof version 2 -> 5), so the proof programs that embed the
/// STARK verifier (`SingleProofV2`, `BlockProgram`) compile to different bytecode
/// and re-hash. The v5 verifier cannot re-check v4 proofs, so pre-v5 history is
/// checkpointed via the hardcoded v4 program digests.
///
/// NOTE: unlike the v3→v4 upgrade, the leaf TYPE SCRIPTS (`NativeCurrency`,
/// `TimeLock`, `TimeLockV2`, `CollectTypeScriptsV2`) are byte-identical across
/// v4 and v5 — their digests did NOT change — so existing coins need NO remap and
/// remain spendable directly.
///
/// Mainnet v5 activation height.
pub const BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(57650u64));

/// Height of the 1st block that follows the `UpgradeVMv7` consensus ruleset on
/// mainnet. UpgradeVMv7 is the triton-vm v7 / tasm-lib upgrade. triton-vm's
/// proof FORMAT version is unchanged (still `proof::CURRENT_VERSION == 5`), but
/// tasm-lib's emitted TASM changed — notably the u128 `OverflowingAdd`/`SafeAdd`/
/// `Sub` snippets now range-check their operand limbs — so the proof programs
/// that embed those snippets (`SingleProof`, `SingleProofV2`, `BlockProgram`)
/// compile to different bytecode and re-hash. The leaf type scripts
/// (`NativeCurrency`, `TimeLock`, `TimeLockV2`, `CollectTypeScripts(V2)`) are
/// byte-identical to v5 — their digests did NOT change — so existing coins need
/// NO remap and remain spendable directly. Pre-v7 history is checkpointed via the
/// hardcoded v5 program digests; UpgradeVMv7 blocks use the recomputed v7 digests.
///
/// Mainnet v7 activation height.
pub const BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V7_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(59200u64));

/// Height of the 1st block that follows the `UpgradeVMv8` consensus ruleset on
/// mainnet. UpgradeVMv8 is the triton-vm v8 upgrade.
///
/// v8 is a security release, not a feature release. It makes the Hash Table and
/// Program Table AIR sound, closing findings NPT-1 and NPT-20: before it, the
/// initial sponge capacity was prover-chosen and Program Table padding could
/// begin mid-chunk, which together made program attestation forgeable. It also
/// randomizes the quotient table, giving Triton VM an explicit zero-knowledge
/// proof for the first time, and adds four guards against panics on malformed
/// proofs.
///
/// The constraint system changes, so the proof format version jumps 5 -> 8 and
/// every proof program re-hashes. The v8 verifier cannot check v7 proofs, so
/// this binary also links triton-vm v7 as a legacy verifier for the v7 era,
/// against the hardcoded v7 program digests; earlier eras are checkpointed.
///
/// The leaf type scripts are byte-identical across v7 and v8 — verified by the
/// `program_hash_has_not_changed` snapshots for `NativeCurrency`, `TimeLock`,
/// `TimeLockV2` and `CollectTypeScripts(V2)`, all unchanged — so existing coins
/// need no remap and remain spendable directly. Only `SingleProof`,
/// `SingleProofV2` and `BlockProgram`, which embed the STARK verifier, re-hash.
///
/// ROLLOUT: this binary verifies the v7 chain but cannot extend it, because a
/// v7-era claim names the hardcoded v7 program digest and no v8 bytecode
/// reproduces it. Before this height it therefore does not compose, nor hold
/// or relay transactions (see `ConsensusRuleSet::is_legacy_era`), and the chain
/// relies on composers still running the previous release to reach it.
///
/// Mainnet v8 activation height.
pub const BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(95_000u64));

/// Enumerates all possible sets of consensus rules.
///
/// Specifically, this enum captures *differences* between consensus rules,
/// across
///  - networks, and
///  - hard and soft forks triggered by blocks.
///
/// Consensus logic not captured by this encapsulation lives on
/// [`Transaction::is_valid`][super::transaction::Transaction::is_valid] and
/// ultimately [`Block::is_valid`][super::block::Block::is_valid].
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, Default, strum_macros::Display)]
pub enum ConsensusRuleSet {
    Reboot,
    HardforkAlpha,
    #[default]
    Xnt,
    /// The +1 year timelock extension hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET`] on
    /// Main (mainnet-only). Under this ruleset, any coin still tagged with the
    /// legacy `TimeLock` hash is governed by `TimeLockV2`, which enforces
    /// `release_date + 1 year < timestamp` instead of the original
    /// `release_date < timestamp`. New post-fork timelock UTXOs use
    /// `TimeLockV2`'s own hash and follow normal release rules.
    TimelockExtension,
    /// The triton-vm v3 / tasm-lib upgrade hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET`] on Main. The VM
    /// upgrade changes the bytecode — and therefore the program digest — of
    /// every consensus program. The single (v3) verifier still validates
    /// pre-upgrade proofs because their program digests are hardcoded per era and
    /// the proof version is carried in the `Claim`; UpgradeVM blocks use the
    /// recomputed v3 program digests.
    UpgradeVM,
    /// The triton-vm v4 upgrade hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET`] on Main. The
    /// VM upgrade bumps the proof format version (1 -> 2) and re-hashes every
    /// consensus program; the leaf type scripts additionally drop the single-word
    /// length-bound. The single (v4) verifier still validates pre-v4 proofs via
    /// hardcoded per-era digests + the claim version; UpgradeVMv4 blocks use the
    /// recomputed v4 program digests. Coins committed under the UpgradeVM (v3) era
    /// remain spendable via the type-script remap (`CollectTypeScriptsV2`).
    UpgradeVMv4,
    /// The triton-vm v5 upgrade hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET`] on Main.
    /// triton-vm's ISA changed, so the proof programs that embed the STARK
    /// verifier (`SingleProofV2`, `BlockProgram`) re-hash; the leaf type scripts
    /// are unchanged. The current (v5) verifier validates only v5 proofs; pre-v5
    /// history is checkpointed via hardcoded per-era digests. UpgradeVMv5 blocks
    /// use the recomputed v5 proof-program digests. Because the type scripts did
    /// not change, coins from every prior era remain spendable with no remap.
    UpgradeVMv5,
    /// The triton-vm v7 / tasm-lib upgrade hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V7_MAIN_NET`] on Main.
    /// triton-vm's proof FORMAT version is unchanged (still
    /// `proof::CURRENT_VERSION == 5`), but tasm-lib's emitted TASM changed — the
    /// u128 `OverflowingAdd`/`SafeAdd`/`Sub` snippets now range-check their operand
    /// limbs — so the proof programs that embed them (`SingleProof`,
    /// `SingleProofV2`, `BlockProgram`) re-hash; the leaf type scripts are
    /// unchanged. The current binary links triton-vm v7, so pre-v7 history (whose
    /// proofs were produced under triton-vm v5) is checkpointed via hardcoded
    /// per-era digests rather than re-verified. UpgradeVMv7 blocks use the
    /// recomputed v7 proof-program digests. Because the type scripts did not
    /// change, coins from every prior era remain spendable with no remap.
    UpgradeVMv7,
    /// The triton-vm v8 upgrade hard fork.
    ///
    /// Activated at [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET`] on Main.
    /// Unlike the preceding VM bumps, this one is a security release. v8 makes
    /// the Hash Table and Program Table AIR sound, closing the forgeable
    /// program-attestation findings NPT-1 and NPT-20, and randomizes the
    /// quotient table so the proof system has an explicit zero-knowledge proof.
    ///
    /// The constraint system changes, so the proof FORMAT version jumps 5 -> 8
    /// and the proof programs that embed the STARK verifier (`SingleProof`,
    /// `SingleProofV2`, `BlockProgram`) re-hash. The v7 era is verified with
    /// the linked legacy triton-vm v7 against the hardcoded v7 program digests;
    /// earlier eras are checkpointed. UpgradeVMv8 blocks use the recomputed v8
    /// proof-program digests.
    UpgradeVMv8,
}

/// The triton-vm crate major a rule set's proofs were produced under. The
/// program digest changes per era, but a single (current) verifier can check
/// every era's proofs given the era-correct digest + claim version, because the
/// version is absorbed into the verifier's Fiat-Shamir transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum_macros::Display)]
pub enum TritonProofVersion {
    /// triton-vm v1.0.0 (proof format version 0) — Reboot, HardforkAlpha.
    V1,
    /// triton-vm v2.0.0 (proof format version 1) — Xnt, TimelockExtension.
    V2,
    /// triton-vm v3.0.0 (proof format version 1) — UpgradeVM.
    V3,
    /// triton-vm v4.0.0 (proof format version 2) — UpgradeVMv4.
    V4,
    /// triton-vm v5.0.0 (proof format version 5; ISA changed) — UpgradeVMv5.
    V5,
    /// triton-vm v7.0.0 (proof format version 5; same format as v5, different
    /// tasm-lib bytecode) — UpgradeVMv7.
    V7,
    /// triton-vm v8.0.0 (proof format version 8) — UpgradeVMv8.
    ///
    /// v8 makes the Hash Table and Program Table AIR sound, closing the
    /// forgeable-program-attestation findings NPT-1 and NPT-20, and randomizes
    /// the quotient table so the proof system has an explicit zero-knowledge
    /// proof. Both change the constraint system, so the proof format version
    /// jumps 5 -> 8 and every proof program re-hashes.
    V8,
}

impl TritonProofVersion {
    /// The `version` field stamped into a [`Claim`]: triton-vm's own
    /// proof-format version (0 for v1.0.0, 1 for v2.0.0+), which is distinct
    /// from the crate major named by this enum.
    pub(crate) fn claim_version(self) -> u32 {
        match self {
            TritonProofVersion::V1 => 0,
            TritonProofVersion::V2 | TritonProofVersion::V3 => 1,
            // v4 is frozen at proof format version 2.
            TritonProofVersion::V4 => 2,
            // v5 is frozen at proof format version 5 (the value the linked
            // triton-vm v5 stamped while v5 was the current era).
            TritonProofVersion::V5 => 5,
            // v7 is FROZEN at proof format version 5. triton-vm v7 kept v5's
            // proof format, and 5 is the value stamped into every v7-era proof
            // already on chain. This must not track the live constant any more:
            // the linked triton-vm is now v8, whose `CURRENT_VERSION` is 8, so
            // tracking it would silently re-version every historical v7 claim.
            TritonProofVersion::V7 => 5,
            // v8 is the CURRENT era: its claim version must match the version the
            // linked triton-vm actually stamps into proofs, so track the live
            // constant rather than a literal (keeps `BlockProgram::claim` in sync
            // with the live `SingleProofV2`/`BlockProgram` provers).
            TritonProofVersion::V8 => tasm_lib::triton_vm::proof::CURRENT_VERSION,
        }
    }
}

impl ConsensusRuleSet {
    /// triton-vm crate major the blocks of this rule set were produced under.
    pub(crate) fn triton_proof_version(&self) -> TritonProofVersion {
        match self {
            ConsensusRuleSet::Reboot | ConsensusRuleSet::HardforkAlpha => TritonProofVersion::V1,
            ConsensusRuleSet::Xnt | ConsensusRuleSet::TimelockExtension => TritonProofVersion::V2,
            ConsensusRuleSet::UpgradeVM => TritonProofVersion::V3,
            ConsensusRuleSet::UpgradeVMv4 => TritonProofVersion::V4,
            ConsensusRuleSet::UpgradeVMv5 => TritonProofVersion::V5,
            ConsensusRuleSet::UpgradeVMv7 => TritonProofVersion::V7,
            ConsensusRuleSet::UpgradeVMv8 => TritonProofVersion::V8,
        }
    }

    /// Rule sets whose proofs this binary cannot check, so their blocks are
    /// trusted (checkpointed) rather than re-verified.
    ///
    /// A Triton VM verifier only checks proofs of its own proof format version.
    /// This binary links triton-vm v9 (format 8) for `UpgradeVMv8` and, as a
    /// legacy verifier, triton-vm v7 (format 5) for `UpgradeVMv7`; see
    /// [`Self::is_legacy_era`]. Every earlier era was produced under a
    /// superseded triton-vm or tasm-lib and is checkpointed.
    ///
    /// `UpgradeVMv5` proofs share format 5 with v7 and might verify under the
    /// legacy verifier, but that era is long past and stays checkpointed,
    /// mirroring neptune-core's "upgrade Triton VM with checkpoint" pattern.
    pub(crate) fn proofs_are_trusted(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5 => true,
            ConsensusRuleSet::UpgradeVMv7 | ConsensusRuleSet::UpgradeVMv8 => false,
        }
    }

    /// Whether this is the era immediately before the current one, which this
    /// binary verifies with the legacy triton-vm v7 but cannot produce proofs
    /// for.
    ///
    /// On main net the chain stays in this era until
    /// [`BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET`]. A node running this
    /// binary before then verifies every block fully, but it must not compose
    /// blocks or create, merge, upgrade or relay transactions: their proofs need
    /// the v7 consensus programs, which this binary does not contain. Composing
    /// a block of this era would fail at the first proof, and a v7 transaction
    /// held in the mempool across the fork would make the first `UpgradeVMv8`
    /// block impossible to compose.
    pub(crate) fn is_legacy_era(&self) -> bool {
        match self {
            ConsensusRuleSet::UpgradeVMv7 => true,
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5
            | ConsensusRuleSet::UpgradeVMv8 => false,
        }
    }

    /// Maximum block size in number of BFieldElements
    pub(crate) const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5
            | ConsensusRuleSet::UpgradeVMv7
            | ConsensusRuleSet::UpgradeVMv8 => {
                // This size is 8MB which should keep it feasible to run archival nodes for
                // many years without requiring excessive disk space.
                1_000_000
            }
        }
    }

    /// Infer the [`ConsensusRuleSet`] from the [`Network`] and the
    /// [`BlockHeight`]. The second argument is necessary to take into account
    /// planned hard or soft forks that activate at a given height. The first
    /// argument is necessary because the forks can activate at different
    /// heights based on the network.
    pub fn infer_from(network: Network, block_height: BlockHeight) -> Self {
        match network {
            Network::Main => {
                // Old Neptune blocks (before Xnt hardfork) use Reboot consensus
                // These blocks were created with Triton VM v0
                if block_height < BLOCK_HEIGHT_HARDFORK_XNT_MAIN_NET {
                    ConsensusRuleSet::Reboot
                } else if block_height < BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET {
                    ConsensusRuleSet::Xnt
                } else if block_height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET {
                    ConsensusRuleSet::TimelockExtension
                } else if block_height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET {
                    ConsensusRuleSet::UpgradeVM
                } else if block_height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET {
                    ConsensusRuleSet::UpgradeVMv4
                } else if block_height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V7_MAIN_NET {
                    ConsensusRuleSet::UpgradeVMv5
                } else if block_height < BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET {
                    ConsensusRuleSet::UpgradeVMv7
                } else {
                    ConsensusRuleSet::UpgradeVMv8
                }
            }
            Network::TestnetMock | Network::RegTest | Network::Testnet(_) => {
                ConsensusRuleSet::UpgradeVMv8
            }
        }
    }

    /// Whether a packed chunk may use the extended length indicator.
    ///
    /// Before `UpgradeVMv8` the indicator is a single `u12`, which caps a chunk
    /// at 4095 relative indices. An attacker who controls sender randomness can
    /// grind more indices than that into a single chunk; the old scheme cannot
    /// express the result, so packing it panics on the block-processing path.
    /// v8 widens the indicator to 23 bits, lifting the cap to 92160.
    ///
    /// This is gated rather than applied unconditionally: accepting the extended
    /// form before activation would let an attacker pick the moment of a chain
    /// split, since an upgraded node would accept blocks its peers reject.
    pub(crate) fn allow_big_chunks(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5
            | ConsensusRuleSet::UpgradeVMv7 => false,
            ConsensusRuleSet::UpgradeVMv8 => true,
        }
    }

    /// Whether this era uses the `HardforkAlpha` proof-of-work layout: the
    /// guesser's commitment prefix is the parent block digest rather than the
    /// full PoW MAST authentication paths, and leaf indices are bit-reversed
    /// (the guesser swaps leaves once in preprocessing, the verifier reverses
    /// the picked indices). Every other era commits to the MAST paths and
    /// indexes leaves directly.
    ///
    /// The guesser and the verifier MUST agree on this for every era, so both
    /// consult this one predicate. It used to be four hand-maintained lists of
    /// variants in `pow.rs`; when `UpgradeVMv8` was added, three were updated
    /// and the fourth, a negated `!=` chain the compiler cannot check, was not.
    /// The guesser then preprocessed v8 under the Alpha layout while the
    /// verifier checked it under the direct layout, and every block the node
    /// mined was rejected by its own `has_proof_of_work`. This match is
    /// exhaustive on purpose.
    pub(crate) fn pow_index_bit_reversal(&self) -> bool {
        match self {
            ConsensusRuleSet::HardforkAlpha => true,
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5
            | ConsensusRuleSet::UpgradeVMv7
            | ConsensusRuleSet::UpgradeVMv8 => false,
        }
    }

    pub(crate) fn max_num_inputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5
            | ConsensusRuleSet::UpgradeVMv7
            | ConsensusRuleSet::UpgradeVMv8 => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_outputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5
            | ConsensusRuleSet::UpgradeVMv7
            | ConsensusRuleSet::UpgradeVMv8 => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_announcements(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::Xnt
            | ConsensusRuleSet::TimelockExtension
            | ConsensusRuleSet::UpgradeVM
            | ConsensusRuleSet::UpgradeVMv4
            | ConsensusRuleSet::UpgradeVMv5
            | ConsensusRuleSet::UpgradeVMv7
            | ConsensusRuleSet::UpgradeVMv8 => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }

    /// How many inputs, outputs, and announcements a block reserves for the
    /// transactions that a mempool transaction is merged with before it can be
    /// mined: the composer's coinbase transaction, which typically has two
    /// outputs, and possibly a negative-fee transaction whose author claims
    /// part of the fee.
    const MERGE_HEADROOM: usize = 5;

    /// The largest number of inputs a transaction may have and still be worth
    /// admitting to the mempool.
    ///
    /// A transaction above this limit can never be mined, because the merged
    /// block transaction would exceed [`max_num_inputs`](Self::max_num_inputs).
    /// Relaying or storing it only spends bandwidth and memory.
    pub(crate) fn max_num_inputs_in_mempool(&self) -> usize {
        self.max_num_inputs().saturating_sub(Self::MERGE_HEADROOM)
    }

    /// Mempool counterpart of [`max_num_outputs`](Self::max_num_outputs); see
    /// [`max_num_inputs_in_mempool`](Self::max_num_inputs_in_mempool).
    pub(crate) fn max_num_outputs_in_mempool(&self) -> usize {
        self.max_num_outputs().saturating_sub(Self::MERGE_HEADROOM)
    }

    /// Mempool counterpart of
    /// [`max_num_announcements`](Self::max_num_announcements); see
    /// [`max_num_inputs_in_mempool`](Self::max_num_inputs_in_mempool).
    pub(crate) fn max_num_announcements_in_mempool(&self) -> usize {
        self.max_num_announcements()
            .saturating_sub(Self::MERGE_HEADROOM)
    }

    /// Whether a transaction is small enough to be admitted to the mempool.
    ///
    /// Returns the offending item kind if any count is above its mempool limit.
    pub(crate) fn mempool_size_check(
        &self,
        num_inputs: usize,
        num_outputs: usize,
        num_announcements: usize,
    ) -> Result<(), TransactionTooBig> {
        if num_inputs > self.max_num_inputs_in_mempool() {
            return Err(TransactionTooBig::TooManyInputs);
        }
        if num_outputs > self.max_num_outputs_in_mempool() {
            return Err(TransactionTooBig::TooManyOutputs);
        }
        if num_announcements > self.max_num_announcements_in_mempool() {
            return Err(TransactionTooBig::TooManyAnnouncements);
        }

        Ok(())
    }
}

/// Why a transaction is too big to be admitted to the mempool. See
/// [`ConsensusRuleSet::mempool_size_check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransactionTooBig {
    #[error("transaction has more inputs than can be mined")]
    TooManyInputs,

    #[error("transaction has more outputs than can be mined")]
    TooManyOutputs,

    #[error("transaction has more announcements than can be mined")]
    TooManyAnnouncements,
}

#[cfg(test)]
pub(crate) mod tests {

    use std::sync::Arc;

    use futures::channel::oneshot;
    use itertools::Itertools;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::export::GlobalStateLock;
    use crate::api::export::InputSelectionPolicy;
    use crate::api::export::KeyType;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::OutputFormat;
    use crate::api::export::ReceivingAddress;
    use crate::api::export::StateLock;
    use crate::api::export::Timestamp;
    use crate::api::export::TransactionProofType;
    use crate::api::export::TxCreationArtifacts;
    use crate::api::export::TxProvingCapability;
    use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
    use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
    use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
    use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
    use crate::api::tx_initiation::builder::tx_input_list_builder::SortOrder;
    use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
    use crate::application::config::cli_args;
    use crate::application::loops::channel::NewBlockFound;
    use crate::application::loops::mine_loop::compose_block_helper;
    use crate::application::loops::mine_loop::create_block_transaction_from;
    use crate::application::loops::mine_loop::guess_nonce;
    use crate::application::loops::mine_loop::GuessingConfiguration;
    use crate::application::loops::mine_loop::TxMergeOrigin;
    use crate::application::triton_vm_job_queue::vm_job_queue;
    use crate::protocol::consensus::block::difficulty_control::Difficulty;
    use crate::protocol::consensus::block::validity::block_primitive_witness::BlockPrimitiveWitness;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::next_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state_with_block;
    use crate::tests::tokio_runtime;

    /// The legacy era is exactly `UpgradeVMv7`, the era before the v8 fork. On
    /// main net it ends at the fork height: a composer whose tip is the last v7
    /// block composes the first v8 block, while one block earlier it waits.
    /// Test networks start in the current era and never are in it.
    #[test]
    fn legacy_era_is_exactly_the_era_before_the_v8_fork() {
        for rule_set in ConsensusRuleSet::iter() {
            assert_eq!(
                rule_set == ConsensusRuleSet::UpgradeVMv7,
                rule_set.is_legacy_era(),
                "{rule_set}"
            );
            assert!(
                !(rule_set.is_legacy_era() && rule_set.proofs_are_trusted()),
                "{rule_set}: the legacy era is verified, not trusted"
            );
        }

        let height = |h: u64| BlockHeight::new(BFieldElement::new(h));
        let fork = u64::from(BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET);
        let first_v7 = u64::from(BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V7_MAIN_NET);
        for h in [first_v7, first_v7 + 1, fork - 2, fork - 1] {
            assert!(
                ConsensusRuleSet::infer_from(Network::Main, height(h)).is_legacy_era(),
                "main net height {h} is in the legacy era"
            );
        }
        for h in [first_v7 - 1, fork, fork + 1] {
            assert!(
                !ConsensusRuleSet::infer_from(Network::Main, height(h)).is_legacy_era(),
                "main net height {h} is not in the legacy era"
            );
        }

        for network in [Network::Testnet(0), Network::RegTest, Network::TestnetMock] {
            for h in [0, first_v7, fork - 1, fork] {
                assert!(
                    !ConsensusRuleSet::infer_from(network, height(h)).is_legacy_era(),
                    "{network} height {h} is not in the legacy era"
                );
            }
        }
    }

    /// A transaction is admissible right up to the mempool limit, and rejected
    /// one item beyond it, for each of the three item kinds.
    ///
    /// The mempool limit sits [`ConsensusRuleSet::MERGE_HEADROOM`] below the
    /// block limit, so that a transaction admitted here still fits in a block
    /// after being merged with the composer's coinbase transaction.
    #[test]
    fn mempool_size_check_is_exact_at_the_limit() {
        for rule_set in ConsensusRuleSet::iter() {
            let max_inputs = rule_set.max_num_inputs_in_mempool();
            let max_outputs = rule_set.max_num_outputs_in_mempool();
            let max_announcements = rule_set.max_num_announcements_in_mempool();

            assert!(
                max_inputs < rule_set.max_num_inputs(),
                "{rule_set}: mempool limit must leave headroom below the block limit"
            );

            assert_eq!(
                Ok(()),
                rule_set.mempool_size_check(max_inputs, max_outputs, max_announcements),
                "{rule_set}: a transaction exactly at the limit must be admissible"
            );

            assert_eq!(
                Err(TransactionTooBig::TooManyInputs),
                rule_set.mempool_size_check(max_inputs + 1, 0, 0),
                "{rule_set}: one input too many must be rejected"
            );
            assert_eq!(
                Err(TransactionTooBig::TooManyOutputs),
                rule_set.mempool_size_check(0, max_outputs + 1, 0),
                "{rule_set}: one output too many must be rejected"
            );
            assert_eq!(
                Err(TransactionTooBig::TooManyAnnouncements),
                rule_set.mempool_size_check(0, 0, max_announcements + 1),
                "{rule_set}: one announcement too many must be rejected"
            );
        }
    }

    async fn tx_with_n_outputs(
        mut state: GlobalStateLock,
        num_outputs: usize,
        timestamp: Timestamp,
    ) -> TxCreationArtifacts {
        let mut addresses_and_amts = vec![];
        let same_address = state
            .api()
            .wallet_mut()
            .next_receiving_address(KeyType::Symmetric)
            .await
            .unwrap();
        for _ in 0..num_outputs {
            let value = OutputFormat::AddressAndAmount(
                same_address.clone(),
                NativeCurrencyAmount::from_nau(1),
            );
            addresses_and_amts.push(value);
        }

        let initiator = state.api().tx_initiator();
        let tx_outputs = initiator.generate_tx_outputs(addresses_and_amts).await;
        drop(initiator);

        let fee = NativeCurrencyAmount::from_nau(14);
        let tx_inputs = TxInputListBuilder::new()
            .spendable_inputs(
                state
                    .lock_guard()
                    .await
                    .wallet_spendable_inputs(timestamp, 0)
                    .await
                    .into_iter()
                    .collect(),
            )
            .policy(InputSelectionPolicy::ByUtxoSize(SortOrder::Ascending))
            .spend_amount(tx_outputs.total_native_coins() + fee)
            .build();
        let tx_inputs = tx_inputs.into_iter().collect_vec();

        let tx_details = TransactionDetailsBuilder::new()
            .inputs(tx_inputs.into_iter().into())
            .outputs(tx_outputs)
            .fee(fee)
            .timestamp(timestamp)
            .build(&mut StateLock::write_guard(&mut state).await)
            .await
            .unwrap();

        // use cli options for building proof, but override proof-type
        let options = TritonVmProofJobOptionsBuilder::new()
            .proof_type(TransactionProofType::SingleProof)
            .proving_capability(TxProvingCapability::SingleProof)
            .build();

        // generate proof
        let block_height = state.lock_guard().await.chain.light_state().header().height;
        let network = state.cli().network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .transaction_details(&tx_details)
            .job_queue(vm_job_queue())
            .proof_job_options(options)
            .build()
            .await
            .unwrap();

        let transaction = TransactionBuilder::new()
            .transaction_details(&tx_details)
            .transaction_proof(proof)
            .build()
            .unwrap();

        TxCreationArtifacts {
            transaction: Arc::new(transaction),
            details: Arc::new(tx_details),
        }
    }

    async fn block_with_n_outputs(
        me: GlobalStateLock,
        num_outputs: usize,
        timestamp: Timestamp,
    ) -> Block {
        let current_tip = me.lock_guard().await.chain.archival_state().get_tip().await;
        let tx_many_outputs = tx_with_n_outputs(me.clone(), num_outputs, timestamp).await;
        let (block_tx, _) = create_block_transaction_from(
            &current_tip,
            me,
            timestamp,
            TritonVmProofJobOptions::default(),
            TxMergeOrigin::ExplicitList(vec![tx_many_outputs.transaction.into()]),
        )
        .await
        .unwrap();
        Block::compose(
            &current_tip,
            block_tx,
            timestamp,
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap()
    }

    async fn mine_to_own_wallet(
        me: GlobalStateLock,
        timestamp: Timestamp,
    ) -> (Block, Vec<ExpectedUtxo>) {
        let current_tip = me.lock_guard().await.chain.archival_state().get_tip().await;
        compose_block_helper(
            current_tip,
            me,
            timestamp,
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap()
    }

    // v8 block-production readiness: build a chain at the v8 fork height and mine
    // the first two post-fork blocks under UpgradeVMv8, to confirm v8 nodes can
    // actually compose+prove+validate blocks across the fork.
    // (No `#[traced_test]`: keeps the output to the readable step logs below.)
    //
    // NOTE: this must always target the CURRENT era's fork height. A binary that
    // links triton-vm v8 can only produce v8-era blocks: a v7-era claim names the
    // hardcoded v7 program digest, which no v8 bytecode reproduces. That is also
    // the operational constraint on the rollout -- a v8 binary cannot extend the
    // v7 chain, so the activation height is the cut-over point, not a date after
    // which the binary may be shipped.
    #[test]
    fn new_blocks_at_upgrade_vm_height() {
        // We want to use the following block primitive witness generator (which
        // uses async code on the inside) in combination with async code. We
        // make this test function async because we would be entering into the
        // same runtime twice. Therefore, we generate the block primitive
        // witness once, in this synchronous wrapper, and continue
        // asynchronously with the helper function.

        // Build on top of a chain at the UpgradeVMv8 fork height. Producing new
        // blocks only works under the current (v8) rule set: pre-v8 history is
        // verifiable via hardcoded per-era program digests but cannot be
        // *extended*, since those claims reference digests that no v8 bytecode
        // reproduces.
        use crate::protocol::consensus::block::difficulty_control::Difficulty;
        let init_block_heigth = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET;
        // MINIMUM difficulty so PoW guessing for the mined blocks is instant; the
        // STARK proving cost is unchanged (independent of difficulty).
        let bpw = BlockPrimitiveWitness::deterministic_with_block_height_and_difficulty(
            init_block_heigth,
            Difficulty::MINIMUM,
        );

        tokio_runtime().block_on(new_blocks_at_upgrade_vm_height_async(bpw));
    }

    async fn new_blocks_at_upgrade_vm_height_async(block_primitive_witness: BlockPrimitiveWitness) {
        // 1. generate state synced to height
        let mut rng = StdRng::seed_from_u64(55512345);
        let network = Network::Main;
        let bob_wallet = WalletEntropy::new_pseudorandom(rng.random());
        let cli = cli_args::Args {
            network,
            compose: true,
            guess: true,
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            ..Default::default()
        };

        let (fake_genesis, block_10_000) =
            Block::fake_block_pair_genesis_and_child_from_witness(block_primitive_witness).await;
        let mut now = block_10_000.header().timestamp;
        assert!(block_10_000.is_valid(&fake_genesis, now, network).await);

        let mut bob = mock_genesis_global_state_with_block(0, bob_wallet, cli, fake_genesis).await;
        bob.set_new_tip(block_10_000.clone()).await.unwrap();

        let observed_block_height = bob.lock_guard().await.chain.light_state().header().height;
        assert_eq!(
            BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET,
            observed_block_height,
        );

        // 2. mine the first 2 post-fork blocks under UpgradeVMv8, confirming each
        //    is BOTH consensus-valid AND proof-of-work mineable.
        use crate::protocol::consensus::block::pow::Pow;
        use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
        eprintln!(
            "\n=== UpgradeVMv8 mining readiness: chain synced to fork height {observed_block_height} ==="
        );
        let blocks_to_mine = 2;
        let mut predecessor = block_10_000;
        for i in 1..=blocks_to_mine {
            now += Timestamp::hours(1);
            let next_height = predecessor.header().height.next();
            eprintln!(
                "\n[mine {i}/{blocks_to_mine}] height {next_height}: composing + proving (coinbase SingleProof + block proof) ..."
            );
            let (next_block, expected_composer_utxos) = mine_to_own_wallet(bob.clone(), now).await;

            // a) consensus validity: every block/tx proof verifies under UpgradeVMv8.
            assert!(
                next_block.is_valid(&predecessor, now, network).await,
                "height {next_height}: block must be consensus-valid under UpgradeVMv8",
            );
            eprintln!("[mine {i}/{blocks_to_mine}] height {next_height}: consensus-valid [OK] (all proofs verify)");

            // b) proof-of-work: grind a winning nonce at the block's own difficulty
            //    and verify it — i.e. prove the block is actually *mineable*. Done
            //    on a clone so the tip-chain stays byte-identical to a real node's.
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, next_height);
            let target = next_block.header().difficulty.target();
            let mut pow_block = next_block.clone();
            let mast_auth_paths = pow_block.pow_mast_paths();
            let guesser_buffer = pow_block.guess_preprocess(None, None, consensus_rule_set);
            let index_picker_preimage = guesser_buffer.index_picker_preimage(&mast_auth_paths);
            let mut guesses = 0u64;
            let valid_pow = loop {
                guesses += 1;
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
            pow_block.set_header_pow(valid_pow);
            assert!(
                pow_block.pow_verify(target, consensus_rule_set),
                "height {next_height}: solved PoW must verify",
            );
            eprintln!(
                "[mine {i}/{blocks_to_mine}] height {next_height}: PoW solved in {guesses} guesses + verified [MINEABLE]"
            );

            // c) the GUESSER fee for this block must be a positive, UNLOCKED
            //    (immediately-spendable) reward. The guesser fee UTXOs are derived
            //    straight off the block, so they can be checked here. (The COMPOSER
            //    reward lands in the wallet and is verified after the loop via
            //    spendable_inputs, which only counts non-time-locked UTXOs.) This
            //    is the period-0 coinbase fix in action: under v4 a time-locked
            //    reward would have tripped the coinbase rule.
            let guesser_utxos = next_block.kernel.guesser_fee_utxos().unwrap();
            let guesser_total = guesser_utxos
                .iter()
                .map(|u| u.get_native_currency_amount())
                .sum::<NativeCurrencyAmount>();
            assert!(
                !guesser_utxos.is_empty() && guesser_total.is_positive(),
                "height {next_height}: guesser must earn a positive fee",
            );
            assert!(
                guesser_utxos.iter().all(|u| u.release_date().is_none()),
                "height {next_height}: guesser fee UTXOs must be UNLOCKED (liquid)",
            );
            eprintln!(
                "[mine {i}/{blocks_to_mine}] height {next_height}: guesser earns {:.6} coins ({} UTXO) — UNLOCKED [OK]",
                guesser_total.to_coins_f64_lossy(),
                guesser_utxos.len(),
            );

            bob.set_new_self_composed_tip(next_block.clone(), expected_composer_utxos)
                .await
                .unwrap();
            predecessor = next_block;
        }
        eprintln!(
            "\n=== {blocks_to_mine} post-fork blocks: composed + proven + validated + mined [OK] ===\n"
        );

        let hopefully_plus_5 = bob.lock_guard().await.chain.light_state().header().height;
        assert_eq!(
            BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET + 2,
            hopefully_plus_5
        );
        // The COMPOSER reward landed in the wallet and must be UNLOCKED: it shows
        // up as confirmed, spendable balance. `spendable_inputs` only counts
        // immediately-spendable (non-time-locked) UTXOs, so a positive count here
        // proves the composer earned liquid coins under v8.
        let composer_available = bob.api().wallet().balances(now).await.confirmed_available;
        let spendable_inputs = bob.api().wallet().spendable_inputs(now, 0).await;
        assert!(
            composer_available.is_positive(),
            "composer must earn spendable (unlocked) balance",
        );
        assert_eq!(
            blocks_to_mine,
            spendable_inputs.len(),
            "Bob must have {blocks_to_mine} spendable inputs after mining {blocks_to_mine} blocks"
        );
        eprintln!(
            "composer earned {:.6} coins across {} UNLOCKED spendable UTXO(s) [OK]",
            composer_available.to_coins_f64_lossy(),
            spendable_inputs.len(),
        );

        // 3. create a block with many outputs so some owned UTXOs get non-empty
        //    chunk dictionaries — checks membership-proof/removal-record updates
        //    across the fork. Kept to 1 block to keep this run focused.
        let num_blocks_with_many_outputs = 1;
        for j in 1..=num_blocks_with_many_outputs {
            now += Timestamp::hours(1);
            let next_height = predecessor.header().height.next();
            eprintln!("[outputs {j}/{num_blocks_with_many_outputs}] height {next_height}: composing block with 24 outputs ...");
            let next_block = block_with_n_outputs(bob.clone(), 24, now).await;
            assert!(next_block.is_valid(&predecessor, now, network).await);
            bob.set_new_tip(next_block.clone()).await.unwrap();
            predecessor = next_block;
            eprintln!("[outputs {j}/{num_blocks_with_many_outputs}] height {next_height}: valid + applied [OK]");
        }
        eprintln!("\n=== TEST PASSED: v8 blocks are composable, provable, valid, and mineable ===\n");
    }

    #[test]
    fn timelock_extension_inactive_on_main_below_activation_height() {
        let below = BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET
            .previous()
            .expect("activation height should not be genesis");
        let rule_set = ConsensusRuleSet::infer_from(Network::Main, below);
        assert_ne!(
            rule_set,
            ConsensusRuleSet::TimelockExtension,
            "TimelockExtension must NOT activate one block before its mainnet activation height"
        );
    }

    #[test]
    fn timelock_extension_active_on_main_at_activation_height() {
        let activation = BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET;
        let rule_set = ConsensusRuleSet::infer_from(Network::Main, activation);
        assert_eq!(
            rule_set,
            ConsensusRuleSet::TimelockExtension,
            "TimelockExtension must activate at exactly its mainnet activation height"
        );
    }

    #[test]
    fn timelock_extension_never_activates_off_mainnet() {
        // The fork is mainnet-only. Off-mainnet networks (Testnet, RegTest,
        // TestnetMock) run the newest ruleset (UpgradeVMv8) from genesis, so they
        // never pass through the TimelockExtension ruleset regardless of height.
        let high = BLOCK_HEIGHT_HARDFORK_TIMELOCK_EXTENSION_MAIN_NET;
        for nw in [
            Network::Testnet(0),
            Network::Testnet(255),
            Network::RegTest,
            Network::TestnetMock,
        ] {
            assert_eq!(
                ConsensusRuleSet::infer_from(nw, high),
                ConsensusRuleSet::UpgradeVMv8,
                "{nw:?} must never activate TimelockExtension"
            );
        }
    }

    #[test]
    fn upgrade_vm_active_on_main_at_activation_height() {
        let activation = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET;
        let rule_set = ConsensusRuleSet::infer_from(Network::Main, activation);
        assert_eq!(
            rule_set,
            ConsensusRuleSet::UpgradeVM,
            "UpgradeVM must activate at exactly its mainnet activation height"
        );
    }

    #[test]
    fn upgrade_vm_v4_active_on_main_at_activation_height() {
        // At exactly the v4 activation height, mainnet switches to UpgradeVMv4;
        // one block below it, mainnet is still on UpgradeVM (v3 verifier).
        let activation = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET;
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation),
            ConsensusRuleSet::UpgradeVMv4,
            "UpgradeVMv4 must activate at exactly its mainnet activation height"
        );
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation.previous().unwrap()),
            ConsensusRuleSet::UpgradeVM,
            "the block below the v4 height must still be UpgradeVM (v3 verifier)"
        );
    }

    #[test]
    fn upgrade_vm_v5_active_on_main_at_activation_height() {
        // At exactly the v5 activation height, mainnet switches to UpgradeVMv5;
        // one block below it, mainnet is still on UpgradeVMv4 (v4 verifier).
        let activation = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET;
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation),
            ConsensusRuleSet::UpgradeVMv5,
            "UpgradeVMv5 must activate at exactly its mainnet activation height"
        );
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation.previous().unwrap()),
            ConsensusRuleSet::UpgradeVMv4,
            "the block below the v5 height must still be UpgradeVMv4 (v4 verifier)"
        );
    }

    #[test]
    fn upgrade_vm_v8_active_on_main_at_activation_height() {
        // At exactly the v8 activation height, mainnet switches to UpgradeVMv8;
        // one block below it, mainnet is still on UpgradeVMv7 (legacy era).
        let activation = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET;
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation),
            ConsensusRuleSet::UpgradeVMv8,
            "UpgradeVMv8 must activate at exactly its mainnet activation height"
        );
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation.previous().unwrap()),
            ConsensusRuleSet::UpgradeVMv7,
            "the block below the v8 height must still be UpgradeVMv7"
        );
    }

    #[test]
    fn upgrade_vm_v7_active_on_main_at_activation_height() {
        // At exactly the v7 activation height, mainnet switches to UpgradeVMv7;
        // one block below it, mainnet is still on UpgradeVMv5 (v5 verifier).
        let activation = BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V7_MAIN_NET;
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation),
            ConsensusRuleSet::UpgradeVMv7,
            "UpgradeVMv7 must activate at exactly its mainnet activation height"
        );
        assert_eq!(
            ConsensusRuleSet::infer_from(Network::Main, activation.previous().unwrap()),
            ConsensusRuleSet::UpgradeVMv5,
            "the block below the v7 height must still be UpgradeVMv5 (v5 verifier)"
        );
    }


    #[test]
    fn current_v8_program_hashes_are_stable() {
        // Drift-detection for the CURRENT (UpgradeVMv7 / triton-vm v7) program
        // hashes. If any of these change accidentally, the activation height
        // would refer to a different program-set and the fork would become
        // incompatible.
        //
        // NOTE: the v7 -> v8 change (triton-vm v8: sound Hash/Program Table AIR,
        // randomized quotient table) re-hashed only the proof programs that embed
        // the STARK verifier. `TimeLockV2` and `CollectTypeScriptsV2` are
        // byte-identical to v5 and v7 (their digests did NOT change), so coins
        // from every prior era stay spendable with no remap; only `SingleProofV2`
        // (and `SingleProof` and `BlockProgram`) moved v7 -> v8.
        use crate::protocol::consensus::transaction::validity::collect_type_scripts_v2::CollectTypeScriptsV2;
        use crate::protocol::consensus::transaction::validity::single_proof_v2::SingleProofV2;
        use crate::protocol::consensus::type_scripts::time_lock_v2::TimeLockV2;
        use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

        // Unchanged across v5 -> v7 -> v8.
        let timelock_v2 = TimeLockV2.hash().to_hex();
        assert_eq!(
            timelock_v2,
            "8b6d23e675c97cb8e1d36a5e926f19449d37673636c64c0769b7778aded85ff29056832e366b580b",
            "TimeLockV2 program hash drifted"
        );

        let cts_v2 = CollectTypeScriptsV2.hash().to_hex();
        assert_eq!(
            cts_v2,
            "1d33643dc5086e915e44d720af4a1efa195254aee6497166f5055a7bcb0d8313ce70f77fe0632c4e",
            "CollectTypeScriptsV2 program hash drifted"
        );

        // Re-hashed v5 (e66985a8…) -> v7 (5c75cc2d…) -> v8.
        let sp_v2 = SingleProofV2.hash().to_hex();
        assert_eq!(
            sp_v2,
            "307f41ff80f6f7af27a6382ae91cf0d54f9464c0cda525652c1e5285c0ab0044374a488c3d7dc75e",
            "SingleProofV2 program hash drifted"
        );
    }
}
