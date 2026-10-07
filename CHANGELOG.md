# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Breaking Changes

- **Hardfork at block height 95000 (`UpgradeVMv8`)**: upgrade to Triton VM v8. v8 is a security release: it makes the Hash Table and Program Table AIR sound, closing the forgeable program-attestation findings NPT-1 and NPT-20, and randomizes the quotient table, giving proofs an explicit zero-knowledge property. The proof format version moves from 5 to 8, so the proof programs that embed the STARK verifier (`SingleProof`, `SingleProofV2`, `BlockProgram`) are re-hashed. Blocks before the fork, including the entire `UpgradeVMv7` era, are checkpointed (trusted, not re-verified) via the pinned v7 digests (`BlockProgram` `f87bda68…`, `SingleProofV2` `5c75cc2d…`). Leaf type scripts are unchanged, so existing coins remain spendable with no remap.
- **Wider removal-record chunk encoding from block 95000**: the packed-chunk length indicator grows from 12 to 23 bits, lifting the per-chunk cap from 4095 to 92160 relative indices. Before activation a sender could grind more indices into one chunk than the old encoding can express, which panicked on the block-processing path.
- **Upgrade timing**: this release links Triton VM v8/v9 only. It cannot produce `UpgradeVMv7` proofs and does not re-verify them, so before height 95000 it cannot compose blocks or create transactions, accepts v7-era blocks on proof-of-work and structural checks alone, and treats v7 transaction proofs relayed by v0.2.x peers as invalid. Composers, guessers, wallets and exchanges should switch to v0.3.0 close to block 95000, and must switch before it: v0.2.x cannot validate blocks after the fork.
- Updated package version from 0.2.5 to 0.3.0 (workspace-wide).

### Added

- **`UpgradeVMv8` consensus rule set**: activation height `BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V8_MAIN_NET = 95000`, `TritonProofVersion::V8` with claim version 8, live v8 program digests (`BlockProgram` `df05b05b…`, `SingleProofV2` `307f41ff…`). `TritonProofVersion::V7` is frozen at claim version 5.
- **Triton VM v9 prover** (tasm-lib v9, twenty-first v3): same AIR, verifier and proof version as v8, so no further fork and no digest change; proofs cross-verify between v8 and v9 in both directions. With 32 prover threads, composing a block drops from about 9 to about 2.5 minutes and peak prover memory from about 158 to about 107 GiB.
- **jemalloc** as the global allocator of the `xnt-core` and `triton-vm-prover` binaries on Linux and macOS (about 10% faster mid-size proofs). Libraries, including `xnt-sdk`, keep their host's allocator.
- Ported from neptune-core v0.16: batched and composable mutator-set updates, archival-state recovery of an inconsistent state on startup, the proof upgrader moving on to the next transaction when one fails, and devnet premine funding on non-mainnet networks.

### Fixed

- Security fixes ported from neptune-core v0.16, v0.17.0 and v0.17.1: reject removal records with duplicated chunk indices (NPT-25), checked arithmetic when unpacking removal records, reject absolute indices whose chunk index overflows `u64`, length guards on proof-collection operands and halt proofs, reject ProofCollection-backed transactions with the merge bit set, check proof-of-work before recursive STARK verification of a received block, prefer the first-seen block at equal height in the fork-choice rule (NPT-3), bound decoded message lengths and the job queue, restrict the RPC cookie file to its owner on Unix, and no longer panic on mispaired authentication structures, negative cumulative-PoW differences, unsorted tree heights or monitored UTXOs without membership proofs.
- Mempool: reject transactions too big to ever be mined, prune by timestamp before applying a new block, deduplicate update jobs, and keep upgrade priority when receiving a merged transaction.
- Mutator set: fixed an off-by-one in the activity split and the archival mutator set returns false for future indices. Database `persist` is cancel-safe, the sync-mode deadline refreshes on canonical progress, the job queue returns the job with the highest upgrade incentive, and gobbler rewards are always registered.
- Peer standing: negative standing now decays (halving every 48 hours) and is persisted; a peer missing from the standing map is sanctioned more strongly.
- The PoW guesser and verifier agree on the leaf layout for `UpgradeVMv8` (previously every block mined under v8 failed the node's own PoW check).
- Release builds for macOS x86-64 and Windows: the dCTIDH dependency now builds there (portable C on macOS x86-64, clang-cl on Windows), producing keys identical to the x86-64 assembly.

### Changed

- rand 0.10, get-size2 0.9, rand_distr 0.6.

## [0.2.5] - 2026-06-19

### Breaking Changes

- **Hardfork at block height 59200 (`UpgradeVMv7`)**: upgrade to Triton VM v7.0.0 / tasm-lib with u128 operand range-checks. The proof programs that embed the affected snippets (`SingleProof`, `SingleProofV2`, `BlockProgram`) are re-hashed; blocks before the fork — including the entire `UpgradeVMv5` era — are checkpointed (trusted, not re-verified) because their proofs were produced under triton-vm v5 and do not verify under the v7 verifier (confirmed against a real mainnet v5 block).
- Updated package version from 0.2.4 to 0.2.5 (workspace-wide).

### Added

- **`UpgradeVMv7` consensus rule set**: activation height `BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V7_MAIN_NET = 59200`, with `TritonProofVersion::V7` whose claim version tracks the live triton-vm `CURRENT_VERSION` (still 5), and pinned pre-v7 program digests (`BlockProgram` `e14d426b…`, `SingleProofV2` `e66985a8…`).
- **Pre-v7 proof checkpointing**: the `UpgradeVMv5` era is now trusted without re-verification (its v5 proofs cannot be checked by the v7 verifier).
- Real `UpgradeVMv5` mainnet block fixture (`block_upgrade_vm_v5_58000.json`) demonstrating the checkpoint boundary.

### Changed

- Proof production, transaction verification, and proof-of-work now select the `UpgradeVMv7` programs at and above the fork height.
- `TritonProofVersion::V5` claim version is frozen at `5` (no longer tracking the live constant, which now belongs to V7).

## [0.2.4] - 2026-06-14

### Breaking Changes

- **Hardfork at block height 57650 (`UpgradeVMv5`)**: upgrade to Triton VM v5.0.0. The proof programs that embed the STARK verifier (`SingleProofV2`, `BlockProgram`) are re-hashed by the new ISA; blocks before the fork — including the entire `UpgradeVMv4` era — are checkpointed (trusted, not re-verified) because their proof format is incompatible with the v5 verifier.
- Updated package version from 0.2.3 to 0.2.4 (workspace-wide).

### Added

- **`UpgradeVMv5` consensus rule set**: activation height `BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V5_MAIN_NET = 57650`, with `TritonProofVersion::V5` whose claim version tracks the live triton-vm `CURRENT_VERSION`, and pinned pre-v5 program digests (`BlockProgram` `1a4df646…`, `SingleProofV2` `15312e1a…`).
- **Pre-v5 proof checkpointing**: the `UpgradeVMv4` era is now trusted without re-verification (its v4 proofs cannot be checked by the v5 verifier).

### Changed

- Proof production, transaction verification, and proof-of-work now select the `UpgradeVMv5` programs at and above the fork height.

### Notes

- Verified end-to-end: blocks 57651/57652 compose + prove + validate + mine under `UpgradeVMv5`, with composer and guesser earning unlocked, spendable rewards.

## [0.2.3] - 2026-06-11

### Breaking Changes

- **Hardfork at block height 56700 (`UpgradeVMv4`)**: upgrade to Triton VM v4.0.0 (proof format version 2). Every consensus program is re-hashed; blocks before the fork are checkpointed (trusted, not re-verified) because their proof format is incompatible with the v4 verifier.
- **Hardfork at block height 55800 (`UpgradeVM`)**: Triton VM v3 with a legacy native-currency hash remap.
- Updated package version from 0.2.0 to 0.2.3 (workspace-wide).

### Added

#### Consensus & Blockchain
- **`UpgradeVM` and `UpgradeVMv4` consensus rule sets**: activation heights `BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_MAIN_NET = 55800` and `BLOCK_HEIGHT_HARDFORK_UPGRADE_VM_V4_MAIN_NET = 56700`, with per-era proof/claim versions and pinned program digests.
- **Backward-compatible coin remap**: legacy and v3-era `NativeCurrency`, `TimeLock`, and `TimeLockV2` program hashes fold onto the current programs, so pre-fork coins remain recognized and spendable across the fork. Coverage spans balance/availability, time-lock release, the wallet/SDK (available, spendable, spent), and real STARK proof generation + verification.
- **Pre-v4 proof checkpointing**: historical blocks are trusted without re-verification.
- **Era-correct guesser-fee derivation**: the re-derived guesser-fee UTXO uses the `NativeCurrency` hash matching the block's era (legacy / v3 / current).

### Changed

- Bumped the `tasm-lib` dependency to the released `v4.0.0` tag (Triton VM 4.0.0) and removed the vendored submodule.

### Fixed

- **Block production under v4**: the composer now honors `MINING_REWARD_TIME_LOCK_PERIOD == 0` and produces a fully-liquid coinbase, so mining works under `UpgradeVMv4`. A v4 program-hash collision otherwise caused a time-locked coinbase to trip the disabled coinbase time-lock rule (`COINBASE_TIMELOCK_INSUFFICIENT`, error id 1000033).

## [0.2.0] - 2026-01-21

### Breaking Changes

- **Hardfork at block height 15256**: Introduced consensus rule separation between old Neptune blocks (Triton VM v0) and new Xnt blocks (Triton VM v1)
- Updated package version from 0.1.0 to 0.2.0

### Added

#### Consensus & Blockchain
- **Consensus rule sets** (`ConsensusRuleSet`): Support for `Reboot`, `HardforkAlpha`, and `Xnt` consensus rules
- **Hardfork activation**: `BLOCK_HEIGHT_HARDFORK_XNT_MAIN_NET` constant set to block 15256
- Automatic consensus rule inference based on network and block height
- Support for validating blocks created with different Triton VM versions

#### UTXO Indexer (#23)
- **UTXO indexer for non-custodial wallets**: Full implementation for efficient UTXO lookup
  - Indexed storage for UTXOs, commitments, and removal records
  - Bucket-based architecture (1000 blocks per bucket)
  - Persistent database backed by LevelDB
  - CLI flag `--utxo-indexer` to enable feature
  - Sync mechanism for indexing historical blocks
  - Support for orphaned block tracking during reorgs

#### Payment System (#17)
- **Payment ID and Subaddress support**: Enhanced privacy and payment tracking
  - `PaymentId` type for unique payment identification
  - Subaddress generation from generation addresses
  - `AddressableKey` trait for unified address handling
  - Wallet database migrations (v3→v4) for payment ID storage
  - Payment ID metadata in UTXO notifications

#### Node.js SDK (#22)
- **NAPI bindings for Node.js**: Complete JavaScript/TypeScript integration
  - Address generation and validation
  - Wallet operations (seed phrases, key derivation)
  - Transaction creation and submission
  - UTXO syncing and balance queries
  - JSON-RPC client wrapper
  - TypeScript type definitions
  - Example code in `examples/xnt-sdk-test.ts`

#### Developer Tools
- **C FFI bindings**: Foreign Function Interface for C/C++ integration
  - Address, wallet, and transaction operations
  - Memory-safe helper functions
  - Auto-generated header file (`include/xnt_ffi.h`)
- **Guesser UTXO tracking** (#16): UTXO management for miners/guessers

### Changed

#### Branding
- **Complete XNT rebranding**: Migrated from Neptune/Zcash to XNT
  - Binary renamed: `neptune-core` → `xnt-core`
  - Updated all documentation references
  - Removed Zcash references

#### Wallet & Addresses
- Enhanced `GenerationAddress` with subaddress derivation
- Updated `ReceivingAddress` with payment ID support
- Improved address validation and type checking
- Added `payment_id` field to `IncomingUtxo` and related structures
- Database schema migrations: v1→v2→v3→v4

#### Transaction Handling
- Mempool re-query after nop proof generation (#19)
- Enhanced transaction output creation with payment metadata
- Improved UTXO notification system

#### API & Documentation
- **Exchange integration API** (#12): Comprehensive RPC endpoints for exchanges
- **Secure wallet RPC** (#13): Enhanced security for wallet operations
- Reorganized RPC documentation by category:
  - Archival, Chain, Mempool, Mining, Node, Wallet
- Complete exchange integration guides with examples
- Updated API documentation with request/response samples

#### Configuration
- Added `--utxo-indexer` CLI flag
- Updated data directory structure for indexer databases
- Improved CLI argument handling

### Fixed

- **Transaction submission documentation** (#24): Corrected API examples
- **Rust tuple type documentation** (#15): Fixed type definitions
- **Missing RPC endpoints** (#14): Added missing methods to integration guide
- Corrected confirmation counts in documentation
- Fixed `unlocked_utxo` visibility (made public)
- Improved chain height display formatting
- Updated HTTPS references in documentation
- Fixed exchange integration examples with correct block explorer links

### Removed

- Removed `rate_limit_until_height` default restriction
- Removed testnet-specific hardfork constant (consolidated to single constant)

---

## [0.1.0] - 2024-12-XX

### Initial Release

- Core Neptune blockchain implementation
- Basic wallet functionality
- RPC server and JSON-RPC API
- Mining and transaction support
- P2P networking
- Initial documentation

[0.2.0]: https://github.com/neptuneprivacy/xnt-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/neptuneprivacy/xnt-core/releases/tag/v0.1.0
