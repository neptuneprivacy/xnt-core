# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
