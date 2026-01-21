# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
