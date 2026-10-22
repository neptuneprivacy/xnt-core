# xnt — Neptune Privacy Core SDK  (nodejs and rust)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Coverage Status](https://img.shields.io/badge/coverage-unknown-lightgrey)

**xnt-core** is the reference implementation for **xnt (Neptune Privacy)** — a privacy-focused decentralized digital cash protocol derived from Neptune Cash.

##

The XNT SDK provides the core tools needed to build applications that interact with the network without custody.

This includes offline transaction signing, so private keys never leave the client or trusted environment.

Why this matters:
Most privacy apps today still depend on custodial backends, trusted relayers, or opaque infrastructure.

The XNT SDK enables applications where users remain in full control, end-to-end.

The SDK is open source and intended as foundational infrastructure for:
- wallet developers
- application builders
- tooling teams
- anyone building on private execution

Builders, the next phase is in your hands.

## Address Types

The SDK supports two address families, both derived from the same wallet seed:

**Generation (long address)**
- **Rust**: `WalletEntropy::derive_spending_key(index)`
- **Node.js (NAPI)**: `wallet.deriveKey(index)`
- **C FFI**: `xnt_wallet_derive_key(wallet, index)`

**dCTIDH-512 (short address)**
- **Rust**: `WalletEntropy::derive_dctidh_spending_key(index)`
- **Node.js (NAPI)**: `wallet.derivedCTIDHKey(index)`
- **C FFI**: `xnt_wallet_derive_dctidh_key(wallet, index)`

Both support subaddresses with payment IDs for deposit tracking.

## Spending Secrets

Besides the seed, two values exported by the SDK let anyone who has them spend
funds, so keep them on the device or in the process that holds the seed: do not
log them, send them to a server or store them unencrypted.

- **Receiver preimage of a dCTIDH key** (`SpendingKey::receiver_preimage`,
  `key.receiverPreimageHex()`, `xnt_spending_key_receiver_preimage[_hex]`). It
  is used for commitments and membership proofs, and for dCTIDH keys it is also
  the unlock preimage of the key's lock script. The helpers that take it as a
  loose argument (`compute_commitment`, `compute_absolute_index_set_hash`,
  `get_membership_proofs` and their NAPI/FFI counterparts) use it locally and do
  not send it to the node.
- **The witness of a built transaction** (`BuiltTransaction::witness_bytes` /
  `to_bytes`, `witnessBytes()` / `toBytes()`, `xnt_built_transaction_witness` /
  `_serialize`). It holds the unlock data of every input.

## Legacy-Format dCTIDH Funds (v0.3)

dCTIDH addresses created before v0.3 use a legacy lock format that v0.3 no
longer accepts as a recipient. Funds received at such addresses before the
upgrade stay with the seed and are found with the legacy key
(`derive_legacy_dctidh_spending_key`, `wallet.deriveLegacydCTIDHKey(i)`,
`xnt_wallet_derive_legacy_dctidh_key`). Such UTXOs are sweep-only: move them to
a current-format address and never count them towards the available balance.
They are recognized only if confirmed below the legacy cutoff height
(`legacy_dctidh_cutoff`, `xntLegacyDctidhCutoff`, `xnt_legacy_dctidh_cutoff`):
the `UpgradeVMv8` activation height on main net, no cutoff on other networks.

`is_legacy` / `isLegacy` / `xnt_spending_key_is_legacy` flag legacy keys and
the UTXOs they decrypt. `build_migration` / `xntBuildMigration` /
`xnt_build_migration` build the transactions that move them to a current-format
address in one call (examples `migrate.rs`, `migrate.ts`, and
`migrate-legacy.ts` with `migrateLegacyFunds`; each a dry run unless given
`dry_run=no`). The plan reports the legacy key index and payment id of every
input, for reconciling the payment ids it merges. See the migration section of
the integration guide for finding and sweeping them.

## Transaction Limits

`TransactionBuilder::build` refuses more than 200 inputs (nodes relay
ProofCollection-backed transactions only up to that) and a fee below 0.0005
coins per input, including a zero fee, unless `set_allow_low_fee(true)` /
`setAllowLowFee(true)` / `xnt_tx_builder_set_allow_low_fee` is set. It also
refuses recipients that cannot receive a UTXO notification. A successful
`submit()` means the node queued the transaction, not that it is in the mempool
or mined; confirm by looking it up.

## Proving Around the Hard Fork at Block 97,000

`BuiltTransaction::prove` / `prove()` / `xnt_built_transaction_prove` prove for
the consensus rule set of the block after the tip whose mutator set the
transaction was built on, whose height `get_mutator_set` records: before main-net
block 97,000 a v7 proof collection, which must pay at least 0.017 coins and have
at most 10 inputs (11 without time locks), and none within 10 blocks of the
fork. For a mutator set without a height, as one restored from bytes, set it
with `MutatorSet::with_tip_height` / `withTipHeight` /
`xnt_mutator_set_set_tip_height`, or prove with `prove_for_tip(tip_height)` /
`proveForTip` / `xnt_built_transaction_prove_for_tip`. See the integration
guide for details.

## C FFI Notes

- The header `include/xnt_ffi.h` is generated by `build.rs` (cbindgen) on every
  build with the `ffi` feature.
- Every exported function catches Rust panics: the function then returns
  `XNT_ERROR_CODE_INTERNAL_ERROR` or its failure value and
  `xnt_get_last_error()` starts with `internal error`. This needs a library
  built with `panic = "unwind"`, the default for release builds.
- Network arguments are a `uint32_t` holding an `XntNetwork` value.
- Amounts are in nau. Functions ending in `_le` take or return them as 16 bytes,
  little-endian two's complement, for callers without a 128-bit integer; the
  others use `__int128` (GCC/Clang on 64-bit targets).
- Indexer scans skip malformed entries instead of failing the whole range;
  `xnt_sync_fetch_utxos_with_skipped` reports how many. Ranges of more than
  10,000 blocks, the indexer's limit per request, are fetched in parts.

We’ll continue improving the SDK and releasing updates as the ecosystem grows.
If you’re building privacy preserving applications and care about non-custodial design, this is for you!

> Nodejs integration source code: https://github.com/neptuneprivacy/xnt-core/tree/main/xnt-sdk

> Examples: https://github.com/neptuneprivacy/xnt-core/blob/main/xnt-sdk/examples/xnt-sdk-test.ts

> Document: https://github.com/neptuneprivacy/xnt-core/blob/main/docs/src/xnt-sdk/exchange-integration.md
