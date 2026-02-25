# sovpool Architecture

## Overview

sovpool is a Rust workspace for Bitcoin CTV (BIP-119) payment pools — shared UTXOs with covenant-enforced unilateral exit paths.

## Crate Dependency Graph

```
sovpool_cli → sovpool_core, sovpool_assess, sovpool_rpc, sovpool_wallet
sovpool_wallet → sovpool_core
sovpool_rpc → sovpool_core, bitcoincore-rpc
sovpool_test → sovpool_core, sovpool_rpc (test only)
sovpool_assess → serde, thiserror (standalone, no bitcoin dep)
sovpool_core → bitcoin 0.32, serde, thiserror (foundation)
```

## Crates

### sovpool_core

Foundation crate. Contains all CTV primitives and pool logic.

| Module | Purpose |
|--------|---------|
| `covenant.rs` | BIP-119 CTV hash computation, `CtvTemplate`, `ctv_script()`, `CovenantBackend` trait, taproot tree construction |
| `pool.rs` | `Participant`, `Pool`, `PoolBuilder`, `PoolState`, recursive N-party sub-pool construction |
| `exit.rs` | `ExitPath`, `ExitPathSet` — CTV-committed exit transactions |
| `tx.rs` | `build_funding_transaction()`, `build_exit_transaction()`, `verify_exit_transaction()` |
| `cooperative.rs` | Cooperative pool state updates via PSBT coordination |
| `timeout.rs` | CSV (OP_CHECKSEQUENCEVERIFY) timeout/recovery paths |
| `fees.rs` | Pay to Anchor (P2A) outputs for CPFP fee bumping |
| `error.rs` | `SovpoolError` error types |

### sovpool_assess

Standalone assessment framework (no bitcoin dependency). Evaluates Bitcoin scaling protocols against six sovereignty criteria.

| Component | Purpose |
|-----------|---------|
| `SovereigntyAssessable` trait | Interface for protocol assessment |
| `protocols/` | Implementations for L1, Lightning, ARK, Cashu, CTV Pool |
| `ComparisonReport` | Side-by-side multi-protocol comparison |

### sovpool_rpc

Thin wrapper around `bitcoincore-rpc` with sovpool-specific operations.

- Cookie file authentication (default, most secure)
- `ManagedNode` — starts/stops a bitcoind process
- Helpers: `mine_blocks()`, `fund_address()`, `get_utxo()`, `send_raw_transaction()`

### sovpool_test

Integration test harness for regtest/signet testing.

- Feature-gated: `ctv-regtest`, `signet`
- `TestHarness` — managed regtest node with funding/mining helpers
- `inquisition` — Bitcoin Inquisition binary discovery
- End-to-end tests: 2-party, 3-party, 5-party sequential exits

### sovpool_cli

Binary crate providing the `sovpool` CLI tool.

- `sovpool assess report <protocol>` — single protocol assessment
- `sovpool assess compare [protocols]` — comparison matrix
- `sovpool pool create` — create a pool (outputs JSON pool definition)
- `sovpool pool exit` — construct exit transaction
- `sovpool pool status` — show pool state

### sovpool_wallet

Pool participation manager. NOT a full wallet — key management is delegated to external signers via PSBT.

- `PoolTracker` — persistent storage for tracked pools
- `psbt` — PSBT creation, base64 import/export, file save/load

## Key Design Decisions

### CovenantBackend Trait

```rust
pub trait CovenantBackend {
    fn commit_to_outputs(&self, outputs: &[TxOut]) -> Result<ScriptBuf>;
    fn verify_commitment(&self, script: &Script, tx: &Transaction) -> Result<bool>;
}
```

This abstraction makes the codebase opcode-agnostic. If CTV doesn't activate:
- **Path A:** Implement `PresignedBackend` (N-of-N multisig pre-signed tx trees)
- **Path B:** Swap in alternative opcode backend (`OP_TXHASH`, `OP_CAT`)
- **Path C:** Continue on Bitcoin Inquisition signet

### Recursive Sub-Pools

For N-party pools (N > 2), each exit creates an (N-1)-party sub-pool. The exit path outputs are:
1. Exiting participant's withdrawal
2. Sub-pool UTXO (taproot address of the remaining participants' pool)

For 2-party pools, exit is direct — no sub-pool needed.

### Three-Leaf Taproot Tree

Each pool's taproot output contains up to three types of script leaves:

```
              [root]
             /      \
     [cooperative]   [right]
      N-of-N leaf   /      \
              [exit_tree]  [timeout_tree]
               /    \        /    \
          [exit_0] [exit_1] [to_0] [to_1] ...
```

1. **Cooperative leaf** — N-of-N CHECKSIGADD script for unanimous state updates
2. **CTV exit leaves** — One per participant, for unilateral exit
3. **Timeout recovery leaves** (optional) — CSV-locked per-participant recovery after configurable delay

### NUMS Internal Key

All pool taproot outputs use the BIP-341 NUMS (Nothing Up My Sleeve) unspendable internal key, ensuring key-path spending is impossible. All spending must go through script-path leaves (cooperative, CTV exit, or timeout recovery).

### Encapsulated API

`Pool` fields are private with accessor methods, preventing external corruption of the taproot tree invariant. The `PoolBuilder` provides the only safe construction path, computing CTV hashes, building the cooperative leaf, optional timeout leaves, and the taproot tree atomically.

### Security Model

- No mainnet keys ever generated or stored
- Cookie file auth for RPC (no passwords in code/env)
- PSBT-based coordination for cooperative updates
- External signer integration via raw PSBT files
- Feature-gating for network-dependent code
