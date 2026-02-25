# sovpool

[![CI](https://github.com/sovpool/sovpool/actions/workflows/ci.yml/badge.svg)](https://github.com/sovpool/sovpool/actions/workflows/ci.yml)

Sovereign covenant payment pools for Bitcoin.

A Rust workspace for building CTV-based (OP_CHECKTEMPLATEVERIFY) payment pools — shared UTXOs where multiple participants transact off-chain while retaining guaranteed unilateral exit to Layer 1.

## Why

Bitcoin's Layer 1 provides the strongest settlement guarantees in existence: energy-secured, sovereign, permissionless, and censorship-resistant. But L1 throughput is limited by design. Existing Layer 2 solutions (Lightning) trade sovereignty for scalability by introducing intermediaries.

Covenant payment pools solve this: multiple users share a single on-chain UTXO, transact off-chain, and any participant can exit to L1 at any time — without anyone's permission. No hubs. No custodians. No service providers in the critical path.

This is the missing infrastructure for Bitcoin as both store of value **and** payment mechanism, without compromising the properties that make it valuable in the first place.

## Sovereignty Assessment

Every protocol is evaluated against six sovereignty criteria. A protocol must satisfy **all six** to be considered sovereign.

| Criterion | L1 | Lightning | ARK | Cashu | CTV Pool |
|---|:---:|:---:|:---:|:---:|:---:|
| Self-Custody | Pass | Pass | Pass | Fail | Pass |
| Unilateral Exit | Pass | Pass | Partial | Fail | Pass |
| No Trusted Third Party | Pass | Partial | Fail | Fail | Pass |
| Censorship Resistance | Pass | Partial | Partial | Partial | Pass |
| On-Chain Settlement | Pass | Pass | Pass | Fail | Pass |
| Liveness Independence | Pass | Partial | Fail | Fail | Pass |
| **Total** | **6/6** | **4.5/6** | **3/6** | **0.5/6** | **6/6** |

CTV payment pools achieve full L1-equivalent sovereignty while enabling shared UTXOs for scaling. Note: cooperative updates require all participants online; unilateral exit is always available.

```bash
# Run the assessment yourself
cargo run --bin sovpool -- assess compare all
```

## Quick Start

```bash
# Build
cargo build

# Run tests
cargo test --lib --bins

# Run all tests including property tests
cargo test

# Clippy
cargo clippy
```

### Pool Operations

```bash
# Create a 2-party pool
cargo run --bin sovpool -- pool create -n 2 --amount 50000

# Create a 5-party pool with JSON output
cargo run --bin sovpool -- pool create -n 5 --amount 20000 --format json > pool.json

# Create a pool with P2A anchor output (required for signet/mainnet)
cargo run --bin sovpool -- pool create -n 3 --amount 10000 --network signet --anchor -f json

# Show pool status
cargo run --bin sovpool -- pool status --pool-file pool.json
```

### Regtest Testing

Requires a CTV-enabled bitcoind ([Bitcoin Inquisition](https://github.com/bitcoin-inquisition/bitcoin/releases)):

```bash
export SOVPOOL_BITCOIND=/path/to/bitcoin-inquisition/bin/bitcoind
cargo test -p sovpool_test --features ctv-regtest
```

### Signet Demo

Run a full pool lifecycle on Bitcoin Inquisition signet (CTV active since block 106704):

```bash
./scripts/signet-demo.sh [bitcoind-datadir]
```

## Architecture

```
sovpool/
├── crates/
│   ├── sovpool_core/      CTV primitives, pool construction, exit paths
│   ├── sovpool_assess/    Sovereignty assessment framework
│   ├── sovpool_rpc/       Bitcoin Core RPC wrapper
│   ├── sovpool_test/      Regtest integration test harness
│   ├── sovpool_cli/       CLI binary
│   └── sovpool_wallet/    Pool tracker and PSBT coordination
├── fuzz/                  Fuzz targets (cargo-fuzz, nightly)
└── docs/                  Architecture, CTV primer, getting started
```

### Key Design

**`CovenantBackend` trait** — Pool logic is opcode-agnostic. `CtvBackend` is the primary implementation. If CTV doesn't activate, swap in `PresignedBackend` (N-of-N multisig pre-signed trees) without rewriting pool construction.

**Recursive N-party pools** — Exit from an N-party pool produces a withdrawal output and an (N-1)-party sub-pool UTXO, enforced by CTV covenants. Every participant always has a valid unilateral exit path.

**Three-leaf taproot tree** — Each pool's taproot output contains:
1. **Cooperative leaf** — N-of-N CHECKSIGADD script for unanimous state updates
2. **CTV exit leaves** — One per participant, for unilateral exit
3. **Timeout recovery leaves** (optional) — CSV-locked per-participant recovery after configurable delay

**Encapsulated API** — Pool fields are private with accessor methods, preventing external corruption of the taproot tree invariant.

## Library Usage

```rust
use sovpool_core::pool::{Participant, PoolBuilder};
use sovpool_core::tx::build_exit_transaction;
use bitcoin::Network;

let pool = PoolBuilder::new()
    .with_network(Network::Regtest)
    .add_participant(alice)
    .add_participant(bob)
    .with_timeout(144)  // optional: 1-day CSV recovery
    .build()?;

// Every participant can exit unilaterally
let exit_tx = build_exit_transaction(&pool, pool_utxo, 0)?;
```

## Documentation

- [Architecture](docs/architecture.md) — Crate structure and design decisions
- [CTV Primer](docs/ctv-primer.md) — BIP-119 explained for developers
- [Getting Started](docs/getting-started.md) — Build, test, and run guide

## Status

CTV (BIP-119) is not yet active on Bitcoin mainnet. sovpool works on:
- **Regtest** — with Bitcoin Inquisition
- **Signet** — Bitcoin Inquisition signet (CTV active)
- **In-memory** — pool construction and verification without a node

**What works:** CTV hash computation (verified against BIP-119 vectors), pool construction with N-party recursive exits, N-of-N cooperative spending leaf, CSV timeout recovery, P2A anchor fees, CLI, sovereignty assessment framework, fuzz targets, CI (8 jobs).

**Pending:** Signet demo with real on-chain transactions (blocked on faucet coins).

**Do not use with mainnet funds.**

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
