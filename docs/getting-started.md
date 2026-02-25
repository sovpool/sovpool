# Getting Started with sovpool

## Prerequisites

- Rust 1.73+ (`rustup update`)
- For regtest testing: Bitcoin Inquisition binary

## Build

```bash
# Build all crates
cargo build

# Run all tests (excluding regtest integration)
cargo test

# Run clippy
cargo clippy
```

## Quick Start: Protocol Assessment

```bash
# Assess a single protocol
cargo run --bin sovpool -- assess report l1
cargo run --bin sovpool -- assess report lightning --format json

# Compare all protocols
cargo run --bin sovpool -- assess compare all

# Compare specific protocols
cargo run --bin sovpool -- assess compare l1,ctv-pool,lightning
```

## Quick Start: Pool Operations

```bash
# Create a 2-party pool (test participants)
cargo run --bin sovpool -- pool create -n 2 --amount 50000

# Create a 5-party pool with JSON output
cargo run --bin sovpool -- pool create -n 5 --amount 20000 --format json > pool.json

# Show pool status
cargo run --bin sovpool -- pool status --pool-file pool.json
```

## Regtest Testing

### 1. Get Bitcoin Inquisition

Download from [bitcoin-inquisition/bitcoin](https://github.com/bitcoin-inquisition/bitcoin/releases).

### 2. Set the binary path

```bash
export SOVPOOL_BITCOIND=/path/to/bitcoin-inquisition/bin/bitcoind
```

### 3. Run integration tests

```bash
cargo test -p sovpool_test --features ctv-regtest
```

This will:
- Start a regtest node
- Create and fund payment pools
- Execute unilateral exits
- Verify UTXO states

## Library Usage

### Assessment Framework

```rust
use sovpool_assess::protocols::*;
use sovpool_assess::{ComparisonReport, SovereigntyAssessable};

// Assess a single protocol
let report = CtvPool.assess();
println!("Score: {}/6", report.total_score());
println!("{}", report.to_markdown());

// Compare protocols
let comparison = ComparisonReport::new(vec![
    BitcoinL1.assess(),
    Lightning.assess(),
    CtvPool.assess(),
]);
println!("{}", comparison.to_markdown());
```

### Pool Construction

```rust
use sovpool_core::pool::{Participant, PoolBuilder};
use sovpool_core::tx::{build_exit_transaction, build_funding_transaction};
use bitcoin::Network;

// Build a 2-party pool
let pool = PoolBuilder::new()
    .with_network(Network::Regtest)
    .add_participant(alice)
    .add_participant(bob)
    .build()?;

println!("Pool address: {}", pool.pool_address);
println!("Exit paths: {}", pool.exit_paths.paths.len());

// Construct exit transaction
let exit_tx = build_exit_transaction(&pool, pool_utxo, 0)?;
```

### Wallet Tracking

```rust
use sovpool_wallet::tracker::{PoolTracker, TrackedPool};

let mut tracker = PoolTracker::new(&storage_dir)?;
tracker.track(pool_entry)?;
tracker.set_pool_utxo("pool1", utxo)?;
tracker.record_exit("pool1", exit_record)?;
```

## Project Structure

```
sovpool/
├── crates/
│   ├── sovpool_core/      # CTV primitives, pool logic
│   ├── sovpool_assess/    # Sovereignty assessment framework
│   ├── sovpool_rpc/       # Bitcoin Core RPC wrapper
│   ├── sovpool_test/      # Integration test harness
│   ├── sovpool_cli/       # CLI binary
│   └── sovpool_wallet/    # Pool participation manager
├── docs/
│   ├── architecture.md
│   ├── ctv-primer.md
│   └── getting-started.md
├── fuzz/                  # Fuzz targets (nightly)
└── Makefile
```
