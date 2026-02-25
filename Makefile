.PHONY: build test clippy fmt check clean regtest fuzz

# Default target
all: check

# Build all crates
build:
	cargo build

# Run all tests (excluding regtest integration and proptest for speed)
test:
	cargo test --lib --bins
	cargo test -p sovpool_assess --test comparison

# Run all tests including property tests (slower)
test-full:
	cargo test

# Run clippy lints
clippy:
	cargo clippy -- -W clippy::all

# Check formatting
fmt:
	cargo fmt --check

# Format code
fmt-fix:
	cargo fmt

# Full check: build + test + clippy + fmt
check: build test clippy fmt

# Run regtest integration tests (requires CTV-enabled bitcoind)
regtest:
	@if [ -z "$$SOVPOOL_BITCOIND" ]; then \
		echo "Set SOVPOOL_BITCOIND to the path of a CTV-enabled bitcoind"; \
		exit 1; \
	fi
	cargo test -p sovpool_test --features ctv-regtest -- --nocapture

# Run signet tests
signet:
	cargo test -p sovpool_test --features signet -- --nocapture

# Run fuzz targets (requires nightly)
fuzz:
	cd fuzz && cargo +nightly fuzz run ctv_hash -- -max_total_time=60

# Clean build artifacts
clean:
	cargo clean

# Build the CLI binary
cli:
	cargo build --bin sovpool --release

# Run the assessment comparison
assess:
	cargo run --bin sovpool -- assess compare all

# Security audit: check for secrets and sensitive files
audit:
	@echo "Checking for sensitive files..."
	@! find . -name "*.pem" -o -name "*.key" -o -name ".env" | grep -v target | grep .
	@echo "Checking for mainnet references in test code..."
	@! grep -r "mainnet\|bitcoin:\|bc1q" crates/ --include="*.rs" | grep -v "//\|Network::\|fn\|mod\|doc\|test"
	@echo "Audit passed."
