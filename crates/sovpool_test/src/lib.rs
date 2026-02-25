//! Integration test harness for sovpool.
//!
//! Provides utilities for running end-to-end tests on regtest and signet
//! using a CTV-enabled bitcoind (Bitcoin Inquisition).
//!
//! Feature-gated: enable `ctv-regtest` or `signet` features to run tests.

#[cfg(any(feature = "ctv-regtest", feature = "signet"))]
pub mod harness;

#[cfg(any(feature = "ctv-regtest", feature = "signet"))]
pub mod inquisition;
