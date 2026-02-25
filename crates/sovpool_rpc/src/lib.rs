//! Bitcoin Core RPC wrapper with sovpool-specific operations.
//!
//! Provides a thin wrapper around `bitcoincore-rpc` with cookie file auth,
//! regtest/signet helpers, and sovpool-specific operations.

pub mod node;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("bitcoincore-rpc error: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),

    #[error("sovpool error: {0}")]
    Sovpool(#[from] sovpool_core::error::SovpoolError),

    #[error("node not found at {0}")]
    NodeNotFound(String),

    #[error("node error: {0}")]
    NodeError(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RpcError>;
