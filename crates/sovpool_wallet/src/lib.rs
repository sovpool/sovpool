//! Pool participation manager.
//!
//! Tracks pools, exit paths, and pool state. NOT a full wallet.
//! Key management is delegated to external signers via PSBT.

pub mod psbt;
pub mod tracker;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("pool not found: {0}")]
    PoolNotFound(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("sovpool error: {0}")]
    Sovpool(#[from] sovpool_core::error::SovpoolError),

    #[error("wallet error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, WalletError>;
