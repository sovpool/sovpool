use thiserror::Error;

#[derive(Debug, Error)]
pub enum SovpoolError {
    #[error("invalid participant count: {0}")]
    InvalidParticipantCount(usize),

    #[error("invalid amount: {0}")]
    InvalidAmount(u64),

    #[error("pool state error: {0}")]
    InvalidState(String),

    #[error("CTV hash computation error: {0}")]
    CtvHashError(String),

    #[error("transaction construction error: {0}")]
    TxError(String),

    #[error("bitcoin error: {0}")]
    Bitcoin(#[from] bitcoin::consensus::encode::Error),
}

pub type Result<T> = std::result::Result<T, SovpoolError>;
