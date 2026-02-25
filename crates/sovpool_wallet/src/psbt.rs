//! PSBT (Partially Signed Bitcoin Transaction) utilities.
//!
//! Provides PSBT-based coordination for pool operations.
//! Actual signing is delegated to external signers.

use bitcoin::consensus::encode;
use bitcoin::psbt::Psbt;
use bitcoin::Transaction;
use std::path::Path;

use crate::{Result, WalletError};

/// Save a PSBT to a file (binary format).
pub fn save_psbt(psbt: &Psbt, path: &Path) -> Result<()> {
    let bytes = psbt.serialize();
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Load a PSBT from a file.
pub fn load_psbt(path: &Path) -> Result<Psbt> {
    let bytes = std::fs::read(path)?;
    Psbt::deserialize(&bytes).map_err(|e| WalletError::Other(format!("invalid PSBT: {e}")))
}

/// Create a PSBT from an unsigned transaction.
pub fn psbt_from_unsigned(tx: Transaction) -> Result<Psbt> {
    Psbt::from_unsigned_tx(tx).map_err(|e| WalletError::Other(format!("PSBT creation: {e}")))
}

/// Export a PSBT as base64 (for interchange).
pub fn psbt_to_base64(psbt: &Psbt) -> String {
    use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(psbt.serialize())
}

/// Import a PSBT from base64.
pub fn psbt_from_base64(s: &str) -> Result<Psbt> {
    use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD
        .decode(s)
        .map_err(|e| WalletError::Other(format!("base64 decode: {e}")))?;
    Psbt::deserialize(&bytes).map_err(|e| WalletError::Other(format!("invalid PSBT: {e}")))
}

/// Export a finalized transaction as hex.
pub fn tx_to_hex(tx: &Transaction) -> String {
    encode::serialize_hex(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;

    fn sample_tx() -> Transaction {
        Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    #[test]
    fn psbt_roundtrip_file() {
        let tx = sample_tx();
        let psbt = psbt_from_unsigned(tx).unwrap();

        let path = std::env::temp_dir().join("sovpool_test.psbt");
        save_psbt(&psbt, &path).unwrap();
        let loaded = load_psbt(&path).unwrap();

        assert_eq!(psbt.serialize(), loaded.serialize());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn psbt_roundtrip_base64() {
        let tx = sample_tx();
        let psbt = psbt_from_unsigned(tx).unwrap();

        let b64 = psbt_to_base64(&psbt);
        let decoded = psbt_from_base64(&b64).unwrap();

        assert_eq!(psbt.serialize(), decoded.serialize());
    }
}
