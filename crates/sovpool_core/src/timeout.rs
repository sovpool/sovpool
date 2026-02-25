//! CSV (OP_CHECKSEQUENCEVERIFY) timeout and recovery paths.
//!
//! Handles offline participant recovery. After a configurable timeout,
//! remaining participants can reclaim the pool without cooperation
//! from the offline party.

use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bitcoin::script::Builder;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{ScriptBuf, Sequence};

/// Default timeout in blocks (approximately 1 day on mainnet).
pub const DEFAULT_TIMEOUT_BLOCKS: u16 = 144;

/// Timeout configuration for pool recovery paths.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct TimeoutConfig {
    /// Number of blocks before the timeout path becomes spendable.
    pub blocks: u16,
}

impl TimeoutConfig {
    pub fn new(blocks: u16) -> Self {
        Self { blocks }
    }

    /// Create a default timeout (144 blocks / ~1 day).
    pub fn default_timeout() -> Self {
        Self {
            blocks: DEFAULT_TIMEOUT_BLOCKS,
        }
    }

    /// Create a 1-week timeout (1008 blocks).
    pub fn one_week() -> Self {
        Self { blocks: 1008 }
    }

    /// Get the CSV sequence value for this timeout.
    pub fn csv_sequence(&self) -> Sequence {
        Sequence::from_height(self.blocks)
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self::default_timeout()
    }
}

/// Build a CSV-locked recovery script.
///
/// Script: `<blocks> OP_CSV OP_DROP <pubkey> OP_CHECKSIG`
///
/// After `blocks` confirmations of the pool UTXO, the recovery key
/// can spend without cooperation from the offline participant.
pub fn csv_recovery_script(timeout: &TimeoutConfig, recovery_key: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(timeout.blocks as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(recovery_key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build a timelocked exit path that combines CTV exit with CSV recovery.
///
/// Normal path: CTV exit (no timeout, participant exits immediately)
/// Recovery path: After CSV timeout, recovery key can sweep
///
/// Both paths are included as leaves in the taproot tree.
pub fn build_timeout_scripts(
    ctv_script: &ScriptBuf,
    timeout: &TimeoutConfig,
    recovery_key: &XOnlyPublicKey,
) -> Vec<ScriptBuf> {
    vec![
        ctv_script.clone(),
        csv_recovery_script(timeout, recovery_key),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        secret_bytes[31] = 1;
        secret_bytes[0] = 0x01;
        let sk = SecretKey::from_slice(&secret_bytes).unwrap();
        let (pubkey, _) = sk.x_only_public_key(&secp);
        pubkey
    }

    #[test]
    fn csv_recovery_script_format() {
        let timeout = TimeoutConfig::new(144);
        let key = test_pubkey();
        let script = csv_recovery_script(&timeout, &key);

        let bytes = script.as_bytes();
        // Should contain OP_CSV (0xb2) and OP_CHECKSIG (0xac)
        assert!(
            bytes.windows(1).any(|w| w[0] == 0xb2),
            "should contain OP_CSV"
        );
        assert!(
            bytes.windows(1).any(|w| w[0] == 0xac),
            "should contain OP_CHECKSIG"
        );
    }

    #[test]
    fn timeout_config_csv_sequence() {
        let timeout = TimeoutConfig::new(144);
        let seq = timeout.csv_sequence();
        // CSV height-based sequence: bit 22 clear, value = 144
        assert!(seq.is_relative_lock_time());
    }

    #[test]
    fn default_timeout_is_one_day() {
        let timeout = TimeoutConfig::default();
        assert_eq!(timeout.blocks, 144);
    }

    #[test]
    fn one_week_timeout() {
        let timeout = TimeoutConfig::one_week();
        assert_eq!(timeout.blocks, 1008);
    }

    #[test]
    fn timeout_scripts_has_two_paths() {
        let key = test_pubkey();
        let timeout = TimeoutConfig::default();

        // Fake CTV script for testing
        let ctv_script = ScriptBuf::from_bytes(vec![0x20; 34]);

        let scripts = build_timeout_scripts(&ctv_script, &timeout, &key);
        assert_eq!(scripts.len(), 2);
    }
}
