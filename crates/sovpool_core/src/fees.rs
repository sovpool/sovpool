//! Fee handling for CTV pool transactions.
//!
//! Uses Pay to Anchor (P2A) outputs for CPFP (Child Pays for Parent)
//! fee bumping. CTV-committed transactions have fixed outputs, so
//! fees must be handled via anchor outputs or pre-committed fee paths.

use bitcoin::script::Builder;
use bitcoin::{Amount, ScriptBuf, TxOut};

/// Minimum dust limit for anchor outputs.
pub const ANCHOR_DUST_SATS: u64 = 240;

/// Default fee rate in sat/vB for exit transactions.
pub const DEFAULT_FEE_RATE: u64 = 2;

/// Fee estimation for pool transactions.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct FeeConfig {
    /// Fee rate in sat/vB.
    pub fee_rate_sat_vb: u64,
    /// Whether to include a P2A anchor output for CPFP.
    pub use_anchor: bool,
}

impl FeeConfig {
    pub fn new(fee_rate: u64) -> Self {
        Self {
            fee_rate_sat_vb: fee_rate,
            use_anchor: true,
        }
    }

    /// Estimate the fee for a transaction with the given virtual size.
    pub fn estimate_fee(&self, vsize: u64) -> Amount {
        Amount::from_sat(self.fee_rate_sat_vb * vsize)
    }
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            fee_rate_sat_vb: DEFAULT_FEE_RATE,
            use_anchor: true,
        }
    }
}

/// Build a Pay to Anchor (P2A) output for CPFP fee bumping.
///
/// P2A uses a standard output script that anyone can spend,
/// allowing any party to attach a child transaction to bump fees.
/// Uses OP_TRUE (anyone-can-spend) with dust amount.
pub fn p2a_anchor_output() -> TxOut {
    TxOut {
        value: Amount::from_sat(ANCHOR_DUST_SATS),
        script_pubkey: p2a_script(),
    }
}

/// The P2A (Pay to Anchor) script: OP_TRUE.
///
/// This is an anyone-can-spend output that allows CPFP.
fn p2a_script() -> ScriptBuf {
    Builder::new()
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script()
}

/// Build a CPFP child transaction that spends the anchor output.
///
/// The child tx spends the anchor and pays the difference as fees,
/// effectively bumping the parent transaction's fee rate.
pub fn build_cpfp_child(
    anchor_outpoint: bitcoin::OutPoint,
    change_address: &bitcoin::Address,
    fee: Amount,
) -> bitcoin::Transaction {
    let anchor_value = Amount::from_sat(ANCHOR_DUST_SATS);
    let change_value = anchor_value.checked_sub(fee).unwrap_or(Amount::ZERO);

    let mut outputs = Vec::new();
    if change_value > Amount::ZERO {
        outputs.push(TxOut {
            value: change_value,
            script_pubkey: change_address.script_pubkey(),
        });
    }

    bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: anchor_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: outputs,
    }
}

/// Estimated virtual size of common transaction types.
pub mod vsize {
    /// Approximate vsize of a 2-output CTV exit transaction (taproot script-path spend).
    pub const EXIT_TX_2OUTPUT: u64 = 200;

    /// Approximate vsize of a funding transaction per input.
    pub const FUNDING_TX_PER_INPUT: u64 = 68;

    /// Base vsize of a funding transaction.
    pub const FUNDING_TX_BASE: u64 = 44;

    /// Approximate vsize of a CPFP child transaction.
    pub const CPFP_CHILD: u64 = 110;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_output_has_dust_value() {
        let anchor = p2a_anchor_output();
        assert_eq!(anchor.value, Amount::from_sat(ANCHOR_DUST_SATS));
    }

    #[test]
    fn fee_estimation() {
        let config = FeeConfig::new(5);
        let fee = config.estimate_fee(200);
        assert_eq!(fee, Amount::from_sat(1000));
    }

    #[test]
    fn default_fee_config() {
        let config = FeeConfig::default();
        assert_eq!(config.fee_rate_sat_vb, DEFAULT_FEE_RATE);
        assert!(config.use_anchor);
    }

    #[test]
    fn p2a_script_is_anyone_can_spend() {
        let script = p2a_script();
        // OP_TRUE = 0x51
        assert_eq!(script.as_bytes(), &[0x51]);
    }
}
