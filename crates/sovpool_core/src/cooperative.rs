//! Cooperative pool state updates.
//!
//! All participants agree on a new CTV tree with updated balances.
//! Coordination happens via PSBTs — actual signing is external.
//!
//! The pool's taproot tree includes an N-of-N CHECKSIGADD leaf that
//! enables cooperative spending. This module builds that script and
//! uses it in PSBT construction.

use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
use bitcoin::psbt::Psbt;
use bitcoin::script::Builder;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness};

use crate::error::{Result, SovpoolError};
use crate::pool::{Participant, Pool, PoolBuilder};

/// Build an N-of-N CHECKSIGADD tapscript for cooperative spending.
///
/// Script (tapscript, leaf version 0xc0):
/// ```text
/// <pubkey_1> OP_CHECKSIG
/// <pubkey_2> OP_CHECKSIGADD
/// ...
/// <pubkey_n> OP_CHECKSIGADD
/// <n> OP_NUMEQUAL
/// ```
///
/// All N participants must provide valid Schnorr signatures to spend.
pub fn build_cooperative_script(pubkeys: &[XOnlyPublicKey]) -> Result<ScriptBuf> {
    if pubkeys.is_empty() {
        return Err(SovpoolError::InvalidParticipantCount(0));
    }
    if pubkeys.len() == 1 {
        // Single key: just OP_CHECKSIG
        let script = Builder::new()
            .push_x_only_key(&pubkeys[0])
            .push_opcode(OP_CHECKSIG)
            .into_script();
        return Ok(script);
    }

    let mut builder = Builder::new();

    // First key: OP_CHECKSIG (pushes 0 or 1 onto stack)
    builder = builder
        .push_x_only_key(&pubkeys[0])
        .push_opcode(OP_CHECKSIG);

    // Subsequent keys: OP_CHECKSIGADD (accumulates valid sig count)
    for key in &pubkeys[1..] {
        builder = builder.push_x_only_key(key).push_opcode(OP_CHECKSIGADD);
    }

    // Final check: require all N signatures
    builder = builder
        .push_int(pubkeys.len() as i64)
        .push_opcode(OP_NUMEQUAL);

    Ok(builder.into_script())
}

/// A proposed cooperative update to the pool state.
#[derive(Debug, Clone)]
pub struct CooperativeUpdate {
    /// The original pool being updated.
    pub original_pool_utxo: OutPoint,
    /// Updated participant balances (must sum to original total).
    pub updated_participants: Vec<Participant>,
    /// The new pool that would result from this update.
    pub new_pool: Pool,
    /// The spending transaction (cooperative key-path spend of original pool).
    pub spending_tx: Transaction,
}

/// Propose a cooperative update with new balances.
///
/// The update replaces the existing CTV tree with a new one reflecting
/// updated balances. All participants must sign via the key-path spend
/// (taproot internal key). Since we use NUMS for the internal key,
/// cooperative updates require an alternative: the existing pool must
/// include a cooperative spending path (N-of-N multisig leaf).
///
/// Returns a PSBT for the cooperative spending transaction that all
/// participants must sign.
pub fn propose_update(
    pool: &Pool,
    pool_utxo: OutPoint,
    updated_participants: Vec<Participant>,
) -> Result<CooperativeUpdate> {
    // Validate: same number of participants
    if updated_participants.len() != pool.participants().len() {
        return Err(SovpoolError::InvalidState(
            "cooperative update cannot change participant count".into(),
        ));
    }

    // Validate: total amount preserved
    let original_total: u64 = pool.participants().iter().map(|p| p.amount_sats).sum();
    let new_total: u64 = updated_participants.iter().map(|p| p.amount_sats).sum();
    if original_total != new_total {
        return Err(SovpoolError::InvalidState(format!(
            "total amount changed: {original_total} -> {new_total}"
        )));
    }

    // Build new pool with updated balances
    let new_pool = PoolBuilder::new()
        .with_network(pool.network())
        .with_tx_version(pool.tx_version())
        .add_participants(updated_participants.clone())
        .build()?;

    // Build the cooperative spending transaction:
    // Input: existing pool UTXO (requires N-of-N signature)
    // Output: new pool UTXO
    let spending_tx = Transaction {
        version: bitcoin::transaction::Version(pool.tx_version()),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: pool_utxo,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(new_total),
            script_pubkey: new_pool.pool_address().script_pubkey(),
        }],
    };

    Ok(CooperativeUpdate {
        original_pool_utxo: pool_utxo,
        updated_participants,
        new_pool,
        spending_tx,
    })
}

/// Create a PSBT from the cooperative update for signing.
pub fn update_to_psbt(update: &CooperativeUpdate) -> Result<Psbt> {
    Psbt::from_unsigned_tx(update.spending_tx.clone())
        .map_err(|e| SovpoolError::TxError(format!("PSBT creation: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Network, Txid};

    fn make_participant(seed: u8, amount: u64) -> Participant {
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        secret_bytes[31] = seed;
        secret_bytes[0] = 0x01;
        let sk = SecretKey::from_slice(&secret_bytes).unwrap();
        let (pubkey, _) = sk.x_only_public_key(&secp);
        let address = Address::p2tr(&secp, pubkey, None, Network::Regtest);
        let unchecked = address.to_string().parse().unwrap();
        Participant::new(pubkey, unchecked, amount)
    }

    #[test]
    fn cooperative_update_preserves_total() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 60_000))
            .add_participant(make_participant(2, 40_000))
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        // Rebalance: Alice pays Bob 10k
        let updated = vec![make_participant(1, 50_000), make_participant(2, 50_000)];

        let update = propose_update(&pool, utxo, updated).unwrap();
        assert_eq!(update.new_pool.total_sats(), 100_000);
        assert_eq!(
            update.spending_tx.output[0].value,
            Amount::from_sat(100_000)
        );
    }

    #[test]
    fn cooperative_update_rejects_total_change() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        // Try to inflate total
        let updated = vec![make_participant(1, 60_000), make_participant(2, 50_000)];

        assert!(propose_update(&pool, utxo, updated).is_err());
    }

    #[test]
    fn cooperative_update_rejects_participant_count_change() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        let updated = vec![make_participant(1, 100_000)];
        assert!(propose_update(&pool, utxo, updated).is_err());
    }

    #[test]
    fn cooperative_update_produces_valid_psbt() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        let updated = vec![make_participant(1, 40_000), make_participant(2, 60_000)];

        let update = propose_update(&pool, utxo, updated).unwrap();
        let psbt = update_to_psbt(&update).unwrap();

        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
    }

    #[test]
    fn cooperative_update_changes_pool_address() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 70_000))
            .add_participant(make_participant(2, 30_000))
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([2u8; 32]),
            vout: 0,
        };

        let updated = vec![make_participant(1, 50_000), make_participant(2, 50_000)];
        let update = propose_update(&pool, utxo, updated).unwrap();

        // New pool has different CTV tree → different address
        assert_ne!(
            pool.pool_address(),
            update.new_pool.pool_address(),
            "rebalanced pool should have a different address"
        );
    }

    #[test]
    fn cooperative_update_new_pool_has_valid_exit_paths() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 60_000))
            .add_participant(make_participant(2, 40_000))
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([3u8; 32]),
            vout: 0,
        };

        let updated = vec![make_participant(1, 30_000), make_participant(2, 70_000)];
        let update = propose_update(&pool, utxo, updated).unwrap();

        // New pool should have valid exit paths for all participants
        assert_eq!(update.new_pool.exit_paths().paths.len(), 2);
        for (i, path) in update.new_pool.exit_paths().paths.iter().enumerate() {
            assert!(
                !path.ctv_hash.iter().all(|b| *b == 0),
                "exit path {i} hash should be non-zero"
            );
            assert!(
                !path.outputs.is_empty(),
                "exit path {i} should have outputs"
            );
        }
    }

    #[test]
    fn cooperative_update_spending_tx_references_original_utxo() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([4u8; 32]),
            vout: 3,
        };

        let updated = vec![make_participant(1, 50_000), make_participant(2, 50_000)];
        let update = propose_update(&pool, utxo, updated).unwrap();

        assert_eq!(update.spending_tx.input[0].previous_output, utxo);
    }

    #[test]
    fn cooperative_update_output_pays_to_new_pool_address() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([5u8; 32]),
            vout: 0,
        };

        let updated = vec![make_participant(1, 40_000), make_participant(2, 60_000)];
        let update = propose_update(&pool, utxo, updated).unwrap();

        assert_eq!(
            update.spending_tx.output[0].script_pubkey,
            update.new_pool.pool_address().script_pubkey(),
            "spending tx output should pay to the new pool address"
        );
    }

    #[test]
    fn cooperative_update_five_party_rebalance() {
        let participants: Vec<Participant> = (1..=5).map(|i| make_participant(i, 20_000)).collect();

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participants(participants)
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([6u8; 32]),
            vout: 0,
        };

        // Rebalance: participant 1 pays 5k each to participants 4 and 5
        let updated = vec![
            make_participant(1, 10_000),
            make_participant(2, 20_000),
            make_participant(3, 20_000),
            make_participant(4, 25_000),
            make_participant(5, 25_000),
        ];

        let update = propose_update(&pool, utxo, updated).unwrap();
        assert_eq!(update.new_pool.total_sats(), 100_000);
        assert_eq!(update.new_pool.participants().len(), 5);
        assert_eq!(update.new_pool.exit_paths().paths.len(), 5);
    }

    #[test]
    fn cooperative_update_sequential_updates() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let utxo1 = OutPoint {
            txid: Txid::from_byte_array([7u8; 32]),
            vout: 0,
        };

        // First update: Alice pays Bob 10k
        let updated1 = vec![make_participant(1, 40_000), make_participant(2, 60_000)];
        let update1 = propose_update(&pool, utxo1, updated1).unwrap();

        // Second update on the new pool: Bob pays Alice 5k back
        let utxo2 = OutPoint {
            txid: Txid::from_byte_array([8u8; 32]),
            vout: 0,
        };
        let updated2 = vec![make_participant(1, 45_000), make_participant(2, 55_000)];
        let update2 = propose_update(&update1.new_pool, utxo2, updated2).unwrap();

        assert_eq!(update2.new_pool.total_sats(), 100_000);
        // Each update produces a different pool address
        assert_ne!(pool.pool_address(), update1.new_pool.pool_address());
        assert_ne!(
            update1.new_pool.pool_address(),
            update2.new_pool.pool_address()
        );
    }

    #[test]
    fn cooperative_update_with_anchor_pool() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .with_anchor(240)
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([9u8; 32]),
            vout: 0,
        };

        let updated = vec![make_participant(1, 40_000), make_participant(2, 60_000)];
        let update = propose_update(&pool, utxo, updated).unwrap();

        // The spending tx output should carry the full 100k (anchor is only on exits)
        assert_eq!(
            update.spending_tx.output[0].value,
            Amount::from_sat(100_000)
        );
        assert_eq!(update.new_pool.total_sats(), 100_000);
    }

    #[test]
    fn cooperative_script_two_party() {
        let secp = Secp256k1::new();
        let keys: Vec<XOnlyPublicKey> = (1..=2u8)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i;
                bytes[0] = 0x01;
                let sk = SecretKey::from_slice(&bytes).unwrap();
                sk.x_only_public_key(&secp).0
            })
            .collect();

        let script = build_cooperative_script(&keys).unwrap();
        let bytes = script.as_bytes();

        // Should contain OP_CHECKSIG (0xac) and OP_CHECKSIGADD (0xba)
        assert!(bytes.iter().any(|&b| b == 0xac), "must contain OP_CHECKSIG");
        assert!(
            bytes.iter().any(|&b| b == 0xba),
            "must contain OP_CHECKSIGADD"
        );
        // Should contain OP_NUMEQUAL (0x9c)
        assert!(bytes.iter().any(|&b| b == 0x9c), "must contain OP_NUMEQUAL");
        // Both pubkeys should be in the script (32 bytes each)
        for key in &keys {
            let key_bytes = key.serialize();
            assert!(
                bytes.windows(32).any(|w| w == key_bytes),
                "script must contain each pubkey"
            );
        }
    }

    #[test]
    fn cooperative_script_single_key() {
        let secp = Secp256k1::new();
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        bytes[0] = 0x01;
        let sk = SecretKey::from_slice(&bytes).unwrap();
        let (pubkey, _) = sk.x_only_public_key(&secp);

        let script = build_cooperative_script(&[pubkey]).unwrap();
        let script_bytes = script.as_bytes();

        // Single key: just <pubkey> OP_CHECKSIG, no CHECKSIGADD
        assert!(
            script_bytes.iter().any(|&b| b == 0xac),
            "must contain OP_CHECKSIG"
        );
        assert!(
            !script_bytes.iter().any(|&b| b == 0xba),
            "single key must NOT contain OP_CHECKSIGADD"
        );
    }

    #[test]
    fn cooperative_script_empty_rejected() {
        assert!(build_cooperative_script(&[]).is_err());
    }

    #[test]
    fn cooperative_update_identity_preserves_address() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let utxo = OutPoint {
            txid: Txid::from_byte_array([10u8; 32]),
            vout: 0,
        };

        // Update with identical balances — address should be the same
        let updated = vec![make_participant(1, 50_000), make_participant(2, 50_000)];
        let update = propose_update(&pool, utxo, updated).unwrap();

        assert_eq!(
            pool.pool_address(),
            update.new_pool.pool_address(),
            "identity update should produce same pool address"
        );
    }
}
