use bitcoin::absolute::LockTime;
use bitcoin::taproot::LeafVersion;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::error::{Result, SovpoolError};
use crate::exit::ExitPath;
use crate::pool::Pool;

/// Construct the funding transaction for a pool.
///
/// Each participant contributes one input. The single output is the pool UTXO
/// locked under the taproot tree with CTV exit paths.
///
/// Returns an unsigned transaction — inputs must be signed externally.
pub fn build_funding_transaction(pool: &Pool, funding_utxos: &[OutPoint]) -> Result<Transaction> {
    if funding_utxos.len() != pool.participants().len() {
        return Err(SovpoolError::TxError(format!(
            "need {} funding UTXOs, got {}",
            pool.participants().len(),
            funding_utxos.len()
        )));
    }

    let inputs: Vec<TxIn> = funding_utxos
        .iter()
        .map(|outpoint| TxIn {
            previous_output: *outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        })
        .collect();

    let pool_output = TxOut {
        value: Amount::from_sat(pool.total_sats()),
        script_pubkey: pool.pool_address().script_pubkey(),
    };

    Ok(Transaction {
        version: bitcoin::transaction::Version(pool.tx_version()),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![pool_output],
    })
}

/// Construct the exit transaction for a participant leaving the pool.
///
/// This is a CTV script-path spend from the pool UTXO.
/// The outputs are predetermined by the CTV commitment.
///
/// The transaction is fully formed — no signature needed for CTV script-path spends.
/// The witness contains the CTV script and the taproot control block.
pub fn build_exit_transaction(
    pool: &Pool,
    pool_utxo: OutPoint,
    participant_index: usize,
) -> Result<Transaction> {
    let exit_path = pool.exit_path(participant_index)?;

    let mut tx = Transaction {
        version: bitcoin::transaction::Version(pool.tx_version()),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: pool_utxo,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: exit_path.outputs.clone(),
    };

    // Build witness: CTV script + control block
    let script_ver = (exit_path.ctv_script.clone(), LeafVersion::TapScript);
    let spend_info = pool.taproot_spend_info().ok_or_else(|| {
        SovpoolError::TxError(
            "taproot spend info not available (pool may need rebuild_taproot())".into(),
        )
    })?;
    let control_block = spend_info
        .control_block(&script_ver)
        .ok_or_else(|| SovpoolError::TxError("control block not found for exit path".into()))?;

    tx.input[0].witness.push(script_ver.0.into_bytes());
    tx.input[0].witness.push(control_block.serialize());

    Ok(tx)
}

/// Verify that an exit transaction matches its CTV commitment.
///
/// Checks that the transaction outputs match what the CTV hash commits to.
pub fn verify_exit_transaction(
    exit_path: &ExitPath,
    tx: &Transaction,
    tx_version: i32,
) -> Result<bool> {
    use crate::covenant::compute_ctv_hash;

    let computed_hash = compute_ctv_hash(&tx.output, tx_version);
    Ok(computed_hash == exit_path.ctv_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{Participant, PoolBuilder};
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

    fn make_outpoint(index: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([index as u8; 32]),
            vout: 0,
        }
    }

    #[test]
    fn build_funding_tx_two_party() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let utxos = vec![make_outpoint(1), make_outpoint(2)];
        let tx = build_funding_transaction(&pool, &utxos).unwrap();

        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_sat(100_000));
        assert_eq!(
            tx.output[0].script_pubkey,
            pool.pool_address().script_pubkey()
        );
    }

    #[test]
    fn build_funding_tx_wrong_utxo_count() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let utxos = vec![make_outpoint(1)]; // only 1, need 2
        assert!(build_funding_transaction(&pool, &utxos).is_err());
    }

    #[test]
    fn build_exit_tx_two_party() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 60_000))
            .add_participant(make_participant(2, 40_000))
            .build()
            .unwrap();

        let pool_utxo = make_outpoint(99);
        let exit_tx = build_exit_transaction(&pool, pool_utxo, 0).unwrap();

        // Alice exits: 2 outputs
        assert_eq!(exit_tx.input.len(), 1);
        assert_eq!(exit_tx.output.len(), 2);
        assert_eq!(exit_tx.output[0].value, Amount::from_sat(60_000));
        assert_eq!(exit_tx.output[1].value, Amount::from_sat(40_000));

        // Witness should have CTV script + control block
        assert_eq!(exit_tx.input[0].witness.len(), 2);
    }

    #[test]
    fn exit_tx_matches_ctv_commitment() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let pool_utxo = make_outpoint(99);
        let exit_tx = build_exit_transaction(&pool, pool_utxo, 0).unwrap();
        let exit_path = pool.exit_path(0).unwrap();

        assert!(verify_exit_transaction(exit_path, &exit_tx, pool.tx_version()).unwrap());
    }

    #[test]
    fn exit_tx_invalid_participant() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 50_000))
            .add_participant(make_participant(2, 50_000))
            .build()
            .unwrap();

        let pool_utxo = make_outpoint(99);
        assert!(build_exit_transaction(&pool, pool_utxo, 5).is_err());
    }

    #[test]
    fn three_party_exit_then_sub_exit() {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, 30_000))
            .add_participant(make_participant(2, 30_000))
            .add_participant(make_participant(3, 40_000))
            .build()
            .unwrap();

        let pool_utxo = make_outpoint(99);

        // Alice exits from 3-party pool
        let exit_tx = build_exit_transaction(&pool, pool_utxo, 0).unwrap();
        assert_eq!(exit_tx.output.len(), 2);
        assert_eq!(exit_tx.output[0].value, Amount::from_sat(30_000)); // Alice
        assert_eq!(exit_tx.output[1].value, Amount::from_sat(70_000)); // Sub-pool

        // The sub-pool UTXO can be used for further exits
        let sub_pool = pool.simulate_exit(0).unwrap().unwrap();
        let sub_pool_utxo = OutPoint {
            txid: exit_tx.compute_txid(),
            vout: 1, // sub-pool is the second output
        };

        // Bob exits from 2-party sub-pool
        let sub_exit_tx = build_exit_transaction(&sub_pool, sub_pool_utxo, 0).unwrap();
        assert_eq!(sub_exit_tx.output.len(), 2);
        assert_eq!(sub_exit_tx.output[0].value, Amount::from_sat(30_000)); // Bob
        assert_eq!(sub_exit_tx.output[1].value, Amount::from_sat(40_000)); // Carol
    }
}
