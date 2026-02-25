//! End-to-end regtest integration tests.
//!
//! These tests require a CTV-enabled bitcoind (Bitcoin Inquisition).
//! Run with: cargo test -p sovpool_test --features ctv-regtest
//!
//! Set SOVPOOL_BITCOIND env var to the path of the bitcoind binary,
//! or place it in the system PATH.

#![cfg(feature = "ctv-regtest")]

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network};
use bitcoincore_rpc::RpcApi;
use sovpool_core::pool::{Participant, PoolBuilder};
use sovpool_core::tx::{build_exit_transaction, verify_exit_transaction};
use sovpool_test::harness::TestHarness;
use sovpool_test::inquisition;

fn find_bitcoind() -> std::path::PathBuf {
    let cache_dir = std::env::temp_dir().join("sovpool_cache");
    inquisition::find_bitcoind(&cache_dir)
        .expect("bitcoind not found. Set SOVPOOL_BITCOIND or install Bitcoin Inquisition")
}

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

/// End-to-end 2-party test:
/// fund pool → mine → exit Alice → mine → verify Alice's UTXO → exit Bob → verify
#[test]
#[ignore = "run individually: CI runs five_party_sequential_exits as the primary regtest test"]
fn two_party_pool_end_to_end() {
    let bitcoind = find_bitcoind();
    let harness = TestHarness::new(&bitcoind).unwrap();

    let alice = make_participant(1, 50_000);
    let bob = make_participant(2, 50_000);

    let (pool, pool_utxo) = harness
        .create_funded_pool_2party(50_000, 50_000, alice, bob)
        .unwrap();

    // Verify pool UTXO exists
    let utxo = harness.get_utxo(&pool_utxo).unwrap();
    assert!(utxo.is_some(), "pool UTXO should exist after funding");

    // Alice exits
    let exit_txid = harness.exit_participant(&pool, pool_utxo, 0).unwrap();
    assert!(exit_txid.to_string().len() == 64, "valid txid returned");

    // Pool UTXO should be spent
    let spent = harness.get_utxo(&pool_utxo).unwrap();
    assert!(spent.is_none(), "pool UTXO should be spent after exit");

    // Bob's output (second output of exit tx) should exist
    let bob_utxo = bitcoin::OutPoint {
        txid: exit_txid,
        vout: 1,
    };
    let bob_output = harness.get_utxo(&bob_utxo).unwrap();
    assert!(
        bob_output.is_some(),
        "Bob's UTXO should exist after Alice exits"
    );
}

/// End-to-end 3-party test with sequential exits through recursive sub-pools.
#[test]
#[ignore = "run individually: CI runs five_party_sequential_exits as the primary regtest test"]
fn three_party_sequential_exits() {
    let bitcoind = find_bitcoind();
    let harness = TestHarness::new(&bitcoind).unwrap();

    let alice = make_participant(1, 30_000);
    let bob = make_participant(2, 30_000);
    let carol = make_participant(3, 40_000);

    let pool = PoolBuilder::new()
        .with_network(Network::Regtest)
        .add_participant(alice)
        .add_participant(bob)
        .add_participant(carol)
        .build()
        .unwrap();

    let total = bitcoin::Amount::from_sat(100_000);
    let fund_txid = harness.fund_address(&pool.pool_address(), total).unwrap();

    let fund_tx = harness
        .node
        .client
        .get_raw_transaction(&fund_txid, None)
        .unwrap();
    let vout = fund_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == pool.pool_address().script_pubkey())
        .unwrap() as u32;

    let pool_utxo = bitcoin::OutPoint {
        txid: fund_txid,
        vout,
    };

    // Alice exits from 3-party pool
    let exit_tx = build_exit_transaction(&pool, pool_utxo, 0).unwrap();
    let exit_path = pool.exit_path(0).unwrap();
    assert!(verify_exit_transaction(exit_path, &exit_tx, pool.tx_version()).unwrap());

    let exit_txid = harness.send_and_mine(&exit_tx).unwrap();

    // Sub-pool UTXO (output 1) should exist
    let sub_pool_utxo = bitcoin::OutPoint {
        txid: exit_txid,
        vout: 1,
    };
    let sub_utxo = harness.get_utxo(&sub_pool_utxo).unwrap();
    assert!(sub_utxo.is_some(), "sub-pool UTXO should exist");

    // Build 2-party sub-pool (Bob + Carol)
    let sub_pool = pool.simulate_exit(0).unwrap().unwrap();

    // Bob exits from 2-party sub-pool
    let sub_exit_tx = build_exit_transaction(&sub_pool, sub_pool_utxo, 0).unwrap();
    let sub_exit_txid = harness.send_and_mine(&sub_exit_tx).unwrap();

    // Carol's output should exist
    let carol_utxo = bitcoin::OutPoint {
        txid: sub_exit_txid,
        vout: 1,
    };
    let carol_output = harness.get_utxo(&carol_utxo).unwrap();
    assert!(carol_output.is_some(), "Carol's UTXO should exist");
}

/// End-to-end 5-party test with sequential exits.
#[test]
fn five_party_sequential_exits() {
    let bitcoind = find_bitcoind();
    let harness = TestHarness::new(&bitcoind).unwrap();

    let participants: Vec<Participant> = (1..=5).map(|i| make_participant(i, 20_000)).collect();

    let pool = PoolBuilder::new()
        .with_network(Network::Regtest)
        .add_participants(participants)
        .build()
        .unwrap();

    let total = bitcoin::Amount::from_sat(100_000);
    let fund_txid = harness.fund_address(&pool.pool_address(), total).unwrap();

    let fund_tx = harness
        .node
        .client
        .get_raw_transaction(&fund_txid, None)
        .unwrap();
    let vout = fund_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == pool.pool_address().script_pubkey())
        .unwrap() as u32;

    let mut current_pool = pool;
    let mut current_utxo = bitcoin::OutPoint {
        txid: fund_txid,
        vout,
    };

    // Sequential exits: participant 0 exits each round
    // 5 → 4 → 3 → 2 → done
    for round in 0..3 {
        let exit_tx = build_exit_transaction(&current_pool, current_utxo, 0).unwrap();
        let exit_txid = harness.send_and_mine(&exit_tx).unwrap();

        // Sub-pool is output 1
        let sub_pool_utxo = bitcoin::OutPoint {
            txid: exit_txid,
            vout: 1,
        };

        let sub_pool = current_pool.simulate_exit(0).unwrap().unwrap();
        assert_eq!(
            sub_pool.participants().len(),
            4 - round,
            "round {round}: wrong participant count"
        );

        current_pool = sub_pool;
        current_utxo = sub_pool_utxo;
    }

    // Final round: 2-party pool, last exit
    let final_exit = build_exit_transaction(&current_pool, current_utxo, 0).unwrap();
    let final_txid = harness.send_and_mine(&final_exit).unwrap();

    // Last participant's output (vout 1) should exist
    let last_utxo = bitcoin::OutPoint {
        txid: final_txid,
        vout: 1,
    };
    let last_output = harness.get_utxo(&last_utxo).unwrap();
    assert!(
        last_output.is_some(),
        "last participant's UTXO should exist"
    );
}
