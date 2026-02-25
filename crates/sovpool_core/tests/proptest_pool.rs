//! Property-based tests for pool invariants.
//!
//! Uses proptest to verify that critical pool properties hold
//! across a wide range of inputs.

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network};
use proptest::prelude::*;
use sovpool_core::pool::{Participant, PoolBuilder};
use sovpool_core::tx::{build_exit_transaction, verify_exit_transaction};

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

proptest! {
    /// Every participant in a pool always has a valid exit path.
    #[test]
    fn every_participant_has_valid_exit_path(
        n in 2usize..=5,
        amount in 10_000u64..=1_000_000,
    ) {
        let participants: Vec<Participant> = (1..=n)
            .map(|i| make_participant(i as u8, amount))
            .collect();

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participants(participants)
            .build()
            .unwrap();

        // Every participant must have an exit path
        prop_assert_eq!(pool.exit_paths().paths.len(), n);

        for i in 0..n {
            let path = pool.exit_path(i).unwrap();
            prop_assert_eq!(path.participant_index, i);
            prop_assert!(!path.outputs.is_empty());
            prop_assert!(path.ctv_hash != [0u8; 32]);
        }
    }

    /// Exit path CTV hashes are all unique within a pool.
    #[test]
    fn exit_paths_have_unique_hashes(
        n in 2usize..=5,
        amount in 10_000u64..=1_000_000,
    ) {
        let participants: Vec<Participant> = (1..=n)
            .map(|i| make_participant(i as u8, amount))
            .collect();

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participants(participants)
            .build()
            .unwrap();

        let hashes: Vec<[u8; 32]> = pool.exit_paths().paths.iter().map(|p| p.ctv_hash).collect();
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                prop_assert_ne!(hashes[i], hashes[j],
                    "exit paths {} and {} should have different CTV hashes", i, j);
            }
        }
    }

    /// Pool total is always the sum of participant amounts.
    #[test]
    fn pool_total_is_sum_of_amounts(
        amounts in prop::collection::vec(10_000u64..=1_000_000, 2..=5),
    ) {
        let participants: Vec<Participant> = amounts
            .iter()
            .enumerate()
            .map(|(i, &amount)| make_participant((i + 1) as u8, amount))
            .collect();

        let expected_total: u64 = amounts.iter().sum();

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participants(participants)
            .build()
            .unwrap();

        prop_assert_eq!(pool.total_sats(), expected_total);
    }

    /// Exit transaction outputs match the CTV commitment.
    #[test]
    fn exit_tx_matches_commitment(
        n in 2usize..=6,
        amount in 10_000u64..=1_000_000,
        exit_idx in 0usize..6,
    ) {
        let exit_idx = exit_idx % n; // ensure valid index

        let participants: Vec<Participant> = (1..=n)
            .map(|i| make_participant(i as u8, amount))
            .collect();

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participants(participants)
            .build()
            .unwrap();

        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([99u8; 32]),
            vout: 0,
        };

        let exit_tx = build_exit_transaction(&pool, outpoint, exit_idx).unwrap();
        let exit_path = pool.exit_path(exit_idx).unwrap();

        prop_assert!(
            verify_exit_transaction(exit_path, &exit_tx, pool.tx_version()).unwrap(),
            "exit tx should match CTV commitment for participant {}", exit_idx
        );
    }

    /// Sequential exits always reduce pool size by 1.
    #[test]
    fn sequential_exits_reduce_pool(
        n in 3usize..=5,
        amount in 10_000u64..=500_000,
    ) {
        let participants: Vec<Participant> = (1..=n)
            .map(|i| make_participant(i as u8, amount))
            .collect();

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participants(participants)
            .build()
            .unwrap();

        let mut current_pool = pool;

        // Exit participants one by one
        for round in 0..(n - 2) {
            let sub_pool = current_pool.simulate_exit(0).unwrap();
            prop_assert!(sub_pool.is_some(), "sub-pool should exist for round {}", round);
            let sub_pool = sub_pool.unwrap();
            prop_assert_eq!(sub_pool.participants().len(), current_pool.participants().len() - 1);
            current_pool = sub_pool;
        }

        // Final exit: 2-party pool → None
        let final_result = current_pool.simulate_exit(0).unwrap();
        prop_assert!(final_result.is_none(), "2-party exit should yield None");
    }

    /// CTV hash is deterministic — same inputs always produce same hash.
    #[test]
    fn ctv_hash_deterministic(
        amount_a in 10_000u64..=1_000_000,
        amount_b in 10_000u64..=1_000_000,
    ) {
        let pool1 = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, amount_a))
            .add_participant(make_participant(2, amount_b))
            .build()
            .unwrap();

        let pool2 = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(make_participant(1, amount_a))
            .add_participant(make_participant(2, amount_b))
            .build()
            .unwrap();

        for i in 0..2 {
            prop_assert_eq!(
                pool1.exit_paths().paths[i].ctv_hash,
                pool2.exit_paths().paths[i].ctv_hash,
                "CTV hashes should be deterministic for participant {}", i
            );
        }
    }
}
