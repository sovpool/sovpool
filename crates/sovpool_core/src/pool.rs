use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Address, Amount, Network, ScriptBuf, TxOut};
use serde::{Deserialize, Serialize};

use crate::cooperative::build_cooperative_script;
use crate::covenant::{build_taproot_with_extra_leaves, compute_ctv_hash, ctv_script};
use crate::error::{Result, SovpoolError};
use crate::exit::{ExitPath, ExitPathSet};
use crate::timeout::{csv_recovery_script, TimeoutConfig};

fn ser_address<S: serde::Serializer>(addr: &Address, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&addr.to_string())
}

fn de_address<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Address, D::Error> {
    let s: String = Deserialize::deserialize(d)?;
    let unchecked: Address<bitcoin::address::NetworkUnchecked> =
        s.parse().map_err(serde::de::Error::custom)?;
    Ok(unchecked.assume_checked())
}

/// A participant in a CTV payment pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub pubkey: XOnlyPublicKey,
    pub withdrawal_address: Address<bitcoin::address::NetworkUnchecked>,
    pub amount_sats: u64,
}

impl Participant {
    pub fn new(
        pubkey: XOnlyPublicKey,
        withdrawal_address: Address<bitcoin::address::NetworkUnchecked>,
        amount_sats: u64,
    ) -> Self {
        Self {
            pubkey,
            withdrawal_address,
            amount_sats,
        }
    }

    /// Create the TxOut for this participant's withdrawal.
    pub fn withdrawal_output(&self, _network: Network) -> Result<TxOut> {
        let address = self.withdrawal_address.clone().assume_checked_ref().clone();
        Ok(TxOut {
            value: Amount::from_sat(self.amount_sats),
            script_pubkey: address.script_pubkey(),
        })
    }
}

/// Pool lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoolState {
    Unfunded,
    Active,
    PartiallyExited,
    FullyExited,
}

/// A CTV payment pool — shared UTXO with unilateral exit paths.
///
/// The pool is a single UTXO locked under a taproot tree where each leaf
/// contains a CTV-committed exit transaction for one participant.
///
/// Fields are private to prevent external mutation that could corrupt
/// the taproot tree invariant. Use accessor methods for read access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pool {
    participants: Vec<Participant>,
    state: PoolState,
    network: Network,
    tx_version: i32,
    /// The taproot address of the pool UTXO.
    #[serde(serialize_with = "ser_address", deserialize_with = "de_address")]
    pool_address: Address,
    /// Exit paths for each participant.
    exit_paths: ExitPathSet,
    /// The taproot spend info for script-path spending.
    #[serde(skip)]
    taproot_spend_info: Option<bitcoin::taproot::TaprootSpendInfo>,
    /// Whether this pool uses P2A anchor outputs.
    use_anchor: bool,
    /// Anchor output value in satoshis.
    anchor_sats: u64,
    /// Optional CSV timeout in blocks for recovery paths.
    timeout_blocks: Option<u16>,
}

impl Pool {
    /// Pool participants.
    pub fn participants(&self) -> &[Participant] {
        &self.participants
    }

    /// Current pool state.
    pub fn state(&self) -> PoolState {
        self.state
    }

    /// Network this pool operates on.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Transaction version.
    pub fn tx_version(&self) -> i32 {
        self.tx_version
    }

    /// The taproot address of the pool UTXO.
    pub fn pool_address(&self) -> &Address {
        &self.pool_address
    }

    /// Exit paths for each participant.
    pub fn exit_paths(&self) -> &ExitPathSet {
        &self.exit_paths
    }

    /// The taproot spend info for script-path spending.
    ///
    /// Returns `None` if the pool was deserialized (taproot_spend_info is not serializable).
    /// Call `rebuild_taproot()` to recompute it after deserialization.
    pub fn taproot_spend_info(&self) -> Option<&bitcoin::taproot::TaprootSpendInfo> {
        self.taproot_spend_info.as_ref()
    }

    /// Whether this pool uses P2A anchor outputs.
    pub fn use_anchor(&self) -> bool {
        self.use_anchor
    }

    /// Anchor output value in satoshis.
    pub fn anchor_sats(&self) -> u64 {
        self.anchor_sats
    }

    /// CSV timeout in blocks, if enabled.
    pub fn timeout_blocks(&self) -> Option<u16> {
        self.timeout_blocks
    }

    /// Total value of the pool in satoshis.
    pub fn total_sats(&self) -> u64 {
        self.participants.iter().map(|p| p.amount_sats).sum()
    }

    /// Get the exit path for a specific participant.
    pub fn exit_path(&self, participant_index: usize) -> Result<&ExitPath> {
        self.exit_paths
            .paths
            .get(participant_index)
            .ok_or_else(|| SovpoolError::InvalidParticipantCount(participant_index))
    }

    /// Rebuild taproot spend info (e.g. after deserialization).
    pub fn rebuild_taproot(&mut self) -> Result<()> {
        let ctv_scripts: Vec<ScriptBuf> = self
            .exit_paths
            .paths
            .iter()
            .map(|ep| ep.ctv_script.clone())
            .collect();
        let pubkeys: Vec<XOnlyPublicKey> = self.participants.iter().map(|p| p.pubkey).collect();
        let cooperative_script = build_cooperative_script(&pubkeys)?;
        let mut extra_leaves = vec![cooperative_script];
        if let Some(blocks) = self.timeout_blocks {
            let timeout_config = TimeoutConfig::new(blocks);
            for participant in &self.participants {
                extra_leaves.push(csv_recovery_script(&timeout_config, &participant.pubkey));
            }
        }
        let spend_info = build_taproot_with_extra_leaves(&ctv_scripts, &extra_leaves)?;
        self.taproot_spend_info = Some(spend_info);
        Ok(())
    }

    /// Simulate a participant exiting, returning the reduced pool (if participants remain).
    ///
    /// For a 2-party pool, exit by one participant means the other gets their
    /// funds directly — no sub-pool needed.
    /// For N-party (N > 2), exit creates a (N-1)-party sub-pool.
    pub fn simulate_exit(&self, participant_index: usize) -> Result<Option<Pool>> {
        if participant_index >= self.participants.len() {
            return Err(SovpoolError::InvalidParticipantCount(participant_index));
        }

        let remaining: Vec<Participant> = self
            .participants
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != participant_index)
            .map(|(_, p)| p.clone())
            .collect();

        if remaining.len() < 2 {
            // Last participant gets funds directly — no sub-pool
            return Ok(None);
        }

        // Build a new pool with remaining participants (inheriting anchor + timeout config)
        let mut builder = PoolBuilder::new()
            .with_network(self.network)
            .with_tx_version(self.tx_version)
            .add_participants(remaining);
        if self.use_anchor {
            builder = builder.with_anchor(self.anchor_sats);
        }
        if let Some(blocks) = self.timeout_blocks {
            builder = builder.with_timeout(blocks);
        }
        let sub_pool = builder.build()?;

        Ok(Some(sub_pool))
    }
}

/// Builder for incremental pool construction.
#[derive(Debug)]
pub struct PoolBuilder {
    participants: Vec<Participant>,
    network: Network,
    tx_version: i32,
    /// Whether to include a P2A anchor output in each exit path for CPFP fee bumping.
    use_anchor: bool,
    /// Anchor output value in satoshis (deducted from exiting participant's withdrawal).
    anchor_sats: u64,
    /// Optional CSV timeout for recovery paths (in blocks).
    timeout_blocks: Option<u16>,
}

impl PoolBuilder {
    pub fn new() -> Self {
        Self {
            participants: Vec::new(),
            network: Network::Regtest,
            tx_version: 2,
            use_anchor: false,
            anchor_sats: 0,
            timeout_blocks: None,
        }
    }

    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub fn with_tx_version(mut self, version: i32) -> Self {
        self.tx_version = version;
        self
    }

    pub fn add_participant(mut self, participant: Participant) -> Self {
        self.participants.push(participant);
        self
    }

    pub fn add_participants(mut self, participants: Vec<Participant>) -> Self {
        self.participants.extend(participants);
        self
    }

    /// Enable P2A anchor outputs for CPFP fee bumping.
    ///
    /// Each exit path will include an anyone-can-spend anchor output.
    /// The anchor cost is deducted from the exiting participant's withdrawal.
    /// Required for broadcasting on networks with non-zero relay fees.
    pub fn with_anchor(mut self, anchor_sats: u64) -> Self {
        self.use_anchor = true;
        self.anchor_sats = anchor_sats;
        self
    }

    /// Enable CSV timeout recovery paths.
    ///
    /// After `blocks` confirmations, each participant can sweep their
    /// share using only their own key (no cooperation needed).
    /// This protects against permanently offline participants.
    pub fn with_timeout(mut self, blocks: u16) -> Self {
        self.timeout_blocks = Some(blocks);
        self
    }

    /// Build the pool. Requires at least 2 participants.
    ///
    /// Constructs:
    /// 1. Exit paths for each participant (CTV-committed transactions)
    /// 2. N-of-N cooperative spending leaf (CHECKSIGADD)
    /// 3. Taproot script tree with cooperative + exit leaves
    /// 4. Pool address (taproot output)
    pub fn build(self) -> Result<Pool> {
        let n = self.participants.len();
        if n < 2 {
            return Err(SovpoolError::InvalidParticipantCount(n));
        }

        // Build exit paths and CTV scripts for each participant
        let exit_paths = self.build_exit_paths()?;
        let ctv_scripts: Vec<ScriptBuf> = exit_paths
            .paths
            .iter()
            .map(|ep| ep.ctv_script.clone())
            .collect();

        // Build N-of-N cooperative spending leaf
        let pubkeys: Vec<XOnlyPublicKey> = self.participants.iter().map(|p| p.pubkey).collect();
        let cooperative_script = build_cooperative_script(&pubkeys)?;

        // Build extra leaves: cooperative + optional timeout recovery
        let mut extra_leaves = vec![cooperative_script];
        if let Some(blocks) = self.timeout_blocks {
            let timeout_config = TimeoutConfig::new(blocks);
            for participant in &self.participants {
                extra_leaves.push(csv_recovery_script(&timeout_config, &participant.pubkey));
            }
        }

        // Build taproot tree with extra leaves + CTV exit leaves
        let taproot_spend_info = build_taproot_with_extra_leaves(&ctv_scripts, &extra_leaves)?;
        let pool_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), self.network);

        Ok(Pool {
            participants: self.participants,
            state: PoolState::Unfunded,
            network: self.network,
            tx_version: self.tx_version,
            pool_address,
            exit_paths,
            taproot_spend_info: Some(taproot_spend_info),
            use_anchor: self.use_anchor,
            anchor_sats: self.anchor_sats,
            timeout_blocks: self.timeout_blocks,
        })
    }

    /// Build exit paths for all participants.
    ///
    /// For each participant i:
    /// - Output 0: participant i's withdrawal (their amount to their address)
    /// - Output 1 (if N > 2): sub-pool UTXO for remaining N-1 participants
    /// - Output 1 (if N == 2): direct payment to the other participant
    fn build_exit_paths(&self) -> Result<ExitPathSet> {
        let n = self.participants.len();
        let mut paths = Vec::with_capacity(n);

        for exit_idx in 0..n {
            let outputs = self.build_exit_outputs(exit_idx)?;
            let ctv_hash = compute_ctv_hash(&outputs, self.tx_version);
            let script = ctv_script(ctv_hash);

            paths.push(ExitPath {
                participant_index: exit_idx,
                outputs: outputs.clone(),
                ctv_hash,
                ctv_script: script,
            });
        }

        Ok(ExitPathSet { paths })
    }

    /// Build the outputs for when participant `exit_idx` exits.
    fn build_exit_outputs(&self, exit_idx: usize) -> Result<Vec<TxOut>> {
        let exiting = &self.participants[exit_idx];
        let mut outputs = Vec::new();

        // Output 0: exiting participant's withdrawal (minus anchor cost if enabled)
        let withdrawal_amount = if self.use_anchor {
            exiting
                .amount_sats
                .checked_sub(self.anchor_sats)
                .ok_or_else(|| {
                    SovpoolError::TxError(format!(
                        "participant {} amount ({}) less than anchor cost ({})",
                        exit_idx, exiting.amount_sats, self.anchor_sats
                    ))
                })?
        } else {
            exiting.amount_sats
        };

        let address = exiting
            .withdrawal_address
            .clone()
            .assume_checked_ref()
            .clone();
        outputs.push(TxOut {
            value: Amount::from_sat(withdrawal_amount),
            script_pubkey: address.script_pubkey(),
        });

        // Remaining participants
        let remaining: Vec<&Participant> = self
            .participants
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != exit_idx)
            .map(|(_, p)| p)
            .collect();

        if remaining.len() == 1 {
            // 2-party pool: other participant gets direct payment
            let other = remaining[0];
            outputs.push(other.withdrawal_output(self.network)?);
        } else {
            // N-party (N > 2): create sub-pool UTXO for remaining participants
            let sub_pool_amount: u64 = remaining.iter().map(|p| p.amount_sats).sum();
            let sub_pool_participants: Vec<Participant> = remaining.into_iter().cloned().collect();

            // Recursively compute the sub-pool address (sub-pools inherit anchor + timeout config)
            let mut sub_builder = PoolBuilder::new()
                .with_network(self.network)
                .with_tx_version(self.tx_version)
                .add_participants(sub_pool_participants);
            if self.use_anchor {
                sub_builder = sub_builder.with_anchor(self.anchor_sats);
            }
            if let Some(blocks) = self.timeout_blocks {
                sub_builder = sub_builder.with_timeout(blocks);
            }
            let sub_pool = sub_builder.build()?;

            outputs.push(TxOut {
                value: Amount::from_sat(sub_pool_amount),
                script_pubkey: sub_pool.pool_address().script_pubkey(),
            });
        }

        // Anchor output (last): P2A anyone-can-spend for CPFP
        if self.use_anchor {
            outputs.push(crate::fees::p2a_anchor_output());
        }

        Ok(outputs)
    }
}

impl Default for PoolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn make_participant(seed: u8, amount: u64, network: Network) -> Participant {
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        secret_bytes[31] = seed;
        secret_bytes[0] = 0x01; // ensure valid scalar
        let sk = SecretKey::from_slice(&secret_bytes).unwrap();
        let (pubkey, _) = sk.x_only_public_key(&secp);

        // Create a simple p2tr address
        let address = Address::p2tr(&secp, pubkey, None, network);
        let unchecked = address.to_string().parse().unwrap();

        Participant::new(pubkey, unchecked, amount)
    }

    #[test]
    fn two_party_pool_construction() {
        let alice = make_participant(1, 50_000, Network::Regtest);
        let bob = make_participant(2, 50_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice)
            .add_participant(bob)
            .build()
            .unwrap();

        assert_eq!(pool.participants().len(), 2);
        assert_eq!(pool.total_sats(), 100_000);
        assert_eq!(pool.state(), PoolState::Unfunded);
        assert_eq!(pool.exit_paths().paths.len(), 2);
        assert!(pool.pool_address().to_string().starts_with("bcrt1p"));
    }

    #[test]
    fn two_party_exit_paths_have_two_outputs() {
        let alice = make_participant(1, 50_000, Network::Regtest);
        let bob = make_participant(2, 50_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice)
            .add_participant(bob)
            .build()
            .unwrap();

        // Each exit path should have 2 outputs:
        // - exiting participant's withdrawal
        // - other participant's direct payment
        for path in &pool.exit_paths().paths {
            assert_eq!(path.outputs.len(), 2);
        }
    }

    #[test]
    fn two_party_exit_amounts_correct() {
        let alice = make_participant(1, 60_000, Network::Regtest);
        let bob = make_participant(2, 40_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice)
            .add_participant(bob)
            .build()
            .unwrap();

        // Alice exits: output[0] = 60k (Alice), output[1] = 40k (Bob)
        let alice_exit = &pool.exit_paths().paths[0];
        assert_eq!(alice_exit.outputs[0].value, Amount::from_sat(60_000));
        assert_eq!(alice_exit.outputs[1].value, Amount::from_sat(40_000));

        // Bob exits: output[0] = 40k (Bob), output[1] = 60k (Alice)
        let bob_exit = &pool.exit_paths().paths[1];
        assert_eq!(bob_exit.outputs[0].value, Amount::from_sat(40_000));
        assert_eq!(bob_exit.outputs[1].value, Amount::from_sat(60_000));
    }

    #[test]
    fn three_party_pool_construction() {
        let alice = make_participant(1, 30_000, Network::Regtest);
        let bob = make_participant(2, 30_000, Network::Regtest);
        let carol = make_participant(3, 40_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice)
            .add_participant(bob)
            .add_participant(carol)
            .build()
            .unwrap();

        assert_eq!(pool.participants().len(), 3);
        assert_eq!(pool.total_sats(), 100_000);
        assert_eq!(pool.exit_paths().paths.len(), 3);
    }

    #[test]
    fn three_party_exit_has_sub_pool() {
        let alice = make_participant(1, 30_000, Network::Regtest);
        let bob = make_participant(2, 30_000, Network::Regtest);
        let carol = make_participant(3, 40_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice)
            .add_participant(bob)
            .add_participant(carol)
            .build()
            .unwrap();

        // Alice exits: output[0] = 30k (Alice), output[1] = 70k (Bob+Carol sub-pool)
        let alice_exit = &pool.exit_paths().paths[0];
        assert_eq!(alice_exit.outputs.len(), 2);
        assert_eq!(alice_exit.outputs[0].value, Amount::from_sat(30_000));
        assert_eq!(alice_exit.outputs[1].value, Amount::from_sat(70_000));
    }

    #[test]
    fn simulate_exit_two_party() {
        let alice = make_participant(1, 50_000, Network::Regtest);
        let bob = make_participant(2, 50_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice)
            .add_participant(bob)
            .build()
            .unwrap();

        // Alice exits a 2-party pool → no sub-pool
        let sub_pool = pool.simulate_exit(0).unwrap();
        assert!(sub_pool.is_none());
    }

    #[test]
    fn simulate_exit_three_party() {
        let alice = make_participant(1, 30_000, Network::Regtest);
        let bob = make_participant(2, 30_000, Network::Regtest);
        let carol = make_participant(3, 40_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice)
            .add_participant(bob)
            .add_participant(carol)
            .build()
            .unwrap();

        // Alice exits → 2-party sub-pool (Bob + Carol)
        let sub_pool = pool.simulate_exit(0).unwrap().unwrap();
        assert_eq!(sub_pool.participants().len(), 2);
        assert_eq!(sub_pool.total_sats(), 70_000);
    }

    #[test]
    fn five_party_pool_construction() {
        let participants: Vec<Participant> = (1..=5)
            .map(|i| make_participant(i, 20_000, Network::Regtest))
            .collect();

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participants(participants)
            .build()
            .unwrap();

        assert_eq!(pool.participants().len(), 5);
        assert_eq!(pool.total_sats(), 100_000);
        assert_eq!(pool.exit_paths().paths.len(), 5);
    }

    #[test]
    fn five_party_sequential_exits() {
        let participants: Vec<Participant> = (1..=5)
            .map(|i| make_participant(i, 20_000, Network::Regtest))
            .collect();

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participants(participants)
            .build()
            .unwrap();

        // Exit participant 0: 5 → 4 party
        let pool4 = pool.simulate_exit(0).unwrap().unwrap();
        assert_eq!(pool4.participants().len(), 4);
        assert_eq!(pool4.total_sats(), 80_000);

        // Exit participant 0 from 4-party: 4 → 3 party
        let pool3 = pool4.simulate_exit(0).unwrap().unwrap();
        assert_eq!(pool3.participants().len(), 3);
        assert_eq!(pool3.total_sats(), 60_000);

        // Exit participant 0 from 3-party: 3 → 2 party
        let pool2 = pool3.simulate_exit(0).unwrap().unwrap();
        assert_eq!(pool2.participants().len(), 2);
        assert_eq!(pool2.total_sats(), 40_000);

        // Exit participant 0 from 2-party: → None (last participant gets funds directly)
        let none = pool2.simulate_exit(0).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn two_party_pool_with_anchor() {
        let alice = make_participant(1, 50_000, Network::Regtest);
        let bob = make_participant(2, 50_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .with_anchor(240)
            .add_participant(alice)
            .add_participant(bob)
            .build()
            .unwrap();

        assert!(pool.use_anchor());
        assert_eq!(pool.anchor_sats(), 240);

        // Alice exits: 3 outputs (withdrawal, bob, anchor)
        let alice_exit = &pool.exit_paths().paths[0];
        assert_eq!(alice_exit.outputs.len(), 3);
        assert_eq!(alice_exit.outputs[0].value, Amount::from_sat(49_760)); // 50k - 240
        assert_eq!(alice_exit.outputs[1].value, Amount::from_sat(50_000)); // Bob direct
        assert_eq!(alice_exit.outputs[2].value, Amount::from_sat(240)); // anchor

        // Total outputs = pool total
        let total: u64 = alice_exit.outputs.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(total, 100_000);
    }

    #[test]
    fn three_party_pool_with_anchor() {
        let alice = make_participant(1, 30_000, Network::Regtest);
        let bob = make_participant(2, 30_000, Network::Regtest);
        let carol = make_participant(3, 40_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .with_anchor(240)
            .add_participant(alice)
            .add_participant(bob)
            .add_participant(carol)
            .build()
            .unwrap();

        // Alice exits: 3 outputs (withdrawal, sub-pool, anchor)
        let alice_exit = &pool.exit_paths().paths[0];
        assert_eq!(alice_exit.outputs.len(), 3);
        assert_eq!(alice_exit.outputs[0].value, Amount::from_sat(29_760)); // 30k - 240
        assert_eq!(alice_exit.outputs[1].value, Amount::from_sat(70_000)); // sub-pool
        assert_eq!(alice_exit.outputs[2].value, Amount::from_sat(240)); // anchor

        let total: u64 = alice_exit.outputs.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(total, 100_000);
    }

    #[test]
    fn anchor_pool_simulate_exit_inherits_anchor() {
        let alice = make_participant(1, 30_000, Network::Regtest);
        let bob = make_participant(2, 30_000, Network::Regtest);
        let carol = make_participant(3, 40_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .with_anchor(240)
            .add_participant(alice)
            .add_participant(bob)
            .add_participant(carol)
            .build()
            .unwrap();

        // Simulate Alice exiting -> Bob+Carol sub-pool
        let sub_pool = pool.simulate_exit(0).unwrap().unwrap();
        assert!(sub_pool.use_anchor());
        assert_eq!(sub_pool.anchor_sats(), 240);
        assert_eq!(sub_pool.participants().len(), 2);

        // Bob exits sub-pool: 3 outputs (withdrawal, carol, anchor)
        let bob_exit = &sub_pool.exit_paths().paths[0];
        assert_eq!(bob_exit.outputs.len(), 3);
        assert_eq!(bob_exit.outputs[0].value, Amount::from_sat(29_760)); // 30k - 240
        assert_eq!(bob_exit.outputs[1].value, Amount::from_sat(40_000)); // Carol direct
        assert_eq!(bob_exit.outputs[2].value, Amount::from_sat(240)); // anchor

        let total: u64 = bob_exit.outputs.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(total, 70_000);
    }

    #[test]
    fn single_participant_rejected() {
        let alice = make_participant(1, 50_000, Network::Regtest);

        let result = PoolBuilder::new().add_participant(alice).build();

        assert!(result.is_err());
    }

    #[test]
    fn cooperative_leaf_in_taproot_tree() {
        let alice = make_participant(1, 50_000, Network::Regtest);
        let bob = make_participant(2, 50_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice.clone())
            .add_participant(bob.clone())
            .build()
            .unwrap();

        let spend_info = pool
            .taproot_spend_info()
            .expect("should have taproot spend info");

        // Build the expected cooperative script
        let pubkeys: Vec<XOnlyPublicKey> = vec![alice.pubkey, bob.pubkey];
        let cooperative_script = crate::cooperative::build_cooperative_script(&pubkeys).unwrap();

        // The cooperative script should be findable in the taproot tree
        let script_ver = (cooperative_script, bitcoin::taproot::LeafVersion::TapScript);
        let control_block = spend_info.control_block(&script_ver);
        assert!(
            control_block.is_some(),
            "cooperative N-of-N leaf must exist in taproot tree"
        );
    }

    #[test]
    fn cooperative_leaf_in_three_party_pool() {
        let participants: Vec<Participant> = (1..=3)
            .map(|i| make_participant(i, 30_000, Network::Regtest))
            .collect();

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participants(participants.clone())
            .build()
            .unwrap();

        let spend_info = pool.taproot_spend_info().unwrap();
        let pubkeys: Vec<XOnlyPublicKey> = participants.iter().map(|p| p.pubkey).collect();
        let cooperative_script = crate::cooperative::build_cooperative_script(&pubkeys).unwrap();

        let script_ver = (cooperative_script, bitcoin::taproot::LeafVersion::TapScript);
        assert!(
            spend_info.control_block(&script_ver).is_some(),
            "3-party cooperative leaf must exist in taproot tree"
        );
    }

    #[test]
    fn timeout_leaf_in_taproot_tree() {
        let alice = make_participant(1, 50_000, Network::Regtest);
        let bob = make_participant(2, 50_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .with_timeout(144)
            .add_participant(alice.clone())
            .add_participant(bob.clone())
            .build()
            .unwrap();

        assert_eq!(pool.timeout_blocks(), Some(144));

        let spend_info = pool.taproot_spend_info().unwrap();
        let timeout_config = crate::timeout::TimeoutConfig::new(144);

        // Each participant should have a timeout recovery leaf
        for participant in pool.participants() {
            let recovery_script =
                crate::timeout::csv_recovery_script(&timeout_config, &participant.pubkey);
            let script_ver = (recovery_script, bitcoin::taproot::LeafVersion::TapScript);
            assert!(
                spend_info.control_block(&script_ver).is_some(),
                "timeout recovery leaf must exist for each participant"
            );
        }
    }

    #[test]
    fn timeout_script_csv_value_correct() {
        let timeout_config = crate::timeout::TimeoutConfig::new(144);
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        secret_bytes[31] = 1;
        secret_bytes[0] = 0x01;
        let sk = SecretKey::from_slice(&secret_bytes).unwrap();
        let (pubkey, _) = sk.x_only_public_key(&secp);

        let script = crate::timeout::csv_recovery_script(&timeout_config, &pubkey);
        let bytes = script.as_bytes();

        // Script: <144> OP_CSV OP_DROP <pubkey> OP_CHECKSIG
        // 144 = 0x0090 in little-endian, pushed as 2-byte integer
        // Verify OP_CSV (0xb2) is present
        assert!(
            bytes.iter().any(|&b| b == 0xb2),
            "script must contain OP_CSV"
        );
        // Verify OP_CHECKSIG (0xac) is present
        assert!(
            bytes.iter().any(|&b| b == 0xac),
            "script must contain OP_CHECKSIG"
        );
        // Verify the pubkey is embedded (32 bytes of x-only key)
        let key_bytes = pubkey.serialize();
        assert!(
            bytes.windows(32).any(|w| w == key_bytes),
            "script must contain the recovery pubkey"
        );
    }

    #[test]
    fn timeout_not_present_without_with_timeout() {
        let alice = make_participant(1, 50_000, Network::Regtest);
        let bob = make_participant(2, 50_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice.clone())
            .add_participant(bob.clone())
            .build()
            .unwrap();

        assert_eq!(pool.timeout_blocks(), None);

        // Timeout recovery leaf should NOT be in the tree
        let spend_info = pool.taproot_spend_info().unwrap();
        let timeout_config = crate::timeout::TimeoutConfig::new(144);
        let recovery_script = crate::timeout::csv_recovery_script(&timeout_config, &alice.pubkey);
        let script_ver = (recovery_script, bitcoin::taproot::LeafVersion::TapScript);
        assert!(
            spend_info.control_block(&script_ver).is_none(),
            "timeout leaf should NOT exist when timeout not configured"
        );
    }

    #[test]
    fn timeout_inherits_to_sub_pool() {
        let alice = make_participant(1, 30_000, Network::Regtest);
        let bob = make_participant(2, 30_000, Network::Regtest);
        let carol = make_participant(3, 40_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .with_timeout(144)
            .add_participant(alice)
            .add_participant(bob.clone())
            .add_participant(carol.clone())
            .build()
            .unwrap();

        // Alice exits → sub-pool should inherit timeout
        let sub_pool = pool.simulate_exit(0).unwrap().unwrap();
        assert_eq!(sub_pool.timeout_blocks(), Some(144));

        // Sub-pool should have timeout leaves for Bob and Carol
        let spend_info = sub_pool.taproot_spend_info().unwrap();
        let timeout_config = crate::timeout::TimeoutConfig::new(144);
        for participant in sub_pool.participants() {
            let recovery_script =
                crate::timeout::csv_recovery_script(&timeout_config, &participant.pubkey);
            let script_ver = (recovery_script, bitcoin::taproot::LeafVersion::TapScript);
            assert!(
                spend_info.control_block(&script_ver).is_some(),
                "sub-pool timeout recovery leaf must exist"
            );
        }
    }

    #[test]
    fn full_pool_lifecycle() {
        // 3-party pool with all leaf types: cooperative, CTV exits, and timeout recovery
        let alice = make_participant(1, 30_000, Network::Regtest);
        let bob = make_participant(2, 30_000, Network::Regtest);
        let carol = make_participant(3, 40_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .with_timeout(144)
            .with_anchor(240)
            .add_participant(alice.clone())
            .add_participant(bob.clone())
            .add_participant(carol.clone())
            .build()
            .unwrap();

        // Verify all three leaf types exist
        let spend_info = pool.taproot_spend_info().unwrap();

        // 1. Cooperative leaf
        let pubkeys: Vec<XOnlyPublicKey> = vec![alice.pubkey, bob.pubkey, carol.pubkey];
        let cooperative_script = crate::cooperative::build_cooperative_script(&pubkeys).unwrap();
        assert!(
            spend_info
                .control_block(&(
                    cooperative_script.clone(),
                    bitcoin::taproot::LeafVersion::TapScript
                ))
                .is_some(),
            "cooperative leaf must exist"
        );

        // 2. CTV exit leaves
        for path in &pool.exit_paths().paths {
            let script_ver = (
                path.ctv_script.clone(),
                bitcoin::taproot::LeafVersion::TapScript,
            );
            assert!(
                spend_info.control_block(&script_ver).is_some(),
                "CTV exit leaf must exist for each participant"
            );
        }

        // 3. Timeout recovery leaves
        let timeout_config = crate::timeout::TimeoutConfig::new(144);
        for participant in pool.participants() {
            let recovery_script =
                crate::timeout::csv_recovery_script(&timeout_config, &participant.pubkey);
            let script_ver = (recovery_script, bitcoin::taproot::LeafVersion::TapScript);
            assert!(
                spend_info.control_block(&script_ver).is_some(),
                "timeout recovery leaf must exist for each participant"
            );
        }

        // Exercise exit path: Alice exits → 2-party sub-pool
        let sub_pool = pool.simulate_exit(0).unwrap().unwrap();
        assert_eq!(sub_pool.participants().len(), 2);
        assert_eq!(sub_pool.total_sats(), 70_000);
        assert!(sub_pool.use_anchor());
        assert_eq!(sub_pool.timeout_blocks(), Some(144));

        // Sub-pool should also have all three leaf types
        let sub_spend_info = sub_pool.taproot_spend_info().unwrap();

        let sub_pubkeys: Vec<XOnlyPublicKey> =
            sub_pool.participants().iter().map(|p| p.pubkey).collect();
        let sub_cooperative = crate::cooperative::build_cooperative_script(&sub_pubkeys).unwrap();
        assert!(
            sub_spend_info
                .control_block(&(sub_cooperative, bitcoin::taproot::LeafVersion::TapScript))
                .is_some(),
            "sub-pool cooperative leaf must exist"
        );

        // Final exit: Bob exits 2-party sub-pool → no sub-pool
        let none = sub_pool.simulate_exit(0).unwrap();
        assert!(none.is_none(), "last exit should not produce sub-pool");
    }

    #[test]
    fn rebuild_taproot_after_serde_roundtrip() {
        let alice = make_participant(1, 50_000, Network::Regtest);
        let bob = make_participant(2, 50_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .with_timeout(144)
            .add_participant(alice)
            .add_participant(bob)
            .build()
            .unwrap();

        // Serialize then deserialize
        let json = serde_json::to_string(&pool).unwrap();
        let mut deserialized: Pool = serde_json::from_str(&json).unwrap();

        // taproot_spend_info is skipped during serde, so it should be None
        assert!(deserialized.taproot_spend_info().is_none());

        // Rebuild and verify
        deserialized.rebuild_taproot().unwrap();
        assert!(deserialized.taproot_spend_info().is_some());

        // Rebuilt pool should have the same address
        assert_eq!(
            pool.pool_address().to_string(),
            deserialized.pool_address().to_string(),
        );

        // Cooperative leaf should be accessible
        let spend_info = deserialized.taproot_spend_info().unwrap();
        let pubkeys: Vec<XOnlyPublicKey> = deserialized
            .participants()
            .iter()
            .map(|p| p.pubkey)
            .collect();
        let cooperative_script = crate::cooperative::build_cooperative_script(&pubkeys).unwrap();
        let script_ver = (cooperative_script, bitcoin::taproot::LeafVersion::TapScript);
        assert!(
            spend_info.control_block(&script_ver).is_some(),
            "cooperative leaf must survive serde roundtrip + rebuild"
        );
    }

    #[test]
    fn exit_paths_have_unique_ctv_hashes() {
        let alice = make_participant(1, 50_000, Network::Regtest);
        let bob = make_participant(2, 50_000, Network::Regtest);

        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice)
            .add_participant(bob)
            .build()
            .unwrap();

        let hash0 = pool.exit_paths().paths[0].ctv_hash;
        let hash1 = pool.exit_paths().paths[1].ctv_hash;
        assert_ne!(
            hash0, hash1,
            "different exit paths must have different CTV hashes"
        );
    }
}
