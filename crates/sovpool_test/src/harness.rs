//! Test harness for end-to-end integration testing.
//!
//! Manages a regtest bitcoind instance and provides helper functions
//! for funding addresses, mining blocks, and verifying UTXOs.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};

use bitcoin::{Address, Amount, Network, OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use sovpool_core::pool::{Participant, Pool, PoolBuilder};
use sovpool_core::tx::{build_exit_transaction, build_funding_transaction};
use sovpool_rpc::node::ManagedNode;
use sovpool_rpc::Result;

/// Atomic counter for unique RPC ports when running tests in parallel.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(18443);

/// Test harness wrapping a managed regtest node.
pub struct TestHarness {
    pub node: ManagedNode,
    pub datadir: PathBuf,
    pub default_address: Address,
}

impl TestHarness {
    /// Start a new test harness with a fresh regtest node.
    ///
    /// `bitcoind_path` should point to a CTV-enabled bitcoind.
    pub fn new(bitcoind_path: &Path) -> Result<Self> {
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let datadir = std::env::temp_dir()
            .join("sovpool_test")
            .join(format!("regtest_{port}"));

        // Clean up any previous data
        let _ = std::fs::remove_dir_all(&datadir);

        let node = ManagedNode::start_regtest_with_port(bitcoind_path, &datadir, port)?;
        node.create_wallet("test")?;
        let default_address = node.new_address()?;

        // Mine initial blocks for maturity (100+ confirmations needed for coinbase)
        node.mine_blocks(101, &default_address)?;

        Ok(Self {
            node,
            datadir,
            default_address,
        })
    }

    /// Fund an address with a specific amount. Mines a block to confirm.
    pub fn fund_address(&self, address: &Address, amount: Amount) -> Result<Txid> {
        let txid = self.node.fund_address(address, amount)?;
        self.mine(1)?;
        Ok(txid)
    }

    /// Mine blocks (to the default address).
    pub fn mine(&self, count: u64) -> Result<Vec<Txid>> {
        self.node.mine_blocks(count, &self.default_address)
    }

    /// Get UTXO at outpoint.
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<bitcoin::TxOut>> {
        self.node.get_utxo(outpoint)
    }

    /// Broadcast a raw transaction and mine a block.
    pub fn send_and_mine(&self, tx: &Transaction) -> Result<Txid> {
        let txid = self.node.send_raw_transaction(tx)?;
        self.mine(1)?;
        Ok(txid)
    }

    /// Create and fund a 2-party pool, returning the pool and its UTXO outpoint.
    pub fn create_funded_pool_2party(
        &self,
        alice_amount: u64,
        bob_amount: u64,
        alice: Participant,
        bob: Participant,
    ) -> Result<(Pool, OutPoint)> {
        let pool = PoolBuilder::new()
            .with_network(Network::Regtest)
            .add_participant(alice)
            .add_participant(bob)
            .build()?;

        let total = Amount::from_sat(alice_amount + bob_amount);
        let fund_txid = self.fund_address(&pool.pool_address(), total)?;

        // Find the pool UTXO (output matching the pool address)
        let fund_tx = self
            .node
            .client
            .get_raw_transaction(&fund_txid, None)
            .map_err(sovpool_rpc::RpcError::Rpc)?;

        let vout = fund_tx
            .output
            .iter()
            .position(|o| o.script_pubkey == pool.pool_address().script_pubkey())
            .expect("pool output not found in funding tx") as u32;

        let pool_utxo = OutPoint {
            txid: fund_txid,
            vout,
        };

        Ok((pool, pool_utxo))
    }

    /// Execute a unilateral exit from a pool.
    pub fn exit_participant(
        &self,
        pool: &Pool,
        pool_utxo: OutPoint,
        participant_index: usize,
    ) -> Result<Txid> {
        let exit_tx = build_exit_transaction(pool, pool_utxo, participant_index)?;
        self.send_and_mine(&exit_tx)
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = self.node.stop();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}
