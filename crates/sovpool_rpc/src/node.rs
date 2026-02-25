use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use bitcoin::{Address, Amount, Network, OutPoint, Txid};
use bitcoincore_rpc::json::GetRawTransactionResult;
use bitcoincore_rpc::{Auth, Client, RpcApi};

use crate::{Result, RpcError};

/// Configuration for a Bitcoin Core node connection.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub rpc_url: String,
    pub auth: NodeAuth,
    pub network: Network,
    pub datadir: Option<PathBuf>,
}

/// Authentication method for RPC connection.
#[derive(Debug, Clone)]
pub enum NodeAuth {
    /// Cookie file authentication (most secure, default).
    CookieFile(PathBuf),
    /// Username/password authentication.
    UserPass { user: String, pass: String },
    /// No authentication (for testing only).
    None,
}

impl NodeConfig {
    /// Create a regtest configuration with default settings.
    pub fn regtest(datadir: &Path) -> Self {
        Self::regtest_with_port(datadir, 18443)
    }

    /// Create a regtest configuration with a specific RPC port.
    pub fn regtest_with_port(datadir: &Path, port: u16) -> Self {
        Self {
            rpc_url: format!("http://127.0.0.1:{port}"),
            auth: NodeAuth::CookieFile(datadir.join("regtest/.cookie")),
            network: Network::Regtest,
            datadir: Some(datadir.to_path_buf()),
        }
    }

    /// Create a signet configuration (Bitcoin Inquisition).
    pub fn signet(datadir: &Path) -> Self {
        Self {
            rpc_url: "http://127.0.0.1:38332".to_string(),
            auth: NodeAuth::CookieFile(datadir.join("signet/.cookie")),
            network: Network::Signet,
            datadir: Some(datadir.to_path_buf()),
        }
    }

    /// Build an RPC client from this config.
    pub fn client(&self) -> Result<Client> {
        let auth = match &self.auth {
            NodeAuth::CookieFile(path) => Auth::CookieFile(path.clone()),
            NodeAuth::UserPass { user, pass } => Auth::UserPass(user.clone(), pass.clone()),
            NodeAuth::None => Auth::None,
        };

        Client::new(&self.rpc_url, auth).map_err(RpcError::Rpc)
    }
}

/// Managed Bitcoin Core node for testing.
///
/// Starts a bitcoind process and provides RPC access.
/// The node is stopped when dropped.
pub struct ManagedNode {
    process: Option<Child>,
    pub config: NodeConfig,
    pub client: Client,
}

impl ManagedNode {
    /// Start a regtest node.
    ///
    /// `bitcoind_path` should point to a CTV-enabled bitcoind binary
    /// (e.g., Bitcoin Inquisition).
    pub fn start_regtest(bitcoind_path: &Path, datadir: &Path) -> Result<Self> {
        Self::start_regtest_with_port(bitcoind_path, datadir, 18443)
    }

    /// Start a regtest node on a specific RPC port.
    pub fn start_regtest_with_port(
        bitcoind_path: &Path,
        datadir: &Path,
        port: u16,
    ) -> Result<Self> {
        std::fs::create_dir_all(datadir)
            .map_err(|e| RpcError::NodeError(format!("create datadir: {e}")))?;

        let process = Command::new(bitcoind_path)
            .args([
                "-regtest",
                "-daemon=0",
                &format!("-datadir={}", datadir.display()),
                "-server",
                "-txindex",
                "-fallbackfee=0.00001",
                "-minrelaytxfee=0",
                "-blockmintxfee=0",
                "-rpcallowip=127.0.0.1",
                "-rpcbind=127.0.0.1",
                &format!("-rpcport={port}"),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| RpcError::NodeNotFound(format!("{}: {e}", bitcoind_path.display())))?;

        let config = NodeConfig::regtest_with_port(datadir, port);

        // Wait for node to become available (up to 30 seconds for slow CI)
        let mut client = None;
        for _ in 0..60 {
            std::thread::sleep(Duration::from_millis(500));
            if let Ok(c) = config.client() {
                if c.get_blockchain_info().is_ok() {
                    client = Some(c);
                    break;
                }
            }
        }

        let client = client.ok_or_else(|| {
            RpcError::NodeError("bitcoind did not start within 30 seconds".into())
        })?;

        Ok(Self {
            process: Some(process),
            config,
            client,
        })
    }

    /// Create a wallet (required for regtest operations).
    pub fn create_wallet(&self, name: &str) -> Result<()> {
        // Try to create; if it already exists, try to load it
        match self.client.create_wallet(name, None, None, None, None) {
            Ok(_) => Ok(()),
            Err(_) => {
                self.client.load_wallet(name).map_err(RpcError::Rpc)?;
                Ok(())
            }
        }
    }

    /// Get a new address from the wallet.
    pub fn new_address(&self) -> Result<Address> {
        let addr = self
            .client
            .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
            .map_err(RpcError::Rpc)?
            .assume_checked();
        Ok(addr)
    }

    /// Mine blocks to a given address and return the coinbase txids.
    pub fn mine_blocks(&self, count: u64, address: &Address) -> Result<Vec<Txid>> {
        let hashes = self
            .client
            .generate_to_address(count, address)
            .map_err(RpcError::Rpc)?;

        let mut txids = Vec::new();
        for hash in &hashes {
            let block = self.client.get_block(hash).map_err(RpcError::Rpc)?;
            if let Some(coinbase) = block.txdata.first() {
                txids.push(coinbase.compute_txid());
            }
        }
        Ok(txids)
    }

    /// Fund an address with a specific amount by sending from the wallet.
    pub fn fund_address(&self, address: &Address, amount: Amount) -> Result<Txid> {
        let txid = self
            .client
            .send_to_address(address, amount, None, None, None, None, None, None)
            .map_err(RpcError::Rpc)?;
        Ok(txid)
    }

    /// Get the raw transaction details.
    pub fn get_raw_transaction(&self, txid: &Txid) -> Result<GetRawTransactionResult> {
        self.client
            .get_raw_transaction_info(txid, None)
            .map_err(RpcError::Rpc)
    }

    /// Find a specific UTXO (outpoint) and verify it exists.
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<bitcoin::TxOut>> {
        // Check if the UTXO is unspent via gettxout
        let utxo = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
            .map_err(RpcError::Rpc)?;

        if utxo.is_none() {
            return Ok(None);
        }

        // Get the actual TxOut from the transaction
        let tx = self
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .map_err(RpcError::Rpc)?;

        Ok(tx.output.get(outpoint.vout as usize).cloned())
    }

    /// Broadcast a raw transaction.
    pub fn send_raw_transaction(&self, tx: &bitcoin::Transaction) -> Result<Txid> {
        self.client.send_raw_transaction(tx).map_err(RpcError::Rpc)
    }

    /// Stop the node.
    pub fn stop(&mut self) -> Result<()> {
        if let Some(ref mut process) = self.process {
            let _ = self.client.stop();
            let _ = process.wait();
            self.process = None;
        }
        Ok(())
    }
}

impl Drop for ManagedNode {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Helper: connect to an already-running node.
pub fn connect(config: NodeConfig) -> Result<Client> {
    config.client()
}
