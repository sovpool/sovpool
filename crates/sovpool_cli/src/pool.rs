use clap::Args;

use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::{Address, Network};
use sovpool_core::pool::{Participant, Pool, PoolBuilder};
use sovpool_core::tx::build_exit_transaction;

#[derive(Args)]
pub struct PoolArgs {
    #[command(subcommand)]
    command: PoolCommand,
}

#[derive(clap::Subcommand)]
enum PoolCommand {
    /// Create a new CTV payment pool
    Create {
        /// Number of participants
        #[arg(short = 'n', long)]
        participants: usize,

        /// Amount per participant in satoshis
        #[arg(short, long)]
        amount: u64,

        /// Network: regtest, signet, testnet
        #[arg(long, default_value = "regtest")]
        network: String,

        /// Include P2A anchor output for CPFP fee bumping (required for signet/mainnet)
        #[arg(long)]
        anchor: bool,

        /// Anchor output value in satoshis (default: 240)
        #[arg(long, default_value = "240")]
        anchor_sats: u64,

        /// Output format: json, summary
        #[arg(short, long, default_value = "summary")]
        format: String,
    },
    /// Construct an exit transaction for a participant
    Exit {
        /// Pool UTXO as txid:vout
        #[arg(long)]
        pool_utxo: String,

        /// Participant index (0-based)
        #[arg(long)]
        participant: usize,

        /// Pool definition file (JSON)
        #[arg(long)]
        pool_file: String,
    },
    /// Show pool status and exit paths
    Status {
        /// Pool definition file (JSON)
        #[arg(long)]
        pool_file: String,
    },
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s.to_lowercase().as_str() {
        "regtest" => Ok(Network::Regtest),
        "signet" => Ok(Network::Signet),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        _ => Err(format!(
            "unknown network: {s}. Valid: regtest, signet, testnet"
        )),
    }
}

fn parse_outpoint(s: &str) -> Result<bitcoin::OutPoint, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("outpoint format: txid:vout".into());
    }
    let txid: bitcoin::Txid = parts[0].parse().map_err(|e| format!("invalid txid: {e}"))?;
    let vout: u32 = parts[1].parse().map_err(|e| format!("invalid vout: {e}"))?;
    Ok(bitcoin::OutPoint { txid, vout })
}

/// Generate deterministic test participants.
/// In production, these would come from actual user keys.
fn generate_test_participants(count: usize, amount: u64, network: Network) -> Vec<Participant> {
    let secp = Secp256k1::new();
    (1..=count)
        .map(|i| {
            let mut secret_bytes = [0u8; 32];
            secret_bytes[31] = i as u8;
            secret_bytes[0] = 0x01;
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes).unwrap();
            let (pubkey, _) = sk.x_only_public_key(&secp);
            let address = Address::p2tr(&secp, pubkey, None, network);
            let unchecked = address.to_string().parse().unwrap();
            Participant::new(pubkey, unchecked, amount)
        })
        .collect()
}

pub fn run(args: PoolArgs) -> Result<(), String> {
    match args.command {
        PoolCommand::Create {
            participants,
            amount,
            network,
            anchor,
            anchor_sats,
            format,
        } => {
            let network = parse_network(&network)?;

            if participants < 2 {
                return Err("need at least 2 participants".into());
            }

            let parts = generate_test_participants(participants, amount, network);

            let mut builder = PoolBuilder::new()
                .with_network(network)
                .add_participants(parts);

            if anchor {
                builder = builder.with_anchor(anchor_sats);
            }

            let pool = builder.build().map_err(|e| e.to_string())?;

            match format.as_str() {
                "json" => {
                    let pool_info = PoolInfo::from_pool(&pool);
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&pool_info).map_err(|e| e.to_string())?
                    );
                }
                "summary" => {
                    println!("Pool created:");
                    println!("  Participants: {}", pool.participants().len());
                    println!("  Total: {} sats", pool.total_sats());
                    println!("  Address: {}", pool.pool_address());
                    println!("  Exit paths: {}", pool.exit_paths().paths.len());
                    println!("  Network: {network}");
                    println!();
                    for (i, path) in pool.exit_paths().paths.iter().enumerate() {
                        println!(
                            "  Exit path {i}: {} sats -> {} outputs, CTV hash: {}",
                            pool.participants()[i].amount_sats,
                            path.outputs.len(),
                            hex::encode(path.ctv_hash),
                        );
                    }
                }
                _ => return Err(format!("unknown format: {format}")),
            }
        }
        PoolCommand::Exit {
            pool_utxo,
            participant,
            pool_file,
        } => {
            let outpoint = parse_outpoint(&pool_utxo)?;
            let pool_json = std::fs::read_to_string(&pool_file).map_err(|e| e.to_string())?;
            let pool_info: PoolInfo =
                serde_json::from_str(&pool_json).map_err(|e| e.to_string())?;
            let pool = pool_info.to_pool().map_err(|e| e.to_string())?;

            let exit_tx =
                build_exit_transaction(&pool, outpoint, participant).map_err(|e| e.to_string())?;

            let tx_hex = bitcoin::consensus::encode::serialize_hex(&exit_tx);
            println!("{tx_hex}");
        }
        PoolCommand::Status { pool_file } => {
            let pool_json = std::fs::read_to_string(&pool_file).map_err(|e| e.to_string())?;
            let pool_info: PoolInfo =
                serde_json::from_str(&pool_json).map_err(|e| e.to_string())?;
            let pool = pool_info.to_pool().map_err(|e| e.to_string())?;

            println!("Pool Status:");
            println!("  State: {:?}", pool.state());
            println!("  Participants: {}", pool.participants().len());
            println!("  Total: {} sats", pool.total_sats());
            println!("  Address: {}", pool.pool_address());
            println!();
            for (i, p) in pool.participants().iter().enumerate() {
                println!(
                    "  [{i}] {} sats, pubkey: {}, addr: {:?}",
                    p.amount_sats, p.pubkey, p.withdrawal_address
                );
            }
        }
    }

    Ok(())
}

/// Serializable pool information for JSON persistence.
#[derive(serde::Serialize, serde::Deserialize)]
struct PoolInfo {
    network: String,
    tx_version: i32,
    address: String,
    total_sats: u64,
    participants: Vec<ParticipantInfo>,
    #[serde(default)]
    use_anchor: bool,
    #[serde(default)]
    anchor_sats: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ParticipantInfo {
    pubkey: String,
    withdrawal_address: String,
    amount_sats: u64,
}

impl PoolInfo {
    fn from_pool(pool: &Pool) -> Self {
        Self {
            network: pool.network().to_string(),
            tx_version: pool.tx_version(),
            address: pool.pool_address().to_string(),
            total_sats: pool.total_sats(),
            participants: pool
                .participants()
                .iter()
                .map(|p| ParticipantInfo {
                    pubkey: p.pubkey.to_string(),
                    withdrawal_address: p.withdrawal_address.clone().assume_checked().to_string(),
                    amount_sats: p.amount_sats,
                })
                .collect(),
            use_anchor: pool.use_anchor(),
            anchor_sats: pool.anchor_sats(),
        }
    }

    fn to_pool(&self) -> Result<Pool, String> {
        let network = parse_network(&self.network)?;
        let participants: Vec<Participant> = self
            .participants
            .iter()
            .map(|p| {
                let pubkey: XOnlyPublicKey =
                    p.pubkey.parse().map_err(|e| format!("bad pubkey: {e}"))?;
                let address: Address<bitcoin::address::NetworkUnchecked> = p
                    .withdrawal_address
                    .parse()
                    .map_err(|e| format!("bad address: {e}"))?;
                Ok(Participant::new(pubkey, address, p.amount_sats))
            })
            .collect::<Result<Vec<_>, String>>()?;

        let mut builder = PoolBuilder::new()
            .with_network(network)
            .with_tx_version(self.tx_version)
            .add_participants(participants);

        if self.use_anchor {
            builder = builder.with_anchor(self.anchor_sats);
        }

        builder.build().map_err(|e| e.to_string())
    }
}

/// Simple hex encoding (avoid adding hex crate dependency).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}
