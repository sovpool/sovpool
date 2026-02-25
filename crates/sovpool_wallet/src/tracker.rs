//! Pool tracking — monitors pool participation, exit paths, and state transitions.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use bitcoin::OutPoint;
use serde::{Deserialize, Serialize};
use sovpool_core::pool::PoolState;

use crate::{Result, WalletError};

/// A tracked pool entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedPool {
    /// Unique identifier for this pool.
    pub pool_id: String,
    /// The pool UTXO outpoint (if funded).
    pub pool_utxo: Option<OutPoint>,
    /// Our participant index in the pool.
    pub our_index: usize,
    /// Current pool state.
    pub state: PoolState,
    /// Network the pool is on.
    pub network: String,
    /// Number of participants.
    pub participant_count: usize,
    /// Our amount in satoshis.
    pub our_amount_sats: u64,
    /// Total pool amount in satoshis.
    pub total_amount_sats: u64,
    /// Pool address (taproot).
    pub pool_address: String,
    /// Path to the pool definition file.
    pub pool_file: PathBuf,
    /// Timestamp when the pool was created (seconds since epoch).
    pub created_at: u64,
    /// Exit transactions that have been broadcast.
    pub exit_history: Vec<ExitRecord>,
}

/// Record of a pool exit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitRecord {
    pub participant_index: usize,
    pub txid: String,
    pub timestamp: u64,
}

/// Pool tracker — persistent storage for tracked pools.
pub struct PoolTracker {
    storage_dir: PathBuf,
    pools: HashMap<String, TrackedPool>,
}

impl PoolTracker {
    /// Create a new tracker with the given storage directory.
    pub fn new(storage_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(storage_dir)?;

        let mut tracker = Self {
            storage_dir: storage_dir.to_path_buf(),
            pools: HashMap::new(),
        };

        tracker.load()?;
        Ok(tracker)
    }

    /// Load all tracked pools from storage.
    fn load(&mut self) -> Result<()> {
        let index_path = self.storage_dir.join("pools.json");
        if index_path.exists() {
            let data = std::fs::read_to_string(&index_path)?;
            self.pools = serde_json::from_str(&data)?;
        }
        Ok(())
    }

    /// Save all tracked pools to storage.
    fn save(&self) -> Result<()> {
        let index_path = self.storage_dir.join("pools.json");
        let data = serde_json::to_string_pretty(&self.pools)?;
        std::fs::write(&index_path, data)?;
        Ok(())
    }

    /// Track a new pool.
    pub fn track(&mut self, pool: TrackedPool) -> Result<()> {
        self.pools.insert(pool.pool_id.clone(), pool);
        self.save()
    }

    /// Get a tracked pool by ID.
    pub fn get(&self, pool_id: &str) -> Result<&TrackedPool> {
        self.pools
            .get(pool_id)
            .ok_or_else(|| WalletError::PoolNotFound(pool_id.to_string()))
    }

    /// Update pool state.
    pub fn update_state(&mut self, pool_id: &str, state: PoolState) -> Result<()> {
        let pool = self
            .pools
            .get_mut(pool_id)
            .ok_or_else(|| WalletError::PoolNotFound(pool_id.to_string()))?;
        pool.state = state;
        self.save()
    }

    /// Record a pool UTXO (after funding).
    pub fn set_pool_utxo(&mut self, pool_id: &str, utxo: OutPoint) -> Result<()> {
        let pool = self
            .pools
            .get_mut(pool_id)
            .ok_or_else(|| WalletError::PoolNotFound(pool_id.to_string()))?;
        pool.pool_utxo = Some(utxo);
        pool.state = PoolState::Active;
        self.save()
    }

    /// Record an exit from the pool.
    pub fn record_exit(&mut self, pool_id: &str, record: ExitRecord) -> Result<()> {
        let pool = self
            .pools
            .get_mut(pool_id)
            .ok_or_else(|| WalletError::PoolNotFound(pool_id.to_string()))?;

        pool.exit_history.push(record);

        // Update state based on exit count
        if pool.exit_history.len() >= pool.participant_count {
            pool.state = PoolState::FullyExited;
        } else {
            pool.state = PoolState::PartiallyExited;
        }

        self.save()
    }

    /// List all tracked pools.
    pub fn list(&self) -> Vec<&TrackedPool> {
        self.pools.values().collect()
    }

    /// List pools filtered by state.
    pub fn list_by_state(&self, state: PoolState) -> Vec<&TrackedPool> {
        self.pools.values().filter(|p| p.state == state).collect()
    }

    /// Remove a tracked pool.
    pub fn remove(&mut self, pool_id: &str) -> Result<()> {
        self.pools.remove(pool_id);
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sample_pool(id: &str) -> TrackedPool {
        TrackedPool {
            pool_id: id.to_string(),
            pool_utxo: None,
            our_index: 0,
            state: PoolState::Unfunded,
            network: "regtest".to_string(),
            participant_count: 2,
            our_amount_sats: 50_000,
            total_amount_sats: 100_000,
            pool_address: "bcrt1ptest...".to_string(),
            pool_file: PathBuf::from("/tmp/pool.json"),
            created_at: now(),
            exit_history: Vec::new(),
        }
    }

    #[test]
    fn track_and_retrieve() {
        let dir = std::env::temp_dir().join("sovpool_wallet_test_track");
        let _ = std::fs::remove_dir_all(&dir);

        let mut tracker = PoolTracker::new(&dir).unwrap();
        tracker.track(sample_pool("pool1")).unwrap();

        let pool = tracker.get("pool1").unwrap();
        assert_eq!(pool.pool_id, "pool1");
        assert_eq!(pool.state, PoolState::Unfunded);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_state() {
        let dir = std::env::temp_dir().join("sovpool_wallet_test_state");
        let _ = std::fs::remove_dir_all(&dir);

        let mut tracker = PoolTracker::new(&dir).unwrap();
        tracker.track(sample_pool("pool2")).unwrap();
        tracker.update_state("pool2", PoolState::Active).unwrap();

        let pool = tracker.get("pool2").unwrap();
        assert_eq!(pool.state, PoolState::Active);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_exit_updates_state() {
        let dir = std::env::temp_dir().join("sovpool_wallet_test_exit");
        let _ = std::fs::remove_dir_all(&dir);

        let mut tracker = PoolTracker::new(&dir).unwrap();
        tracker.track(sample_pool("pool3")).unwrap();
        tracker.update_state("pool3", PoolState::Active).unwrap();

        tracker
            .record_exit(
                "pool3",
                ExitRecord {
                    participant_index: 0,
                    txid: "abc123".to_string(),
                    timestamp: now(),
                },
            )
            .unwrap();

        let pool = tracker.get("pool3").unwrap();
        assert_eq!(pool.state, PoolState::PartiallyExited);
        assert_eq!(pool.exit_history.len(), 1);

        // Second exit completes the pool (2 participants)
        tracker
            .record_exit(
                "pool3",
                ExitRecord {
                    participant_index: 1,
                    txid: "def456".to_string(),
                    timestamp: now(),
                },
            )
            .unwrap();

        let pool = tracker.get("pool3").unwrap();
        assert_eq!(pool.state, PoolState::FullyExited);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persistence_across_instances() {
        let dir = std::env::temp_dir().join("sovpool_wallet_test_persist");
        let _ = std::fs::remove_dir_all(&dir);

        {
            let mut tracker = PoolTracker::new(&dir).unwrap();
            tracker.track(sample_pool("pool4")).unwrap();
        }

        // New instance should load from disk
        let tracker = PoolTracker::new(&dir).unwrap();
        let pool = tracker.get("pool4").unwrap();
        assert_eq!(pool.pool_id, "pool4");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_by_state_filter() {
        let dir = std::env::temp_dir().join("sovpool_wallet_test_filter");
        let _ = std::fs::remove_dir_all(&dir);

        let mut tracker = PoolTracker::new(&dir).unwrap();
        tracker.track(sample_pool("active1")).unwrap();
        tracker.update_state("active1", PoolState::Active).unwrap();
        tracker.track(sample_pool("unfunded1")).unwrap();

        let active = tracker.list_by_state(PoolState::Active);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].pool_id, "active1");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
