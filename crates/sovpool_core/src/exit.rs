use bitcoin::{ScriptBuf, TxOut};
use serde::{Deserialize, Serialize};

/// A single exit path — CTV-committed transaction paying a participant.
///
/// Each exit path represents one participant's ability to unilaterally
/// withdraw from the pool by broadcasting the CTV-committed exit transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitPath {
    /// Index of the participant who can use this exit path.
    pub participant_index: usize,
    /// The outputs of the exit transaction (withdrawal + optional sub-pool).
    pub outputs: Vec<TxOut>,
    /// The CTV template hash committing to these outputs.
    pub ctv_hash: [u8; 32],
    /// The CTV locking script for this exit path.
    pub ctv_script: ScriptBuf,
}

/// All exit paths for a given pool state.
///
/// For an N-party pool, there are N exit paths (one per participant).
/// Each exit path produces a withdrawal output for the exiting participant
/// and either a direct payment (2-party) or a sub-pool UTXO (N > 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitPathSet {
    pub paths: Vec<ExitPath>,
}

impl ExitPathSet {
    /// Get the exit path for a specific participant.
    pub fn for_participant(&self, index: usize) -> Option<&ExitPath> {
        self.paths.iter().find(|p| p.participant_index == index)
    }

    /// Number of exit paths.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Whether there are no exit paths.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}
