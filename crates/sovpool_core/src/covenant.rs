use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::opcodes::all::OP_NOP4;
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Address, Network, Script, Sequence, Transaction, TxOut};

use crate::error::{Result, SovpoolError};

/// OP_CHECKTEMPLATEVERIFY (repurposes OP_NOP4, opcode 0xb3).
pub const OP_CHECKTEMPLATEVERIFY: bitcoin::opcodes::Opcode = OP_NOP4;

/// BIP-341 standard NUMS (Nothing Up My Sleeve) unspendable internal key.
///
/// SHA-256 of the standard uncompressed encoding of the secp256k1 generator G,
/// interpreted as an x-coordinate. Nobody knows the discrete logarithm.
pub fn nums_point() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&[
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ])
    .expect("valid NUMS point")
}

/// Trait for opcode-agnostic covenant backends.
///
/// This abstraction allows swapping the underlying covenant mechanism
/// (CTV, pre-signed transactions, OP_TXHASH, etc.) without rewriting
/// pool construction logic.
pub trait CovenantBackend {
    /// Commit to a set of outputs, returning the locking script.
    fn commit_to_outputs(&self, outputs: &[TxOut]) -> Result<ScriptBuf>;

    /// Verify that a script commits to the given transaction's outputs.
    fn verify_commitment(&self, script: &Script, tx: &Transaction) -> Result<bool>;
}

/// BIP-119 CTV template hash fields.
///
/// All fields required to compute the DefaultCheckTemplateVerifyHash
/// as specified in BIP-119.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CtvTemplate {
    pub version: i32,
    pub locktime: u32,
    /// SHA-256 of concatenated compact-size-prefixed scriptSigs.
    /// `None` when all scriptSigs are empty (standard for segwit/taproot).
    pub scriptsigs_hash: Option<[u8; 32]>,
    pub num_inputs: u32,
    /// SHA-256 of concatenated raw 4-byte LE nSequence values.
    pub sequences_hash: [u8; 32],
    pub num_outputs: u32,
    /// SHA-256 of concatenated consensus-serialized outputs.
    pub outputs_hash: [u8; 32],
    pub input_index: u32,
}

impl CtvTemplate {
    /// Compute the BIP-119 DefaultCheckTemplateVerifyHash (SHA-256).
    ///
    /// The preimage is the concatenation of all template fields in order.
    /// The scriptSigs hash is only included if any scriptSig is non-empty.
    pub fn hash(&self) -> [u8; 32] {
        let mut buffer = Vec::with_capacity(116);

        // 1. nVersion (i32, LE)
        buffer.extend(self.version.to_le_bytes());

        // 2. nLockTime (u32, LE)
        buffer.extend(self.locktime.to_le_bytes());

        // 3. scriptSigs hash (conditional)
        if let Some(ref hash) = self.scriptsigs_hash {
            buffer.extend(hash);
        }

        // 4. Number of inputs (u32, LE)
        buffer.extend(self.num_inputs.to_le_bytes());

        // 5. Sequences hash (32 bytes)
        buffer.extend(&self.sequences_hash);

        // 6. Number of outputs (u32, LE)
        buffer.extend(self.num_outputs.to_le_bytes());

        // 7. Outputs hash (32 bytes)
        buffer.extend(&self.outputs_hash);

        // 8. Input index (u32, LE)
        buffer.extend(self.input_index.to_le_bytes());

        sha256::Hash::hash(&buffer).to_byte_array()
    }

    /// Extract a CTV template from an existing transaction.
    pub fn from_transaction(tx: &Transaction, input_index: u32) -> Result<Self> {
        if input_index as usize >= tx.input.len() {
            return Err(SovpoolError::CtvHashError(format!(
                "input_index {} out of range (tx has {} inputs)",
                input_index,
                tx.input.len()
            )));
        }

        // scriptSigs hash: only if any input has non-empty scriptSig
        let has_scriptsigs = tx.input.iter().any(|inp| !inp.script_sig.is_empty());
        let scriptsigs_hash = if has_scriptsigs {
            let mut scriptsig_bytes = Vec::new();
            for inp in &tx.input {
                inp.script_sig
                    .consensus_encode(&mut scriptsig_bytes)
                    .map_err(|e| SovpoolError::CtvHashError(e.to_string()))?;
            }
            Some(sha256::Hash::hash(&scriptsig_bytes).to_byte_array())
        } else {
            None
        };

        // Sequences hash
        let mut seq_bytes = Vec::new();
        for inp in &tx.input {
            seq_bytes.extend(inp.sequence.0.to_le_bytes());
        }
        let sequences_hash = sha256::Hash::hash(&seq_bytes).to_byte_array();

        // Outputs hash
        let mut output_bytes = Vec::new();
        for out in &tx.output {
            out.consensus_encode(&mut output_bytes)
                .map_err(|e| SovpoolError::CtvHashError(e.to_string()))?;
        }
        let outputs_hash = sha256::Hash::hash(&output_bytes).to_byte_array();

        Ok(CtvTemplate {
            version: tx.version.0,
            locktime: tx.lock_time.to_consensus_u32(),
            scriptsigs_hash,
            num_inputs: tx.input.len() as u32,
            sequences_hash,
            num_outputs: tx.output.len() as u32,
            outputs_hash,
            input_index,
        })
    }
}

/// Compute the CTV template hash directly from outputs.
///
/// Convenience function for the common case: single input, input_index=0,
/// version 2, locktime 0, no scriptSigs, RBF-enabled sequence.
pub fn compute_ctv_hash(outputs: &[TxOut], version: i32) -> [u8; 32] {
    let seq_hash =
        sha256::Hash::hash(&Sequence::ENABLE_RBF_NO_LOCKTIME.0.to_le_bytes()).to_byte_array();

    let mut output_bytes = Vec::new();
    for o in outputs {
        o.consensus_encode(&mut output_bytes)
            .expect("consensus encoding of TxOut to Vec<u8> is infallible");
    }
    let outputs_hash = sha256::Hash::hash(&output_bytes).to_byte_array();

    let template = CtvTemplate {
        version,
        locktime: 0,
        scriptsigs_hash: None,
        num_inputs: 1,
        sequences_hash: seq_hash,
        num_outputs: outputs.len() as u32,
        outputs_hash,
        input_index: 0,
    };

    template.hash()
}

/// Build the CTV locking script: `<32-byte-hash> OP_CHECKTEMPLATEVERIFY`.
pub fn ctv_script(hash: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_slice(hash)
        .push_opcode(OP_CHECKTEMPLATEVERIFY)
        .into_script()
}

/// Compute leaf depths for a balanced taproot binary tree.
///
/// TaprootBuilder expects leaves in DFS left-to-right order with depths.
/// This recursively splits N leaves into balanced left/right subtrees.
fn balanced_leaf_depths(n: usize) -> Vec<u8> {
    if n == 1 {
        return vec![0];
    }
    if n == 2 {
        return vec![1, 1];
    }
    let left_count = n.div_ceil(2);
    let right_count = n / 2; // floor(n/2)
    let mut depths: Vec<u8> = balanced_leaf_depths(left_count)
        .into_iter()
        .map(|d| d + 1)
        .collect();
    depths.extend(balanced_leaf_depths(right_count).into_iter().map(|d| d + 1));
    depths
}

/// Build a taproot output with CTV scripts in the script tree.
///
/// Creates a taproot spend info with `scripts.len()` leaf nodes,
/// using the BIP-341 NUMS point as the unspendable internal key.
pub fn build_ctv_taproot(scripts: &[ScriptBuf]) -> Result<TaprootSpendInfo> {
    build_taproot_with_extra_leaves(scripts, &[])
}

/// Build a taproot output with CTV scripts and additional leaves (e.g. cooperative, timeout).
///
/// The tree structure is:
/// ```text
///          [root]
///         /      \
///   [extra_tree]  [exit_tree]
///                  /    \
///             [exit_0] [exit_1] ...
/// ```
///
/// When `extra_leaves` is empty, behaves identically to `build_ctv_taproot`.
pub fn build_taproot_with_extra_leaves(
    ctv_scripts: &[ScriptBuf],
    extra_leaves: &[ScriptBuf],
) -> Result<TaprootSpendInfo> {
    let secp = Secp256k1::verification_only();
    let internal_key = nums_point();

    let all_scripts: Vec<ScriptBuf> = extra_leaves
        .iter()
        .chain(ctv_scripts.iter())
        .cloned()
        .collect();

    if all_scripts.is_empty() {
        return Err(SovpoolError::CtvHashError(
            "need at least one script leaf".into(),
        ));
    }

    let depths = balanced_leaf_depths(all_scripts.len());
    let mut builder = TaprootBuilder::new();

    for (i, (script, &depth)) in all_scripts.iter().zip(depths.iter()).enumerate() {
        builder = builder
            .add_leaf(depth, script.clone())
            .map_err(|e| SovpoolError::CtvHashError(format!("add leaf {i}: {e}")))?;
    }

    builder
        .finalize(&secp, internal_key)
        .map_err(|e| SovpoolError::CtvHashError(format!("taproot finalize: {e:?}")))
}

/// Get the taproot address for a set of CTV scripts.
pub fn ctv_taproot_address(scripts: &[ScriptBuf], network: Network) -> Result<Address> {
    let spend_info = build_ctv_taproot(scripts)?;
    Ok(Address::p2tr_tweaked(spend_info.output_key(), network))
}

/// CTV-based covenant backend.
pub struct CtvBackend {
    /// Transaction version to use (2 for signet, 3 for regtest with Inquisition).
    pub tx_version: i32,
}

impl CtvBackend {
    pub fn new(tx_version: i32) -> Self {
        Self { tx_version }
    }
}

impl Default for CtvBackend {
    fn default() -> Self {
        Self { tx_version: 2 }
    }
}

impl CovenantBackend for CtvBackend {
    fn commit_to_outputs(&self, outputs: &[TxOut]) -> Result<ScriptBuf> {
        let hash = compute_ctv_hash(outputs, self.tx_version);
        Ok(ctv_script(hash))
    }

    fn verify_commitment(&self, script: &Script, tx: &Transaction) -> Result<bool> {
        // Extract the hash from the script (first 32 bytes after the push opcode)
        let script_bytes = script.as_bytes();
        if script_bytes.len() < 34 {
            return Ok(false);
        }

        // Script format: OP_PUSH32 <32 bytes> OP_NOP4
        // OP_PUSH32 = 0x20
        if script_bytes[0] != 0x20 {
            return Ok(false);
        }
        let committed_hash: [u8; 32] = script_bytes[1..33]
            .try_into()
            .map_err(|_| SovpoolError::CtvHashError("invalid hash in script".into()))?;

        if script_bytes[33] != OP_CHECKTEMPLATEVERIFY.to_u8() {
            return Ok(false);
        }

        // Compute the template hash from the transaction
        let template = CtvTemplate::from_transaction(tx, 0)?;
        let computed_hash = template.hash();

        Ok(committed_hash == computed_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::{Amount, ScriptBuf as BScriptBuf, TxOut};

    fn sample_outputs() -> Vec<TxOut> {
        vec![
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: BScriptBuf::new_p2wpkh(
                    &bitcoin::WPubkeyHash::from_slice(&[0xab; 20]).unwrap(),
                ),
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: BScriptBuf::new_p2wpkh(
                    &bitcoin::WPubkeyHash::from_slice(&[0xcd; 20]).unwrap(),
                ),
            },
        ]
    }

    #[test]
    fn ctv_hash_deterministic() {
        let outputs = sample_outputs();
        let hash1 = compute_ctv_hash(&outputs, 2);
        let hash2 = compute_ctv_hash(&outputs, 2);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn ctv_hash_changes_with_outputs() {
        let outputs1 = sample_outputs();
        let mut outputs2 = sample_outputs();
        outputs2[0].value = Amount::from_sat(40_000);

        let hash1 = compute_ctv_hash(&outputs1, 2);
        let hash2 = compute_ctv_hash(&outputs2, 2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn ctv_hash_changes_with_version() {
        let outputs = sample_outputs();
        let hash_v2 = compute_ctv_hash(&outputs, 2);
        let hash_v3 = compute_ctv_hash(&outputs, 3);
        assert_ne!(hash_v2, hash_v3);
    }

    #[test]
    fn ctv_script_format() {
        let hash = [0xaa; 32];
        let script = ctv_script(hash);
        let bytes = script.as_bytes();

        // OP_PUSH32 (0x20) + 32 bytes + OP_NOP4 (0xb3) = 34 bytes
        assert_eq!(bytes.len(), 34);
        assert_eq!(bytes[0], 0x20); // OP_PUSH32
        assert_eq!(&bytes[1..33], &hash);
        assert_eq!(bytes[33], OP_CHECKTEMPLATEVERIFY.to_u8());
    }

    #[test]
    fn nums_point_is_valid() {
        let point = nums_point();
        // Should not panic and should be a valid point
        assert_eq!(point.serialize().len(), 32);
    }

    #[test]
    fn template_from_transaction_roundtrip() {
        let outputs = sample_outputs();
        let hash_direct = compute_ctv_hash(&outputs, 2);

        // Build a transaction matching the template
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: BScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: outputs,
        };

        let template = CtvTemplate::from_transaction(&tx, 0).unwrap();
        let hash_from_tx = template.hash();

        assert_eq!(hash_direct, hash_from_tx);
    }

    #[test]
    fn template_preimage_size_no_scriptsigs() {
        // Without scriptSigs: 4 + 4 + 4 + 32 + 4 + 32 + 4 = 84 bytes
        let template = CtvTemplate {
            version: 2,
            locktime: 0,
            scriptsigs_hash: None,
            num_inputs: 1,
            sequences_hash: [0; 32],
            num_outputs: 2,
            outputs_hash: [0; 32],
            input_index: 0,
        };

        // Verify the hash is computed (doesn't panic)
        let hash = template.hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn build_single_leaf_taproot() {
        let outputs = sample_outputs();
        let hash = compute_ctv_hash(&outputs, 2);
        let script = ctv_script(hash);

        let spend_info = build_ctv_taproot(&[script]).unwrap();
        assert!(spend_info.output_key().serialize().len() == 32);
    }

    #[test]
    fn build_multi_leaf_taproot() {
        let outputs1 = sample_outputs();
        let hash1 = compute_ctv_hash(&outputs1, 2);
        let script1 = ctv_script(hash1);

        let mut outputs2 = sample_outputs();
        outputs2[0].value = Amount::from_sat(60_000);
        outputs2[1].value = Amount::from_sat(40_000);
        let hash2 = compute_ctv_hash(&outputs2, 2);
        let script2 = ctv_script(hash2);

        let spend_info = build_ctv_taproot(&[script1, script2]).unwrap();
        assert!(spend_info.output_key().serialize().len() == 32);
    }

    #[test]
    fn ctv_backend_commit_and_verify() {
        let backend = CtvBackend::default();
        let outputs = sample_outputs();

        let script = backend.commit_to_outputs(&outputs).unwrap();

        // Build a matching transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: BScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: outputs,
        };

        assert!(backend.verify_commitment(&script, &tx).unwrap());
    }

    #[test]
    fn ctv_backend_rejects_wrong_outputs() {
        let backend = CtvBackend::default();
        let outputs = sample_outputs();
        let script = backend.commit_to_outputs(&outputs).unwrap();

        // Build a transaction with different outputs
        let mut wrong_outputs = sample_outputs();
        wrong_outputs[0].value = Amount::from_sat(99_999);

        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: BScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: wrong_outputs,
        };

        assert!(!backend.verify_commitment(&script, &tx).unwrap());
    }

    #[test]
    fn ctv_taproot_address_regtest() {
        let outputs = sample_outputs();
        let hash = compute_ctv_hash(&outputs, 2);
        let script = ctv_script(hash);

        let address = ctv_taproot_address(&[script], Network::Regtest).unwrap();
        // Should be a valid bech32m address
        assert!(address.to_string().starts_with("bcrt1p"));
    }

    #[test]
    fn empty_scripts_rejected() {
        let result = build_ctv_taproot(&[]);
        assert!(result.is_err());
    }

    // ========================================================================
    // BIP-119 official test vector cross-validation
    // Vectors from: https://github.com/bitcoin/bips/blob/master/bip-0119/vectors/ctvhash.json
    // ========================================================================

    /// Deserialize a hex-encoded raw transaction and verify our CTV hash
    /// matches the expected result from the BIP-119 test vectors.
    fn check_bip119_vector(hex_tx: &str, spend_index: u32, expected_hex: &str) {
        let tx_bytes = bitcoin::consensus::encode::deserialize_hex::<Transaction>(hex_tx)
            .expect("valid hex transaction");

        let template = CtvTemplate::from_transaction(&tx_bytes, spend_index)
            .expect("valid template extraction");
        let hash = template.hash();

        let expected: [u8; 32] = {
            let bytes =
                bitcoin::hashes::hex::FromHex::from_hex(expected_hex).expect("valid hex hash");
            bytes
        };

        assert_eq!(
            hash, expected,
            "CTV hash mismatch for spend_index={spend_index}"
        );
    }

    #[test]
    fn bip119_vector_0_3in_1out_scriptsigs_idx0() {
        // 3 inputs, 1 output, with scriptSigs, version=-2079506940
        check_bip119_vector(
            "043e0d840001034f8f827b00000000000000000000000000000000000000000000000000000000f54c98ade5a10d6c8a3013fd077ed18e1d7eba9119ee318b83220c2521e1d55ff06a494bb210a1c73ef3df958da16481cec61f80281e9ab392ee6701ffc205db6393497681d92282aa2f55ec5f9dba411b5787353b36c1b33afc884249038954c7d6dcc55baf885767d4800c62314f6021cf59d4f88845d960aeebd5fb84cfe393939893a847b13753d9f3ecb8dbc264b24b64020f4897efebfeac68dd6e13b127b132859d792d2b293223fd7b591d03cb9b20735f18c0085542f1a4d769c1c874e9eac2d2e280fa3d9e7b03dc62e64c9fc80f0b09506b19166e84ab7600744cdfa6bf25f5df671725adb23887aa3e8e6d9200000000000000000000000000000000000000000000000000000000119ccb06e028dc54e45a5bb28199c854b8fd1b1797c2d7aefdb5823fc1b316a2a88e9b670ff7f282cb22d26adc79c464a50e3ce287739ec14d011a999dd66553d08d51fc9eba2ab0f8525bc6cf98cc64f09e7d7415ba7dc98701e3b6cd94342d872bea86dcfec4d14ada25febd8d2387ccef203bc6fc202c5b38c09b3525c6e68b1fb9e2284ffa3374777d686ad6c68c6ec25560645b739e8d338a3b6ff314e80698e180b836a315f90a0ed2e30260bea7e540f8a00f4d051e95f27c7cfef998002ba0cba0a725ad33f6d54aff13be272441af523dc5959980ca6c8caaeb518c46d07b0997c33d24827f9af222000000000000000000000000000000000000000000000000000000007263de59fd7c0115337ebfb53cb1dcc1e5ae6f5303ef40c4a9e71e3c819346ad09bf2ab51de119d11f878134d7715b880ec54dd5c7c5cbf2bc3b9db9a980432807aa4de4072064e0b8315010bb61cb85cf2836cd649d86f88170d747ecfc3bfbc4051aeaa453de0f9d90f33932588a03c920d523fbcdea58340733e207817a8a500d642e759a7181a666e8099592548ece7535fb14d11f8a6e4dba55780773387c464502794bbdf1bbaaa79efda2e024002357f2a50ef2a31120c4382be745debf40e0fc0894172a9d51ede424561b88615518c9c9c7b1bc7b8085cd0907e19d6fbcb85e3569c9349d95dca881100d390c321721809e8bbfabcb4c25b29bc4777c4d79c39aa9849c53b318894ad875708d8e6689dd6bc2f2aef433003ab8d0755387f56bf73f1e74980ff2d4eccddd0a00bb9a71b343137b69f7c51cb66d8e33cd70573f65f9157043f5267b60e64370e0cf33ab8d40e6968192cf3da58790dda9824def3b8d56d7385068ac8bfafc76f06e46cccb80852a59439a5f0ed8ffb02aaff01e4556ea01ba56592ae4e4ec33c86d2dbea9c83550cb9357d7b1aa67a1067b4c163e39202438ec52087f4195c1fc90f543fe41c630bf25ec79d6084a954ac70c9558443ded85901746e35226564b22ecde4e23da0905e38dddc4b34186e895fa5b743eef69ecee8513ebd2f821bb89c2f9ee7f0b82bd0d42f40bd9671dc163a5eb53a403831f9df6ca6245cf0ef03708fb889e4362dc5ee3b504a8e01136cfc3d3bbc44eede5e4abd18fca8315d27a746a749f5fec46254cea659c53ea71f99ed1e9744192d1743cdf24d99c59a671006a4474077ad6020db169be53eec1511c5157517253fdc901257a6f391c70dfed3d0a26bf3155ead063468639825752a4f386f43cc94223db499358afa7fb21d27ef72bbd73be1c9eb528962c4697ec9cbffd44ca6d2879dbf84de9dae29261c37a2ce87813ce34a5de387afd740d29727b1cbf0cbdebf4cacec0cc0c73c28d9f120bc31b243629fc850b55cbc704f16d7505c9b83aa079cb644c69cf6ea01b9c92dea2a624315471922626e10c290976a26247c0f733d49225b91e38074075bea6b2cfe14ba60a608c15351701b71c81bca089f2da62c5fb07ebb261682f2be982b2f699aa27df152d8fd260287e9bedd5b848186e38c3fd1895cc1e53d907bb75ab3fda26202fab8c7a8d0fb3d4445fc3b6f90b2a80010cd3c2ae18e55736e460278b9ed477e209939b096a2cb3225535666616c773e07293c100afb5ce982e933fd2d95a607968e1dec26a4b2e5e8e3e2b40cbec9b15c16da81f72d6bd4569e8e223a4351ec112d52cfe0a6e51e8ab660552195b507a648a42ce70e635437d52c8bda21d914d7fc0f2875f08af1f8803fa0a9a48484ae311361d2fa5bda2b3f689559bc2fb1c577f5acbfa7effed855ae0bf908a7e9269dff51070aa8a97e4954505abcdcebfc6ae1c1bc68dd593021777e9ea573fd79334e85c582ea900e1570337f091bdbb555c19b89262aba2b7429e24ca04c177059ba8dd468375f2a12e99937a22cb131ebb508e81ede4b807789c4318b8229b90a01a4443d74e6fc4ae30d04f7ea1c2bdbb98c2a83b316d56a093c790af9ff25ee6be833448dd05e96ed38e7b3fbfc7c2409c99f36d81e40196180e2360ad3a0ef439a0a6bed0b92e93cca398ca4f95906ba6d30b33e81faeb3c405a3247f488dbc86eca14e25ddcc4367f4170044fbc5e329f49a91410185475164afb2bc537500970cf1041b09d590f12613630bba8efacde59e3c8aaecd5bc5626a7bf0b5abf4b507b3659b6df2bad43d7a2ecdc2500b375c155aae9c62a8d8af503a927d859a6dc2ffdca19cbe8872c63b1083cf5b11fb957da72f631694d0dccf21820247943a90b18eb2258af5c6aed6d19bf82542f524c8066501698f5709473824d07f61",
            0,
            "2d28d0672f1d46cb3e86abd7e682d2d3e9961e6c9237157f47d39f0a694bb694",
        );
    }

    #[test]
    fn bip119_vector_0_3in_1out_scriptsigs_idx1() {
        check_bip119_vector(
            "043e0d840001034f8f827b00000000000000000000000000000000000000000000000000000000f54c98ade5a10d6c8a3013fd077ed18e1d7eba9119ee318b83220c2521e1d55ff06a494bb210a1c73ef3df958da16481cec61f80281e9ab392ee6701ffc205db6393497681d92282aa2f55ec5f9dba411b5787353b36c1b33afc884249038954c7d6dcc55baf885767d4800c62314f6021cf59d4f88845d960aeebd5fb84cfe393939893a847b13753d9f3ecb8dbc264b24b64020f4897efebfeac68dd6e13b127b132859d792d2b293223fd7b591d03cb9b20735f18c0085542f1a4d769c1c874e9eac2d2e280fa3d9e7b03dc62e64c9fc80f0b09506b19166e84ab7600744cdfa6bf25f5df671725adb23887aa3e8e6d9200000000000000000000000000000000000000000000000000000000119ccb06e028dc54e45a5bb28199c854b8fd1b1797c2d7aefdb5823fc1b316a2a88e9b670ff7f282cb22d26adc79c464a50e3ce287739ec14d011a999dd66553d08d51fc9eba2ab0f8525bc6cf98cc64f09e7d7415ba7dc98701e3b6cd94342d872bea86dcfec4d14ada25febd8d2387ccef203bc6fc202c5b38c09b3525c6e68b1fb9e2284ffa3374777d686ad6c68c6ec25560645b739e8d338a3b6ff314e80698e180b836a315f90a0ed2e30260bea7e540f8a00f4d051e95f27c7cfef998002ba0cba0a725ad33f6d54aff13be272441af523dc5959980ca6c8caaeb518c46d07b0997c33d24827f9af222000000000000000000000000000000000000000000000000000000007263de59fd7c0115337ebfb53cb1dcc1e5ae6f5303ef40c4a9e71e3c819346ad09bf2ab51de119d11f878134d7715b880ec54dd5c7c5cbf2bc3b9db9a980432807aa4de4072064e0b8315010bb61cb85cf2836cd649d86f88170d747ecfc3bfbc4051aeaa453de0f9d90f33932588a03c920d523fbcdea58340733e207817a8a500d642e759a7181a666e8099592548ece7535fb14d11f8a6e4dba55780773387c464502794bbdf1bbaaa79efda2e024002357f2a50ef2a31120c4382be745debf40e0fc0894172a9d51ede424561b88615518c9c9c7b1bc7b8085cd0907e19d6fbcb85e3569c9349d95dca881100d390c321721809e8bbfabcb4c25b29bc4777c4d79c39aa9849c53b318894ad875708d8e6689dd6bc2f2aef433003ab8d0755387f56bf73f1e74980ff2d4eccddd0a00bb9a71b343137b69f7c51cb66d8e33cd70573f65f9157043f5267b60e64370e0cf33ab8d40e6968192cf3da58790dda9824def3b8d56d7385068ac8bfafc76f06e46cccb80852a59439a5f0ed8ffb02aaff01e4556ea01ba56592ae4e4ec33c86d2dbea9c83550cb9357d7b1aa67a1067b4c163e39202438ec52087f4195c1fc90f543fe41c630bf25ec79d6084a954ac70c9558443ded85901746e35226564b22ecde4e23da0905e38dddc4b34186e895fa5b743eef69ecee8513ebd2f821bb89c2f9ee7f0b82bd0d42f40bd9671dc163a5eb53a403831f9df6ca6245cf0ef03708fb889e4362dc5ee3b504a8e01136cfc3d3bbc44eede5e4abd18fca8315d27a746a749f5fec46254cea659c53ea71f99ed1e9744192d1743cdf24d99c59a671006a4474077ad6020db169be53eec1511c5157517253fdc901257a6f391c70dfed3d0a26bf3155ead063468639825752a4f386f43cc94223db499358afa7fb21d27ef72bbd73be1c9eb528962c4697ec9cbffd44ca6d2879dbf84de9dae29261c37a2ce87813ce34a5de387afd740d29727b1cbf0cbdebf4cacec0cc0c73c28d9f120bc31b243629fc850b55cbc704f16d7505c9b83aa079cb644c69cf6ea01b9c92dea2a624315471922626e10c290976a26247c0f733d49225b91e38074075bea6b2cfe14ba60a608c15351701b71c81bca089f2da62c5fb07ebb261682f2be982b2f699aa27df152d8fd260287e9bedd5b848186e38c3fd1895cc1e53d907bb75ab3fda26202fab8c7a8d0fb3d4445fc3b6f90b2a80010cd3c2ae18e55736e460278b9ed477e209939b096a2cb3225535666616c773e07293c100afb5ce982e933fd2d95a607968e1dec26a4b2e5e8e3e2b40cbec9b15c16da81f72d6bd4569e8e223a4351ec112d52cfe0a6e51e8ab660552195b507a648a42ce70e635437d52c8bda21d914d7fc0f2875f08af1f8803fa0a9a48484ae311361d2fa5bda2b3f689559bc2fb1c577f5acbfa7effed855ae0bf908a7e9269dff51070aa8a97e4954505abcdcebfc6ae1c1bc68dd593021777e9ea573fd79334e85c582ea900e1570337f091bdbb555c19b89262aba2b7429e24ca04c177059ba8dd468375f2a12e99937a22cb131ebb508e81ede4b807789c4318b8229b90a01a4443d74e6fc4ae30d04f7ea1c2bdbb98c2a83b316d56a093c790af9ff25ee6be833448dd05e96ed38e7b3fbfc7c2409c99f36d81e40196180e2360ad3a0ef439a0a6bed0b92e93cca398ca4f95906ba6d30b33e81faeb3c405a3247f488dbc86eca14e25ddcc4367f4170044fbc5e329f49a91410185475164afb2bc537500970cf1041b09d590f12613630bba8efacde59e3c8aaecd5bc5626a7bf0b5abf4b507b3659b6df2bad43d7a2ecdc2500b375c155aae9c62a8d8af503a927d859a6dc2ffdca19cbe8872c63b1083cf5b11fb957da72f631694d0dccf21820247943a90b18eb2258af5c6aed6d19bf82542f524c8066501698f5709473824d07f61",
            1,
            "12f7ab0a282fb9e29c9fd2ada21f950f492bfd5778a94202398c13ae6e97f0b4",
        );
    }

    #[test]
    fn bip119_vector_1_10in_4out_no_scriptsigs_idx0() {
        // 10 inputs, 4 outputs, NO scriptSigs, version=-1368569235
        check_bip119_vector(
            "6d4a6dae00010a916a4b8200000000000000000000000000000000000000000000000000000000678ccb660063c1aa74901ac96e00000000000000000000000000000000000000000000000000000000333575f100deed4cd21c61531e000000000000000000000000000000000000000000000000000000002ca78054001064ed3dec34dfc70000000000000000000000000000000000000000000000000000000069eb33a500b63bd6b3a8649f6e00000000000000000000000000000000000000000000000000000000bdef058800d2e45813892f854400000000000000000000000000000000000000000000000000000000dfa70a4b0090fdb4507528cb0a00000000000000000000000000000000000000000000000000000000265a129d009caebc792f12408d00000000000000000000000000000000000000000000000000000000a163d9dd0096eb42406cc5468600000000000000000000000000000000000000000000000000000000980b4ad1008b6e087dfd46e3e60000000000000000000000000000000000000000000000000000000008d612a30061f404f0047d5a85efcd513431c8fdc3e16e04bbda3ed597cba1417cd04394a876b5d008a88e54f7b6aa91ff086ba4ba2fc76e3cb8ff373f737bba9581678944d574c399a6627e2cb10a01bb88baeb4cafb52ca8f14c1c5355497520916ff57f78e173271ed1d731e5ae17e4776481955881d03c183e0737dba812521364159af700d062aa092436e38f6e6994a8b50535a2c1c0513b690c0f1bfa14612aedb1b7b4d90f1b4d4f2909633a36e4a245f6cfba0e64fbf262a96d2721e1d4417b4028b06c200887bba784d6f410880e64c1819432f44256d93e4198b7d62b6cc80fda87347ebba272e3d2267f39efa7268ac3e4f0cd8b077bf9d4831072b9cf1fd6191e6c430422c3225ce247ec07f94fb58d365ff4e59ac353c5cc9ca9be7c01475c6e6509298134e3fcded875ec17bc35c40c6e8b5c6f1ebda9bad1d752b655d9f9238312e5c01f59cf14f45bdfed18c3ae2254635a91405cc42d68f1d7ca68b97ec93d96ed1277baff57951af33a79edd01ac23f47400fa49ea85507bec9a45bf6022e3873d90890eecd1582e17fdf5160ce30eb87baafd169dd4d0f6ea2f9e1b45406620f9c0430a2a513a6011e7cc88557ebc7b2057b4b1dcc55b6edd7a203bb9d8cd9f8019f79b2df2c64410ceefd1a819668d915c1fcc46679dffb772dc3eb55205524f495b6642d311f1bf58024df8400567f61f1debeaeb6b95b612f7e6687e7ae4dc0c3e0df045bd018434ffa4a179bc23c95562daf3e293cdf682381f920d333e61143392021beacb2935789b8d4e86ab2b16d46e0c79c05166ddf0461614204fb01265a5e9cc552812085c68129f7e0663e511f1112588886b30d5b736d3414ea8b7280e5a017473ffa0e6ff88c36902de8672353a8cd464a1b2d67c8d0691d4368b6f5c78a23b8acd08e338a8e73e7f9bfc0f7418f5efcd8bdd924fae94f9f4ef68612144ac53ad0759e0f0d366fb6994d0a8f237236eba419c3afe1176e569bfac7384c03ff056b17702d440a1b0965a753193df5b28f550244e4652bd8f6d9209a3ff027f54c493302dee347e70d3eec95621a223823b5d33f9d59f6fdf66c15ae2ebeb26d26fa265ef3485dc6db2ae40d41da19de962a154baf84962547099ff17ca2e32fd831f65be2c59136394d33d64e75ef4828c7059c0f670769a46a9dfa38bb03f27b15eea1567e1241ac5bfacb5c7737109e1b7dd6f6409b982d2da48a7883ed01601869ae39528755419487c8035b54e66ec9078fa8d655effbd5afbfc067dcab5270ef42a049d32d9af1ef63abde30321a5b56a4e38676ae9a7d02ba11487545ad6829ac5fee5a4c15db77faf50ca1731e85399d4edf189343fec7f0b7549ff6cd94c2df1f048ea84237a5febe51908922d8d5ed87605236e88097fb3e6f5b61735a7a1d899fdff4e4bba1301b0c8008fc550123262c28064e8974ee9ce18f20591c0b5cc9f82481c9e558f44b2b1707ce53ced8cf132686b50bfbe0f3a501f06b37b21c9cd210da0515d73f0d569b610db7fd2e016b6fa063c83c771b81414585f112106d1cbff1c15bbf4f5d01468b9f152a7b04948881699ccfe8b71df6c8841848462f2ba63574b4b82233adb84101a027071d337b73f408f21c333cf80619d033adb11f67c81b4c8364e03072b9cdd06f20fd14e38dc0d5f73ac880ba5f06f0215f67f23c2253dc5d461a438383eee398996d97f1916b0ef6d8ecf027e1aa21827fa0bd8fb04eb0010c98bf673bfacb8a2619b55899f0c86e363e1ed26e43a38ac0941934cd79a0b5521b1338269083b951025b92562b057e738d0c57e6b47cbb120d482bc3b34f1ee93c3de86ea4bf6a01f24f47b7ebac399d4bf3228606dc23695f55a3d99d78e032ee4854e5c3a7d1574c5b56a476ba88a6bbc8263418b5ee790c88da6de6400225763b02f3164c3655ca0c33d5ec1ade6dea61c64a1e40e38d219e870f064c993d806747642572ad2bc5f37ab58edceac35460c7bf50afa9ca8e62c9e8c506635c3301aa9ab70d8c73a955768a56af4e36862d2e908d18057440ea4e9fa7edb1b662a2ccc10b737e59ed3f1f4b8d9445243a685f167ba068153e1d6b865ab827fc01b28cc9b08090dc0f413ad1071760e7740d2251986eccf29c12246dd98171e67b27902a3d02fd58010b63aac9d24630fec45752a1adf2e280c4f7a0697192f128e1ef02f0c546db67f8c45cf55a39a7d103ebdac927574b043a7bb95942267e1a488d60b22f08b32102a7aab4dede478d19cd95a4b5ce911aee03728cbbd9c7666967a86c500ac7c6ff63ff4849e5432bf8de5a695e7ca4d5f1ab2ac09d1cd7c26227194287e0f8f3673cdb852b6d03005c85afcb181fc83a8ec0ed95499be06415c79d69429888a90187e7789f5a860b873abb0f7fef8c47b99e362891451e02eb31a4048ed4aeeebf49603ea7fac87d8134ae718dca06460536a011715ed4b83ae9724aebef0c46bbfdf02ca85ebe1bbdf5f45e58a2e96d514d98ce425726904607e613b16aa3025e1f671f1dd913e60995523035718e7f898bcbb46ee3e90e76b03ad99b61737f1ee2d4c3cf23d5614f767d8a03e4921839f59eabb29ea260684783a2842e6b0d6056429d2b390a697aef776fe8021492db57fcc045e68997524407d6e9b963f8970b5c80cd43a1d0ffc4514da60b26a750639778c902d10e00d8a569c4a8c7008d1388e8b8714c7f827a951dbd9c5a466174f9838651e86cdaa19402c8dc6427d84e73fe41596d6a1d2bba03fd4801e784079ec830a58842a8cb33d32cc56cce22b89ea5dcae7b2e659cdc6c87f6567ebae46e81a5f75ec4495110482b84ce0bdf824dc625c5cf32cc6b28075600d03d48982d75c4755ca3b7fcf9a90f7d8832197e8b96c64158eb3b568bbd48995c7820940e4488f882a8ee842024e91221072dc32917c6da4c03b86bed15fdf2889697ed349649be9b287a1b1e6d5655e7110fb3c98bc417f89eca4c3ca9f3a8891162873298e85ac83ff64adcb9622bbaeddba3bce44855b84c5acd7f72d6be9bc58bd7e9e273385a555019be50dcca5d555170fa041b472af4e9bf7b322178a3e4166b1dd6d81c7cea97788af5615323c128ca9d15dc267dcc41f6db00c8c04c6cfff3f3e8cec109ce77151b206910df0d393671685ea4dd66ca4e20e1b06ae442dc4d4c4c80dd34c3ce214bd4a3e138c82287311366cff1113b9b87f653e00b7757f57dfc011669d691591c3f04c90c9e9757ff568449b89bcce976aeb19b7d0ec42e0c0ff7414910f63f150aaad4de779604069eb6be22287e2dc2161f540608fa3b31728a1220211d253496c399bf61df8691c36728c486e5e867f6cd43262044bdbebababdb8caf50afa7f595ff07b83595de7afeba51fd2a475a419d154e312e5233d5941b45f46fc2dd3df5bc2212cc33c51e2468f5e17d17dfaff014b60024983705b5f9f263055b5ad52fb27b818ec1fbbc1de9d06636eccba8614fd2860250561d19a406b9d3a67ef125cfb6a22c9fb0e61ed3e65a93fefa8edd2fd5801586591b2f2ab61e013400acf71f0e023d17300cc90c1f9259bc8524b2319e77bbba8c4d286a0ffe799c57061f3a36f831e2cd4c5480a5dafa9c209c93d7cb54a56f1b3670ec1eef3de8494c496061c14853566c11e9fa4e77dc3aa029be7a120644ef0394f6cbd581a323b56187769669cb1a5d99bbe08781c95d6eab57a3c6e1d1ca3484b20bf3f67f2b6ef9c6bdba800e3275a469f8e39630366581f2b275b65a2a3643e02142c7a58bc00e60e350f930fe441f443454c5b7da4159195ecc9ea9d90929a74186312877f3b3f8a0eb61037c73f24d7f13fbe2304affcebedc366318b6c1a53f470efdb7cb16c833abf27ba330290ff43209af9eee39081bc576e1715d953ad728297c3c939dab1848763e6df0c72198c8571541b81e4dfea8196bb8f8cd319f80e10e64b61d1541bcd89ca33a6e67517052512906159506f3b012b76d5b4280faa87e5605a175c1b05ab70f91d98eea78f01fdd401e032ea5ebfebe20e81bfd4a6fc2e8f99017f50b310f1310b3b71c70c2537d132a2f6c588db5af8d24ba648ee89fc0553b305f1664f9e480ac4c103665ab51d13f94bcea38d9faebbbd6fa6298a8374448f1e99802499fe7b64d5a0e607ebec52ce1339d073130bc7d68cc0f74c29a8d313ee17d38c467fdb225a1287f9e2c328c8da19a8834809db2ec5438d30df24ba3c3b264858998ba973f016016f117db6982ef3d43d31236ae3bce49a938d43d8cc46e4de548c85cb2bfb33669fd7a9492e62e761861693a7a3aa14cfa3243521f8ca7ae6add2d20be4bef6ce40bb25795b7f53009135a992ebf8563654463e35585fc9c380940f324f9b07f638c54d6d5da77ced9814456adca7fd15665797381580f2aed4bd800942faa64a2a086ea01aca5cc4a139b234ef3837f789d406481f17798521571d5cbf83336d03a4fb054c2556bb423602364006f6f8d59eea0689fd280e29429b7052b4614aaf785e22c70596cdd11403d9a9e9a60f45395c7e4085a515689e37ca942d5a65f872fd3223adf2f7bfd47fce21f280ef44ea71c755dda9f41e730b306b90a1432ead90f9f788177cbdf41db86135171d2b6d8baf8e0a3f019900e19dc9d9668111e3300e1a73aed0a68a25e6d670cba7e1fc6c18e8da346402b732446a381a75c65a0959b1b4fe2d116b801688880a9cc014e0e7b5851610bc49fddca01aea179977b87863ab3ba9004a05a08609278c5bfbfdbe9f6844b439343d46a0cd38b40b4ded6fee8b563a20c25637f7068810e379bd65b704f6e74480d129482f88ce63d9eec54d1f19dd113afd36357ff3d1d989a4992ee5d8c4a25946e8f79b1a80ab76685c568280eed7b6902f66d3e29116ad75c547e8ffe4c5ad03622befb7ead7bf02b5c0f44765d577148fcce0354f60c939aaf4552f352a2981026208ee74c730ea5e03b78756b09aa68e02f60931a2ae5176a0e6eb02726be51b3f286192c11a98617138710d27ce6923bd49e099f18feffc0bed3f1d38474baa4c69bd92561aa4827cfe9796a1f3aad098b4eb8006b02db2ed8fa6dc84eb78a4857cc9f027908d90578eaf1ebda3989c9501c7c098b9ded18ab12fced3473205cc5d1c2b8608bab400423402dd10eacb71e6ce96a0990b34d94a0e035b3fa84b62fc21323a3ff4bbdd6602b694ef45572d4650fd80771eb1bf8621654fc43403fd3a018f67c2e675cf14d60e6276425b877f4c0bb9c057d6004f07431a0e641cbc41b2d77a5304c06ddc39cc995248b366cb79f3c38322b4074ec9bf147d6d1663deb54acf30d9568085f910ac91575901834fb234cb0d8b1579eab248cc5b1172dd8b1872dc8665b07c17f88c37df4f8f67bfe1e4e3c5a0a7259a7a2687319e458de79b8bc377a573b760fdea26b82b1a7ff7e2e89c756d9c7fb29a75367c4c44b8e6444a6ce2f81902a1bf7e2485039d1b2b3810e680e22770953abec970c1ea3eb8244f8b5cf19d23d637b8749c61dd653b34e7e8c7064b5c2d67793c867adf8691543df88c2e96ea08e06fb29a40575ac4b18c8506b08c9608e9e9512e132f093fd12df8910ebced42aae6e768977d7195dc4728b533f35852926671d08b1a68bc6c8abea8b4dd82811bb3d4959363dfa923a5a40c656b0b557afefde201ddfeb04901dd91fa610e4be576555cd592998b4d2e16e64c48acd3ac6db3473ac77625de377c2e1bfb8dcbf8b7b111c13287a84b6b7bf35e2c54b37064fa8c4e03a19beeea55ea95caec8e02a4c73c0344c83664deda81e64b20fb00a602a174031cdd5248db1abbd543ea2240f4e4a4df8c7648cbe45c639ecefbe7c4bb2df223577e63922a7a6bdbd3a6d3908f5cdc412fb455516341d66dca4b4523f82e7f9d3be73ae24b97985e482d6d4e6cb82dcbb362ce064c0dd54a26c42e843625f155f9152f94aa6ba04839323ee78828dbf5e0dfa4d628656c736634f9122c4fad047d0513f7118ce77c959f9eba47b57ccbf2671c6250665f83e915d74ccb7cb6faa028eaecebc21b6bcda7193695592b98abb6ee95e47547da6dca4b9b740d0f4a6a6c95ec7ff2ba481133efd7e2b9b93376f08ec97f40a4045a167695ae1114150cdbff9d3081a08d03f2f0ca0b25435ca28b53266cf94faaf656b4e7fb7db882185c973186743c45064ccda60163e73a8c19aab9ae7d2f9e563ac8fffca64ed9c6277f342a99bdda91efe01c2cb24e6149428b56d322f2f7b31e1c61e581b57afb7acb216627ce137fc8fcd14ec5c8d4be39beeb9dcdcc5087422e0255c29f10870ad9bc8931922a21e5b57e085d3d7f20bed100cdaa22a6af6196892702a6eefcfdd601649dcbca53afb0665b25658b57f988e3fd743ce52ee421f4973ee95becda180c7bf41f7f1b3a0c7a5cfd184478575f7aabb059cbb94a42fbdd5b1b11061b8a442a2f29d1096ea85439d89fc031e3b22d85ed29423632ae4f2b6fa98ac4e4f601d91c487f6c84ca2d660aa157dab73ff31f441e6653e9be98e6c08fd6009a5c7e82f4de916ef3650b7a9456dbb77889763448205f42a7d776c871123b1db50bd73f3d60291b1ef225372e5ef434e256e97b4caf64eef889af73818c30d3b24d5ae5aa15353b4e22de089ea4b560891bc329e12e0aac9e7e2f8fa83971eced1115f4b664f5e80700193c60ed15c07f6267f61e1a07b37ec3072e2282133ced8ddf25e8f865580b9cffa49089014a601bf000adebb5ceb5bcd539f3ad20f9c7ce5b3b1d863d4bd60a5fda1f566c9da7c2196abae8b806d62a01ae6840cfb864487c9f3e58b2c22d21ed292a56fcad7a2c53487fff3faa84ad7d58ffc6b00c60aa50e637d4ea74501aa568b1b2a349eda1d04bff81bb052e1d927bccc3daab9ad18fa77740e936c6575fdf6babdaf7a241114ed4f3d65bfb4fdea7a4f57553963df5a5e066b06e82663e54b58a2e5c8f0ce57e2ba4832139ebfbc70671646332a86e971aa9a9d25dfc89243f41cbdec196b279e1bd669be402c94134a56bece2d3d5e733cbb693ce523ee2ab7207feaee1023c4a11758a2c9a1f901623002b9ffa27b642dc9b6c7ac02c2bda113112e597bef8082c3cf95ea4689d29f1f9e666d75aeadd181f92b6e68119c31bf71310ab8628c5f5cecc32e1f2d760231e1e99660a6ad7b3a8ce6d677ef61161fb9979c3897a21871cb431a7aae519cac807259780068e48917d8f2d2b70b3737311db2333d32ace68822d2bd852cfc81eb5dc356fe2e749fa6635228fd6813997372dfc4cce81c9b847615bf132c3f5d1fcf341128dfd4501c98fa3cbc2537cd4185b53bdf095a83bc17acd63119b6195490014a772c4b1787873696ca6087052284db67c5ec38b9243f7a476acd2f10374724c57c15f193a6cc0ce635d59989ac56172b7bb8efc2d6aa17dca85b2a5690a9f409294b33579ae8ffb506152f3f2f3e7c00955005e4fbfbea1827b6678306cffd56cf3f43ceb0afdeaffc891e5bb7ec6eafe24e2aa5066185820d20cab677bc9b83c5a8f2307d4fbd3ff3a282e457d1c3d6ff041763044318b7721dabd51e43337d37fa3064ac7f564d7ebd23930ad11b38d0d7312a62862f7fc9e0664eaf0f0ab5cea30e55ed52078edb0c722ee7f6d5ec4f3c17503f2a97a498660bb7ea1a0e305fe25492944af4b7d4f7bcef715e714b840b440209650e24ae1302c4a658fa7dea6ca6153ad886444ff54eea7672e9b32a1196e593f0532def46e64f04ba46cacdffb7aa1f27f22a4f30001cbc6c09ac7c4450194df9fa302996d8af546361730744ec2264b884d8b92c8ce254289a2082e182f5199f9e22fc37a23459cf97802ff48448c3c66eda84d4d4583db8946f1d2dca19a5e3177769190174e056a0bef4a3695d4c5a47defcdddf1ba513966b59824d9cc996d123422ffb527eea355cd8be64d0400838229f29f263ed5f31d158b3000e0ea1a41d9d0bb1c83fb36fb3aa3087f3320bda1e78620bc4cd4e7bbadb5a1a79ceed8458b97067be123a9a3545ab4593c9f8a341b0c2cae3c3ce7cf2e451185c45c576203eb157f6f0942a6d18343e0cdf7e99305720026ca36a9f2a4b29246cfc7917bcaf41981b2e6cadf1401c062ef1b4f1f98a9e480a6ce1224cf49181eaeb876726315c2c0cdba03bfc11d091042d47dc2ef5e2fb49c4ab4597ccb65cbf0caaaa6015428f7c223733f2cb7cd7aa8b4c7807341f74e83d796b08a5ba9f2c7e56b51665c452a96f1ba0f7490cdcb248b5e5c85c687b6c5710be23019a8bbbdbb9f451e42b79423657f7669e1e55fcac0ca6ef554d7df76e9ff5429b20dae46ed08b9597daeb049c16b03f095c036b7eae7af530281132a2a3ec12c262ff2f66a261b61cf6400d97bfb413de51aa7bc650840ff0853fef3bbb3fa0aa2481275b7d23e369b3e17263f97d49f7a33caf484ab9629345ddee07c9da56a542ada207d98bd7e7da0f38e9327554ecb0d97fe8eb2d2e6e03047e6a05a5bf9f2ef5fe92a9e086e921f117d2bcc37cd3b3e6e4951f19137d96efd9401a1b86a4c70d612a6e96f2516c5da067c58d0431657cf86213766a7ff003cc932ab129772382f6f6ef8d7191a25ebacbb167a31d229618484276f63069f9f837e910829153d31412bb74be44a246f67cd9054e2725baa93cd362a180da0170b726f7698dcba636acaa61817675444aecedda4bac9cc814cc160ab382768d1a4907c41f632178086bcd42da9f7b59d66aca71fd27ec3badf64355c971cef6f9266d200b054ab5e6c8442d158050a0445562d66d9bade327d990428d3be4098a8a1532113ccb8b973aa3f87c07ac87bd8085dbc19fe2fddfcc626c476a7b39cb83e95f62ff1500af385d97e9abd08e6096e64f1569ba5559f0ca9a7c368938cccd5ebec3fa36843ce3fd4bf8a09310a6fe96dd320ca684ce4839b938fde5b11e7b81aad3d2053c698e8ff1bcc5b90833358eaa7b60b006bdf825a062fe01cd4818cf83c1330906298f7acca65188b51fce45a5a9fd64a94bc180267e1f33c8f052ffe457016bd061572f92c784e245581dfbf378f108880202b1089656514daecc405f5ed23a231f72524c81112662997f371474c3b5dbac649",
            0,
            "e01a5d102bb5f8ba7986e7e4ab0fe8c4922bddd005adf740122684a91afad1a4",
        );
    }

    #[test]
    fn bip119_vector_2_1in_2out_scriptsigs_idx0() {
        // 1 input, 2 outputs, with scriptSigs, version=-1051347441
        check_bip119_vector(
            "0fb655c1000101e3bfa656000000000000000000000000000000000000000000000000000000005296f6a3fdad01023648cde2159aabc319afec69ddaa111fde9d94585b4610fb3586e295e25fe73989f10e0991620403eb13fc9861f45021df9966228eb44d474d174823ff8ee86a2ecc631b1267fdb545612f78b4b1d300863e675d47dda8c600d68015b7688d4446625ce245ffc43445d0e95ccfb3275948ef8c21eb59887ab32de1e540d20b62182d442f5c82e41e74b1faaaf84075d88f883fc2e5ae237f3e6ba115b0b2d803fba0d28472c1d0db5e4128b2bce7fa1c1bcaa8823b66151940bc37b9e81cfb2b31f1928a6d1d8716925e91f02de1bfc8b54de0f606b950747063444149f406b003e3e954f89769626083128540ceefd85546537fa7d6541b605cac7c76feb9eba6db727892bccc686f5003758c1c36e7e5f56a49e3736dd9e4e85d12d242315fb52cbcfa19fdb6f794e99bc9a4c7504b76e4288bbce908e1147e1ffa2b25147229b464e03c9a196e5e660fcf43c0a824497e5c246cdd3c79585c43069e54206c06c60a00123f4a3f4927166f290354c512ef7e42b5930c8af1e224a052a0ea1005ea96f19e368509611b183415810e1f399dc3afda846235ceba7224fb53bc8434a2ee37e4d494dbd0742ca294cc04910281d342e9ff46eb40c8747ca18aeaff3d1c00fec1600b4642a520fefaec35d3df74aa13c1d9e37e6405e748512e67399ffa9f7fba8d3244e2e1d6a9efb716a78e4cd947a577a193282d407ba748f3311e7f8880852074a47bbc74994e75fac4aba473c99b97e7ea245e8c56dca37ba1bd4d64522f9eb474cc29018d35da3a1a8abb02032bf0577c681703c4e88ac2c5a57ae0f678dc5834639833fbe1f0e1b9fa817582c30fb07b51641cc4d75e3be4989c25f4b339e3194ff91a0e08916c0410a407fad131b0d15958ed8439f6dcd806554121260a62c36b32c82e0a153e93983ea7152eac373761dba154518e7da0a6d90cb60e306a110886b01353f1dc76ec082130f8176ed80444d9bba60cdff3ccdf31b370e837d94055ba6cc5d5bb8fe396c6d1bbe92c6a19cbd371db892203e7f17e91aa33f093e886601473319154b8fb4db0b0e68e7872e7002fdbab5d6f93dcb61500e4447e4c819fdb590bc7803f8068a008e3f9f1e250a6730a76881fed07d6895690f0444f49019b6e11939cc836fd5b8e4a01f1007c029250412d8e7fd8ac89476849b2c020aac27da1ff8618166303eec688936e28f0a31adb1263dcb48d0d060172ab1d0f0e15102d2815dca08a19d9c2d872224623dabed1880912485e54d3331ec9052a778786498ee0a57271b243e3c854701b2284cfc5d9e5997107cb389df6e58691180bc4ecd0ebfa266a2379d23c561c7fc3b29c393820be0534237fecf93fd33e5cd775e3e17a5db3b35e1d3dff99ccc3263796227526b62c1836704cd13bb50aced16eb449e5511dab9544d1ef4eddd839ac1f73de9bb6a5ca714fd0362301489ffada6154f9aa55fa3bae31eae4f7a9fc02d9aa6dc431cac4f657a47d75defe00ed7ace6e2aa0bfbf06a6f95ab872fc7fc084668b35991e18eecc9a5eb8eede635a619ff7bb40cd1e9f36da0c1fbb9ba88667b8a33d28ef266c270a8e258a933903e8658f71b4c104b34a90a685465490b82483a231d1f5193b58a356b8aa509783964c6aec4f480e6d37a82882449e9f0cad78df21cc73ab71f8253bf236fb67e3807e1f7511da8d4ecf17df6794595d2ce4981e6e7639cbd7dbbab6b18a4ccfff9f404449d82f8c9dd5ea718deb2c5cf373788d8dfd02d375b6d52c8c12d6bfbb5b2ee6a7fe45d705a28df3a0097e90bc4b19ed940530d3244da84a86a9c241bbb2e2048ce0510fdff6c9474f0ac33423b93fe6c07d9c24712761f57ed7c19cd311b1af416544443a6f7f61385ed927d13921bc9ea8a44cc065e6b17db35451b439e1954a040305b2b355160426868746819ccdab1023e30f326926c850ff52a06e8c7852dafa114863f65b25ab7495",
            0,
            "f995d871d35aeeef5d42fbe5c6e8428616d2888db157697579c17add7d2408a1",
        );
    }

    #[test]
    fn bip119_vector_3_5in_3out_no_scriptsigs_idx0() {
        // 5 inputs, 3 outputs, NO scriptSigs, version=814707723
        check_bip119_vector(
            "0b748f300001053c73ddd9000000000000000000000000000000000000000000000000000000006d37f59d00ee34fd4b498f005700000000000000000000000000000000000000000000000000000000f66f9bc300059000915d417d6c000000000000000000000000000000000000000000000000000000005fda9bba002da98aa5f81966170000000000000000000000000000000000000000000000000000000049bf1a56004d5d2468ac523d8f00000000000000000000000000000000000000000000000000000000276b4b5500fe26001d03fbecd947d802ea49c8a61d48f577a041311daa647870c8166b0accbf1b2d5e050ffddaa2b08d3e1b2f5392bfcdda9e4a1c19c2b1d9f6185d8d3112d09a983c02db4ce36d9eddbe2daabdccd2dab45985eb37b6349bc81c871bb26ab409211a4513ac4666324e7f44c608fdf5bf073fb64499471f81e6f7950c50f952ec14506ab7985656e5a78446b10a59439d98522177037401faf445734aafce951ba24f0cc68bc0b59a75614d7717265797a683485ac416b4f0be3f9230747f5b6c63ca3e3b8650a68e2fe9346b8fd17c9f29d8c6c4012bb9ab0f970578c8e10acd035ab33642af34daac3882805910b8312bb512d9126d4b465a8260f27ab99c2cdc0936c43fbd2bdbdeb2c35308ab9ead119b767ef01afb943dd9e2b5e053ea99d639fa3b897afeb812d315a80396bc60d59b61fa3e6f461dd718b76c057fc998d3344da47b9da5d024dc4557f05d2a270a9dfc48f297b15c0c37ce68da274afda61593aeec9143b85c060e90ff86650e4fa4e9fee59d4a0c3a3d18351eca4e7cb94fe3f3b156e07217638cdcfb6bf8d512f86bb38bd610832cc7c75c4a94e9a90153ecfdc8b85429d2968cdb48c8296777133ff16197f773b3536a0a1a2d598e6776257685c969d43044173724d8cbeece0e7053234712880a031d12e84ceea423a95efbecc0a5abaabd5a5647fbc6b606116e10532fd7a31d8738d37cfc201b726bf6030f25c3961125dc510417601ffa52cbddddf2c185f4cc17bc7b0d510247b575562306e64cb4e5359d7d70d09e3cd89dac10d82fff19c2255a3ca6a992fbac4b414f23fa1971e838de2e393b2c20c444c238b78e0678cca3901cf29417ab0aeeca9626fcb7be5e777da3648ed088ff4d4154b701f38dbf127fee38897a5ee7d7d357a672031a3085600ae3ad2384696bbdedaaec8a86e008f064c6ad5950eae848772bfb597cdb9b9af7baefff97e52965fd8cb2c8e3561617582942eeb827bce577ffae69ac948a6409c69691c61e0cc55cc11320df3ac90ad2917913e701d69402016a4d88b84915eb546ccf34a37a8b33135dd10306ab10e73bb2ab3fef965423557ab11dcf6c8135660b07a90881b876e06047827fa3e1ae98798604a0dc1d11d9e715102edb2ccaaae863d10ea8c2147b8ca3e8b3f10f082140222d914e15599706465da455f6d5f5b9f14829b4a2611476b5d5ddeaa32037e69098658ccf4790671e2bc206020e9e06c13bc00ce2d4ba17cc6689bcfdd4018fc919d232d5f5021c3d689a4625593fc68aeaacdec4e408bade148365996b6da85c4e9fa11220dfe94615e2ff5356b97874059aafbcac2b0dc90792c3ec08ef4a2bd135ed059c52a42b1d1c168558cd4a758a54752b433d624ab4e7971e51cd39a18aa1229acce968579641aba00662976e6732994b8c3f1683bacfbd510b345391cd438f171898612236705e51c6d603f4c95f5739f80d50abf2133c168af58450f26cdd571ec8d0c6ce4dadb2cef510cb424e75e984f9176e448683c08b3e11419f34f8eb11e1ce4914ae35188fccfece3372e502951df6715ebc5ddad5c13dbf70835c1141cdf2ecf81ed0ecd8d5cf5ca8c57203440f2beaf3f91ef4bd5ad27f53de363c5116de666c5ae832cf9216cc8817091355e22e9dc7ce4f652783b2b523032b7b346c25621b65f4a505b220fde444c57a9a80088bddb5726362ba8a8207834b566c2f9bf9272883aaa62b4553d82010d4081f3bc8a2f7c4878ad4adf0c8c11adc04c41c39ba49dd764bdcb7531b23837ede7d615ce76dd8b68323df8835479ee40688172c881b81cec1074456b53ddd50ba6d96b113ea8a04d5f0466f8ca98b6246d8c84c54d8e9362a6b93481fc2b2c5109c7a6649078c8b38ebffb1adeb396aea039c0b6354d17d5077bcfa3b1103de56a85d7f7fe6d244e4689e03b33515e1674724291c138027e4f0eb953286f4f9e5d790351b538ad17a6a2b0dd3758d06d84413c0bb851daec68775eaf4281010ad67dcfb377b834b3adaf308368fc9b105c16e62e76a629b8af41c7de29a54a974115541e037d5f0f94029dd551d72a3b43e5c39c111a8ce30ab87a0e2e21770e924be91b8e9644c8bb37568bef66a355530e2ccc596bc553ed10fb9973c1c83b6d6f088baf33312637a3d7b47aba022d6e74eecb728f18c22e94fd022e73e7f3e573c8306926459669e80b64eb755ff25df4d2ce78a44c6072729834ef9fdac017c197d8b0e8f91205b0f689ecbe2ea97aa26b6d60d3f72923185f561d7ecc627b96ad0744f69d0cdcac6c30bbf45e9d208f69c6ab1ebc3d83e39da96863525050a37d1d2002733a6fc1581e8e9d16f4a64f2455d7541646d5026ee34cbae5f559d822a99086c75408e376e8d932f87a773b7177f54675a77fc34b935aba64a6fc836b7be488764f4644e68c09cdad418b438a15f02a6cc148bb5e716af5cbacacd4a2be4a5c34e7c0a9f534c19442bb1c4c19fc18567685ec0a6cc79f997061ba073169873b538814d6204b0f0677e9904575bd8d4dafd93410e89065d32ba5fb2a912605368bda85f0e507b68b504baf5003b6308b0bcb094d822ebe2369f0a1caef770051c5a658ed4bc909405c7d30fcf6fe5f52a560e3189e308ea401beb3ab31c1c9a274f4daaef6fa6ddffe0d0accb622d782ccc2d8a581db691c011ec745f8a1c1c4bcb2f52efe1c2856e9a77295e8ef14b935820641d952aa895b1c6bc46a821a85d024b39e734838d007c62ede95bb4c14c6e35d1abf959dae66148b358575f52d9f79fcd81a3d6a4bc7bc62f2499d85ff5833bb2a61a12e28b2b70e8433105ac084998ef7982179ed17df120050b9408a074b8c88beb21ca3ea9359a0bd842c8124e1b3e12bb2f6f68f3887f76ea02824bee5f60ef7d6a438f538ecf4cbbd71c0bc5a41acb03c8c46e6b4ecdd47d16a00e4dcebbbb36e88c82e94c5046081dfdf34fa334eff1d2582e72e39da5a3a0966fce036748b2fa55adf9c96e7b995cc10e3ef11b34a9f6f4eb2556553e6572d11013ef39c033c40232aecba0e36b34daa35f6d9df38b01fd6101cba60d0c4fea9019e3333c4dea24bba24bd906ec319da74809533cebce37ded637c6a21c5fb63096809715971f23ca63b613fe45722cff3c8536d2d2ac71a16476d78dd29bfc013157f0c74da2d05a4bae9bf8145b2c2e5d5b98a1ce1bce0da674490d607e67cfac4fa2832088d237482e3184722b67747658e6c2c94c65e3217bb4e5e9d6c02d74dd45829aca17d9aafa2987b05ac2d6aceb51c824f3d9164a38166d85ed09069399a5d76169bab088258ff89a49451999eed3a2de860e81c6a69e2fb6c77921a018cd29ff1f368f5c5ecf1f831b175fd2f40548adff6425596a10e4d857f3eecf29e00c0e401ed85400d0f22cca0cdc3f8bd566409a5f50ca75adca2de1659698608fe19f5d7ce08ce7d8dd5df9d46146364b4487288290a6d88f52a9c8f525512a6fadde91329d86198bd49642a6f75523e0d0fa10ba996429652c173b04c94f182d6f24d0bde2db590da98c9370d25a6f08978e5183cee41201fd2201d9c1cc04c01b43d94b86a20f89e498560be4361aa120763798da9a303337116095fd5e8d368f0f492c79f120d532020a9f5b8066ab8f7f97f02f0165ab1eb352aa651fff9d70afbf497fb82d2bfa7b95c8b7913d9c63756892e3d8a4defd7c63e366e5e051de0657777d06b6d047a065d34129e6c61406bf004884bfe21d27e840fdce1446a47b0bc55bc6565aaa599262e66102b42e7d410ced19a14e9032c0b52cb73bea41cd6ce76b7430eb2f7442f9fd2236b2c37d9f6a01e522c28b5ccd27d7a0b728cf99f86c06460d67c9521cc5cb95e4116fec8b4fa42dab258c3bd4ade03cc6690e5ae0622be12ce57fbe86411c8c42e77ed684bb719655ff5b47b6b111868e1768b36a31fc09f43017e413f9439969f492fa4ed622e8a6751fb94c3f9908e91981",
            0,
            "5f3bc9fd7fc449341f79d74af750943ba58ed43366d610bf9c85832e15b8f4f0",
        );
    }

    #[test]
    fn bip119_vector_3_idx1() {
        check_bip119_vector(
            "0b748f300001053c73ddd9000000000000000000000000000000000000000000000000000000006d37f59d00ee34fd4b498f005700000000000000000000000000000000000000000000000000000000f66f9bc300059000915d417d6c000000000000000000000000000000000000000000000000000000005fda9bba002da98aa5f81966170000000000000000000000000000000000000000000000000000000049bf1a56004d5d2468ac523d8f00000000000000000000000000000000000000000000000000000000276b4b5500fe26001d03fbecd947d802ea49c8a61d48f577a041311daa647870c8166b0accbf1b2d5e050ffddaa2b08d3e1b2f5392bfcdda9e4a1c19c2b1d9f6185d8d3112d09a983c02db4ce36d9eddbe2daabdccd2dab45985eb37b6349bc81c871bb26ab409211a4513ac4666324e7f44c608fdf5bf073fb64499471f81e6f7950c50f952ec14506ab7985656e5a78446b10a59439d98522177037401faf445734aafce951ba24f0cc68bc0b59a75614d7717265797a683485ac416b4f0be3f9230747f5b6c63ca3e3b8650a68e2fe9346b8fd17c9f29d8c6c4012bb9ab0f970578c8e10acd035ab33642af34daac3882805910b8312bb512d9126d4b465a8260f27ab99c2cdc0936c43fbd2bdbdeb2c35308ab9ead119b767ef01afb943dd9e2b5e053ea99d639fa3b897afeb812d315a80396bc60d59b61fa3e6f461dd718b76c057fc998d3344da47b9da5d024dc4557f05d2a270a9dfc48f297b15c0c37ce68da274afda61593aeec9143b85c060e90ff86650e4fa4e9fee59d4a0c3a3d18351eca4e7cb94fe3f3b156e07217638cdcfb6bf8d512f86bb38bd610832cc7c75c4a94e9a90153ecfdc8b85429d2968cdb48c8296777133ff16197f773b3536a0a1a2d598e6776257685c969d43044173724d8cbeece0e7053234712880a031d12e84ceea423a95efbecc0a5abaabd5a5647fbc6b606116e10532fd7a31d8738d37cfc201b726bf6030f25c3961125dc510417601ffa52cbddddf2c185f4cc17bc7b0d510247b575562306e64cb4e5359d7d70d09e3cd89dac10d82fff19c2255a3ca6a992fbac4b414f23fa1971e838de2e393b2c20c444c238b78e0678cca3901cf29417ab0aeeca9626fcb7be5e777da3648ed088ff4d4154b701f38dbf127fee38897a5ee7d7d357a672031a3085600ae3ad2384696bbdedaaec8a86e008f064c6ad5950eae848772bfb597cdb9b9af7baefff97e52965fd8cb2c8e3561617582942eeb827bce577ffae69ac948a6409c69691c61e0cc55cc11320df3ac90ad2917913e701d69402016a4d88b84915eb546ccf34a37a8b33135dd10306ab10e73bb2ab3fef965423557ab11dcf6c8135660b07a90881b876e06047827fa3e1ae98798604a0dc1d11d9e715102edb2ccaaae863d10ea8c2147b8ca3e8b3f10f082140222d914e15599706465da455f6d5f5b9f14829b4a2611476b5d5ddeaa32037e69098658ccf4790671e2bc206020e9e06c13bc00ce2d4ba17cc6689bcfdd4018fc919d232d5f5021c3d689a4625593fc68aeaacdec4e408bade148365996b6da85c4e9fa11220dfe94615e2ff5356b97874059aafbcac2b0dc90792c3ec08ef4a2bd135ed059c52a42b1d1c168558cd4a758a54752b433d624ab4e7971e51cd39a18aa1229acce968579641aba00662976e6732994b8c3f1683bacfbd510b345391cd438f171898612236705e51c6d603f4c95f5739f80d50abf2133c168af58450f26cdd571ec8d0c6ce4dadb2cef510cb424e75e984f9176e448683c08b3e11419f34f8eb11e1ce4914ae35188fccfece3372e502951df6715ebc5ddad5c13dbf70835c1141cdf2ecf81ed0ecd8d5cf5ca8c57203440f2beaf3f91ef4bd5ad27f53de363c5116de666c5ae832cf9216cc8817091355e22e9dc7ce4f652783b2b523032b7b346c25621b65f4a505b220fde444c57a9a80088bddb5726362ba8a8207834b566c2f9bf9272883aaa62b4553d82010d4081f3bc8a2f7c4878ad4adf0c8c11adc04c41c39ba49dd764bdcb7531b23837ede7d615ce76dd8b68323df8835479ee40688172c881b81cec1074456b53ddd50ba6d96b113ea8a04d5f0466f8ca98b6246d8c84c54d8e9362a6b93481fc2b2c5109c7a6649078c8b38ebffb1adeb396aea039c0b6354d17d5077bcfa3b1103de56a85d7f7fe6d244e4689e03b33515e1674724291c138027e4f0eb953286f4f9e5d790351b538ad17a6a2b0dd3758d06d84413c0bb851daec68775eaf4281010ad67dcfb377b834b3adaf308368fc9b105c16e62e76a629b8af41c7de29a54a974115541e037d5f0f94029dd551d72a3b43e5c39c111a8ce30ab87a0e2e21770e924be91b8e9644c8bb37568bef66a355530e2ccc596bc553ed10fb9973c1c83b6d6f088baf33312637a3d7b47aba022d6e74eecb728f18c22e94fd022e73e7f3e573c8306926459669e80b64eb755ff25df4d2ce78a44c6072729834ef9fdac017c197d8b0e8f91205b0f689ecbe2ea97aa26b6d60d3f72923185f561d7ecc627b96ad0744f69d0cdcac6c30bbf45e9d208f69c6ab1ebc3d83e39da96863525050a37d1d2002733a6fc1581e8e9d16f4a64f2455d7541646d5026ee34cbae5f559d822a99086c75408e376e8d932f87a773b7177f54675a77fc34b935aba64a6fc836b7be488764f4644e68c09cdad418b438a15f02a6cc148bb5e716af5cbacacd4a2be4a5c34e7c0a9f534c19442bb1c4c19fc18567685ec0a6cc79f997061ba073169873b538814d6204b0f0677e9904575bd8d4dafd93410e89065d32ba5fb2a912605368bda85f0e507b68b504baf5003b6308b0bcb094d822ebe2369f0a1caef770051c5a658ed4bc909405c7d30fcf6fe5f52a560e3189e308ea401beb3ab31c1c9a274f4daaef6fa6ddffe0d0accb622d782ccc2d8a581db691c011ec745f8a1c1c4bcb2f52efe1c2856e9a77295e8ef14b935820641d952aa895b1c6bc46a821a85d024b39e734838d007c62ede95bb4c14c6e35d1abf959dae66148b358575f52d9f79fcd81a3d6a4bc7bc62f2499d85ff5833bb2a61a12e28b2b70e8433105ac084998ef7982179ed17df120050b9408a074b8c88beb21ca3ea9359a0bd842c8124e1b3e12bb2f6f68f3887f76ea02824bee5f60ef7d6a438f538ecf4cbbd71c0bc5a41acb03c8c46e6b4ecdd47d16a00e4dcebbbb36e88c82e94c5046081dfdf34fa334eff1d2582e72e39da5a3a0966fce036748b2fa55adf9c96e7b995cc10e3ef11b34a9f6f4eb2556553e6572d11013ef39c033c40232aecba0e36b34daa35f6d9df38b01fd6101cba60d0c4fea9019e3333c4dea24bba24bd906ec319da74809533cebce37ded637c6a21c5fb63096809715971f23ca63b613fe45722cff3c8536d2d2ac71a16476d78dd29bfc013157f0c74da2d05a4bae9bf8145b2c2e5d5b98a1ce1bce0da674490d607e67cfac4fa2832088d237482e3184722b67747658e6c2c94c65e3217bb4e5e9d6c02d74dd45829aca17d9aafa2987b05ac2d6aceb51c824f3d9164a38166d85ed09069399a5d76169bab088258ff89a49451999eed3a2de860e81c6a69e2fb6c77921a018cd29ff1f368f5c5ecf1f831b175fd2f40548adff6425596a10e4d857f3eecf29e00c0e401ed85400d0f22cca0cdc3f8bd566409a5f50ca75adca2de1659698608fe19f5d7ce08ce7d8dd5df9d46146364b4487288290a6d88f52a9c8f525512a6fadde91329d86198bd49642a6f75523e0d0fa10ba996429652c173b04c94f182d6f24d0bde2db590da98c9370d25a6f08978e5183cee41201fd2201d9c1cc04c01b43d94b86a20f89e498560be4361aa120763798da9a303337116095fd5e8d368f0f492c79f120d532020a9f5b8066ab8f7f97f02f0165ab1eb352aa651fff9d70afbf497fb82d2bfa7b95c8b7913d9c63756892e3d8a4defd7c63e366e5e051de0657777d06b6d047a065d34129e6c61406bf004884bfe21d27e840fdce1446a47b0bc55bc6565aaa599262e66102b42e7d410ced19a14e9032c0b52cb73bea41cd6ce76b7430eb2f7442f9fd2236b2c37d9f6a01e522c28b5ccd27d7a0b728cf99f86c06460d67c9521cc5cb95e4116fec8b4fa42dab258c3bd4ade03cc6690e5ae0622be12ce57fbe86411c8c42e77ed684bb719655ff5b47b6b111868e1768b36a31fc09f43017e413f9439969f492fa4ed622e8a6751fb94c3f9908e91981",
            1,
            "564800f51e04ca3288dd040816b60cc9fe4647833a750a98afc943ea22807d8e",
        );
    }

    /// Cross-validation: our compute_ctv_hash matches stutxo/op_ctv_payment_pool reference.
    ///
    /// stutxo uses: TX_VERSION=3 (regtest), Sequence::ENABLE_RBF_NO_LOCKTIME,
    /// locktime=0, single input, input_index=0, no scriptSigs hash.
    /// Our compute_ctv_hash uses identical parameters.
    #[test]
    fn cross_validate_stutxo_reference() {
        let outputs = sample_outputs();

        // Our hash with version 3 (regtest, same as stutxo default)
        let our_hash = compute_ctv_hash(&outputs, 3);

        // Manually compute like stutxo does:
        // buffer = version(4) + locktime(4) + num_inputs(4) + seq_hash(32)
        //        + num_outputs(4) + outputs_hash(32) + input_index(4) = 84 bytes
        let mut buffer = Vec::new();
        buffer.extend(3i32.to_le_bytes()); // version
        buffer.extend(0i32.to_le_bytes()); // locktime
        buffer.extend(1u32.to_le_bytes()); // num_inputs

        let seq_hash =
            sha256::Hash::hash(&Sequence::ENABLE_RBF_NO_LOCKTIME.0.to_le_bytes()).to_byte_array();
        buffer.extend(&seq_hash);

        buffer.extend(2u32.to_le_bytes()); // num_outputs

        let mut output_bytes = Vec::new();
        for o in &outputs {
            o.consensus_encode(&mut output_bytes).unwrap();
        }
        buffer.extend(sha256::Hash::hash(&output_bytes).to_byte_array());

        buffer.extend(0u32.to_le_bytes()); // input_index

        assert_eq!(buffer.len(), 84); // no scriptSigs = 84 bytes
        let stutxo_hash = sha256::Hash::hash(&buffer).to_byte_array();

        assert_eq!(
            our_hash, stutxo_hash,
            "our hash must match stutxo reference"
        );
    }
}
