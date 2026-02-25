#![no_main]
use libfuzzer_sys::fuzz_target;

use bitcoin::{Amount, ScriptBuf, TxOut};
use sovpool_core::covenant::{compute_ctv_hash, CtvTemplate};

fuzz_target!(|data: &[u8]| {
    // Need at least 8 bytes for one output (amount)
    if data.len() < 8 {
        return;
    }

    // Construct outputs from fuzz input
    let mut outputs = Vec::new();
    let mut offset = 0;

    while offset + 8 <= data.len() {
        let amount_bytes: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
        let amount = u64::from_le_bytes(amount_bytes);

        // Clamp amount to valid range (1 sat to 21M BTC)
        let amount = amount % 2_100_000_000_000_000;
        if amount == 0 {
            offset += 8;
            continue;
        }

        // Use remaining bytes (up to 32) as a simple script
        let script_end = (offset + 8 + 22).min(data.len());
        let script_bytes = &data[offset + 8..script_end];
        let script = ScriptBuf::from_bytes(script_bytes.to_vec());

        outputs.push(TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: script,
        });

        offset = script_end;
    }

    if outputs.is_empty() {
        return;
    }

    // Compute CTV hash — should never panic
    let hash = compute_ctv_hash(&outputs, 2);

    // Verify determinism: same inputs → same hash
    let hash2 = compute_ctv_hash(&outputs, 2);
    assert_eq!(hash, hash2, "CTV hash must be deterministic");

    // Different version → different hash (unless outputs are empty)
    let hash_v3 = compute_ctv_hash(&outputs, 3);
    if !outputs.is_empty() {
        assert_ne!(hash, hash_v3, "different version should produce different hash");
    }
});
