# CTV Primer — OP_CHECKTEMPLATEVERIFY (BIP-119)

## What is CTV?

CTV (OP_CHECKTEMPLATEVERIFY, BIP-119) is a proposed Bitcoin opcode that enables **covenants** — restrictions on how a UTXO can be spent. Specifically, CTV constrains a transaction's outputs by committing to a template hash of the spending transaction.

## How It Works

### The Template Hash

CTV commits to a SHA-256 hash of:
1. **nVersion** (4 bytes, i32 LE)
2. **nLockTime** (4 bytes, u32 LE)
3. **scriptSigs hash** (32 bytes, conditional — omitted for segwit/taproot)
4. **Number of inputs** (4 bytes, u32 LE)
5. **Sequences hash** (32 bytes — SHA-256 of concatenated nSequence values)
6. **Number of outputs** (4 bytes, u32 LE)
7. **Outputs hash** (32 bytes — SHA-256 of concatenated consensus-serialized outputs)
8. **Input index** (4 bytes, u32 LE)

The final hash is `SHA-256(concatenation of above fields)`.

### The Script

A CTV locking script is simply:
```
<32-byte-template-hash> OP_CHECKTEMPLATEVERIFY
```

When this script is executed, the opcode:
1. Pops the 32-byte hash from the stack
2. Computes the template hash from the spending transaction
3. Fails the script if they don't match

### Key Property

CTV **determines the outputs at locking time**. When you create a CTV output, you are pre-committing to exactly what transactions can spend it. No signature is needed — the covenant itself enforces the spending rules.

## CTV Payment Pools

### Concept

A payment pool is a shared UTXO where multiple participants pool their funds into a single on-chain output. CTV enables **trustless unilateral exit** from these pools.

### How sovpool Uses CTV

1. **Pool creation**: Participants agree on a CTV tree. Each leaf is an exit path for one participant.
2. **Funding**: All participants contribute to a single taproot UTXO whose script tree contains the CTV exit paths.
3. **Unilateral exit**: Any participant can exit by broadcasting the CTV-committed exit transaction. No cooperation needed.
4. **Recursive sub-pools**: For N-party pools, exiting creates an (N-1)-party sub-pool UTXO.

### Example: 3-Party Pool

```
Pool UTXO (Alice + Bob + Carol = 100k sats)
  └─ Taproot tree:
     ├─ Leaf 0: CTV(Alice exits → [Alice: 30k, SubPool(Bob+Carol): 70k])
     ├─ Leaf 1: CTV(Bob exits → [Bob: 30k, SubPool(Alice+Carol): 70k])
     └─ Leaf 2: CTV(Carol exits → [Carol: 40k, SubPool(Alice+Bob): 60k])
```

If Alice exits:
- She broadcasts the CTV exit transaction (leaf 0)
- Output 0: 30k sats to Alice's address
- Output 1: 70k sats to a new 2-party pool (Bob + Carol)

Bob and Carol can then exit from their sub-pool independently.

## Current Status

- CTV signaling begins March 30, 2026
- CTV is NOT on mainnet yet
- Available on Bitcoin Inquisition (regtest and custom signet)
- sovpool implements and tests against regtest with Inquisition

## Opcode Details

| Item | Value |
|------|-------|
| Opcode | OP_NOP4 = 0xb3 (decimal 179) |
| BIP | 119 |
| Hash | Single SHA-256 (not double) |
| Script | `<32-byte-hash> OP_NOP4` |
| Activation | Pending (signaling from March 30, 2026) |
