# ZKMTD Technical Reference

## 1. Architecture

ZKMTD consists of four components: STARK proof system, Moving Target Defense, batching system, and blockchain adapters.

## 2. STARK Proof System

### 2.1 Field

Uses Goldilocks field (modulus 2^64 - 2^32 + 1). Provides 64-bit native operations and FFT-friendly structure.

### 2.2 Hash Function

Poseidon2 hash optimized for Goldilocks field. ZK-friendly with low multiplicative complexity.

### 2.3 Supported Circuits

**Fibonacci AIR** (width=2): Verifies Fibonacci sequence computation. Trace format is [F(n), F(n+1)] per row.

**Sum AIR** (width=3): Proves `c = a + b` for each row. Independent row constraints.

**Multiplication AIR** (width=3): Proves `c = a * b` for each row. Independent row constraints.

**Range AIR** (width=35): Proves value >= threshold without revealing actual value. Uses 32-bit decomposition.

### 2.4 Proof Flow

Generation: Build trace -> Verify constraints -> Commit via Merkle -> FRI proof -> Bind to MTD params

Verification: Check binding hash -> Verify FRI -> Check constraints at query points

## 3. Moving Target Defense

### 3.1 Epoch System

Default epoch duration is 3600 seconds. Epoch value = unix_timestamp / duration.

### 3.2 Parameter Derivation

From seed and epoch, derives: FRI seed (32 bytes), salt (32 bytes), domain separator (32 bytes).

### 3.3 Security Properties

**Replay Prevention**: Proofs bound to epochs. Invalid after epoch change.

**Forward Secrecy**: Past epochs not compromised by current epoch exposure.

## 4. Solana Integration

### 4.1 Compute Limits

Solana limits instructions to ~200K CU. Full STARK needs ~500K CU.

### 4.2 Lightweight Verification

On-chain: Commitment binding check only (~15K CU). Off-chain: Full STARK verification.

### 4.3 Recommended Flow

Client generates and verifies full proof locally. Submits lightweight proof to chain. Chain verifies commitment binding.

## 5. Batching

### 5.1 Merkle Tree

Binary tree commits multiple proofs. Root hash represents entire batch.

### 5.2 Inclusion Proofs

Provides path from leaf to root for individual proof verification within batch.

## 6. Error Types

**InvalidWitness**: Constraint violation. Contains reason.

**InvalidProof**: Malformed or failed verification.

**InvalidEpoch**: Out of range or mismatch.

**InvalidPublicInputs**: Wrong format or values.

**MerkleError**: Tree operation failure.

## 7. Performance

Proof generation (8 rows): ~5ms

Proof generation (256 rows): ~15ms

Verification: ~2ms

Batch verification (10): ~5ms

## 8. Security Notes

### 8.1 Seed Management

Treat seed as cryptographic key. Generate securely, store safely, never transmit plaintext.

### 8.2 Epoch Sync

Prover and verifier must agree on epoch. Use NTP synchronized time.

## 9. Committed Public Inputs (Privacy-by-Default)

### 9.1 Overview

All proofs commit public_values with a Poseidon2 salt before on-chain submission. There is no separate "standard mode" — privacy is the only mode.

### 9.2 Commitment Scheme

```
committed_hash = Poseidon2(public_values || pv_salt, "ZKMTD::PV::Commit")
binding_hash   = Poseidon2(public_values || committed_hash || value_count || epoch || params, "ZKMTD_BINDING")
```

Note: `value_count` (u32 LE) is included in the binding hash to prevent metadata manipulation (defense-in-depth).

### 9.3 Salt Derivation

```
pv_salt = Poseidon2(seed || epoch || nonce, "ZKMTD::PV::Salt")
```

### 9.4 Key Types

- `CommittedPublicInputs { commitment: [u8; 32], value_count: u32 }`
- `IntegratedProof.committed_public_values: CommittedPublicInputs` (always present)
- `IntegratedProof.pv_salt: Option<[u8; 32]>` (erasable for GDPR)

### 9.5 API

- `prove_fibonacci(num_rows, pv_salt)` — generates Fibonacci proof with committed public values
- `prove_sum(a, b, pv_salt)` — generates Sum proof with committed public values
- `prove_multiplication(a, b, pv_salt)` — generates Multiplication proof with committed public values
- `prove_range(value, threshold, pv_salt)` — generates Range proof with committed public values
- `verify(&proof)` — verifies binding hash + STARK proof (auto-dispatches by AIR type)
- `verify_with_salt(&proof, values, salt)` — re-derives commitment and verifies

### 9.6 GDPR Erasure

Call `proof.erase_salt()` to securely zero and remove the salt using the `zeroize` crate (prevents compiler dead-store elimination). The proof remains verifiable via `verify()` but commitment reversal becomes impossible.

Note: `pv_salt` is `pub(crate)` — external code must use `erase_salt()` for secure deletion and `has_salt()` for presence checks. The `Debug` implementation masks the salt as `<redacted>`.

## 10. API Stability

Stable: IntegratedProver, IntegratedVerifier, Epoch public methods, CommittedPublicInputs, ProofAirType.

Deprecated: MTDProver, MTDVerifier (use IntegratedProver for production).

Unstable: Internal serialization formats, configuration defaults.

## 11. Extension Points

Custom AIR: Implement p3_air::Air trait.

Custom entropy: Implement EntropySource trait.

Custom adapters: Add module under src/adapters/.
