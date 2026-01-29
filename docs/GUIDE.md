# ZKMTD Quick Start Guide

## 1. Overview

ZKMTD is a post-quantum zero-knowledge proof library combining STARK proofs with Moving Target Defense.

## 2. Installation

Add to your Cargo.toml:

```toml
[dependencies]
zkmtd = { git = "https://github.com/farm32df1/ZKPMTD.git", features = ["std", "full-p3"] }
```

### 2.1 Feature Flags

**std**: Standard library support. Recommended for most applications.

**alloc**: Heap allocation without std. For embedded or WASM.

**full-p3**: Complete Plonky3 STARK. Required for proof generation.

**solana-program**: On-chain verification for Solana programs.

## 3. Basic Usage

The library provides IntegratedProver for proof generation and IntegratedVerifier for verification. Both require a seed and epoch for initialization.

See `examples/basic_proof.rs` for complete working code.

### 3.1 Key Concepts

**Seed**: Application-specific secret used to derive cryptographic parameters.

**Epoch**: Time period during which parameters remain constant. Changing epochs invalidates old proofs.

**Trace Size**: Must be a power of 2 (4, 8, 16, 32, ...).

## 4. Moving Target Defense

### 4.1 Epoch System

Epochs represent time windows. Default duration is 3600 seconds (1 hour). When epoch changes, all cryptographic parameters rotate.

### 4.2 Security Property

Proofs are bound to specific epochs. A proof valid in epoch N becomes invalid in epoch N+1. This prevents replay attacks.

## 5. Independent Verification

Verifiers can be created independently from provers. Both need the same seed and epoch to work together.

See `examples/mtd_demo.rs` for epoch transition examples.

## 6. Batch Proofs

Multiple proofs can be committed using Merkle trees for efficient batch verification.

See `examples/batch_proof.rs` for batch operations.

## 7. Committed Public Inputs (Privacy-by-Default)

All proofs commit public values with a Poseidon2 salt. There is no separate "standard mode" — privacy is the only mode.

### 7.1 Proof Generation

```rust
use zkmtd::stark::integrated::IntegratedProver;
use zkmtd::utils::hash::derive_pv_salt;
use zkmtd::mtd::Epoch;

let prover = IntegratedProver::new(b"my-seed", Epoch::new(100))?;
let pv_salt = derive_pv_salt(b"my-seed", 100, b"user-session-nonce");
let proof = prover.prove_fibonacci(8, pv_salt)?;

// Only the committed hash goes on-chain
let hash = proof.committed_values_hash();
```

### 7.2 Sum / Multiplication / Range Proofs

```rust
// Sum proof: prove c[i] = a[i] + b[i]
let a = vec![1u64, 2, 3, 4];
let b = vec![10u64, 20, 30, 40];
let sum_proof = prover.prove_sum(&a, &b, pv_salt)?;

// Multiplication proof: prove c[i] = a[i] * b[i]
let mul_proof = prover.prove_multiplication(&a, &b, pv_salt)?;

// Range proof: prove value >= threshold (privacy-preserving)
let range_proof = prover.prove_range(1000, 500, pv_salt)?;
```

### 7.3 Verification

```rust
let verifier = prover.get_verifier();

// Binding hash + STARK verification (no salt needed, auto-dispatches by AIR type)
assert!(verifier.verify(&proof)?);

// Full verification with salt (off-chain only, re-derives commitment)
let values = proof.public_values();
assert!(verifier.verify_with_salt(&proof, values, &pv_salt)?);
```

### 7.3 GDPR Erasure

```rust
proof.erase_salt(); // Salt securely zeroed via zeroize crate and removed
assert!(!proof.has_salt()); // Salt is gone
// On-chain hash is now irreversible
assert!(verifier.verify(&proof)?); // Still verifiable
```

See `examples/committed_inputs.rs` for complete working code.

## 8. Error Handling

The library uses ZKMTDError for all error conditions:

**InvalidWitness**: Trace does not satisfy constraints.

**InvalidProof**: Proof verification failed.

**InvalidEpoch**: Epoch mismatch or out of range.

## 9. Running Examples

```bash
cargo run --example basic_proof --features "std,full-p3"
cargo run --example mtd_demo --features "std,full-p3"
cargo run --example batch_proof --features "std,full-p3"
cargo run --example committed_inputs --features "std,full-p3"
```

## 10. Running Tests

```bash
cargo test --features "std,full-p3"
```

## 11. Next Steps

For detailed technical information, see TECHNICAL.md.

For API documentation, run `cargo doc --open --features "std,full-p3"`.
