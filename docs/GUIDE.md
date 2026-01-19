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

## 7. Error Handling

The library uses ZKMTDError for all error conditions:

**InvalidWitness**: Trace does not satisfy constraints.

**InvalidProof**: Proof verification failed.

**InvalidEpoch**: Epoch mismatch or out of range.

## 8. Running Examples

```bash
cargo run --example basic_proof --features "std,full-p3"
cargo run --example mtd_demo --features "std,full-p3"
cargo run --example batch_proof --features "std,full-p3"
```

## 9. Running Tests

```bash
cargo test --features "std,full-p3"
```

## 10. Next Steps

For detailed technical information, see TECHNICAL.md.

For API documentation, run `cargo doc --open --features "std,full-p3"`.
