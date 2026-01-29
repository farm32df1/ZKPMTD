# ZKMTD

**Post-Quantum Zero-Knowledge Moving Target Defense Library**

A zero-knowledge proof library combining Plonky3 STARK proofs with Moving Target Defense for quantum-resistant, replay-proof cryptographic verification.

## 1. Features

**128-bit Soundness**: Hash-based STARK proofs with 128-bit security level (60 FRI queries + 8-bit PoW). Immune to Shor's algorithm. No elliptic curve cryptography.

**No Trusted Setup**: All parameters are publicly verifiable. No ceremony required.

**Moving Target Defense**: Cryptographic parameters rotate every epoch. Previous epoch proofs automatically invalidated.

**Privacy-by-Default**: All proofs commit public values with Poseidon2 + salt. No plaintext values on-chain. GDPR-compliant erasure via salt deletion.

**Solana Ready**: Lightweight verification within on-chain compute limits.

## 2. Installation

```toml
[dependencies]
zkmtd = { git = "https://github.com/farm32df1/ZKPMTD.git", features = ["std", "full-p3"] }
```

**Feature Flags**
- `std`: Standard library support (recommended)
- `alloc`: Heap allocation for no_std environments
- `full-p3`: Complete Plonky3 STARK (required for proof generation)
- `solana-program`: On-chain verification support

## 3. Core Concepts

**Seed**: Application-specific secret for deriving cryptographic parameters.

**Epoch**: Time window during which parameters remain constant (default 3600 seconds). All parameters rotate on epoch change.

**Trace**: Computation record. Size must be power of 2 (4, 8, 16, 32...).

## 4. Workflow

**Proof Generation**: Initialize prover with seed and epoch. Build computation trace. Verify AIR constraints. Generate STARK proof. Bind to MTD parameters.

**Proof Verification**: Extract public values. Verify MTD binding. Verify STARK mathematics. Return result.

## 5. Supported Circuits

**Fibonacci AIR**: Proves computational integrity of Fibonacci sequence.

**Sum AIR**: Proves `c = a + b` for each row. Validates addition computations.

**Multiplication AIR**: Proves `c = a * b` for each row. Validates multiplication computations.

**Range AIR**: Proves value meets threshold without revealing actual value (privacy-preserving). Uses 32-bit decomposition.

## 6. Solana Integration

**Compute Unit Usage**
- Lightweight verification: ~15,000 CU (commitment binding only)
- Batch verification (10 proofs): ~20,000 CU
- Full STARK verification: ~500,000 CU (exceeds Solana limit)

**Recommended Flow**: Generate and verify full STARK proof off-chain. Submit lightweight proof on-chain. Verify commitment binding only.

## 7. Module Structure

```
src/
├── core/       Type definitions (Proof, Witness, PublicInputs, Errors)
├── stark/      STARK proof system (AIR, Prover, Verifier, Integrated)
├── mtd/        Moving Target Defense (Epoch, WarpingParams, Entropy)
├── batching/   Batch proof system (Merkle tree)
├── adapters/   Blockchain adapters
├── utils/      Hash, compression, constants
└── solana/     On-chain lightweight verification (feature-gated)
```

## 8. Examples

```bash
cargo run --example basic_proof --features "std,full-p3"
cargo run --example mtd_demo --features "std,full-p3"
cargo run --example batch_proof --features "std,full-p3"
cargo run --example solana_cu_estimate --features "std,full-p3"
cargo run --example committed_inputs --features "std,full-p3"
```

## 9. Testing

```bash
cargo test --features "std,full-p3"
```

283 tests passing (unit, integration, soundness, compression, STARK scenarios, committed inputs, property tests, library workflows)

**Fuzzing**: 5 targets with 24M+ combined runs, 0 crashes
```bash
cd fuzz && cargo +nightly fuzz run fuzz_proof_deserialize
```

**Coverage**: 85.57% line coverage
```bash
cargo llvm-cov --features "std,full-p3"
```

## 10. Documentation

- [docs/GUIDE.md](docs/GUIDE.md): Usage guide
- [docs/TECHNICAL.md](docs/TECHNICAL.md): Technical reference
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): Internal architecture
- [docs/SECURITY_PROOF.md](docs/SECURITY_PROOF.md): Formal security analysis
- [docs/AUDIT_REPORT.md](docs/AUDIT_REPORT.md): Code audit report
- API docs: `cargo doc --open --features "std,full-p3"`

## 11. License

MIT License. See [LICENSE-MIT](LICENSE-MIT).
