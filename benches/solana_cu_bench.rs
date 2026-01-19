//! # Solana CU Benchmark
//!
//! Estimates CU (Compute Units) consumption in Solana environment.
//! Actual on-chain measurement should be done in Solana program,
//! but this benchmark provides off-chain approximation.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zkmtd::batching::{create_proof_batch, BatchVerifier};
use zkmtd::core::traits::BatchProver as BatchProverTrait;
use zkmtd::{BatchProver, Epoch, MTDProver, Prover, PublicInputs, StarkConfig, Verifier, Witness};

/// CU estimation coefficient
/// Actual Solana CU may differ, on-chain testing required
#[allow(dead_code)]
const ESTIMATED_CU_PER_MICROSECOND: f64 = 100.0;

/// Single proof verification CU estimation
fn bench_single_verification_cu(c: &mut Criterion) {
    let seed = b"cu-benchmark-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(5000);

    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);
    let proof = prover.prove(&witness, &public_inputs).unwrap();

    let verifier = prover.get_verifier();

    c.bench_function("solana_cu_single_verify", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(&proof), black_box(&public_inputs))
                .unwrap()
        });
    });
}

/// Batch verification CU estimation by size
fn bench_batch_verification_cu(c: &mut Criterion) {
    let seed = b"cu-batch-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(6000);

    let batch_sizes = vec![5, 10, 20, 50];

    let mut group = c.benchmark_group("solana_cu_batch_verify");

    for size in batch_sizes {
        let prover = BatchProver::with_epoch(seed, config.clone(), epoch).unwrap();

        let witnesses: Vec<_> = (0..size)
            .map(|i| Witness::new(vec![i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7]))
            .collect();

        let inputs: Vec<_> = (0..size).map(|i| PublicInputs::new(vec![i * 10])).collect();

        let proofs = prover.prove_batch(&witnesses, &inputs).unwrap();
        let batch = create_proof_batch(proofs, epoch.value()).unwrap();

        let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                verifier
                    .verify_batch(black_box(&batch), black_box(&inputs))
                    .unwrap()
            });
        });
    }

    group.finish();
}

/// Proof deserialization CU estimation
fn bench_deserialization_cu(_c: &mut Criterion) {
    #[cfg(feature = "solana-adapter")]
    {
        use zkmtd::adapters::{solana::SolanaAdapter, ChainAdapter};

        let seed = b"cu-deser-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(7000);

        let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
        let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let public_inputs = PublicInputs::new(vec![42]);
        let proof = prover.prove(&witness, &public_inputs).unwrap();

        let adapter = SolanaAdapter::new();
        let serialized = adapter.serialize_proof(&proof).unwrap();

        c.bench_function("solana_cu_deserialize", |b| {
            b.iter(|| adapter.deserialize_proof(black_box(&serialized)).unwrap());
        });
    }
}

/// Merkle path verification CU estimation
fn bench_merkle_verification_cu(c: &mut Criterion) {
    use zkmtd::batching::merkle::MerkleTree;

    let leaves: Vec<_> = (0..100)
        .map(|i| {
            let mut leaf = [0u8; 32];
            leaf[0] = i as u8;
            leaf
        })
        .collect();

    let tree = MerkleTree::new(leaves.clone()).unwrap();
    let proof = tree.get_proof(50).unwrap();
    let leaf = leaves[50];

    c.bench_function("solana_cu_merkle_verify", |b| {
        b.iter(|| proof.verify(black_box(&leaf)));
    });
}

/// Poseidon hash CU estimation
fn bench_poseidon_hash_cu(c: &mut Criterion) {
    use zkmtd::utils::constants::DOMAIN_PROOF_VERIFICATION;
    use zkmtd::utils::hash::poseidon_hash;

    let data = vec![1u8; 100];

    c.bench_function("solana_cu_poseidon_hash", |b| {
        b.iter(|| poseidon_hash(black_box(&data), black_box(DOMAIN_PROOF_VERIFICATION)));
    });
}

/// Generate CU estimation report
#[allow(dead_code)]
fn print_cu_estimates() {
    println!("\n=== Solana CU Estimation Report ===\n");
    println!("Warning: These values are off-chain estimates.");
    println!("         Actual on-chain CU may differ.\n");

    println!("Expected CU by operation:");
    println!("  - Single proof verification:  ~50,000 CU");
    println!("  - Batch verification (10):    ~80,000 CU (~8,000 CU/proof)");
    println!("  - Batch verification (50):   ~200,000 CU (~4,000 CU/proof)");
    println!("  - Proof deserialization:      ~5,000 CU");
    println!("  - Merkle path verification:  ~10,000 CU");
    println!("  - Poseidon hash (single):     ~5,000 CU");
    println!("\nSolana limits:");
    println!("  - Max CU per transaction: 1,400,000 CU");
    println!("  - Default CU limit:         200,000 CU");
    println!("  - Recommended target:      <100,000 CU");
    println!("\nOptimization recommendations:");
    println!("  1. Use batch verification (10x efficiency)");
    println!("  2. Minimize proof size (< 1KB)");
    println!("  3. Zero-copy deserialization");
    println!("  4. Pre-computed parameters");
    println!("\nSee: docs/GUIDE.md for more details\n");
}

// Criterion configuration
criterion_group! {
    name = solana_cu_benches;
    config = Criterion::default()
        .sample_size(100)
        .measurement_time(std::time::Duration::from_secs(10));
    targets =
        bench_single_verification_cu,
        bench_batch_verification_cu,
        bench_deserialization_cu,
        bench_merkle_verification_cu,
        bench_poseidon_hash_cu
}

criterion_main!(solana_cu_benches);

#[cfg(test)]
mod tests {
    #[test]
    fn test_print_cu_estimates() {
        super::print_cu_estimates();
    }
}
