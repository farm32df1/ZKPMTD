//! # MTD Benchmark
//!
//! Measures MTD system performance.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zkmtd::batching::{create_proof_batch, BatchVerifier};
use zkmtd::core::traits::BatchProver as BatchProverTrait;
use zkmtd::{BatchProver, Epoch, PublicInputs, StarkConfig, Witness};

fn bench_batch_proof_generation(c: &mut Criterion) {
    let seed = b"batch-benchmark-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(2000);
    let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();

    let witnesses: Vec<_> = (0..10)
        .map(|i| Witness::new(vec![i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7]))
        .collect();

    let inputs: Vec<_> = (0..10).map(|i| PublicInputs::new(vec![i * 10])).collect();

    c.bench_function("batch_proof_generation_10", |b| {
        b.iter(|| {
            let _proofs = prover
                .prove_batch(black_box(&witnesses), black_box(&inputs))
                .unwrap();
        });
    });
}

fn bench_batch_verification(c: &mut Criterion) {
    let seed = b"batch-benchmark-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(2000);
    let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();

    let witnesses: Vec<_> = (0..10)
        .map(|i| Witness::new(vec![i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7]))
        .collect();

    let inputs: Vec<_> = (0..10).map(|i| PublicInputs::new(vec![i * 10])).collect();

    let proofs = prover.prove_batch(&witnesses, &inputs).unwrap();
    let batch = create_proof_batch(proofs, epoch.value()).unwrap();

    let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());

    c.bench_function("batch_verification_10", |b| {
        b.iter(|| {
            let _valid = verifier
                .verify_batch(black_box(&batch), black_box(&inputs))
                .unwrap();
        });
    });
}

fn bench_epoch_advancement(c: &mut Criterion) {
    use zkmtd::MTDManager;

    let seed = b"epoch-benchmark-seed";
    let mut manager = MTDManager::with_epoch(seed, Epoch::new(3000)).unwrap();

    c.bench_function("epoch_advancement", |b| {
        b.iter(|| {
            let _params = manager.advance().unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_batch_proof_generation,
    bench_batch_verification,
    bench_epoch_advancement
);
criterion_main!(benches);
