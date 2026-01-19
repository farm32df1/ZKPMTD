//! # STARK Benchmark
//!
//! Measures STARK proof generation and verification performance.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zkmtd::{Epoch, MTDProver, Prover, PublicInputs, StarkConfig, Verifier, Witness};

fn bench_proof_generation(c: &mut Criterion) {
    let seed = b"benchmark-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(1000);
    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();

    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    c.bench_function("stark_proof_generation", |b| {
        b.iter(|| {
            let _proof = prover
                .prove(black_box(&witness), black_box(&public_inputs))
                .unwrap();
        });
    });
}

fn bench_proof_verification(c: &mut Criterion) {
    let seed = b"benchmark-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(1000);
    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();

    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);
    let proof = prover.prove(&witness, &public_inputs).unwrap();

    let verifier = prover.get_verifier();

    c.bench_function("stark_proof_verification", |b| {
        b.iter(|| {
            let _valid = verifier
                .verify(black_box(&proof), black_box(&public_inputs))
                .unwrap();
        });
    });
}

fn bench_mtd_params_generation(c: &mut Criterion) {
    use zkmtd::mtd::WarpingParams;

    let seed = b"benchmark-seed";
    let epoch = Epoch::new(1000);

    c.bench_function("mtd_params_generation", |b| {
        b.iter(|| {
            let _params = WarpingParams::generate(black_box(seed), black_box(epoch)).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_proof_generation,
    bench_proof_verification,
    bench_mtd_params_generation
);
criterion_main!(benches);
