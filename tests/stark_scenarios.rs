//! STARK scenario tests

#![cfg(feature = "full-p3")]

use zkmtd::stark::{RealStarkProver, RealStarkVerifier, SimpleAir};

#[test]
fn test_completeness_small_trace() {
    // Small trace (8 rows)
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let proof = prover.prove_fibonacci(8).expect("Failed to generate proof");

    let verifier = prover.get_verifier();
    let is_valid = verifier
        .verify_fibonacci(&proof)
        .expect("Verification failed");

    assert!(
        is_valid,
        "Completeness violation: valid proof (8 rows) was rejected"
    );
}

#[test]
fn test_completeness_medium_trace() {
    // Medium trace (64 rows)
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let proof = prover
        .prove_fibonacci(64)
        .expect("Failed to generate proof");

    let verifier = prover.get_verifier();
    let is_valid = verifier
        .verify_fibonacci(&proof)
        .expect("Verification failed");

    assert!(
        is_valid,
        "Completeness violation: valid proof (64 rows) was rejected"
    );
}

#[test]
fn test_completeness_large_trace() {
    // Large trace (256 rows)
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let proof = prover
        .prove_fibonacci(256)
        .expect("Failed to generate proof");

    let verifier = prover.get_verifier();
    let is_valid = verifier
        .verify_fibonacci(&proof)
        .expect("Verification failed");

    assert!(
        is_valid,
        "Completeness violation: valid proof (256 rows) was rejected"
    );
}

#[test]
fn test_completeness_independent_verifier() {
    // Verify with an independent verifier
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air.clone()).expect("Failed to create prover");

    let proof = prover
        .prove_fibonacci(16)
        .expect("Failed to generate proof");

    // Create a new independent verifier
    let independent_verifier = RealStarkVerifier::new(air).expect("Failed to create verifier");
    let is_valid = independent_verifier
        .verify_fibonacci(&proof)
        .expect("Verification failed");

    assert!(
        is_valid,
        "Completeness violation: independent verifier rejected a valid proof"
    );
}

#[test]
fn test_soundness_tampered_public_values() {
    // Case where public values are tampered
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let mut proof = prover.prove_fibonacci(8).expect("Failed to generate proof");

    // Tamper with public values (modify initial value)
    proof.public_values[0] = 999; // Should be 0 but tampered to 999

    let verifier = prover.get_verifier();
    let is_valid = verifier
        .verify_fibonacci(&proof)
        .expect("Verification failed");

    assert!(
        !is_valid,
        "Soundness violation: tampered public values were accepted"
    );
}

#[test]
fn test_soundness_tampered_num_rows() {
    // Case where trace row count is tampered
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let mut proof = prover.prove_fibonacci(8).expect("Failed to generate proof");

    // Tamper with row count (8 -> 16)
    proof.num_rows = 16; // Actually an 8-row proof but tampered to 16

    let verifier = prover.get_verifier();
    let is_valid = verifier
        .verify_fibonacci(&proof)
        .expect("Verification failed");

    assert!(
        !is_valid,
        "Soundness violation: tampered row count was accepted"
    );
}

#[test]
fn test_soundness_invalid_trace_size() {
    // Non-power-of-two trace size - should be rejected at proof generation stage
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let result = prover.prove_fibonacci(7);
    assert!(
        result.is_err(),
        "Soundness violation: invalid trace size was accepted"
    );

    let result = prover.prove_fibonacci(10);
    assert!(
        result.is_err(),
        "Soundness violation: invalid trace size was accepted"
    );
}

#[test]
fn test_soundness_too_small_trace() {
    // Trace size too small
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let result = prover.prove_fibonacci(1);
    assert!(
        result.is_err(),
        "Soundness violation: too small trace was accepted"
    );
}

#[test]
fn test_consistency_multiple_verifications() {
    // Verify the same proof multiple times
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let proof = prover.prove_fibonacci(8).expect("Failed to generate proof");
    let verifier = prover.get_verifier();

    // Multiple verifications should always yield the same result
    for i in 0..5 {
        let is_valid = verifier
            .verify_fibonacci(&proof)
            .expect("Verification failed");
        assert!(
            is_valid,
            "Consistency violation: failed on verification #{}",
            i + 1
        );
    }
}

#[test]
fn test_consistency_different_provers_same_air() {
    // Different provers created with the same AIR
    let air = SimpleAir::fibonacci();

    let prover1 = RealStarkProver::new(air.clone()).expect("Failed to create prover 1");
    let prover2 = RealStarkProver::new(air.clone()).expect("Failed to create prover 2");

    let proof1 = prover1
        .prove_fibonacci(8)
        .expect("Failed to generate proof 1");
    let proof2 = prover2
        .prove_fibonacci(8)
        .expect("Failed to generate proof 2");

    // Verify with respective verifiers
    let verifier1 = prover1.get_verifier();
    let verifier2 = prover2.get_verifier();

    assert!(
        verifier1
            .verify_fibonacci(&proof1)
            .expect("Verification failed"),
        "Prover 1's proof failed with verifier 1"
    );
    assert!(
        verifier2
            .verify_fibonacci(&proof2)
            .expect("Verification failed"),
        "Prover 2's proof failed with verifier 2"
    );
}

#[test]
fn test_fibonacci_public_values_correctness() {
    // Verify public values are correct Fibonacci sequence
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    // 8-row Fibonacci: [0,1], [1,1], [1,2], [2,3], [3,5], [5,8], [8,13], [13,21]
    // Public values: [initial_a=0, initial_b=1, final_a=13, final_b=21]
    let proof = prover.prove_fibonacci(8).expect("Failed to generate proof");

    assert_eq!(proof.public_values[0], 0, "F(0) = 0");
    assert_eq!(proof.public_values[1], 1, "F(1) = 1");
    assert_eq!(proof.public_values[2], 13, "F(7) = 13 (last row a)");
    assert_eq!(proof.public_values[3], 21, "F(8) = 21 (last row b)");
}

#[test]
fn test_fibonacci_larger_values() {
    // Verify larger Fibonacci numbers (16 rows)
    // 16 rows: F(15)=610, F(16)=987
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let proof = prover
        .prove_fibonacci(16)
        .expect("Failed to generate proof");

    assert_eq!(proof.public_values[0], 0, "F(0) = 0");
    assert_eq!(proof.public_values[1], 1, "F(1) = 1");
    assert_eq!(proof.public_values[2], 610, "F(15) = 610");
    assert_eq!(proof.public_values[3], 987, "F(16) = 987");
}

#[test]
fn test_edge_case_minimum_valid_trace() {
    // Minimum valid trace size (2 rows)
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let proof = prover.prove_fibonacci(2).expect("Failed to generate proof");

    let verifier = prover.get_verifier();
    let is_valid = verifier
        .verify_fibonacci(&proof)
        .expect("Verification failed");

    assert!(is_valid, "Minimum valid trace (2 rows) proof was rejected");

    // Public values check: [0, 1, 1, 1]
    // Row 0: [0, 1]
    // Row 1: [1, 1]
    assert_eq!(proof.public_values[0], 0);
    assert_eq!(proof.public_values[1], 1);
    assert_eq!(proof.public_values[2], 1); // F(1) = 1
    assert_eq!(proof.public_values[3], 1); // F(2) = 1
}

#[test]
fn test_edge_case_power_of_two_boundary() {
    // Power of two boundary value tests
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    // 2^2 = 4
    assert!(prover.prove_fibonacci(4).is_ok());

    // 2^3 = 8
    assert!(prover.prove_fibonacci(8).is_ok());

    // 2^4 = 16
    assert!(prover.prove_fibonacci(16).is_ok());

    // Non-powers of two should fail
    assert!(prover.prove_fibonacci(3).is_err());
    assert!(prover.prove_fibonacci(5).is_err());
    assert!(prover.prove_fibonacci(6).is_err());
    assert!(prover.prove_fibonacci(9).is_err());
}

#[test]
fn test_performance_prove_verify_cycle() {
    use std::time::Instant;

    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    // Measure prove/verify time for various sizes
    for size in [8, 16, 32, 64, 128] {
        let start_prove = Instant::now();
        let proof = prover
            .prove_fibonacci(size)
            .expect("Failed to generate proof");
        let prove_time = start_prove.elapsed();

        let verifier = prover.get_verifier();
        let start_verify = Instant::now();
        let is_valid = verifier
            .verify_fibonacci(&proof)
            .expect("Verification failed");
        let verify_time = start_verify.elapsed();

        println!(
            "Trace size {}: prove {:?}, verify {:?}",
            size, prove_time, verify_time
        );

        assert!(is_valid, "Proof for size {} failed verification", size);
    }
}
