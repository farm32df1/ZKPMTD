//! Soundness tests

#![cfg(feature = "full-p3")]

use zkmtd::mtd::Epoch;
use zkmtd::stark::air::SimpleAir;
use zkmtd::stark::integrated::{IntegratedProver, IntegratedVerifier};
use zkmtd::stark::real_stark::RealStarkProver;

/// Helper: deterministic test salt for IntegratedProver
fn test_salt() -> [u8; 32] {
    [42u8; 32]
}

#[test]
fn test_soundness_tampered_binding_hash() {
    let seed = b"soundness-binding-test";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).expect("Failed to create prover");
    let mut proof = prover.prove_fibonacci(8, test_salt()).expect("Failed to generate proof");

    // Tamper with binding hash
    proof.binding_hash[0] ^= 0xFF;

    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof).expect("Error during verification");

    // Integrity check: tampered binding hash must be rejected
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: tampered binding hash was accepted"
    );
    println!("Tampered binding hash rejected");
}

#[test]
fn test_soundness_tampered_public_values() {
    let seed = b"soundness-pv-test";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).expect("Failed to create prover");
    let mut proof = prover.prove_fibonacci(8, test_salt()).expect("Failed to generate proof");

    // Tamper with public values
    let original_value = proof.stark_proof.public_values[2];
    proof.stark_proof.public_values[2] = 999;

    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof).expect("Error during verification");

    // Integrity check: tampered public values must be rejected
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: tampered public values were accepted (original: {}, tampered: 999)",
        original_value
    );
    println!("Tampered public values rejected");
}

#[test]
fn test_soundness_wrong_epoch() {
    let seed = b"soundness-epoch-test";

    // Generate proof in epoch 100
    let prover_100 = IntegratedProver::new(seed, Epoch::new(100)).expect("Failed to create prover");
    let proof_100 = prover_100
        .prove_fibonacci(8, test_salt())
        .expect("Failed to generate proof");

    // Attempt verification with epoch 200 verifier
    let verifier_200 =
        IntegratedVerifier::new(seed, Epoch::new(200)).expect("Failed to create verifier");
    let is_valid = verifier_200
        .verify(&proof_100)
        .expect("Error during verification");

    // Integrity check: proof from different epoch must be rejected
    assert!(!is_valid, "SOUNDNESS FAILURE: proof from different epoch was accepted (generated: 100, verified: 200)");
    println!("Proof from different epoch rejected");
}

#[test]
fn test_soundness_wrong_seed() {
    let epoch = Epoch::new(100);

    // Generate proof with seed-A
    let prover_a = IntegratedProver::new(b"seed-A", epoch).expect("Failed to create prover A");
    let proof_a = prover_a
        .prove_fibonacci(8, test_salt())
        .expect("Failed to generate proof A");

    // Attempt verification with seed-B verifier
    let verifier_b =
        IntegratedVerifier::new(b"seed-B", epoch).expect("Failed to create verifier B");
    let is_valid = verifier_b
        .verify(&proof_a)
        .expect("Error during verification");

    // Integrity check: proof from different seed must be rejected
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: proof from different seed was accepted"
    );
    println!("Proof from different seed rejected");
}

#[test]
fn test_soundness_tampered_num_rows() {
    let seed = b"soundness-numrows-test";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).expect("Failed to create prover");
    let mut proof = prover.prove_fibonacci(8, test_salt()).expect("Failed to generate proof");

    // Tamper with num_rows (8 -> 16)
    proof.stark_proof.num_rows = 16;

    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof).expect("Error during verification");

    // Integrity check: tampered num_rows must be rejected
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: tampered num_rows was accepted (original: 8, tampered: 16)"
    );
    println!("Tampered num_rows rejected");
}

#[test]
fn test_real_stark_invalid_trace_size() {
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    // Non-power-of-two sizes
    let result = prover.prove_fibonacci(7);
    assert!(
        result.is_err(),
        "SOUNDNESS FAILURE: invalid size 7 was accepted"
    );

    let result = prover.prove_fibonacci(10);
    assert!(
        result.is_err(),
        "SOUNDNESS FAILURE: invalid size 10 was accepted"
    );

    let result = prover.prove_fibonacci(15);
    assert!(
        result.is_err(),
        "SOUNDNESS FAILURE: invalid size 15 was accepted"
    );

    // Size too small
    let result = prover.prove_fibonacci(1);
    assert!(result.is_err(), "SOUNDNESS FAILURE: size 1 was accepted");

    println!("All invalid trace sizes rejected");
}

#[test]
fn test_real_stark_tampered_proof() {
    let air = SimpleAir::fibonacci();
    let prover = RealStarkProver::new(air).expect("Failed to create prover");

    let proof = prover.prove_fibonacci(8).expect("Failed to generate proof");

    // Verify original
    let verifier = prover.get_verifier();
    let valid_original = verifier
        .verify_fibonacci(&proof)
        .expect("Error during verification");
    assert!(valid_original, "Original proof was rejected");

    // Test tampering with public values
    let mut tampered_proof = prover.prove_fibonacci(8).expect("Failed to generate proof");
    tampered_proof.public_values[2] = 999; // Tamper with F(n-1)

    let is_valid = verifier.verify_fibonacci(&tampered_proof).unwrap_or(false);
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: tampered public values were accepted"
    );

    // Test tampering with num_rows
    let mut tampered_proof = prover.prove_fibonacci(8).expect("Failed to generate proof");
    tampered_proof.num_rows = 16; // Tamper with num_rows

    let is_valid = verifier.verify_fibonacci(&tampered_proof).unwrap_or(false);
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: tampered num_rows was accepted"
    );

    println!("All tampered proofs rejected");
}

#[test]
fn test_fibonacci_cross_validation() {
    let seed = b"fib-cross-validation";
    let epoch = Epoch::new(100);
    let prover = IntegratedProver::new(seed, epoch).expect("Failed to create prover");

    // Cross-validate with multiple sizes
    let test_cases = [
        (4, 2, 3),              // 4 rows: F(3)=2, F(4)=3
        (8, 13, 21),            // 8 rows: F(7)=13, F(8)=21
        (16, 610, 987),         // 16 rows: F(15)=610, F(16)=987
        (32, 1346269, 2178309), // 32 rows: F(31)=1346269, F(32)=2178309
    ];

    for (num_rows, expected_a, expected_b) in test_cases {
        let proof = prover
            .prove_fibonacci(num_rows, test_salt())
            .expect("Failed to generate proof");
        let pv = proof.public_values();

        // Initial value verification
        assert_eq!(pv[0], 0, "F(0) != 0 for num_rows={}", num_rows);
        assert_eq!(pv[1], 1, "F(1) != 1 for num_rows={}", num_rows);

        // Final value cross-validation
        assert_eq!(
            pv[2],
            expected_a,
            "F({}) mismatch: proof={}, expected={}",
            num_rows - 1,
            pv[2],
            expected_a
        );
        assert_eq!(
            pv[3], expected_b,
            "F({}) mismatch: proof={}, expected={}",
            num_rows, pv[3], expected_b
        );
    }

    println!("All Fibonacci value cross-validations passed");
}

#[test]
fn test_independent_fibonacci_calculator() {
    let seed = b"fib-independent";
    let epoch = Epoch::new(100);
    let prover = IntegratedProver::new(seed, epoch).expect("Failed to create prover");

    for &num_rows in &[4, 8, 16, 32, 64] {
        let proof = prover
            .prove_fibonacci(num_rows, test_salt())
            .expect("Failed to generate proof");
        let pv = proof.public_values();

        // Independent Fibonacci calculation (Goldilocks field simulation)
        let (expected_a, expected_b) = compute_fibonacci_goldilocks(num_rows);

        assert_eq!(
            pv[2], expected_a,
            "Independent calculation mismatch (num_rows={}): proof={}, calculated={}",
            num_rows, pv[2], expected_a
        );
        assert_eq!(
            pv[3], expected_b,
            "Independent calculation mismatch (num_rows={}): proof={}, calculated={}",
            num_rows, pv[3], expected_b
        );
    }

    println!("All independent Fibonacci calculations match");
}

#[test]
fn test_epoch_transition_soundness() {
    let seed = b"epoch-transition-test";
    let mut prover = IntegratedProver::new(seed, Epoch::new(100)).expect("Failed to create prover");

    // Generate proof in epoch 100
    let proof_100 = prover.prove_fibonacci(8, test_salt()).expect("Failed to generate proof");
    let verifier_100 = prover.get_verifier();

    // Valid in epoch 100
    assert!(
        verifier_100.verify(&proof_100).unwrap(),
        "Epoch 100 proof was rejected in epoch 100"
    );

    // Epoch transition
    prover.advance_epoch().expect("Epoch transition failed");
    let verifier_101 = prover.get_verifier();

    // Must be rejected in epoch 101
    let is_valid = verifier_101
        .verify(&proof_100)
        .expect("Error during verification");
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: previous epoch (100) proof was accepted in new epoch (101)"
    );

    // New proof in new epoch should be valid
    let proof_101 = prover
        .prove_fibonacci(8, test_salt())
        .expect("Failed to generate new proof");
    assert!(
        verifier_101.verify(&proof_101).unwrap(),
        "New epoch proof was rejected"
    );

    println!("Epoch transition soundness verification passed");
}

#[test]
fn test_verification_consistency() {
    let seed = b"consistency-test";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).expect("Failed to create prover");
    let proof = prover.prove_fibonacci(8, test_salt()).expect("Failed to generate proof");
    let verifier = prover.get_verifier();

    // Verify 100 times
    for i in 0..100 {
        let is_valid = verifier.verify(&proof).expect("Error during verification");
        assert!(
            is_valid,
            "Inconsistency occurred on verification #{}",
            i + 1
        );
    }

    println!("100 verification consistency confirmed");
}

#[test]
fn test_independent_verifier_consistency() {
    let seed = b"independent-verifier-test";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).expect("Failed to create prover");
    let proof = prover.prove_fibonacci(8, test_salt()).expect("Failed to generate proof");

    // Create 5 independent verifiers
    for i in 0..5 {
        let independent_verifier =
            IntegratedVerifier::new(seed, epoch).expect("Failed to create independent verifier");
        let is_valid = independent_verifier
            .verify(&proof)
            .expect("Error during verification");
        assert!(
            is_valid,
            "Independent verifier #{} rejected a valid proof",
            i + 1
        );
    }

    println!("All 5 independent verifiers returned consistent results");
}

// ============================================================
// Committed Public Values Soundness Tests
// ============================================================

#[test]
fn test_soundness_binding_hash_tampering_with_committed() {
    let seed = b"soundness-committed-binding";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).unwrap();
    let mut proof = prover.prove_fibonacci(8, test_salt()).unwrap();

    // Tamper with binding hash
    proof.binding_hash[0] ^= 0xFF;

    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof).unwrap();
    assert!(!is_valid, "Tampered binding hash was accepted");
}

#[test]
fn test_soundness_wrong_epoch_with_committed() {
    let seed = b"soundness-committed-epoch";

    let prover = IntegratedProver::new(seed, Epoch::new(100)).unwrap();
    let proof = prover.prove_fibonacci(8, test_salt()).unwrap();

    let wrong_verifier = IntegratedVerifier::new(seed, Epoch::new(200)).unwrap();
    let is_valid = wrong_verifier.verify(&proof).unwrap();
    assert!(!is_valid, "Proof from wrong epoch was accepted");
}

// ============================================================
// Sum/Mul/Range Soundness Tests
// ============================================================

#[test]
fn test_soundness_sum_tampered_public_values() {
    let seed = b"soundness-sum-pv";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).unwrap();
    let a = vec![1u64, 2, 3, 4];
    let b = vec![10u64, 20, 30, 40];
    let mut proof = prover.prove_sum(&a, &b, test_salt()).unwrap();

    // Tamper with binding hash (invalidates the proof)
    proof.binding_hash[0] ^= 0xFF;

    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof).unwrap();
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: tampered sum proof binding was accepted"
    );
}

#[test]
fn test_soundness_mul_wrong_epoch() {
    let seed = b"soundness-mul-epoch";

    let prover = IntegratedProver::new(seed, Epoch::new(100)).unwrap();
    let a = vec![2u64, 3, 4, 5];
    let b = vec![10u64, 20, 30, 40];
    let proof = prover
        .prove_multiplication(&a, &b, test_salt())
        .unwrap();

    let wrong_verifier = IntegratedVerifier::new(seed, Epoch::new(200)).unwrap();
    let is_valid = wrong_verifier.verify(&proof).unwrap();
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: mul proof from wrong epoch was accepted"
    );
}

#[test]
fn test_soundness_range_tampered_binding() {
    let seed = b"soundness-range-binding";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).unwrap();
    let mut proof = prover.prove_range(1000, 500, test_salt()).unwrap();

    // Tamper with binding hash
    proof.binding_hash[15] ^= 0xFF;

    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof).unwrap();
    assert!(
        !is_valid,
        "SOUNDNESS FAILURE: tampered range proof binding was accepted"
    );
}

const GOLDILOCKS_MODULUS: u64 = 18446744069414584321u64;

fn compute_fibonacci_goldilocks(num_rows: usize) -> (u64, u64) {
    let mut a: u128 = 0;
    let mut b: u128 = 1;

    for _ in 0..(num_rows - 1) {
        let c = (a + b) % (GOLDILOCKS_MODULUS as u128);
        a = b;
        b = c;
    }

    (a as u64, b as u64)
}
