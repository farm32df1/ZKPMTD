//! Property-based tests for ZKMTD using proptest
//!
//! Verifies cryptographic properties hold for random inputs:
//! - Completeness: valid proofs always verify
//! - Soundness: tampered proofs always reject
//! - Hash determinism, collision resistance, domain separation

#![cfg(feature = "full-p3")]

use proptest::prelude::*;
use zkmtd::mtd::Epoch;
use zkmtd::stark::integrated::IntegratedProver;
use zkmtd::utils::hash::poseidon_hash;

fn test_salt_from(seed: u8) -> [u8; 32] {
    [seed; 32]
}

// Power-of-two trace sizes suitable for STARK
fn valid_trace_size() -> impl Strategy<Value = usize> {
    prop::sample::select(vec![2usize, 4, 8, 16, 32, 64])
}

// ============================================================
// 1. Completeness: random seed/epoch/salt/trace → prove→verify = true
// ============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_completeness_fibonacci(
        seed_val in 1u64..10000u64,
        epoch_val in 1u64..10000u64,
        salt_byte in 1u8..255u8,
        trace_size in valid_trace_size(),
    ) {
        let seed = seed_val.to_le_bytes();
        let epoch = Epoch::new(epoch_val);
        let pv_salt = test_salt_from(salt_byte);

        let prover = IntegratedProver::new(&seed, epoch).unwrap();
        let proof = prover.prove_fibonacci(trace_size, pv_salt).unwrap();

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        prop_assert!(is_valid, "Completeness violation: valid Fibonacci proof rejected");
    }
}

// ============================================================
// 2. Soundness (binding): tampered binding_hash → verify = false
// ============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_soundness_tampered_binding(
        seed_val in 1u64..10000u64,
        epoch_val in 1u64..10000u64,
        tamper_idx in 0usize..32usize,
    ) {
        let seed = seed_val.to_le_bytes();
        let epoch = Epoch::new(epoch_val);

        let prover = IntegratedProver::new(&seed, epoch).unwrap();
        let mut proof = prover.prove_fibonacci(8, test_salt_from(42)).unwrap();

        // Tamper with binding hash
        proof.binding_hash[tamper_idx] ^= 0xFF;

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        prop_assert!(!is_valid, "Soundness violation: tampered binding hash accepted");
    }
}

// ============================================================
// 3. Soundness (PV): tampered public_values → verify = false
// ============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_soundness_tampered_public_values(
        seed_val in 1u64..10000u64,
        epoch_val in 1u64..10000u64,
        tamper_val in 100u64..99999u64,
    ) {
        let seed = seed_val.to_le_bytes();
        let epoch = Epoch::new(epoch_val);

        let prover = IntegratedProver::new(&seed, epoch).unwrap();
        let mut proof = prover.prove_fibonacci(8, test_salt_from(42)).unwrap();

        // Tamper a public value
        let idx = 2; // last row first column
        let original = proof.stark_proof.public_values[idx];
        proof.stark_proof.public_values[idx] = tamper_val;

        // Only check if we actually changed the value
        if tamper_val != original {
            let verifier = prover.get_verifier();
            let is_valid = verifier.verify(&proof).unwrap();
            prop_assert!(!is_valid, "Soundness violation: tampered public values accepted");
        }
    }
}

// ============================================================
// 4. Hash determinism: same input → same output
// ============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_hash_determinism(data in prop::collection::vec(any::<u8>(), 1..256)) {
        let domain = b"TEST_DOMAIN";
        let hash1 = poseidon_hash(&data, domain);
        let hash2 = poseidon_hash(&data, domain);
        prop_assert_eq!(hash1, hash2, "Hash is not deterministic");
    }
}

// ============================================================
// 5. Hash collision resistance: different input → different output
// ============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_hash_collision_resistance(
        data1 in prop::collection::vec(any::<u8>(), 1..256),
        data2 in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        if data1 != data2 {
            let domain = b"TEST_DOMAIN";
            let hash1 = poseidon_hash(&data1, domain);
            let hash2 = poseidon_hash(&data2, domain);
            prop_assert_ne!(hash1, hash2, "Hash collision detected");
        }
    }
}

// ============================================================
// 6. Domain separation: same data + different domain → different hash
// ============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_domain_separation(data in prop::collection::vec(any::<u8>(), 1..256)) {
        let hash_a = poseidon_hash(&data, b"DOMAIN_A");
        let hash_b = poseidon_hash(&data, b"DOMAIN_B");
        prop_assert_ne!(hash_a, hash_b, "Domain separation failure: same hash for different domains");
    }
}

// ============================================================
// 7. Sum completeness: random a,b → prove_sum→verify = true
// ============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_completeness_sum(
        seed_val in 1u64..10000u64,
        epoch_val in 1u64..10000u64,
        // Use small values to avoid Goldilocks overflow
        a_vals in prop::collection::vec(1u64..1000u64, 2..8),
    ) {
        let seed = seed_val.to_le_bytes();
        let epoch = Epoch::new(epoch_val);
        let b_vals: Vec<u64> = a_vals.iter().map(|x| x + 1).collect();

        let prover = IntegratedProver::new(&seed, epoch).unwrap();
        let proof = prover.prove_sum(&a_vals, &b_vals, test_salt_from(42)).unwrap();

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        prop_assert!(is_valid, "Completeness violation: valid Sum proof rejected");
    }
}

// ============================================================
// 8. Mul completeness: random a,b → prove_mul→verify = true
// ============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_completeness_mul(
        seed_val in 1u64..10000u64,
        epoch_val in 1u64..10000u64,
        a_vals in prop::collection::vec(1u64..100u64, 2..8),
    ) {
        let seed = seed_val.to_le_bytes();
        let epoch = Epoch::new(epoch_val);
        let b_vals: Vec<u64> = a_vals.iter().map(|x| x + 1).collect();

        let prover = IntegratedProver::new(&seed, epoch).unwrap();
        let proof = prover.prove_multiplication(&a_vals, &b_vals, test_salt_from(42)).unwrap();

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        prop_assert!(is_valid, "Completeness violation: valid Mul proof rejected");
    }
}

// ============================================================
// 9. Range completeness: value >= threshold → prove_range→verify = true
// ============================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_completeness_range(
        seed_val in 1u64..10000u64,
        epoch_val in 1u64..10000u64,
        threshold in 1u64..1000u64,
        delta in 0u64..1000u64,
    ) {
        let seed = seed_val.to_le_bytes();
        let epoch = Epoch::new(epoch_val);
        let value = threshold + delta; // Ensure value >= threshold

        let prover = IntegratedProver::new(&seed, epoch).unwrap();
        let proof = prover.prove_range(value, threshold, test_salt_from(42)).unwrap();

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        prop_assert!(is_valid, "Completeness violation: valid Range proof rejected");
    }
}
