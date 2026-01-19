//! Solana CU tests

#![cfg(feature = "solana-adapter")]

use zkmtd::adapters::{SolanaAdapter, SolanaChainAdapter};
use zkmtd::core::traits::Prover;
use zkmtd::prelude::*;
use zkmtd::{Epoch, MTDProver, StarkConfig};

#[test]
fn test_single_proof_cu_estimate() {
    let seed = b"solana-cu-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(12345);

    let prover = MTDProver::with_epoch(seed, config, epoch).expect("Failed to create prover");

    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    let proof = prover
        .prove(&witness, &public_inputs)
        .expect("Failed to generate proof");

    let adapter = SolanaAdapter::new();
    let estimated_cu = adapter.estimate_compute_units(proof.size());

    println!("Proof size: {} bytes", proof.size());
    println!("Estimated CU: {}", estimated_cu);

    // Verify CU is within reasonable range
    assert!(estimated_cu > 0, "CU is 0");
    assert!(
        estimated_cu < 200_000,
        "CU exceeds default limit (200,000): {}",
        estimated_cu
    );

    println!("Single proof CU verification passed: {} CU", estimated_cu);
}

#[test]
fn test_serialization_size_limit() {
    let seed = b"size-limit-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(12345);

    let prover = MTDProver::with_epoch(seed, config, epoch).expect("Failed to create prover");

    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    let proof = prover
        .prove(&witness, &public_inputs)
        .expect("Failed to generate proof");

    let adapter = SolanaAdapter::new();
    let serialized = adapter
        .serialize_proof(&proof)
        .expect("Serialization failed");

    println!("Serialized size: {} bytes", serialized.len());
    println!("Solana transaction limit: 1232 bytes");

    // Verify Solana transaction size limit
    assert!(
        serialized.len() <= 1232,
        "Serialized size exceeds Solana limit: {} > 1232",
        serialized.len()
    );

    println!("Serialization size limit passed");
}

#[test]
fn test_roundtrip_integrity() {
    let seed = b"roundtrip-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(12345);

    let prover = MTDProver::with_epoch(seed, config, epoch).expect("Failed to create prover");

    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    let original_proof = prover
        .prove(&witness, &public_inputs)
        .expect("Failed to generate proof");

    let adapter = SolanaAdapter::new();

    // Serialize -> Deserialize
    let serialized = adapter
        .serialize_proof(&original_proof)
        .expect("Serialization failed");
    let deserialized = adapter
        .deserialize_proof(&serialized)
        .expect("Deserialization failed");

    // Integrity verification
    assert_eq!(
        original_proof.version, deserialized.version,
        "Version mismatch"
    );
    assert_eq!(original_proof.epoch, deserialized.epoch, "Epoch mismatch");
    assert_eq!(original_proof.data, deserialized.data, "Data mismatch");

    // Deserialized proof should also be verifiable
    let verifier = prover.get_verifier();
    let is_valid = verifier
        .verify(&deserialized, &public_inputs)
        .expect("Verification failed");

    assert!(is_valid, "Deserialized proof failed verification");

    println!("Roundtrip integrity passed");
}

#[test]
fn test_cu_limit_check() {
    let adapter = SolanaAdapter::new();

    // Small proof: should pass
    let small_cu = adapter.check_cu_limit(100);
    assert!(small_cu.is_ok(), "Small proof failed CU limit");
    println!("100 byte proof: {} CU", small_cu.unwrap());

    // Medium proof: should pass
    let medium_cu = adapter.check_cu_limit(500);
    assert!(medium_cu.is_ok(), "Medium proof failed CU limit");
    println!("500 byte proof: {} CU", medium_cu.unwrap());

    // Very large proof: should fail
    let huge_size = 50_000; // 50KB
    let huge_cu = adapter.check_cu_limit(huge_size);
    // 50KB * 10 CU/byte = 500,000 CU > 200,000 limit
    assert!(huge_cu.is_err(), "Very large proof passed CU limit");
    println!("{} byte proof: CU limit exceeded (as expected)", huge_size);

    println!("CU limit check passed");
}

#[test]
fn test_cu_estimation_scaling() {
    let adapter = SolanaAdapter::new();

    let sizes = [50, 100, 200, 500, 1000];
    let mut prev_cu = 0u32;

    println!("\nCU estimation scaling:");
    for &size in &sizes {
        let cu = adapter.estimate_compute_units(size);
        println!("  {} bytes: {} CU", size, cu);

        // CU should increase with size
        assert!(cu > prev_cu, "CU does not increase with size");
        prev_cu = cu;
    }

    println!("CU estimation scaling passed");
}

#[test]
fn test_onchain_data_conversion() {
    let seed = b"onchain-data-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(12345);

    let prover = MTDProver::with_epoch(seed, config, epoch).expect("Failed to create prover");

    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    let proof = prover
        .prove(&witness, &public_inputs)
        .expect("Failed to generate proof");

    let adapter = SolanaAdapter::new();
    let domain = b"DEFI_VERIFY"; // Max 16 bytes

    let onchain_data = adapter
        .to_onchain_data(&proof, domain)
        .expect("On-chain data conversion failed");

    println!("On-chain data:");
    println!("  - Commitment: {:?}", &onchain_data.proof_commitment[0..8]);
    println!("  - Epoch: {}", onchain_data.epoch);
    println!(
        "  - Domain: {:?}",
        &onchain_data.domain[0..domain.len().min(16)]
    );
    println!("  - Verification status: {}", onchain_data.verified);

    // Verification
    assert_eq!(onchain_data.epoch, proof.epoch, "Epoch mismatch");
    assert!(
        !onchain_data.verified,
        "Initial verification status is true"
    );

    // Verify commitment is not all zeros
    let all_zeros = onchain_data.proof_commitment.iter().all(|&b| b == 0);
    assert!(!all_zeros, "Commitment is all zeros");

    println!("On-chain data conversion passed");
}
