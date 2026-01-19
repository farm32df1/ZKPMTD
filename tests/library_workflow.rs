//! Library Workflow Scenario Tests
//!
//! Validates the privacy-preserving verification workflow described in docs/WORKFLOW.md

use zkmtd::core::errors::Result;
use zkmtd::mtd::Epoch;
use zkmtd::stark::config::StarkConfig;
use zkmtd::stark::prover::MTDProver;
use zkmtd::utils::hash::poseidon_hash;
use zkmtd::{Prover, PublicInputs, Verifier, Witness};

#[cfg(feature = "solana-program")]
use zkmtd::solana::{LightweightProof, OnchainVerifier, ProofCommitment};

/// Simulates user's sensitive data that should never leave the device
struct UserSensitiveData {
    age: u64,
    balance: u64,
    _medical_status: bool,
}

/// Simulates the off-chain proof generation on user's device
fn offchain_generate_proof(
    sensitive_data: &UserSensitiveData,
    requirement_threshold: u64,
    seed: &[u8],
    epoch: Epoch,
) -> Result<(zkmtd::Proof, bool)> {
    // User checks if they meet the requirement locally
    let meets_requirement = sensitive_data.age >= requirement_threshold;

    // Create witness from sensitive data (stays on device)
    let witness = Witness::new(vec![
        sensitive_data.age,
        requirement_threshold,
        meets_requirement as u64,
        0,
    ]);

    // Public inputs contain only the threshold, not the actual age
    let public_inputs = PublicInputs::new(vec![requirement_threshold]);

    // Generate proof using MTD prover
    let config = StarkConfig::for_testing();
    let prover = MTDProver::with_epoch(seed, config, epoch)?;
    let proof = prover.prove(&witness, &public_inputs)?;

    Ok((proof, meets_requirement))
}

/// Simulates off-chain verification
fn offchain_verify(
    proof: &zkmtd::Proof,
    public_inputs: &PublicInputs,
    seed: &[u8],
    epoch: Epoch,
) -> Result<bool> {
    let config = StarkConfig::for_testing();
    let prover = MTDProver::with_epoch(seed, config, epoch)?;
    let verifier = prover.get_verifier();
    verifier.verify(proof, public_inputs)
}

/// Creates a lightweight commitment for on-chain submission
fn create_lightweight_commitment(proof: &zkmtd::Proof, seed: &[u8]) -> [u8; 32] {
    poseidon_hash(&proof.data, seed)
}

/// Simulates on-chain epoch validation
fn validate_epoch(proof_epoch: u64, current_epoch: u64, tolerance: u64) -> bool {
    if proof_epoch > current_epoch {
        return false;
    }
    current_epoch.saturating_sub(tolerance) <= proof_epoch
}

#[test]
fn test_workflow_age_verification_pass() {
    // Scenario: User is 25 years old, requirement is age >= 18
    let user_data = UserSensitiveData {
        age: 25,
        balance: 50000,
        _medical_status: true,
    };

    let seed = b"test-application-seed";
    let epoch = Epoch::new(100);
    let age_requirement = 18;

    // Off-chain: User generates proof on their device
    let (proof, meets_requirement) =
        offchain_generate_proof(&user_data, age_requirement, seed, epoch)
            .expect("Proof generation failed");

    // Verify the requirement check is correct
    assert!(meets_requirement, "User should meet age requirement");

    // Off-chain verification
    let public_inputs = PublicInputs::new(vec![age_requirement]);
    let is_valid = offchain_verify(&proof, &public_inputs, seed, epoch)
        .expect("Verification failed");
    assert!(is_valid, "Proof should be valid");

    // Create lightweight commitment for on-chain
    let commitment = create_lightweight_commitment(&proof, seed);
    assert_ne!(commitment, [0u8; 32], "Commitment should not be zero");

    // The actual age (25) is not in the commitment
    // Only the cryptographic hash is transmitted
}

#[test]
fn test_workflow_age_verification_fail() {
    // Scenario: User is 16 years old, requirement is age >= 18
    let user_data = UserSensitiveData {
        age: 16,
        balance: 1000,
        _medical_status: false,
    };

    let seed = b"test-application-seed";
    let epoch = Epoch::new(100);
    let age_requirement = 18;

    // Off-chain: User generates proof
    let (proof, meets_requirement) =
        offchain_generate_proof(&user_data, age_requirement, seed, epoch)
            .expect("Proof generation failed");

    // User does NOT meet the requirement
    assert!(!meets_requirement, "User should NOT meet age requirement");

    // Proof is still cryptographically valid
    let public_inputs = PublicInputs::new(vec![age_requirement]);
    let is_valid = offchain_verify(&proof, &public_inputs, seed, epoch)
        .expect("Verification failed");
    assert!(is_valid, "Proof structure is valid even if user doesn't qualify");
}

#[test]
fn test_workflow_replay_attack_prevention() {
    // Scenario: Attacker captures a valid proof and tries to replay it in a later epoch
    let user_data = UserSensitiveData {
        age: 25,
        balance: 50000,
        _medical_status: true,
    };

    let seed = b"test-application-seed";
    let original_epoch = Epoch::new(100);
    let age_requirement = 18;

    // Generate proof in epoch 100
    let (proof, _) =
        offchain_generate_proof(&user_data, age_requirement, seed, original_epoch)
            .expect("Proof generation failed");

    // Proof is valid in epoch 100
    assert!(validate_epoch(proof.epoch, 100, 1), "Valid in original epoch");

    // Attacker tries to replay in epoch 102 (outside tolerance)
    assert!(
        !validate_epoch(proof.epoch, 102, 1),
        "Replay attack should fail in future epoch"
    );

    // Attacker tries to replay in epoch 105
    assert!(
        !validate_epoch(proof.epoch, 105, 1),
        "Replay attack should fail in much later epoch"
    );
}

#[test]
fn test_workflow_epoch_tolerance() {
    // Scenario: Proof generated during network delay, arrives in next epoch
    let user_data = UserSensitiveData {
        age: 30,
        balance: 100000,
        _medical_status: true,
    };

    let seed = b"test-application-seed";
    let epoch = Epoch::new(100);
    let age_requirement = 21;

    // Generate proof in epoch 100
    let (proof, _) =
        offchain_generate_proof(&user_data, age_requirement, seed, epoch)
            .expect("Proof generation failed");

    // With tolerance of 1, proof should be valid in epoch 100 and 101
    assert!(validate_epoch(proof.epoch, 100, 1), "Valid in generation epoch");
    assert!(validate_epoch(proof.epoch, 101, 1), "Valid with tolerance");

    // But not in epoch 102
    assert!(!validate_epoch(proof.epoch, 102, 1), "Invalid outside tolerance");

    // With higher tolerance (for satellite/interplanetary networks)
    assert!(validate_epoch(proof.epoch, 105, 5), "Valid with higher tolerance");
}

#[test]
fn test_workflow_sensitive_data_isolation() {
    // Scenario: Verify that sensitive data never appears in transmitted data
    let user_data = UserSensitiveData {
        age: 42,
        balance: 123456,
        _medical_status: true,
    };

    let seed = b"isolation-test-seed";
    let epoch = Epoch::new(200);

    let (proof, _) = offchain_generate_proof(&user_data, 18, seed, epoch)
        .expect("Proof generation failed");

    // Create commitment
    let commitment = create_lightweight_commitment(&proof, seed);

    // The actual age (42) should not appear in raw form
    let age_bytes = user_data.age.to_le_bytes();
    let balance_bytes = user_data.balance.to_le_bytes();

    // Commitment is a hash, should not contain raw values
    assert!(
        !commitment.windows(8).any(|w| w == age_bytes),
        "Raw age should not appear in commitment"
    );

    assert!(
        !commitment.windows(8).any(|w| w == balance_bytes),
        "Raw balance should not appear in commitment"
    );
}

#[test]
fn test_workflow_financial_compliance() {
    // Scenario: Prove balance >= $10000 without revealing actual balance
    let user_data = UserSensitiveData {
        age: 35,
        balance: 75000, // Actual balance: $75,000
        _medical_status: true,
    };

    let seed = b"financial-compliance-seed";
    let epoch = Epoch::new(300);
    let balance_requirement = 10000u64;

    // Create witness with balance check
    let meets_requirement = user_data.balance >= balance_requirement;
    let witness = Witness::new(vec![
        user_data.balance,
        balance_requirement,
        meets_requirement as u64,
        0,
    ]);

    let public_inputs = PublicInputs::new(vec![balance_requirement]);

    let config = StarkConfig::for_testing();
    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
    let proof = prover.prove(&witness, &public_inputs).unwrap();

    // Verify
    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof, &public_inputs).unwrap();
    assert!(is_valid, "Financial proof should be valid");

    // Create lightweight commitment
    let commitment = create_lightweight_commitment(&proof, seed);

    // The actual balance ($75,000) should not appear in commitment
    let balance_bytes = user_data.balance.to_le_bytes();
    assert!(
        !commitment.windows(8).any(|w| w == balance_bytes),
        "Actual balance should not appear in commitment"
    );
}

#[test]
fn test_workflow_different_seeds_different_proofs() {
    // Scenario: Same data with different seeds produces different proofs
    let user_data = UserSensitiveData {
        age: 25,
        balance: 50000,
        _medical_status: true,
    };

    let seed1 = b"application-one-seed";
    let seed2 = b"application-two-seed";
    let epoch = Epoch::new(100);

    let (proof1, _) = offchain_generate_proof(&user_data, 18, seed1, epoch).unwrap();
    let (proof2, _) = offchain_generate_proof(&user_data, 18, seed2, epoch).unwrap();

    // Proofs should be different
    assert_ne!(proof1.data, proof2.data, "Different seeds should produce different proofs");

    // Commitments should also be different
    let commitment1 = create_lightweight_commitment(&proof1, seed1);
    let commitment2 = create_lightweight_commitment(&proof2, seed2);
    assert_ne!(commitment1, commitment2, "Commitments should differ");
}

#[test]
fn test_workflow_batch_verification() {
    // Scenario: Multiple users submit proofs
    let users = vec![
        UserSensitiveData {
            age: 25,
            balance: 50000,
            _medical_status: true,
        },
        UserSensitiveData {
            age: 30,
            balance: 75000,
            _medical_status: true,
        },
        UserSensitiveData {
            age: 22,
            balance: 30000,
            _medical_status: false,
        },
    ];

    let seed = b"batch-test-seed";
    let epoch = Epoch::new(400);
    let age_requirement = 21;

    let mut all_valid = true;
    let mut proofs_count = 0;

    for user in &users {
        let (proof, meets_requirement) =
            offchain_generate_proof(user, age_requirement, seed, epoch)
                .expect("Proof generation failed");

        if meets_requirement {
            let public_inputs = PublicInputs::new(vec![age_requirement]);
            let is_valid = offchain_verify(&proof, &public_inputs, seed, epoch).unwrap();
            all_valid = all_valid && is_valid;
            proofs_count += 1;
        }
    }

    // All 3 users are >= 21, so all proofs should be valid
    assert!(all_valid, "All batch proofs should be valid");
    assert_eq!(proofs_count, 3, "Should have 3 valid proofs");
}

#[test]
fn test_workflow_complete_flow() {
    // Complete end-to-end workflow test

    // Step 1: User has sensitive data on their device
    let user_sensitive_data = UserSensitiveData {
        age: 28,
        balance: 45000,
        _medical_status: true,
    };

    // Step 2: Application requires age >= 21
    let requirement = 21u64;
    let seed = b"complete-flow-test";
    let epoch = Epoch::new(500);

    // Step 3: User generates ZK proof locally
    let (proof, meets_requirement) =
        offchain_generate_proof(&user_sensitive_data, requirement, seed, epoch)
            .expect("Off-chain proof generation failed");

    assert!(meets_requirement, "User meets requirement");

    // Step 4: Off-chain verification
    let public_inputs = PublicInputs::new(vec![requirement]);
    let verification_result = offchain_verify(&proof, &public_inputs, seed, epoch)
        .expect("Verification failed");
    assert!(verification_result, "Off-chain verification passed");

    // Step 5: Create lightweight commitment for on-chain
    let commitment = create_lightweight_commitment(&proof, seed);
    assert_ne!(commitment, [0u8; 32]);

    // Step 6: Validate epoch
    assert!(validate_epoch(proof.epoch, epoch.value(), 1));

    // Step 7: Simulated on-chain storage
    struct OnchainStorage {
        commitment: [u8; 32],
        proof_valid: bool,
        epoch: u64,
        // Note: NO personal data stored
    }

    let storage = OnchainStorage {
        commitment,
        proof_valid: verification_result,
        epoch: epoch.value(),
    };

    assert!(storage.proof_valid);
    assert_eq!(storage.epoch, 500);
    assert_ne!(storage.commitment, [0u8; 32]);

    // Verification complete: User's actual age (28) was never transmitted or stored
}

#[test]
fn test_workflow_cross_epoch_proof_invalidation() {
    // Scenario: Prove that proofs become invalid when verified with wrong epoch
    let user_data = UserSensitiveData {
        age: 25,
        balance: 50000,
        _medical_status: true,
    };

    let seed = b"cross-epoch-test";
    let epoch_100 = Epoch::new(100);
    let epoch_200 = Epoch::new(200);

    // Generate proof in epoch 100
    let (proof, _) = offchain_generate_proof(&user_data, 18, seed, epoch_100).unwrap();

    // Verify with correct epoch - should pass
    let public_inputs = PublicInputs::new(vec![18]);
    let valid_in_100 = offchain_verify(&proof, &public_inputs, seed, epoch_100).unwrap();
    assert!(valid_in_100, "Should be valid in original epoch");

    // Try to verify with different epoch (epoch 200) - should fail
    // The verifier created with different epoch will have different MTD params
    let result = offchain_verify(&proof, &public_inputs, seed, epoch_200);

    // This should fail because the proof was bound to epoch 100's parameters
    assert!(
        result.is_err() || !result.unwrap(),
        "Should be invalid in different epoch"
    );
}
