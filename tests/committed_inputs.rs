//! End-to-end tests for committed public inputs (privacy-by-default)

#![cfg(feature = "full-p3")]

use zkmtd::core::types::CommittedPublicInputs;
use zkmtd::mtd::Epoch;
use zkmtd::stark::integrated::{IntegratedProver, IntegratedVerifier};
use zkmtd::utils::hash::derive_pv_salt;

#[test]
fn test_e2e_prove_verify() {
    let seed = b"e2e-privacy-test";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).unwrap();
    let pv_salt = derive_pv_salt(seed, epoch.value(), b"user-nonce");
    let proof = prover.prove_fibonacci(8, pv_salt).unwrap();

    assert_ne!(proof.committed_values_hash(), &[0u8; 32]);

    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof).unwrap();
    assert!(is_valid, "Proof should be valid");
}

#[test]
fn test_e2e_independent_verifier() {
    let seed = b"e2e-independent";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).unwrap();
    let pv_salt = [55u8; 32];
    let proof = prover.prove_fibonacci(8, pv_salt).unwrap();

    // Independent verifier (same seed + epoch, different instance)
    let verifier = IntegratedVerifier::new(seed, epoch).unwrap();
    let is_valid = verifier.verify(&proof).unwrap();
    assert!(is_valid, "Independent verifier should accept valid proof");
}

#[test]
fn test_e2e_commitment_forgery_rejected() {
    let seed = b"e2e-forgery";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).unwrap();
    let pv_salt = [42u8; 32];
    let mut proof = prover.prove_fibonacci(8, pv_salt).unwrap();

    // Forge the commitment (attacker tries to substitute a different commitment)
    proof.committed_public_values.commitment = [0xAA; 32];

    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof).unwrap();
    assert!(!is_valid, "Forged commitment should be rejected");
}

#[test]
fn test_e2e_gdpr_erasure_scenario() {
    let seed = b"e2e-gdpr-erasure";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).unwrap();
    let pv_salt = derive_pv_salt(seed, epoch.value(), b"user-data-nonce");
    let mut proof = prover.prove_fibonacci(8, pv_salt).unwrap();
    let verifier = prover.get_verifier();

    // Step 1: Full verification with salt
    let public_values = proof.public_values().to_vec();
    assert!(verifier.verify_with_salt(&proof, &public_values, &pv_salt).unwrap());

    // Step 2: GDPR deletion — erase salt
    proof.erase_salt();
    assert!(!proof.has_salt());

    // Step 3: On-chain binding hash still verifiable (without salt)
    assert!(
        verifier.verify(&proof).unwrap(),
        "Proof must remain verifiable after salt erasure"
    );

    // Step 4: Cannot re-derive commitment (privacy preserved)
    let fake_salt = [0u8; 32];
    assert!(
        !verifier.verify_with_salt(&proof, &public_values, &fake_salt).unwrap(),
        "Cannot verify_with_salt with erased salt"
    );
}

#[test]
fn test_e2e_public_values_tampering_rejected() {
    let seed = b"e2e-pv-tamper";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).unwrap();
    let pv_salt = [42u8; 32];
    let mut proof = prover.prove_fibonacci(8, pv_salt).unwrap();

    // Tamper with actual public values inside STARK proof
    proof.stark_proof.public_values[2] = 999;

    let verifier = prover.get_verifier();
    let is_valid = verifier.verify(&proof).unwrap();
    assert!(!is_valid, "Tampered public values should be rejected");
}

#[test]
fn test_e2e_cross_epoch_rejection() {
    let seed = b"e2e-cross-epoch";

    // Generate proof at epoch 100
    let prover = IntegratedProver::new(seed, Epoch::new(100)).unwrap();
    let pv_salt = [42u8; 32];
    let proof = prover.prove_fibonacci(8, pv_salt).unwrap();

    // Verify with epoch 200 verifier → should fail
    let wrong_verifier = IntegratedVerifier::new(seed, Epoch::new(200)).unwrap();
    let is_valid = wrong_verifier.verify(&proof).unwrap();
    assert!(!is_valid, "Cross-epoch proof should be rejected");
}

#[test]
fn test_e2e_committed_public_inputs_unit() {
    let values = vec![0u64, 1, 13, 21];
    let salt = [42u8; 32];

    let committed = CommittedPublicInputs::commit(&values, &salt);
    assert_eq!(committed.value_count, 4);

    // Valid verification
    assert!(committed.verify(&values, &salt));

    // Wrong values
    assert!(!committed.verify(&[0, 1, 99, 21], &salt));

    // Wrong salt
    assert!(!committed.verify(&values, &[0u8; 32]));

    // Wrong count
    assert!(!committed.verify(&[0, 1], &salt));
}

#[test]
fn test_e2e_derive_pv_salt_consistency() {
    let seed = b"salt-consistency";

    // Same inputs → same salt
    let s1 = derive_pv_salt(seed, 100, b"nonce");
    let s2 = derive_pv_salt(seed, 100, b"nonce");
    assert_eq!(s1, s2);

    // Different epoch → different salt
    let s3 = derive_pv_salt(seed, 101, b"nonce");
    assert_ne!(s1, s3);

    // Different nonce → different salt
    let s4 = derive_pv_salt(seed, 100, b"different-nonce");
    assert_ne!(s1, s4);
}

#[test]
fn test_e2e_wrong_seed_rejection() {
    // Generate proof with seed-A
    let prover = IntegratedProver::new(b"seed-A", Epoch::new(100)).unwrap();
    let proof = prover.prove_fibonacci(8, [42u8; 32]).unwrap();

    // Verify with seed-B → should fail
    let wrong_verifier = IntegratedVerifier::new(b"seed-B", Epoch::new(100)).unwrap();
    let is_valid = wrong_verifier.verify(&proof).unwrap();
    assert!(!is_valid, "Wrong seed proof should be rejected");
}

#[test]
fn test_e2e_different_salts_produce_different_commitments() {
    let seed = b"e2e-salt-diff";
    let epoch = Epoch::new(100);

    let prover = IntegratedProver::new(seed, epoch).unwrap();

    let proof_a = prover.prove_fibonacci(8, [1u8; 32]).unwrap();
    let proof_b = prover.prove_fibonacci(8, [2u8; 32]).unwrap();

    // Different salts → different binding hashes
    assert_ne!(proof_a.binding_hash, proof_b.binding_hash);

    // Different salts → different committed hashes
    assert_ne!(
        proof_a.committed_values_hash(),
        proof_b.committed_values_hash()
    );
}
