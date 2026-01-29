//! Fuzz target for Lightweight proof verification
//! Tests: OnchainVerifier::verify() with arbitrary proofs
//! Goal: Ensure no panics, epoch validation, commitment checking

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zkmtd::solana::lightweight::LightweightProof;
use zkmtd::solana::onchain_verifier::OnchainVerifier;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    commitment: [u8; 32],
    merkle_root: [u8; 32],
    epoch: u64,
    timestamp: u64,
    public_values: Vec<u64>,
    committed_values: [u8; 32],
    current_epoch: u64,
    expected_committed: [u8; 32],
    epoch_tolerance: u64,
}

fuzz_target!(|input: FuzzInput| {
    // Limit public values size
    if input.public_values.len() > 100 {
        return;
    }

    // Create proof
    let proof = LightweightProof {
        commitment: input.commitment,
        merkle_root: input.merkle_root,
        epoch: input.epoch,
        timestamp: input.timestamp,
        public_values: input.public_values.clone(),
        committed_values: input.committed_values,
    };

    // Create verifier with tolerance
    let tolerance = input.epoch_tolerance % 100; // Reasonable tolerance
    let verifier = OnchainVerifier::new(input.current_epoch, input.expected_committed)
        .with_epoch_tolerance(tolerance);

    // Verify - should never panic
    let _ = verifier.verify(&proof);

    // Test with expected values
    let verifier_with_values = verifier.with_expected_values(input.public_values);
    let _ = verifier_with_values.verify(&proof);
});
