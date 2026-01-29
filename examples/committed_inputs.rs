//! Committed Public Inputs Example
//!
//! Demonstrates privacy-preserving proof generation and GDPR-compliant salt erasure.
//! All proofs commit public values with a salt (privacy-by-default).
//!
//! Run: cargo run --example committed_inputs --features "std,full-p3"

use zkmtd::mtd::Epoch;
use zkmtd::stark::integrated::IntegratedProver;
use zkmtd::utils::hash::derive_pv_salt;

fn main() {
    println!("=== ZKMTD Committed Public Inputs Demo ===\n");

    let seed = b"demo-application-seed";
    let epoch = Epoch::new(100);

    // --- Proof Generation (privacy-by-default) ---
    println!("[1] Generate Proof (privacy-by-default)");
    let prover = IntegratedProver::new(seed, epoch).expect("Prover creation failed");
    let pv_salt = derive_pv_salt(seed, epoch.value(), b"user-session-nonce");
    let proof = prover
        .prove_fibonacci(8, pv_salt)
        .expect("Proof generation failed");

    let verifier = prover.get_verifier();
    let valid = verifier.verify(&proof).expect("Verification error");
    println!("    Committed hash: {:02x?}", &proof.committed_values_hash()[..8]);
    println!("    Public values:  {:?}", proof.public_values());
    println!("    Valid: {}\n", valid);

    // --- Full Verification (with salt) ---
    println!("[2] Full Verification (off-chain, with salt)");
    let public_values = proof.public_values().to_vec();
    let full_valid = verifier
        .verify_with_salt(&proof, &public_values, &pv_salt)
        .expect("Full verification error");
    println!("    Full valid (with salt): {}\n", full_valid);

    // --- GDPR Erasure ---
    println!("[3] GDPR Erasure Scenario");
    let mut erasable_proof = prover
        .prove_fibonacci(8, pv_salt)
        .expect("Proof generation failed");

    println!("    Before erasure: salt present = {}", erasable_proof.has_salt());
    erasable_proof.erase_salt();
    println!("    After erasure:  salt present = {}", erasable_proof.has_salt());

    let still_valid = verifier.verify(&erasable_proof).expect("Verification error");
    println!("    Proof still verifiable: {}", still_valid);
    println!("    On-chain committed hash is now irreversible.\n");

    // --- Different Salts Produce Different Commitments ---
    println!("[4] Different Salts → Different Commitments");
    let proof_a = prover.prove_fibonacci(8, [1u8; 32]).expect("Proof A failed");
    let proof_b = prover.prove_fibonacci(8, [2u8; 32]).expect("Proof B failed");
    println!(
        "    Salt [1u8;32] binding hash: {:02x?}",
        &proof_a.binding_hash[..8]
    );
    println!(
        "    Salt [2u8;32] binding hash: {:02x?}",
        &proof_b.binding_hash[..8]
    );
    println!(
        "    Different: {}",
        proof_a.binding_hash != proof_b.binding_hash
    );

    println!("\n=== Demo Complete ===");
}
