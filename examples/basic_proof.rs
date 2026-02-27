//! # Basic Proof Example
//!
//! Basic proof generation and verification example using ZKMTD.
#![allow(deprecated)]

use zkmtd::{MTDProver, Prover, PublicInputs, StarkConfig, SystemEntropy, Verifier, Witness};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZKMTD Basic Proof Example ===\n");

    // 1. Initial setup
    println!("1. System initialization...");
    let seed = b"my-secret-seed-12345";
    let mut entropy = SystemEntropy::new();
    let config = StarkConfig::default();

    // 2. Create prover
    println!("2. Creating MTD prover...");
    let prover = MTDProver::new(seed, config, &mut entropy)?;
    println!("   Current Epoch: {}", prover.current_epoch());

    // 3. Prepare witness and public inputs
    println!("\n3. Preparing witness and public inputs...");
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);
    println!("   Witness size: {} elements", witness.len());
    println!("   Public inputs: {:?}", public_inputs.data);

    // 4. Generate proof
    println!("\n4. Generating proof...");
    let proof = prover.prove(&witness, &public_inputs)?;
    println!("   Proof generated!");
    println!("   Proof size: {} bytes", proof.size());
    println!("   Proof epoch: {}", proof.epoch);

    // 5. Create verifier
    println!("\n5. Creating verifier...");
    let verifier = prover.get_verifier();

    // 6. Verify proof
    println!("6. Verifying proof...");
    let is_valid = verifier.verify(&proof, &public_inputs)?;

    if is_valid {
        println!("   Proof is valid!");
    } else {
        println!("   Proof is invalid!");
    }

    // 7. Statistics
    println!("\n=== Statistics ===");
    println!("Min witness size: {}", prover.min_witness_size());
    println!(
        "Min public inputs size: {}",
        prover.min_public_inputs_size()
    );

    Ok(())
}
