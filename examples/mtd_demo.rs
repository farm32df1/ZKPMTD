//! # MTD Demo
//!
//! Example demonstrating Moving Target Defense behavior.
//! Shows how different parameters are generated with each epoch change.
#![allow(deprecated)]

use zkmtd::{Epoch, MTDManager, MTDProver, Prover, PublicInputs, StarkConfig, Witness};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZKMTD Moving Target Defense Demo ===\n");

    let seed = b"mtd-demo-seed";
    let config = StarkConfig::for_testing();

    // Create MTD manager
    println!("1. Initializing MTD manager...");
    let mut mtd_manager = MTDManager::with_epoch(seed, Epoch::new(100))?;
    println!("   Starting Epoch: {}", mtd_manager.current_epoch());

    // Generate proofs across multiple epochs
    println!("\n2. Generating proofs across epochs and observing parameter changes...\n");

    for i in 0..5 {
        let current_epoch = mtd_manager.current_epoch();
        let params = mtd_manager.current_params();

        println!("--- Epoch {} ---", current_epoch.value());
        println!("  Domain separator: {:?}...", &params.domain_separator[..8]);
        println!("  Salt: {:?}...", &params.salt[..8]);
        println!("  FRI seed: {:?}...", &params.fri_seed[..8]);

        // Generate proof with this epoch's prover
        let prover = MTDProver::with_epoch(seed, config.clone(), current_epoch)?;
        let witness = Witness::new(vec![i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7]);
        let public_inputs = PublicInputs::new(vec![i * 10]);

        let proof = prover.prove(&witness, &public_inputs)?;
        println!("  Proof generated (size: {} bytes)", proof.size());

        // Advance to next epoch
        if i < 4 {
            mtd_manager.advance()?;
            println!();
        }
    }

    println!("\n3. Summary of parameter changes:");
    println!("   Completely different cryptographic parameters were generated for each epoch.");
    println!("   This is the core of Moving Target Defense!");
    println!("   Attackers cannot find a fixed target.\n");

    Ok(())
}
