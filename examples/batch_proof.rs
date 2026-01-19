//! # Batch Proof Example
//!
//! Example of bundling multiple proofs into a batch for efficient verification.

use zkmtd::batching::create_proof_batch;
use zkmtd::core::traits::BatchProver as BatchProverTrait;
use zkmtd::{BatchProver, BatchVerifier, Epoch, PublicInputs, StarkConfig, Witness};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZKMTD Batch Proof Example ===\n");

    // 1. Initial setup
    let seed = b"batch-demo-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(200);

    println!("1. Creating batch prover...");
    let prover = BatchProver::with_epoch(seed, config, epoch)?;
    println!("   Epoch: {}", prover.current_epoch());

    // 2. Prepare multiple witnesses
    println!("\n2. Preparing witnesses for 10 proofs...");
    let mut witnesses = Vec::new();
    let mut public_inputs_list = Vec::new();

    for i in 1..=10 {
        let witness = Witness::new(vec![i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7]);
        let public_inputs = PublicInputs::new(vec![i * 100]);

        witnesses.push(witness);
        public_inputs_list.push(public_inputs);
    }
    println!("   Done: 10 witnesses prepared");

    // 3. Generate batch proofs
    println!("\n3. Generating batch proofs...");
    let proofs = prover.prove_batch(&witnesses, &public_inputs_list)?;
    println!("   Done: 10 proofs generated");

    // Print individual proof sizes
    println!("\n   Individual proof sizes:");
    for (i, proof) in proofs.iter().enumerate() {
        println!("     Proof #{}: {} bytes", i + 1, proof.size());
    }

    // 4. Create proof batch
    println!("\n4. Bundling proofs into batch...");
    let batch = create_proof_batch(proofs, epoch.value())?;
    println!("   Done: Batch created");
    println!("   Batch size: {} proofs", batch.len());
    println!("   Merkle root: {:?}...", &batch.merkle_root[..8]);

    // 5. Verify batch
    println!("\n5. Verifying batch...");
    let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());
    let is_valid = verifier.verify_batch(&batch, &public_inputs_list)?;

    if is_valid {
        println!("   Batch is valid!");
    } else {
        println!("   Batch is invalid!");
    }

    // 6. Verify individual proof (within batch)
    println!("\n6. Verifying individual proof within batch...");
    let index = 5;
    let single_valid =
        verifier.verify_single_in_batch(&batch, index, &public_inputs_list[index])?;

    if single_valid {
        println!("   Proof #{} is included in batch and valid!", index + 1);
    }

    // 7. Statistics
    println!("\n=== Statistics ===");
    println!("Total proofs: {}", batch.len());
    println!("Batch Epoch: {}", batch.epoch);
    println!("\nNote: Batch verification is ~5x faster than individual verification!");

    Ok(())
}
