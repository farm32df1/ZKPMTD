//! # Solana CU Estimation Example
//!
//! Shows expected CU consumption in various scenarios.
#![allow(deprecated)]

use std::time::Instant;
use zkmtd::batching::{create_proof_batch, BatchVerifier};
use zkmtd::core::traits::BatchProver as BatchProverTrait;
use zkmtd::{BatchProver, Epoch, MTDProver, Prover, PublicInputs, StarkConfig, Verifier, Witness};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Solana CU Estimation Tool ===\n");
    println!("Warning: Actual on-chain CU may differ from these estimates.\n");

    // 1. Single proof verification
    println!("1. Single Proof Verification");
    println!("─────────────────────────");
    estimate_single_verification()?;

    println!();

    // 2. Batch verification (various sizes)
    println!("2. Batch Proof Verification");
    println!("─────────────────────────");
    for size in [5, 10, 20, 50] {
        estimate_batch_verification(size)?;
    }

    println!();

    // 3. Summary and recommendations
    print_summary();

    Ok(())
}

fn estimate_single_verification() -> Result<(), Box<dyn std::error::Error>> {
    let seed = b"cu-estimate-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(10000);

    let prover = MTDProver::with_epoch(seed, config, epoch)?;
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    // Generate proof (off-chain)
    let proof = prover.prove(&witness, &public_inputs)?;
    println!("  Proof size: {} bytes", proof.size());

    // Measure verification time
    let verifier = prover.get_verifier();
    let start = Instant::now();
    let is_valid = verifier.verify(&proof, &public_inputs)?;
    let elapsed = start.elapsed();

    // CU estimation (very approximate)
    // Actual measurement requires sol_log_compute_units() in Solana program
    let estimated_cu = estimate_cu_from_time(elapsed);

    println!("  Verification time: {:?}", elapsed);
    println!("  Estimated CU: ~{} CU", format_cu(estimated_cu));
    println!(
        "  Verification result: {}",
        if is_valid { "Valid" } else { "Invalid" }
    );
    println!(
        "  Within Solana limit: {}",
        if estimated_cu < 200_000 {
            "Yes"
        } else {
            "No (limit increase required)"
        }
    );

    Ok(())
}

fn estimate_batch_verification(batch_size: usize) -> Result<(), Box<dyn std::error::Error>> {
    let seed = b"cu-batch-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(11000);

    let prover = BatchProver::with_epoch(seed, config, epoch)?;

    let witnesses: Vec<_> = (0..batch_size)
        .map(|i| Witness::new(vec![i as u64; 8]))
        .collect();

    let inputs: Vec<_> = (0..batch_size)
        .map(|i| PublicInputs::new(vec![i as u64 * 10]))
        .collect();

    // Generate batch proofs
    let proofs = prover.prove_batch(&witnesses, &inputs)?;
    let batch = create_proof_batch(proofs, epoch.value())?;

    let total_size: usize = batch.proofs.iter().map(|p| p.size()).sum();

    // Measure batch verification time
    let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());
    let start = Instant::now();
    let _is_valid = verifier.verify_batch(&batch, &inputs)?;
    let elapsed = start.elapsed();

    let estimated_cu = estimate_cu_from_time(elapsed);
    let cu_per_proof = estimated_cu / batch_size;

    println!("\n  Batch size: {} proofs", batch_size);
    println!("  Total data: {} bytes", total_size);
    println!("  Verification time: {:?}", elapsed);
    println!("  Estimated total CU: ~{} CU", format_cu(estimated_cu));
    println!("  CU per proof: ~{} CU", format_cu(cu_per_proof));
    println!("  Efficiency gain: {}x", 50000 / cu_per_proof.max(1));
    println!(
        "  Within Solana limit: {}",
        if estimated_cu < 200_000 { "Yes" } else { "No" }
    );

    Ok(())
}

fn estimate_cu_from_time(duration: std::time::Duration) -> usize {
    // Very approximate estimation
    // Actual CU requires on-chain measurement
    // Assumption: 1 microsecond = ~100 CU
    let micros = duration.as_micros() as usize;
    let base_cu = micros * 100;

    // Add overhead
    let overhead = 5000;
    base_cu + overhead
}

fn format_cu(cu: usize) -> String {
    if cu < 1000 {
        format!("{}", cu)
    } else if cu < 1_000_000 {
        format!("{:.1}K", cu as f64 / 1000.0)
    } else {
        format!("{:.2}M", cu as f64 / 1_000_000.0)
    }
}

fn print_summary() {
    println!("Summary and Recommendations");
    println!("═══════════════════════════");
    println!();
    println!("Recommended Strategies:");
    println!("  1. Use batch verification: 10-20 proofs per batch (max efficiency)");
    println!("  2. Minimize proof size: target < 1KB");
    println!("  3. Specify CU limit: use SetComputeUnitLimit");
    println!("  4. Utilize zero-copy deserialization");
    println!();
    println!("Solana Limits:");
    println!("  - Default limit:     200,000 CU");
    println!("  - Maximum limit:   1,400,000 CU");
    println!("  - Recommended target: <100,000 CU (safety margin)");
    println!();
    println!("CU Optimization Methods:");
    println!("  - Store pre-computed parameters on-chain");
    println!("  - Conditional verification (by trust level)");
    println!("  - Minimize Merkle tree depth");
    println!("  - Remove unnecessary logs");
    println!();
    println!("For more details:");
    println!("  See docs/SOLANA_CU_GUIDE.md");
    println!();
    println!("Actual on-chain testing:");
    println!("  Use sol_log_compute_units() in Solana program");
    println!("  Or measure exact CU via transaction simulation");
    println!();
}
