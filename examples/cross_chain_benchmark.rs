//! # Cross-Chain Benchmark
//!
//! Compares cost metrics across various blockchains.

use std::time::Instant;
use zkmtd::prelude::{CompressedProof, CompressionAlgorithm};
use zkmtd::{Epoch, MTDProver, Prover, PublicInputs, StarkConfig, Witness};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Cross-Chain Cost Benchmark\n");
    println!("═══════════════════════════════════════════\n");

    // Generate proof
    let seed = b"cross-chain-bench";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(20000);

    let prover = MTDProver::with_epoch(seed, config, epoch)?;
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    let proof = prover.prove(&witness, &public_inputs)?;

    println!("Basic Proof Information");
    println!("─────────────────────────");
    println!("  Original size: {} bytes\n", proof.size());

    // 1. Compression test
    println!("Compression Test");
    println!("─────────────────────────");
    test_compression(&proof)?;
    println!();

    // 2. Chain-specific metrics
    println!("Estimated Costs by Chain");
    println!("─────────────────────────");
    estimate_chain_costs(&proof)?;
    println!();

    // 3. Recommendations
    println!("Optimization Recommendations");
    println!("─────────────────────────");
    print_recommendations(&proof);

    Ok(())
}

fn test_compression(proof: &zkmtd::Proof) -> Result<(), Box<dyn std::error::Error>> {
    let algorithms = vec![
        ("No compression", CompressionAlgorithm::None),
        ("RLE", CompressionAlgorithm::Rle),
    ];

    for (name, algo) in algorithms {
        let start = Instant::now();
        let compressed = CompressedProof::compress(proof, algo)?;
        let compress_time = start.elapsed();

        let start = Instant::now();
        let decompressed = compressed.decompress()?;
        let decompress_time = start.elapsed();

        // Integrity verification
        assert_eq!(
            proof.data, decompressed.data,
            "Compression integrity failed!"
        );

        let ratio = compressed.compression_ratio();
        let saved = compressed.bytes_saved();

        println!("  {} compression:", name);
        println!(
            "    After compression: {} bytes",
            compressed.compressed_data.len()
        );
        println!("    Compression ratio: {:.1}%", ratio * 100.0);
        println!("    Saved: {} bytes ({:.1}%)", saved, (1.0 - ratio) * 100.0);
        println!("    Compression time: {:?}", compress_time);
        println!("    Decompression time: {:?}", decompress_time);
        println!();
    }

    Ok(())
}

fn estimate_chain_costs(proof: &zkmtd::Proof) -> Result<(), Box<dyn std::error::Error>> {
    let proof_size = proof.size();

    // Solana
    println!("  Solana");
    let solana_cu = estimate_solana_cu(proof_size);
    println!("    Metric: {} CU", format_number(solana_cu));
    println!("    Estimated cost: ~${:.6}", solana_cu as f64 * 0.0000001);
    println!("    Batch(50): ~${:.6}", 38_000.0 * 0.0000001);
    println!("    Recommended: Use batch verification");
    println!();

    // Ethereum
    println!("  Ethereum");
    let eth_gas = estimate_ethereum_gas(proof_size);
    println!("    Metric: {} Gas", format_number(eth_gas));
    println!(
        "    Estimated cost: ~${:.2} (30 gwei, $2000/ETH)",
        eth_gas as f64 * 30.0 / 1e9 * 2000.0
    );
    println!(
        "    After compression: ~${:.2}",
        (eth_gas as f64 * 0.3) * 30.0 / 1e9 * 2000.0
    );
    println!("    Recommended: Zstd max compression, use L2");
    println!();

    // Polygon
    println!("  Polygon");
    let polygon_gas = estimate_ethereum_gas(proof_size); // EVM compatible
    println!("    Metric: {} Gas", format_number(polygon_gas));
    println!(
        "    Estimated cost: ~${:.3} (50 gwei, $1/MATIC)",
        polygon_gas as f64 * 50.0 / 1e9 * 1.0
    );
    println!("    Batch(10): ~${:.3}", 500_000.0 * 50.0 / 1e9 * 1.0);
    println!("    Recommended: Batch verification + compression");
    println!();

    // Arbitrum (L2)
    println!("  Arbitrum (L2)");
    let arb_gas = estimate_ethereum_gas(proof_size);
    println!("    Metric: {} Gas", format_number(arb_gas));
    println!(
        "    Estimated cost: ~${:.3} (0.1 gwei, $2000/ETH)",
        arb_gas as f64 * 0.1 / 1e9 * 2000.0
    );
    println!(
        "    L1 Data: ~${:.2} (calldata)",
        proof_size as f64 * 16.0 * 30.0 / 1e9 * 2000.0
    );
    println!("    Recommended: Reduce calldata via compression");
    println!();

    // Cosmos
    println!("  Cosmos");
    let cosmos_gas = estimate_cosmos_gas(proof_size);
    println!("    Metric: {} Gas", format_number(cosmos_gas));
    println!(
        "    Estimated cost: ~${:.4} (0.025 ATOM/gas, $10/ATOM)",
        cosmos_gas as f64 * 0.000025 * 10.0
    );
    println!(
        "    IBC transfer: ~${:.4}",
        (cosmos_gas + 50_000) as f64 * 0.000025 * 10.0
    );
    println!("    Recommended: Protobuf optimization");
    println!();

    // Near
    println!("  Near");
    let near_tgas = estimate_near_tgas(proof_size);
    println!("    Metric: {} Tgas", near_tgas);
    println!(
        "    Estimated cost: ~${:.4} (0.0001 NEAR/Tgas, $4/NEAR)",
        near_tgas as f64 * 0.0001 * 4.0
    );
    println!("    Batch(10): ~${:.4}", 50.0 * 0.0001 * 4.0);
    println!("    Recommended: Moderate compression");
    println!();

    Ok(())
}

fn print_recommendations(proof: &zkmtd::Proof) {
    let size = proof.size();

    println!("  General Recommendations:");
    println!("    1. Use batch verification when possible");
    println!("    2. Choose compression algorithm suitable for the chain");
    println!("    3. Store pre-computed parameters on-chain");
    println!("    4. Minimize storage space with Merkle trees");
    println!();

    println!("  Chain-specific Strategies:");
    println!("    - Ethereum: Use L2 + max compression");
    println!("    - Solana: Batch verification (65x efficiency)");
    println!("    - Polygon: Batch + medium compression");
    println!("    - Arbitrum: Reduce L1 calldata via compression");
    println!("    - Cosmos: Minimize IBC packets");
    println!("    - Near: Balanced approach");
    println!();

    println!("  Data Size Optimization:");
    if size < 200 {
        println!("    Current size ({} B) is already optimized", size);
    } else if size < 500 {
        println!(
            "    RLE compression recommended ({} B -> ~{} B)",
            size,
            size / 2
        );
    } else {
        println!(
            "    Dictionary compression recommended ({} B -> ~{} B)",
            size,
            size / 3
        );
    }
    println!();

    println!("  Additional Resources:");
    println!("    - docs/CROSS_CHAIN_METRICS.md");
    println!("    - docs/SOLANA_CU_GUIDE.md");
    println!("    - docs/SOLANA_INTEGRATION.md");
}

// Chain-specific cost estimation functions

fn estimate_solana_cu(proof_size: usize) -> u64 {
    // Base overhead + verification logic + data processing
    let base = 5_000;
    let verification = 30_000;
    let data_processing = (proof_size / 10) as u64 * 100;

    base + verification + data_processing
}

fn estimate_ethereum_gas(proof_size: usize) -> u64 {
    // Calldata: 16 gas per non-zero byte
    let calldata = proof_size as u64 * 16;

    // Verification computation
    let computation = 250_000;

    // Storage (Merkle root storage)
    let storage = 20_000;

    calldata + computation + storage
}

fn estimate_cosmos_gas(proof_size: usize) -> u64 {
    // Cosmos SDK base cost
    let base = 10_000;

    // Verification logic
    let verification = 150_000;

    // Data processing
    let data = (proof_size / 10) as u64 * 50;

    base + verification + data
}

fn estimate_near_tgas(proof_size: usize) -> u64 {
    // Near's Tgas (10^12 Gas)
    // 1 Tgas = ~1ms execution time (approximately)

    let base = 5; // 5 Tgas
    let verification = 20; // 20 Tgas
    let data = (proof_size / 100) as u64;

    base + verification + data
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let mut count = 0;

    for ch in s.chars().rev() {
        if count > 0 && count % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
        count += 1;
    }

    result.chars().rev().collect()
}
