//! Compression integrity tests
#![allow(deprecated)]

use zkmtd::prelude::{CompressedProof, CompressionAlgorithm};
use zkmtd::{Epoch, MTDProver, Prover, PublicInputs, StarkConfig, Verifier, Witness};

#[test]
fn test_compression_lossless_rle() {
    let seed = b"compression-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(30000);

    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();

    // Test various witness patterns
    let test_cases: [Vec<u64>; 4] = [
        vec![1, 2, 3, 4, 5, 6, 7, 8],                 // Sequential
        vec![1, 1, 1, 1, 2, 2, 2, 2],                 // Repeating
        vec![1, 2, 1, 2, 1, 2, 1, 2],                 // Alternating
        vec![100, 200, 300, 400, 500, 600, 700, 800], // Large values
    ];

    for (i, witness_data) in test_cases.iter().enumerate() {
        let witness = Witness::new(witness_data.clone());
        let public_inputs = PublicInputs::new(vec![i as u64]);

        // Generate original proof
        let original_proof = prover.prove(&witness, &public_inputs).unwrap();

        // RLE compression
        let compressed =
            CompressedProof::compress(&original_proof, CompressionAlgorithm::Rle).unwrap();

        // Decompress
        let decompressed_proof = compressed.decompress().unwrap();

        // Integrity verification: all fields must be equal
        assert_eq!(
            original_proof.data, decompressed_proof.data,
            "Test case {}: proof data mismatch",
            i
        );

        assert_eq!(
            original_proof.epoch, decompressed_proof.epoch,
            "Test case {}: epoch mismatch",
            i
        );

        assert_eq!(
            original_proof.version, decompressed_proof.version,
            "Test case {}: version mismatch",
            i
        );

        // Verify verifiability
        let verifier = prover.get_verifier();
        let is_valid = verifier
            .verify(&decompressed_proof, &public_inputs)
            .unwrap();
        assert!(
            is_valid,
            "Test case {}: verification failed after compression",
            i
        );
    }
}

#[test]
fn test_compression_tamper_detection() {
    let seed = b"tamper-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(31000);

    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    let proof = prover.prove(&witness, &public_inputs).unwrap();
    let mut compressed = CompressedProof::compress(&proof, CompressionAlgorithm::None).unwrap();

    // Tamper with data
    if !compressed.compressed_data.is_empty() {
        compressed.compressed_data[0] ^= 0xFF;
    }

    // Should error on decompression
    let result = compressed.decompress();
    assert!(result.is_err(), "Tampered data was not detected!");
}

#[test]
fn test_compression_checksum_mismatch() {
    let seed = b"checksum-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(32000);

    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    let proof = prover.prove(&witness, &public_inputs).unwrap();
    let mut compressed = CompressedProof::compress(&proof, CompressionAlgorithm::None).unwrap();

    // Tamper with checksum
    compressed.checksum[0] ^= 0xFF;

    // Should error with checksum mismatch on decompression
    let result = compressed.decompress();
    assert!(result.is_err(), "Checksum tampering was not detected!");
}

#[test]
fn test_compression_size_mismatch() {
    let seed = b"size-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(33000);

    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    let proof = prover.prove(&witness, &public_inputs).unwrap();
    let mut compressed = CompressedProof::compress(&proof, CompressionAlgorithm::None).unwrap();

    // Tamper with original size
    compressed.original_size = 99999;

    // Should error with size mismatch on decompression
    let result = compressed.decompress();
    assert!(result.is_err(), "Size mismatch was not detected!");
}

#[test]
fn test_compression_algorithm_consistency() {
    let seed = b"algo-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(34000);

    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);

    let proof = prover.prove(&witness, &public_inputs).unwrap();

    // Test all algorithms
    let algorithms = vec![CompressionAlgorithm::None, CompressionAlgorithm::Rle];

    for algo in algorithms {
        let compressed = CompressedProof::compress(&proof, algo).unwrap();
        let decompressed = compressed.decompress().unwrap();

        assert_eq!(
            proof.data, decompressed.data,
            "Data mismatch for algorithm {:?}",
            algo
        );

        // Verify verifiability
        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&decompressed, &public_inputs).unwrap();
        assert!(is_valid, "Verification failed for algorithm {:?}", algo);
    }
}

#[test]
fn test_compression_empty_proof() {
    use zkmtd::Proof;

    let empty_proof = Proof::default();

    let compressed = CompressedProof::compress(&empty_proof, CompressionAlgorithm::None).unwrap();

    let decompressed = compressed.decompress().unwrap();

    assert_eq!(empty_proof.data, decompressed.data);
}

#[test]
fn test_compression_large_proof() {
    let seed = b"large-test";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(35000);

    let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();

    // Large witness (1024 elements)
    let large_witness: Vec<u64> = (0..1024).collect();
    let witness = Witness::new(large_witness);
    let public_inputs = PublicInputs::new(vec![42]);

    let proof = prover.prove(&witness, &public_inputs).unwrap();

    println!("Original proof size: {} bytes", proof.size());

    // Compress
    let compressed = CompressedProof::compress(&proof, CompressionAlgorithm::Rle).unwrap();

    println!(
        "Compressed size: {} bytes",
        compressed.compressed_data.len()
    );
    println!(
        "Compression ratio: {:.1}%",
        compressed.compression_ratio() * 100.0
    );

    // Integrity verification
    let decompressed = compressed.decompress().unwrap();
    assert_eq!(proof.data, decompressed.data);

    // Verifiability
    let verifier = prover.get_verifier();
    assert!(verifier.verify(&decompressed, &public_inputs).unwrap());
}

#[test]
fn test_compression_ratio_calculation() {
    use zkmtd::Proof;

    let proof = Proof::new(vec![1; 100], 100);
    let compressed = CompressedProof::compress(&proof, CompressionAlgorithm::Rle).unwrap();

    let ratio = compressed.compression_ratio();
    let saved = compressed.bytes_saved();

    println!("Compression ratio: {:.2}", ratio);
    println!("Saved: {} bytes", saved);

    // RLE compresses repeating data well
    assert!(ratio < 1.0, "Compression ratio should be less than 100%");
}
