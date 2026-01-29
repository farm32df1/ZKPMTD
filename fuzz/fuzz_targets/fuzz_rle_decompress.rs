//! Fuzz target for RLE decompression
//! Tests: CompressedProof::decompress() with arbitrary compressed data
//! Goal: Ensure DoS protection, no memory exhaustion, bounds checking

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zkmtd::utils::compression::{CompressedProof, CompressionAlgorithm};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    original_size: usize,
    compressed_data: Vec<u8>,
    algorithm: u8, // 0 = None, 1 = Rle
    checksum: [u8; 32],
    epoch: u64,
    version: u8,
}

fuzz_target!(|input: FuzzInput| {
    // Limit input size to prevent OOM during fuzzing
    if input.compressed_data.len() > 10_000 {
        return;
    }
    if input.original_size > 100_000 {
        return;
    }

    let algorithm = match input.algorithm % 2 {
        0 => CompressionAlgorithm::None,
        _ => CompressionAlgorithm::Rle,
    };

    let compressed = CompressedProof {
        original_size: input.original_size,
        compressed_data: input.compressed_data,
        algorithm,
        checksum: input.checksum,
        epoch: input.epoch,
        version: input.version,
    };

    // Should never panic, only return Ok or Err
    let _ = compressed.decompress();
});
