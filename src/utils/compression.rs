//! Compression - lossless proof compression with integrity verification

use crate::core::errors::{Result, ZKMTDError};
use crate::core::types::{HashDigest, Proof};
use crate::utils::hash::poseidon_hash;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CompressionAlgorithm {
    None,
    Rle,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompressedProof {
    pub original_size: usize,
    #[cfg(feature = "alloc")]
    pub compressed_data: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub compressed_data: heapless::Vec<u8, 2048>,
    pub algorithm: CompressionAlgorithm,
    pub checksum: HashDigest,
    pub epoch: u64,
    pub version: u8,
}

impl CompressedProof {
    #[cfg(feature = "alloc")]
    pub fn compress(proof: &Proof, algorithm: CompressionAlgorithm) -> Result<Self> {
        let original_data = &proof.data;
        let original_size = original_data.len();

        // 1. Calculate checksum (before compression)
        let checksum = poseidon_hash(original_data, b"COMPRESSION_CHECKSUM");

        // 2. Perform compression
        let compressed_data = match algorithm {
            CompressionAlgorithm::None => original_data.clone(),
            CompressionAlgorithm::Rle => compress_rle(original_data)?,
        };

        // 3. Integrity verification (decompress immediately after compression to verify)
        let decompressed = match algorithm {
            CompressionAlgorithm::None => compressed_data.clone(),
            CompressionAlgorithm::Rle => decompress_rle(&compressed_data)?,
        };

        // Verify identical to original
        if decompressed != *original_data {
            return Err(ZKMTDError::SerializationError {
                reason: "Compression integrity verification failed: data mismatch after compression/decompression".into(),
            });
        }

        Ok(Self {
            original_size,
            compressed_data,
            algorithm,
            checksum,
            epoch: proof.epoch,
            version: proof.version,
        })
    }

    #[cfg(feature = "alloc")]
    pub fn decompress(&self) -> Result<Proof> {
        // 1. Perform decompression
        let decompressed_data = match self.algorithm {
            CompressionAlgorithm::None => self.compressed_data.clone(),
            CompressionAlgorithm::Rle => decompress_rle(&self.compressed_data)?,
        };

        // 2. Size verification
        if decompressed_data.len() != self.original_size {
            return Err(ZKMTDError::SerializationError {
                reason: alloc::format!(
                    "Size mismatch: expected {} != actual {}",
                    self.original_size,
                    decompressed_data.len()
                ),
            });
        }

        // 3. Checksum verification
        let checksum = poseidon_hash(&decompressed_data, b"COMPRESSION_CHECKSUM");
        if checksum != self.checksum {
            return Err(ZKMTDError::SerializationError {
                reason: "Checksum mismatch: data is corrupted".into(),
            });
        }

        // 4. Reconstruct proof
        Ok(Proof {
            data: decompressed_data,
            epoch: self.epoch,
            version: self.version,
        })
    }

    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        self.compressed_data.len() as f64 / self.original_size as f64
    }

    pub fn bytes_saved(&self) -> usize {
        self.original_size
            .saturating_sub(self.compressed_data.len())
    }
}

#[cfg(feature = "alloc")]
fn compress_rle(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut compressed = Vec::new();
    let mut current = data[0];
    let mut count: u8 = 1;

    for &byte in &data[1..] {
        if byte == current && count < 255 {
            count += 1;
        } else {
            compressed.push(current);
            compressed.push(count);
            current = byte;
            count = 1;
        }
    }

    // Add last run
    compressed.push(current);
    compressed.push(count);

    Ok(compressed)
}

#[cfg(feature = "alloc")]
#[allow(clippy::manual_is_multiple_of)]
fn decompress_rle(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    if data.len() % 2 != 0 {
        return Err(ZKMTDError::SerializationError {
            reason: "Invalid RLE data: length is odd".into(),
        });
    }

    let mut decompressed = Vec::new();

    for chunk in data.chunks_exact(2) {
        let value = chunk[0];
        let count = chunk[1];

        for _ in 0..count {
            decompressed.push(value);
        }
    }

    Ok(decompressed)
}

pub fn select_compression_algorithm(data_size: usize, _target_chain: &str) -> CompressionAlgorithm {
    if data_size < 100 {
        CompressionAlgorithm::None
    } else {
        CompressionAlgorithm::Rle
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_rle_compression() {
        let data = vec![1, 1, 1, 2, 2, 3, 4, 4, 4, 4];
        let compressed = compress_rle(&data).unwrap();
        let decompressed = decompress_rle(&compressed).unwrap();

        assert_eq!(data, decompressed, "RLE compression/decompression failed");
        assert!(compressed.len() < data.len(), "No compression efficiency");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_compressed_proof_integrity() {
        let original_proof = Proof::new(vec![1, 2, 3, 4, 5, 6, 7, 8], 100);

        // Compress
        let compressed =
            CompressedProof::compress(&original_proof, CompressionAlgorithm::Rle).unwrap();

        // Decompress
        let decompressed = compressed.decompress().unwrap();

        // Verify
        assert_eq!(original_proof.data, decompressed.data);
        assert_eq!(original_proof.epoch, decompressed.epoch);
        assert_eq!(original_proof.version, decompressed.version);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_compression_ratio() {
        let data = vec![1; 100]; // Repetitive data (compresses well)
        let proof = Proof::new(data, 100);

        let compressed = CompressedProof::compress(&proof, CompressionAlgorithm::Rle).unwrap();

        // Verify compression statistics
        assert!(compressed.original_size > 0);
        assert!(!compressed.compressed_data.is_empty());
        assert!(
            compressed.compression_ratio() < 0.5,
            "Compression ratio should be less than 50%"
        );
        assert!(compressed.bytes_saved() > 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_tampered_data_detection() {
        let proof = Proof::new(vec![1, 2, 3, 4, 5], 100);
        let mut compressed = CompressedProof::compress(&proof, CompressionAlgorithm::None).unwrap();

        // Tamper data
        compressed.compressed_data[0] = 99;

        // Decompression should fail with checksum error
        let result = compressed.decompress();
        assert!(result.is_err(), "Tampered data was not detected");
    }

    #[test]
    fn test_algorithm_selection() {
        assert_eq!(
            select_compression_algorithm(50, "solana"),
            CompressionAlgorithm::None
        );

        assert_eq!(
            select_compression_algorithm(1000, "ethereum"),
            CompressionAlgorithm::Rle
        );

        assert_eq!(
            select_compression_algorithm(1500, "solana"),
            CompressionAlgorithm::Rle
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_empty_data() {
        let data: Vec<u8> = vec![];
        let compressed = compress_rle(&data).unwrap();
        let decompressed = decompress_rle(&compressed).unwrap();

        assert_eq!(data, decompressed);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_single_byte() {
        let data = vec![42];
        let compressed = compress_rle(&data).unwrap();
        let decompressed = decompress_rle(&compressed).unwrap();

        assert_eq!(data, decompressed);
    }
}
