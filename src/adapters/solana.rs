//! Solana Adapter - CU-optimized proof serialization
//!
//! Witness data never stored on-chain. Only commitment and public inputs.
//! Transaction size limit: 1232 bytes.

use crate::adapters::SolanaChainAdapter;
use crate::core::errors::{Result, ZKMTDError};
use crate::core::types::Proof;

#[cfg(feature = "alloc")]
use alloc::{format, vec::Vec};

#[derive(Debug, Clone, Copy)]
pub struct SolanaOptimizationConfig {
    pub max_compute_units: u32,
    pub enable_compression: bool,
    pub max_tx_size: usize,
}

impl Default for SolanaOptimizationConfig {
    fn default() -> Self {
        Self {
            max_compute_units: 200_000,
            enable_compression: true,
            max_tx_size: 1000, // Set with margin below Solana limit
        }
    }
}

#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub struct OnChainProofData {
    pub proof_commitment: [u8; 32],
    pub epoch: u64,
    pub verified: bool,
    pub domain: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
pub struct SolanaAdapter {
    pub config: SolanaOptimizationConfig,
}

impl SolanaAdapter {
    pub fn new() -> Self {
        Self {
            config: SolanaOptimizationConfig::default(),
        }
    }

    pub fn with_config(config: SolanaOptimizationConfig) -> Self {
        Self { config }
    }

    #[cfg(feature = "alloc")]
    fn validate_no_sensitive_data(&self, proof: &Proof) -> Result<()> {
        // Suspicious if proof size is abnormally large
        if proof.data.len() > 10_000 {
            return Err(ZKMTDError::SerializationError {
                reason: format!(
                    "Proof size is abnormally large: {} bytes. Witness data may be included.",
                    proof.data.len()
                ),
            });
        }

        Ok(())
    }
}

impl Default for SolanaAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SolanaChainAdapter for SolanaAdapter {
    fn name(&self) -> &str {
        "Solana"
    }

    #[cfg(feature = "alloc")]
    fn serialize_proof(&self, proof: &Proof) -> Result<Vec<u8>> {
        // Security: Validate no sensitive data included
        self.validate_no_sensitive_data(proof)?;

        // Check Solana transaction size limit (1232 bytes)
        let estimated_size = 1 + 8 + 4 + proof.data.len();
        if estimated_size > self.config.max_tx_size {
            return Err(ZKMTDError::SerializationError {
                reason: format!(
                    "Proof exceeds Solana transaction size limit: {} > {}. \
                    Enable compression or split the proof.",
                    estimated_size, self.config.max_tx_size
                ),
            });
        }

        // Serialize to Solana on-chain format (excluding personal information)
        let mut serialized = Vec::with_capacity(estimated_size);

        // Protocol version (1 byte)
        serialized.push(proof.version);

        // Epoch - expiration time (8 bytes)
        serialized.extend_from_slice(&proof.epoch.to_le_bytes());

        // Proof data length (4 bytes)
        let data_len = proof.data.len() as u32;
        serialized.extend_from_slice(&data_len.to_le_bytes());

        // Proof commitment data (excluding Witness)
        serialized.extend_from_slice(&proof.data);

        Ok(serialized)
    }

    #[cfg(feature = "alloc")]
    fn deserialize_proof(&self, data: &[u8]) -> Result<Proof> {
        // Minimum size validation (version 1 + epoch 8 + length 4 = 13 bytes)
        if data.len() < 13 {
            return Err(ZKMTDError::SerializationError {
                reason: format!(
                    "On-chain data is too short: {} bytes. Minimum 13 bytes required.",
                    data.len()
                ),
            });
        }

        // Parse version
        let version = data[0];
        if version != 1 {
            return Err(ZKMTDError::SerializationError {
                reason: format!("Unsupported protocol version: {}", version),
            });
        }

        // Parse Epoch
        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&data[1..9]);
        let epoch = u64::from_le_bytes(epoch_bytes);

        // Parse proof data length
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&data[9..13]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        // Bounds check (Security: prevent buffer overflow)
        if length > 100_000 {
            return Err(ZKMTDError::SerializationError {
                reason: format!(
                    "Proof length is abnormally large: {} bytes. Maximum 100KB.",
                    length
                ),
            });
        }

        if data.len() < 13 + length {
            return Err(ZKMTDError::SerializationError {
                reason: format!(
                    "Data length mismatch: expected {} bytes, actual {} bytes",
                    13 + length,
                    data.len()
                ),
            });
        }

        // Extract proof data
        let proof_data = data[13..13 + length].to_vec();

        Ok(Proof {
            data: proof_data,
            epoch,
            version,
        })
    }

    fn estimate_compute_units(&self, proof_size: usize) -> u32 {
        const BASE_CU: u32 = 5_000; // Transaction base cost
        const PER_BYTE_CU: u32 = 10; // Byte processing cost
        const HASH_CU: u32 = 100; // Poseidon2 hash cost

        // Number of hash blocks (32-byte units)
        let hash_blocks = proof_size.div_ceil(32) as u32;

        let total_cu = BASE_CU + (proof_size as u32 * PER_BYTE_CU) + (hash_blocks * HASH_CU);

        // Add 10% safety margin
        (total_cu as f32 * 1.1) as u32
    }
}

#[cfg(feature = "alloc")]
impl SolanaAdapter {
    pub fn to_onchain_data(&self, proof: &Proof, domain: &[u8]) -> Result<OnChainProofData> {
        use crate::utils::hash::poseidon_hash;

        // Generate commitment by hashing entire proof (cannot recover original)
        let proof_commitment = poseidon_hash(&proof.data, domain);

        // Domain tag (max 16 bytes)
        let mut domain_tag = [0u8; 16];
        let copy_len = domain.len().min(16);
        domain_tag[..copy_len].copy_from_slice(&domain[..copy_len]);

        Ok(OnChainProofData {
            proof_commitment,
            epoch: proof.epoch,
            verified: false, // Pre-verification state
            domain: domain_tag,
        })
    }

    pub fn check_cu_limit(&self, proof_size: usize) -> Result<u32> {
        let estimated_cu = self.estimate_compute_units(proof_size);

        if estimated_cu > self.config.max_compute_units {
            return Err(ZKMTDError::ResourceLimitExceeded {
                reason: format!(
                    "Estimated CU usage exceeds limit: {} > {}",
                    estimated_cu, self.config.max_compute_units
                ),
            });
        }

        Ok(estimated_cu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_solana_adapter_serialize() {
        let adapter = SolanaAdapter::new();
        let proof = Proof::new(vec![1, 2, 3, 4, 5], 12345);

        let serialized = adapter.serialize_proof(&proof).unwrap();
        assert!(!serialized.is_empty());
        assert_eq!(serialized[0], 1); // version
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_solana_adapter_roundtrip() {
        let adapter = SolanaAdapter::new();
        let original = Proof::new(vec![1, 2, 3, 4, 5], 12345);

        let serialized = adapter.serialize_proof(&original).unwrap();
        let deserialized = adapter.deserialize_proof(&serialized).unwrap();

        assert_eq!(original.version, deserialized.version);
        assert_eq!(original.epoch, deserialized.epoch);
        assert_eq!(original.data, deserialized.data);
    }

    #[test]
    fn test_solana_adapter_name() {
        let adapter = SolanaAdapter::new();
        assert_eq!(adapter.name(), "Solana");
    }
}
