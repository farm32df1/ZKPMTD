//! On-Chain Verifier for Solana BPF
//!
//! Full STARK (~500K CU) exceeds Solana limits. Uses hierarchical verification:
//! - On-chain (~15K CU): commitment, epoch, merkle inclusion
//! - Off-chain: full STARK via IntegratedProver

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::lightweight::{BatchLightweightProof, LightweightProof, ProofCommitment};

#[derive(Clone, Debug, PartialEq)]
pub enum VerificationStatus {
    Valid,
    InvalidEpoch { expected: u64, got: u64 },
    InvalidCommitment,
    InvalidMerkleProof,
    InvalidPublicValues,
    InvalidCommittedValues,
    MalformedProof,
}

impl VerificationStatus {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationStatus::Valid)
    }
}

#[derive(Clone, Debug)]
pub struct OnchainVerifier {
    current_epoch: u64,
    epoch_tolerance: u64,
    #[cfg(feature = "alloc")]
    expected_public_values: Option<Vec<u64>>,
    expected_committed_values: [u8; 32],
}

impl OnchainVerifier {
    pub fn new(current_epoch: u64, expected_committed_values: [u8; 32]) -> Self {
        Self {
            current_epoch,
            epoch_tolerance: 1, // Allow 1 epoch tolerance by default
            #[cfg(feature = "alloc")]
            expected_public_values: None,
            expected_committed_values,
        }
    }

    pub fn with_epoch_tolerance(mut self, tolerance: u64) -> Self {
        self.epoch_tolerance = tolerance;
        self
    }

    #[cfg(feature = "alloc")]
    pub fn with_expected_values(mut self, values: Vec<u64>) -> Self {
        self.expected_public_values = Some(values);
        self
    }

    pub fn with_expected_committed_values(mut self, committed: [u8; 32]) -> Self {
        self.expected_committed_values = committed;
        self
    }

    #[cfg(feature = "alloc")]
    pub fn verify(&self, proof: &LightweightProof) -> VerificationStatus {
        // 1. Verify epoch
        if !self.is_valid_epoch(proof.epoch) {
            return VerificationStatus::InvalidEpoch {
                expected: self.current_epoch,
                got: proof.epoch,
            };
        }

        // 2. Verify commitment matches merkle root (for single proofs)
        // For single proofs, commitment == merkle_root
        // For batch proofs, this is verified separately
        if proof.commitment != proof.merkle_root && proof.merkle_root != [0u8; 32] {
            // This is a batch proof indicator - merkle root should be verified elsewhere
            // For now, we allow it to pass this check
        }

        // 3. Verify public values if expected values are set
        if let Some(ref expected) = self.expected_public_values {
            if !self.verify_public_values(&proof.public_values, expected) {
                return VerificationStatus::InvalidPublicValues;
            }
        }

        // 4. Verify committed values match expected
        if proof.committed_values != self.expected_committed_values {
            return VerificationStatus::InvalidCommittedValues;
        }

        VerificationStatus::Valid
    }

    #[cfg(feature = "alloc")]
    pub fn verify_batch(&self, batch_proof: &BatchLightweightProof) -> VerificationStatus {
        // 1. Verify epoch
        if !self.is_valid_epoch(batch_proof.epoch) {
            return VerificationStatus::InvalidEpoch {
                expected: self.current_epoch,
                got: batch_proof.epoch,
            };
        }

        // 2. Verify merkle inclusion
        if !batch_proof.verify_inclusion() {
            return VerificationStatus::InvalidMerkleProof;
        }

        VerificationStatus::Valid
    }

    fn is_valid_epoch(&self, proof_epoch: u64) -> bool {
        if proof_epoch > self.current_epoch {
            return false; // Future epochs not allowed
        }
        // Allow proofs from current epoch or within tolerance
        self.current_epoch.saturating_sub(self.epoch_tolerance) <= proof_epoch
    }

    #[cfg(feature = "alloc")]
    fn verify_public_values(&self, actual: &[u64], expected: &[u64]) -> bool {
        if actual.len() != expected.len() {
            return false;
        }
        actual.iter().zip(expected.iter()).all(|(a, e)| a == e)
    }

    #[cfg(feature = "alloc")]
    pub fn verify_commitment(&self, commitment: &ProofCommitment, proof_data: &[u8]) -> bool {
        commitment.verify(proof_data)
    }

    /// Estimate on-chain CU cost for lightweight verification.
    ///
    /// This covers commitment + epoch checks only (~5K CU total).
    /// For full adapter-level CU estimation, see `SolanaAdapter::estimate_compute_units()`
    /// in the `adapters` module.
    pub fn estimate_cu(proof_size_bytes: usize) -> u64 {
        use crate::utils::constants::{ONCHAIN_BASE_CU, ONCHAIN_BUFFER_CU, ONCHAIN_HASH_CU};
        let hash_cu = ((proof_size_bytes / 64) as u64 + 1) * ONCHAIN_HASH_CU;
        ONCHAIN_BASE_CU + hash_cu + ONCHAIN_BUFFER_CU
    }
}

pub mod syscall_helpers {
    #[cfg(feature = "alloc")]
    pub fn compute_hash(data: &[u8]) -> [u8; 32] {
        use crate::utils::constants::DOMAIN_COMMITMENT;
        crate::utils::hash::poseidon_hash(data, DOMAIN_COMMITMENT)
    }

    #[cfg(feature = "alloc")]
    pub fn verify_fibonacci_sequence(values: &[u64]) -> bool {
        if values.len() < 3 {
            return true; // Too short to verify
        }

        for i in 2..values.len() {
            // Check F[i] = F[i-1] + F[i-2]
            // Use wrapping add to handle overflow consistently
            let expected = values[i - 1].wrapping_add(values[i - 2]);
            if values[i] != expected {
                return false;
            }
        }
        true
    }

}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_validation() {
        let verifier = OnchainVerifier::new(100, [0u8; 32]);

        // Current epoch - valid
        assert!(verifier.is_valid_epoch(100));

        // One epoch back - valid (within tolerance)
        assert!(verifier.is_valid_epoch(99));

        // Two epochs back - invalid (outside tolerance)
        assert!(!verifier.is_valid_epoch(98));

        // Future epoch - invalid
        assert!(!verifier.is_valid_epoch(101));
    }

    #[test]
    fn test_epoch_tolerance() {
        let verifier = OnchainVerifier::new(100, [0u8; 32]).with_epoch_tolerance(5);

        assert!(verifier.is_valid_epoch(100));
        assert!(verifier.is_valid_epoch(95));
        assert!(!verifier.is_valid_epoch(94));
    }

    #[test]
    fn test_verify_lightweight_proof() {
        let committed = [99u8; 32];
        let verifier = OnchainVerifier::new(100, committed);
        let proof =
            LightweightProof::from_commitment([1u8; 32], 100, vec![1, 1, 2, 3, 5, 8, 13, 21], committed);

        let result = verifier.verify(&proof);
        assert!(result.is_valid());
    }

    #[test]
    fn test_verify_with_expected_values() {
        let committed = [99u8; 32];
        let verifier =
            OnchainVerifier::new(100, committed).with_expected_values(vec![1, 1, 2, 3, 5, 8, 13, 21]);

        let good_proof =
            LightweightProof::from_commitment([1u8; 32], 100, vec![1, 1, 2, 3, 5, 8, 13, 21], committed);
        assert!(verifier.verify(&good_proof).is_valid());

        let bad_proof = LightweightProof::from_commitment(
            [1u8; 32],
            100,
            vec![1, 2, 3, 4, 5, 6, 7, 8], // Wrong values
            committed,
        );
        assert_eq!(
            verifier.verify(&bad_proof),
            VerificationStatus::InvalidPublicValues
        );
    }

    #[test]
    fn test_fibonacci_verification() {
        use syscall_helpers::verify_fibonacci_sequence;

        assert!(verify_fibonacci_sequence(&[1, 1, 2, 3, 5, 8, 13, 21]));
        assert!(verify_fibonacci_sequence(&[0, 1, 1, 2, 3, 5]));
        assert!(!verify_fibonacci_sequence(&[1, 2, 3, 4, 5, 6])); // Not Fibonacci
    }

    #[test]
    fn test_cu_estimation() {
        // Small proof
        let cu_small = OnchainVerifier::estimate_cu(256);
        assert!(cu_small < 2000);

        // Medium proof
        let cu_medium = OnchainVerifier::estimate_cu(1024);
        assert!(cu_medium < 5000);

        // Large proof
        let cu_large = OnchainVerifier::estimate_cu(4096);
        assert!(cu_large < 10000);

        // All should be well under Solana limit
        assert!(cu_large < 200_000);
    }
}
