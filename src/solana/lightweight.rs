//! Lightweight Proof Structures for Solana
//!
//! Borsh-serializable proofs optimized for Solana CU constraints.
//! On-chain: commitment + epoch + merkle (~15K CU)
//! Off-chain: full STARK via IntegratedProver

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct LightweightProof {
    pub commitment: [u8; 32],
    pub merkle_root: [u8; 32],
    pub epoch: u64,
    pub timestamp: u64,
    #[cfg(feature = "alloc")]
    pub public_values: Vec<u64>,
    #[cfg(not(feature = "alloc"))]
    pub public_values: [u64; 4],
    /// Committed public values hash (always present — privacy-by-default).
    /// On-chain only sees this hash, not the actual values.
    pub committed_values: [u8; 32],
}

impl LightweightProof {
    #[cfg(feature = "alloc")]
    pub fn new(
        commitment: [u8; 32],
        merkle_root: [u8; 32],
        epoch: u64,
        timestamp: u64,
        public_values: Vec<u64>,
        committed_values: [u8; 32],
    ) -> Self {
        Self {
            commitment,
            merkle_root,
            epoch,
            timestamp,
            public_values,
            committed_values,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn from_commitment(
        commitment: [u8; 32],
        epoch: u64,
        public_values: Vec<u64>,
        committed_values: [u8; 32],
    ) -> Self {
        Self {
            commitment,
            merkle_root: commitment, // Single proof: merkle root = commitment
            epoch,
            timestamp: 0, // Will be set by on-chain program
            public_values,
            committed_values,
        }
    }

    pub const fn estimated_cu() -> u64 {
        5_000 // Based on actual measurement (4,232 CU) with safety buffer
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct ProofCommitment {
    pub hash: [u8; 32],
    pub epoch: u64,
    pub seed_fingerprint: u64,
}

impl ProofCommitment {
    #[cfg(feature = "alloc")]
    pub fn from_data(proof_data: &[u8], epoch: u64, seed: &[u8]) -> Self {
        use crate::utils::constants::DOMAIN_COMMITMENT;
        use crate::utils::hash::poseidon_hash;

        let hash = poseidon_hash(proof_data, DOMAIN_COMMITMENT);
        let seed_hash = poseidon_hash(seed, crate::utils::constants::DOMAIN_SEED_FINGERPRINT);
        let seed_fingerprint = u64::from_le_bytes(seed_hash[0..8].try_into().unwrap_or([0u8; 8]));

        Self {
            hash,
            epoch,
            seed_fingerprint,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn verify(&self, proof_data: &[u8]) -> bool {
        use crate::utils::constants::DOMAIN_COMMITMENT;
        use crate::utils::hash::poseidon_hash;

        let computed_hash = poseidon_hash(proof_data, DOMAIN_COMMITMENT);
        crate::utils::hash::constant_time_eq_fixed(&self.hash, &computed_hash)
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct BatchLightweightProof {
    pub merkle_root: [u8; 32],
    pub proof_count: u32,
    pub epoch: u64,
    #[cfg(feature = "alloc")]
    pub merkle_path: Vec<[u8; 32]>,
    pub leaf_index: u32,
    pub leaf_commitment: [u8; 32],
}

impl BatchLightweightProof {
    #[cfg(feature = "alloc")]
    #[allow(clippy::manual_is_multiple_of)]
    pub fn verify_inclusion(&self) -> bool {
        use crate::utils::constants::DOMAIN_MERKLE;
        use crate::utils::hash::poseidon_hash;

        let mut current = self.leaf_commitment;
        let mut index = self.leaf_index;

        for sibling in &self.merkle_path {
            let combined = if index % 2 == 0 {
                [current.as_slice(), sibling.as_slice()].concat()
            } else {
                [sibling.as_slice(), current.as_slice()].concat()
            };
            current = poseidon_hash(&combined, DOMAIN_MERKLE);
            index /= 2;
        }

        current == self.merkle_root
    }

    pub fn estimated_cu(&self) -> u64 {
        #[cfg(feature = "alloc")]
        let depth = self.merkle_path.len() as u64;
        #[cfg(not(feature = "alloc"))]
        let depth = 10u64; // Assume max depth

        500 + (depth * 300)
    }
}

#[cfg(all(test, feature = "alloc", feature = "borsh"))]
mod tests {
    use super::*;

    #[test]
    fn test_lightweight_proof_serialization() {
        let proof = LightweightProof::new(
            [1u8; 32],
            [2u8; 32],
            100,
            1234567890,
            vec![1, 1, 2, 3, 5, 8, 13, 21],
            [3u8; 32],
        );

        let serialized = borsh::to_vec(&proof).unwrap();
        let deserialized: LightweightProof = borsh::from_slice(&serialized).unwrap();

        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_proof_commitment_verify() {
        let data = b"test proof data";
        let commitment = ProofCommitment::from_data(data, 100, b"seed");

        assert!(commitment.verify(data));
        assert!(!commitment.verify(b"wrong data"));
    }

    #[test]
    fn test_estimated_cu() {
        assert!(LightweightProof::estimated_cu() < 200_000);
    }
}
