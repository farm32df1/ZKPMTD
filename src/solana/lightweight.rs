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

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[cfg(feature = "borsh")]
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

    #[test]
    fn test_lightweight_proof_new() {
        let proof = LightweightProof::new(
            [1u8; 32],
            [2u8; 32],
            100,
            1234567890,
            vec![1, 2, 3, 4],
            [3u8; 32],
        );

        assert_eq!(proof.commitment, [1u8; 32]);
        assert_eq!(proof.merkle_root, [2u8; 32]);
        assert_eq!(proof.epoch, 100);
        assert_eq!(proof.timestamp, 1234567890);
        assert_eq!(proof.public_values, vec![1, 2, 3, 4]);
        assert_eq!(proof.committed_values, [3u8; 32]);
    }

    #[test]
    fn test_lightweight_proof_from_commitment() {
        let commitment = [5u8; 32];
        let proof = LightweightProof::from_commitment(
            commitment,
            200,
            vec![10, 20, 30],
            [6u8; 32],
        );

        assert_eq!(proof.commitment, commitment);
        assert_eq!(proof.merkle_root, commitment); // Single proof: merkle_root == commitment
        assert_eq!(proof.epoch, 200);
        assert_eq!(proof.timestamp, 0); // Default timestamp
        assert_eq!(proof.public_values, vec![10, 20, 30]);
        assert_eq!(proof.committed_values, [6u8; 32]);
    }

    #[test]
    fn test_proof_commitment_from_data() {
        let data = b"some proof data";
        let seed = b"my_secret_seed";
        let commitment = ProofCommitment::from_data(data, 50, seed);

        assert_eq!(commitment.epoch, 50);
        assert_ne!(commitment.hash, [0u8; 32]);
        assert_ne!(commitment.seed_fingerprint, 0);
    }

    #[test]
    fn test_proof_commitment_deterministic() {
        let data = b"proof data";
        let seed = b"seed";

        let c1 = ProofCommitment::from_data(data, 100, seed);
        let c2 = ProofCommitment::from_data(data, 100, seed);

        assert_eq!(c1.hash, c2.hash);
        assert_eq!(c1.seed_fingerprint, c2.seed_fingerprint);
    }

    #[test]
    fn test_proof_commitment_different_data() {
        let seed = b"seed";
        let c1 = ProofCommitment::from_data(b"data1", 100, seed);
        let c2 = ProofCommitment::from_data(b"data2", 100, seed);

        assert_ne!(c1.hash, c2.hash);
    }

    #[test]
    fn test_proof_commitment_different_seed() {
        let data = b"proof data";
        let c1 = ProofCommitment::from_data(data, 100, b"seed1");
        let c2 = ProofCommitment::from_data(data, 100, b"seed2");

        assert_ne!(c1.seed_fingerprint, c2.seed_fingerprint);
    }

    #[test]
    fn test_batch_lightweight_proof_verify_inclusion() {
        use crate::utils::constants::DOMAIN_MERKLE;
        use crate::utils::hash::poseidon_hash;

        // Build a simple Merkle tree manually
        let leaf0 = [1u8; 32];
        let leaf1 = [2u8; 32];

        let combined = [leaf0.as_slice(), leaf1.as_slice()].concat();
        let root = poseidon_hash(&combined, DOMAIN_MERKLE);

        // Create batch proof for leaf0
        let batch_proof = BatchLightweightProof {
            merkle_root: root,
            proof_count: 2,
            epoch: 100,
            merkle_path: vec![leaf1],
            leaf_index: 0,
            leaf_commitment: leaf0,
        };

        assert!(batch_proof.verify_inclusion());
    }

    #[test]
    fn test_batch_lightweight_proof_verify_inclusion_right_leaf() {
        use crate::utils::constants::DOMAIN_MERKLE;
        use crate::utils::hash::poseidon_hash;

        let leaf0 = [1u8; 32];
        let leaf1 = [2u8; 32];

        let combined = [leaf0.as_slice(), leaf1.as_slice()].concat();
        let root = poseidon_hash(&combined, DOMAIN_MERKLE);

        // Create batch proof for leaf1 (index 1, odd)
        let batch_proof = BatchLightweightProof {
            merkle_root: root,
            proof_count: 2,
            epoch: 100,
            merkle_path: vec![leaf0],
            leaf_index: 1,
            leaf_commitment: leaf1,
        };

        assert!(batch_proof.verify_inclusion());
    }

    #[test]
    fn test_batch_lightweight_proof_verify_inclusion_invalid() {
        let batch_proof = BatchLightweightProof {
            merkle_root: [1u8; 32],
            proof_count: 2,
            epoch: 100,
            merkle_path: vec![[2u8; 32]],
            leaf_index: 0,
            leaf_commitment: [3u8; 32], // Wrong leaf
        };

        assert!(!batch_proof.verify_inclusion());
    }

    #[test]
    fn test_batch_lightweight_proof_estimated_cu() {
        let batch_proof = BatchLightweightProof {
            merkle_root: [1u8; 32],
            proof_count: 4,
            epoch: 100,
            merkle_path: vec![[2u8; 32], [3u8; 32]], // depth = 2
            leaf_index: 0,
            leaf_commitment: [4u8; 32],
        };

        let cu = batch_proof.estimated_cu();
        // 500 + (2 * 300) = 1100
        assert_eq!(cu, 1100);
    }

    #[test]
    fn test_batch_lightweight_proof_estimated_cu_deeper() {
        let batch_proof = BatchLightweightProof {
            merkle_root: [1u8; 32],
            proof_count: 16,
            epoch: 100,
            merkle_path: vec![[2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]], // depth = 4
            leaf_index: 0,
            leaf_commitment: [6u8; 32],
        };

        let cu = batch_proof.estimated_cu();
        // 500 + (4 * 300) = 1700
        assert_eq!(cu, 1700);
    }

    #[test]
    fn test_lightweight_proof_clone_debug() {
        let proof = LightweightProof::new(
            [1u8; 32],
            [2u8; 32],
            100,
            12345,
            vec![1, 2],
            [3u8; 32],
        );

        let cloned = proof.clone();
        assert_eq!(proof, cloned);

        let debug = format!("{:?}", proof);
        assert!(debug.contains("LightweightProof"));
    }

    #[test]
    fn test_proof_commitment_clone_debug() {
        let commitment = ProofCommitment::from_data(b"data", 100, b"seed");
        let cloned = commitment.clone();

        assert_eq!(commitment.hash, cloned.hash);
        assert_eq!(commitment.epoch, cloned.epoch);

        let debug = format!("{:?}", commitment);
        assert!(debug.contains("ProofCommitment"));
    }

    #[test]
    fn test_batch_lightweight_proof_clone_debug() {
        let batch = BatchLightweightProof {
            merkle_root: [1u8; 32],
            proof_count: 2,
            epoch: 100,
            merkle_path: vec![[2u8; 32]],
            leaf_index: 0,
            leaf_commitment: [3u8; 32],
        };

        let cloned = batch.clone();
        assert_eq!(batch.merkle_root, cloned.merkle_root);

        let debug = format!("{:?}", batch);
        assert!(debug.contains("BatchLightweightProof"));
    }
}
