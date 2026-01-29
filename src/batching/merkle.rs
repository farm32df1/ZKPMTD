//! MerkleTree - binary hash tree for batch proof integrity

use crate::core::errors::{Result, ZKMTDError};
use crate::core::types::HashDigest;
use crate::utils::constants::DOMAIN_MERKLE;
use crate::utils::hash::{combine_hashes, poseidon_hash};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<HashDigest>,
    levels: Vec<Vec<HashDigest>>,
    root: HashDigest,
}

#[cfg(feature = "alloc")]
impl MerkleTree {
    pub fn new(leaves: Vec<HashDigest>) -> Result<Self> {
        if leaves.is_empty() {
            return Err(ZKMTDError::MerkleError {
                reason: "Leaves are empty".into(),
            });
        }

        let mut levels = Vec::new();
        levels.push(leaves.clone());

        // Build tree levels
        let mut current_level = leaves.clone();
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            let mut i = 0;
            while i < current_level.len() {
                if i + 1 < current_level.len() {
                    // Combine two nodes
                    let combined =
                        combine_hashes(&current_level[i], &current_level[i + 1], DOMAIN_MERKLE);
                    next_level.push(combined);
                    i += 2;
                } else {
                    // For odd count, combine last node with itself
                    let combined =
                        combine_hashes(&current_level[i], &current_level[i], DOMAIN_MERKLE);
                    next_level.push(combined);
                    i += 1;
                }
            }

            levels.push(next_level.clone());
            current_level = next_level;
        }

        let root = *current_level.first().ok_or(ZKMTDError::MerkleError {
            reason: "Root computation failed".into(),
        })?;

        Ok(Self {
            leaves,
            levels,
            root,
        })
    }

    pub fn root(&self) -> &HashDigest {
        &self.root
    }

    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    #[allow(clippy::manual_is_multiple_of)]
    pub fn get_proof(&self, index: usize) -> Result<MerklePath> {
        if index >= self.leaves.len() {
            return Err(ZKMTDError::MerkleError {
                reason: alloc::format!("Invalid index: {} >= {}", index, self.leaves.len()),
            });
        }

        let mut siblings = Vec::new();
        let mut current_index = index;

        // Collect sibling nodes at each level
        for level_idx in 0..(self.levels.len() - 1) {
            let level = &self.levels[level_idx];
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = if sibling_index < level.len() {
                level[sibling_index]
            } else {
                // For odd count, use self
                level[current_index]
            };

            siblings.push(sibling);
            current_index /= 2;
        }

        Ok(MerklePath {
            leaf_index: index,
            siblings,
            root: self.root,
        })
    }

    pub fn leaves(&self) -> &[HashDigest] {
        &self.leaves
    }
}

#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub struct MerklePath {
    pub leaf_index: usize,
    pub siblings: Vec<HashDigest>,
    pub root: HashDigest,
}

#[cfg(feature = "alloc")]
impl MerklePath {
    /// Compute the root hash from this path and the given leaf.
    /// Returns the computed root without comparing to any expected value.
    #[allow(clippy::manual_is_multiple_of)]
    pub fn compute_root(&self, leaf: &HashDigest) -> HashDigest {
        let mut current_hash = *leaf;
        let mut current_index = self.leaf_index;

        for sibling in &self.siblings {
            current_hash = if current_index % 2 == 0 {
                // Left child
                combine_hashes(&current_hash, sibling, DOMAIN_MERKLE)
            } else {
                // Right child
                combine_hashes(sibling, &current_hash, DOMAIN_MERKLE)
            };
            current_index /= 2;
        }

        current_hash
    }

    /// Verify this path against an externally-provided trusted root.
    /// This is the RECOMMENDED verification method for security-critical code.
    ///
    /// The `expected_root` should come from a trusted source (e.g., on-chain state,
    /// signed batch header, etc.), NOT from the proof itself.
    #[allow(clippy::manual_is_multiple_of)]
    pub fn verify_against(&self, leaf: &HashDigest, expected_root: &HashDigest) -> bool {
        use crate::utils::hash::constant_time_eq_fixed;
        let computed_root = self.compute_root(leaf);
        constant_time_eq_fixed(&computed_root, expected_root)
    }

    /// Verify this path against the internally stored root.
    ///
    /// WARNING: Only use this when the MerklePath was constructed internally
    /// (e.g., from MerkleTree::get_proof()). For externally-provided paths,
    /// use `verify_against()` with a trusted root instead.
    #[allow(clippy::manual_is_multiple_of)]
    pub fn verify(&self, leaf: &HashDigest) -> bool {
        self.verify_against(leaf, &self.root)
    }

    pub fn len(&self) -> usize {
        self.siblings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }
}

pub fn hash_leaf(data: &[u8]) -> HashDigest {
    poseidon_hash(data, DOMAIN_MERKLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_merkle_tree_creation() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves.clone()).unwrap();
        assert_eq!(tree.num_leaves(), 4);
        assert_ne!(tree.root(), &[0u8; 32]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_merkle_tree_empty_leaves() {
        let leaves: Vec<HashDigest> = vec![];
        let result = MerkleTree::new(leaves);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = vec![[1u8; 32]];
        let tree = MerkleTree::new(leaves).unwrap();
        assert_eq!(tree.num_leaves(), 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_merkle_proof_generation() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves.clone()).unwrap();

        for i in 0..4 {
            let proof = tree.get_proof(i).unwrap();
            assert_eq!(proof.leaf_index, i);
            assert!(!proof.siblings.is_empty());
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_merkle_proof_verification() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves.clone()).unwrap();

        // Verify paths for all leaves
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.get_proof(i).unwrap();
            assert!(
                proof.verify(leaf),
                "Path verification failed for index {}",
                i
            );
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_merkle_proof_invalid() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.get_proof(0).unwrap();

        // Verify with wrong leaf
        let wrong_leaf = [99u8; 32];
        assert!(!proof.verify(&wrong_leaf), "Wrong leaf was verified");
    }

    #[test]
    fn test_hash_leaf() {
        let data = b"test data";
        let hash = hash_leaf(data);
        assert_ne!(hash, [0u8; 32]);

        // Same data produces same hash
        let hash2 = hash_leaf(data);
        assert_eq!(hash, hash2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_merkle_tree_odd_leaves() {
        // Odd number of leaves
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let tree = MerkleTree::new(leaves.clone()).unwrap();
        assert_eq!(tree.num_leaves(), 3);

        // Verify all leaves
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.get_proof(i).unwrap();
            assert!(proof.verify(leaf));
        }
    }
}
