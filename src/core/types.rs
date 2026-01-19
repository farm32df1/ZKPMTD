//! Core types: Proof, Witness (zeroize on drop), PublicInputs, ProofBatch

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    #[cfg(feature = "alloc")]
    pub data: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub data: heapless::Vec<u8, 65536>,
    pub epoch: u64,
    pub version: u8,
}

impl Default for Proof {
    fn default() -> Self {
        Self {
            #[cfg(feature = "alloc")]
            data: Vec::new(),
            #[cfg(not(feature = "alloc"))]
            data: heapless::Vec::new(),
            epoch: 0,
            version: 1,
        }
    }
}

impl Proof {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u8>, epoch: u64) -> Self {
        Self { data, epoch, version: 1 }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Secret witness data - auto-cleared on drop via zeroize
#[derive(Clone, Default)]
pub struct Witness {
    #[cfg(feature = "alloc")]
    pub data: Vec<u64>,
    #[cfg(not(feature = "alloc"))]
    pub data: heapless::Vec<u64, 1024>,
}

impl core::fmt::Debug for Witness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Witness")
            .field("len", &self.data.len())
            .field("data", &"<redacted>")
            .finish()
    }
}

impl Zeroize for Witness {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for Witness {}

impl Witness {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u64>) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[cfg(feature = "alloc")]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        use crate::utils::hash::bytes_to_fields;
        Self { data: bytes_to_fields(bytes) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicInputs {
    #[cfg(feature = "alloc")]
    pub data: Vec<u64>,
    #[cfg(not(feature = "alloc"))]
    pub data: heapless::Vec<u64, 256>,
}

impl PublicInputs {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u64>) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProofBatch {
    pub proofs: Vec<Proof>,
    pub merkle_root: [u8; 32],
    pub epoch: u64,
}

#[cfg(feature = "alloc")]
impl ProofBatch {
    pub fn new(proofs: Vec<Proof>, merkle_root: [u8; 32], epoch: u64) -> Self {
        Self { proofs, merkle_root, epoch }
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }
}

pub type FieldElement = u64;
pub type HashDigest = [u8; 32];

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_proof_creation() {
        let proof = Proof::default();
        assert!(proof.is_empty());
        assert_eq!(proof.epoch, 0);
        assert_eq!(proof.version, 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_proof_with_data() {
        let data = vec![1, 2, 3, 4, 5];
        let proof = Proof::new(data.clone(), 12345);
        assert_eq!(proof.size(), 5);
        assert!(!proof.is_empty());
        assert_eq!(proof.epoch, 12345);
    }

    #[test]
    fn test_witness_zeroize() {
        #[cfg(feature = "alloc")]
        {
            let mut witness = Witness::new(vec![1, 2, 3, 4, 5]);
            assert_eq!(witness.len(), 5);

            witness.zeroize();

            // After zeroize, all values should be 0
            for &val in &witness.data {
                assert_eq!(val, 0);
            }
        }
    }

    #[test]
    fn test_public_inputs() {
        let inputs = PublicInputs::default();
        assert!(inputs.is_empty());
        assert_eq!(inputs.len(), 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_proof_batch() {
        let proof1 = Proof::new(vec![1, 2, 3], 100);
        let proof2 = Proof::new(vec![4, 5, 6], 100);
        let proofs = vec![proof1, proof2];
        let merkle_root = [0u8; 32];

        let batch = ProofBatch::new(proofs, merkle_root, 100);
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
    }
}
