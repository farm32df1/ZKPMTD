//! BatchVerifier - verifies proof batches with Merkle root and epoch checks

use crate::batching::merkle::{hash_leaf, MerkleTree};
use crate::core::errors::{Result, ZKMTDError};
use crate::core::traits::Verifier;
use crate::core::types::{Proof, ProofBatch, PublicInputs};
use crate::stark::prover::MTDVerifier as MTDVerifierInner;
use crate::utils::hash::constant_time_eq;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct BatchVerifier {
    verifier: MTDVerifierInner,
}

impl BatchVerifier {
    pub fn new(verifier: MTDVerifierInner) -> Self {
        Self { verifier }
    }

    #[cfg(feature = "alloc")]
    pub fn verify_batch(&self, batch: &ProofBatch, public_inputs: &[PublicInputs]) -> Result<bool> {
        // 1. Batch size verification
        if batch.proofs.len() != public_inputs.len() {
            return Err(ZKMTDError::BatchError {
                reason: alloc::format!(
                    "Number of proofs and public inputs do not match: {} != {}",
                    batch.proofs.len(),
                    public_inputs.len()
                ),
            });
        }

        if batch.is_empty() {
            return Err(ZKMTDError::BatchError {
                reason: "Batch is empty".into(),
            });
        }

        // 2. Epoch consistency verification
        for proof in &batch.proofs {
            if proof.epoch != batch.epoch {
                return Err(ZKMTDError::InvalidEpoch {
                    current: batch.epoch,
                    reason: alloc::format!(
                        "Proof Epoch does not match batch Epoch: {} != {}",
                        proof.epoch,
                        batch.epoch
                    ),
                });
            }
        }

        // 3. Merkle root verification (constant-time comparison)
        let computed_root = self.compute_merkle_root(&batch.proofs)?;
        if !constant_time_eq(&computed_root, &batch.merkle_root) {
            return Ok(false);
        }

        // 4. Individual verification of each proof
        for (proof, inputs) in batch.proofs.iter().zip(public_inputs.iter()) {
            let is_valid = self.verifier.verify(proof, inputs)?;
            if !is_valid {
                return Ok(false);
            }
        }

        Ok(true)
    }

    #[cfg(feature = "alloc")]
    pub fn verify_single_in_batch(
        &self,
        batch: &ProofBatch,
        index: usize,
        public_inputs: &PublicInputs,
    ) -> Result<bool> {
        if index >= batch.proofs.len() {
            return Err(ZKMTDError::BatchError {
                reason: alloc::format!("Invalid index: {} >= {}", index, batch.proofs.len()),
            });
        }

        let proof = &batch.proofs[index];

        // 1. Epoch verification
        if proof.epoch != batch.epoch {
            return Ok(false);
        }

        // 2. Merkle path verification
        let leaves: Vec<_> = batch.proofs.iter().map(|p| hash_leaf(&p.data)).collect();

        let merkle_tree = MerkleTree::new(leaves)?;
        let merkle_proof = merkle_tree.get_proof(index)?;

        let leaf_hash = hash_leaf(&proof.data);
        if !merkle_proof.verify(&leaf_hash) {
            return Ok(false);
        }

        // 3. Proof verification
        self.verifier.verify(proof, public_inputs)
    }

    #[cfg(feature = "alloc")]
    fn compute_merkle_root(&self, proofs: &[Proof]) -> Result<[u8; 32]> {
        let leaves: Vec<_> = proofs.iter().map(|proof| hash_leaf(&proof.data)).collect();

        let merkle_tree = MerkleTree::new(leaves)?;
        Ok(*merkle_tree.root())
    }

    pub fn inner_verifier(&self) -> &MTDVerifierInner {
        &self.verifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batching::aggregator::{create_proof_batch, BatchProver};
    use crate::core::traits::BatchProver as BatchProverTrait;
    use crate::core::types::Witness;
    use crate::mtd::Epoch;
    use crate::stark::StarkConfig;
    use alloc::vec;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_verifier_valid_batch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();
        let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());

        let witnesses = vec![
            Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            Witness::new(vec![9, 10, 11, 12, 13, 14, 15, 16]),
        ];

        let inputs = vec![PublicInputs::new(vec![42]), PublicInputs::new(vec![43])];

        let proofs = prover.prove_batch(&witnesses, &inputs).unwrap();
        let batch = create_proof_batch(proofs, epoch.value()).unwrap();

        let is_valid = verifier.verify_batch(&batch, &inputs).unwrap();
        assert!(is_valid, "Valid batch was rejected");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_verifier_tampered_merkle_root() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();
        let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());

        let witnesses = vec![Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8])];

        let inputs = vec![PublicInputs::new(vec![42])];

        let proofs = prover.prove_batch(&witnesses, &inputs).unwrap();
        let mut batch = create_proof_batch(proofs, epoch.value()).unwrap();

        // Tamper Merkle root
        batch.merkle_root = [99u8; 32];

        let is_valid = verifier.verify_batch(&batch, &inputs).unwrap();
        assert!(!is_valid, "Tampered batch was accepted");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_verifier_single_in_batch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();
        let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());

        let witnesses = vec![
            Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            Witness::new(vec![9, 10, 11, 12, 13, 14, 15, 16]),
            Witness::new(vec![17, 18, 19, 20, 21, 22, 23, 24]),
        ];

        let inputs = vec![
            PublicInputs::new(vec![42]),
            PublicInputs::new(vec![43]),
            PublicInputs::new(vec![44]),
        ];

        let proofs = prover.prove_batch(&witnesses, &inputs).unwrap();
        let batch = create_proof_batch(proofs, epoch.value()).unwrap();

        // Verify each proof individually
        for (i, input) in inputs.iter().enumerate() {
            let is_valid = verifier.verify_single_in_batch(&batch, i, input).unwrap();
            assert!(is_valid, "Proof at index {} was rejected", i);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_verifier_mismatched_lengths() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();
        let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());

        let witnesses = vec![Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8])];

        let inputs_for_prove = vec![PublicInputs::new(vec![42])];

        let proofs = prover.prove_batch(&witnesses, &inputs_for_prove).unwrap();
        let batch = create_proof_batch(proofs, epoch.value()).unwrap();

        // Wrong number of public inputs
        let wrong_inputs = vec![PublicInputs::new(vec![42]), PublicInputs::new(vec![43])];

        let result = verifier.verify_batch(&batch, &wrong_inputs);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_verifier_empty_batch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();
        let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());

        let empty_batch = ProofBatch::new(vec![], [0u8; 32], epoch.value());
        let inputs: Vec<PublicInputs> = vec![];

        let result = verifier.verify_batch(&empty_batch, &inputs);
        assert!(result.is_err());
    }
}
