//! Proof Aggregator - bundles multiple proofs into Merkle tree batch

use crate::batching::merkle::{hash_leaf, MerkleTree};
use crate::core::errors::{Result, ZKMTDError};
use crate::core::traits::{BatchProver as BatchProverTrait, Prover};
use crate::core::types::{Proof, ProofBatch, PublicInputs, Witness};
use crate::mtd::Epoch;
use crate::stark::MTDProver;
use crate::utils::constants::MAX_BATCH_SIZE;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[derive(Debug)]
pub struct BatchProver {
    prover: MTDProver,
}

impl BatchProver {
    pub fn new<E: crate::core::traits::EntropySource>(
        seed: &[u8],
        config: crate::stark::StarkConfig,
        entropy: &mut E,
    ) -> Result<Self> {
        let prover = MTDProver::new(seed, config, entropy)?;
        Ok(Self { prover })
    }

    pub fn with_epoch(
        seed: &[u8],
        config: crate::stark::StarkConfig,
        epoch: Epoch,
    ) -> Result<Self> {
        let prover = MTDProver::with_epoch(seed, config, epoch)?;
        Ok(Self { prover })
    }

    pub fn current_epoch(&self) -> Epoch {
        self.prover.current_epoch()
    }
    pub fn advance_epoch(&mut self) -> Result<()> {
        self.prover.advance_epoch()
    }
    pub fn inner_prover(&self) -> &MTDProver {
        &self.prover
    }
}

#[cfg(feature = "alloc")]
impl BatchProverTrait for BatchProver {
    fn prove_batch(
        &self,
        witnesses: &[Witness],
        public_inputs: &[PublicInputs],
    ) -> Result<Vec<Proof>> {
        if witnesses.len() != public_inputs.len() {
            return Err(ZKMTDError::BatchError {
                reason: alloc::format!(
                    "Number of witnesses and public inputs do not match: {} != {}",
                    witnesses.len(),
                    public_inputs.len()
                ),
            });
        }

        if witnesses.is_empty() {
            return Err(ZKMTDError::BatchError {
                reason: "Batch is empty".into(),
            });
        }

        if witnesses.len() > MAX_BATCH_SIZE {
            return Err(ZKMTDError::BatchError {
                reason: alloc::format!(
                    "Batch size exceeds limit: {} > {}",
                    witnesses.len(),
                    MAX_BATCH_SIZE
                ),
            });
        }

        // Generate proof for each witness
        let mut proofs = Vec::with_capacity(witnesses.len());
        for (witness, inputs) in witnesses.iter().zip(public_inputs.iter()) {
            let proof = self.prover.prove(witness, inputs)?;
            proofs.push(proof);
        }

        Ok(proofs)
    }
}

#[cfg(feature = "alloc")]
impl Prover for BatchProver {
    fn prove(&self, witness: &Witness, public_inputs: &PublicInputs) -> Result<Proof> {
        self.prover.prove(witness, public_inputs)
    }

    fn min_witness_size(&self) -> usize {
        self.prover.min_witness_size()
    }

    fn min_public_inputs_size(&self) -> usize {
        self.prover.min_public_inputs_size()
    }
}

#[cfg(feature = "alloc")]
pub fn create_proof_batch(proofs: Vec<Proof>, epoch: u64) -> Result<ProofBatch> {
    if proofs.is_empty() {
        return Err(ZKMTDError::BatchError {
            reason: "Proofs are empty".into(),
        });
    }

    for proof in &proofs {
        if proof.epoch != epoch {
            return Err(ZKMTDError::BatchError {
                reason: alloc::format!("Proof Epoch mismatch: {} != {}", proof.epoch, epoch),
            });
        }
    }

    let leaves: Vec<_> = proofs.iter().map(|proof| hash_leaf(&proof.data)).collect();
    let merkle_tree = MerkleTree::new(leaves)?;

    Ok(ProofBatch::new(proofs, *merkle_tree.root(), epoch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::traits::BatchProver as BatchProverTrait;
    use crate::core::types::Witness;
    use crate::stark::StarkConfig;
    use alloc::vec;

    #[cfg(feature = "std")]
    use crate::mtd::entropy::SystemEntropy;

    #[cfg(feature = "std")]
    #[test]
    fn test_batch_prover_creation() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let mut entropy = SystemEntropy::new();

        let prover = BatchProver::new(seed, config, &mut entropy).unwrap();
        // Epoch is u64 so always >= 0, instead verify prover exists
        assert_eq!(prover.min_witness_size(), 4);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_prover_prove_batch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();

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
        assert_eq!(proofs.len(), 3);

        for proof in &proofs {
            assert!(!proof.is_empty());
            assert_eq!(proof.epoch, epoch.value());
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_prover_mismatched_lengths() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();

        let witnesses = vec![Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8])];

        let inputs = vec![PublicInputs::new(vec![42]), PublicInputs::new(vec![43])];

        let result = prover.prove_batch(&witnesses, &inputs);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_prover_empty_batch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();

        let witnesses: Vec<Witness> = vec![];
        let inputs: Vec<PublicInputs> = vec![];

        let result = prover.prove_batch(&witnesses, &inputs);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_create_proof_batch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();

        let witnesses = vec![
            Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            Witness::new(vec![9, 10, 11, 12, 13, 14, 15, 16]),
        ];

        let inputs = vec![PublicInputs::new(vec![42]), PublicInputs::new(vec![43])];

        let proofs = prover.prove_batch(&witnesses, &inputs).unwrap();
        let batch = create_proof_batch(proofs, epoch.value()).unwrap();

        assert_eq!(batch.len(), 2);
        assert_eq!(batch.epoch, epoch.value());
        assert_ne!(batch.merkle_root, [0u8; 32]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_create_proof_batch_mismatched_epochs() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();

        let prover1 = BatchProver::with_epoch(seed, config.clone(), Epoch::new(100)).unwrap();
        let prover2 = BatchProver::with_epoch(seed, config, Epoch::new(200)).unwrap();

        let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let inputs = PublicInputs::new(vec![42]);

        let proof1 = prover1.prove(&witness, &inputs).unwrap();
        let proof2 = prover2.prove(&witness, &inputs).unwrap();

        let proofs = vec![proof1, proof2];
        let result = create_proof_batch(proofs, 100);
        assert!(result.is_err());
    }
}
