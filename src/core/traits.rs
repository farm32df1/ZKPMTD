//! Core traits: Prover, Verifier, EntropySource, BatchProver

use crate::core::errors::{Result, ZKMTDError};
use crate::core::types::{Proof, PublicInputs, Witness};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Prover trait - generates ZK proofs from witness
pub trait Prover {
    fn prove(&self, witness: &Witness, public_inputs: &PublicInputs) -> Result<Proof>;
    fn min_witness_size(&self) -> usize;
    fn min_public_inputs_size(&self) -> usize;
}

/// Verifier trait - validates ZK proofs
pub trait Verifier {
    fn verify(&self, proof: &Proof, public_inputs: &PublicInputs) -> Result<bool>;

    #[cfg(feature = "alloc")]
    fn verify_batch(&self, proofs: &[Proof], public_inputs: &[PublicInputs]) -> Result<Vec<bool>> {
        use alloc::vec::Vec;

        if proofs.len() != public_inputs.len() {
            return Err(ZKMTDError::InvalidPublicInputs {
                reason: alloc::format!(
                    "Mismatch between number of proofs and public inputs: {} proofs, {} public inputs",
                    proofs.len(),
                    public_inputs.len()
                ),
            });
        }

        let mut results = Vec::with_capacity(proofs.len());
        for (proof, inputs) in proofs.iter().zip(public_inputs.iter()) {
            results.push(self.verify(proof, inputs)?);
        }
        Ok(results)
    }
}

/// Entropy source trait - provides cryptographically secure randomness for MTD
pub trait EntropySource {
    #[cfg(feature = "alloc")]
    fn generate(&mut self, num_bytes: usize) -> Result<Vec<u8>>;
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<()>;
    fn entropy_bits(&self) -> usize;
    fn is_cryptographically_secure(&self) -> bool {
        false
    }
}

/// Batch prover trait - generates multiple proofs efficiently
#[cfg(feature = "alloc")]
pub trait BatchProver: Prover {
    fn prove_batch(
        &self,
        witnesses: &[Witness],
        public_inputs: &[PublicInputs],
    ) -> Result<Vec<Proof>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct DummyProver;

    impl Prover for DummyProver {
        fn prove(&self, _witness: &Witness, _public_inputs: &PublicInputs) -> Result<Proof> {
            Ok(Proof::default())
        }

        fn min_witness_size(&self) -> usize {
            4
        }

        fn min_public_inputs_size(&self) -> usize {
            2
        }
    }

    struct DummyVerifier;

    impl Verifier for DummyVerifier {
        fn verify(&self, _proof: &Proof, _public_inputs: &PublicInputs) -> Result<bool> {
            Ok(true)
        }
    }

    struct FailingVerifier;

    impl Verifier for FailingVerifier {
        fn verify(&self, _proof: &Proof, _public_inputs: &PublicInputs) -> Result<bool> {
            Err(ZKMTDError::VerificationFailed {
                reason: "test error".into(),
            })
        }
    }

    struct DummyEntropy;

    impl EntropySource for DummyEntropy {
        #[cfg(feature = "alloc")]
        fn generate(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
            Ok(vec![0u8; num_bytes])
        }

        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<()> {
            output.fill(0);
            Ok(())
        }

        fn entropy_bits(&self) -> usize {
            128
        }
        // Uses default is_cryptographically_secure() -> false
    }

    #[test]
    fn test_prover_trait() {
        let prover = DummyProver;
        assert_eq!(prover.min_witness_size(), 4);
        assert_eq!(prover.min_public_inputs_size(), 2);
    }

    #[test]
    fn test_prover_prove() {
        let prover = DummyProver;
        let witness = Witness::default();
        let inputs = PublicInputs::default();
        assert!(prover.prove(&witness, &inputs).is_ok());
    }

    #[test]
    fn test_verifier_trait() {
        let verifier = DummyVerifier;
        let proof = Proof::default();
        let public_inputs = PublicInputs::default();
        assert!(verifier.verify(&proof, &public_inputs).unwrap());
    }

    #[test]
    fn test_verifier_batch_success() {
        let verifier = DummyVerifier;
        let proofs = vec![Proof::default(), Proof::default()];
        let inputs = vec![PublicInputs::default(), PublicInputs::default()];

        let results = verifier.verify_batch(&proofs, &inputs).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|&r| r));
    }

    #[test]
    fn test_verifier_batch_mismatched() {
        let verifier = DummyVerifier;
        let proofs = vec![Proof::default(), Proof::default()];
        let inputs = vec![PublicInputs::default()];

        let result = verifier.verify_batch(&proofs, &inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_verifier_batch_error_propagation() {
        let verifier = FailingVerifier;
        let proofs = vec![Proof::default()];
        let inputs = vec![PublicInputs::default()];

        let result = verifier.verify_batch(&proofs, &inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_default_not_secure() {
        let entropy = DummyEntropy;
        assert!(!entropy.is_cryptographically_secure());
        assert_eq!(entropy.entropy_bits(), 128);
    }

    #[test]
    fn test_entropy_generate() {
        let mut entropy = DummyEntropy;
        let bytes = entropy.generate(16).unwrap();
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_entropy_fill_bytes() {
        let mut entropy = DummyEntropy;
        let mut buf = [1u8; 8];
        entropy.fill_bytes(&mut buf).unwrap();
        assert_eq!(buf, [0u8; 8]);
    }
}
