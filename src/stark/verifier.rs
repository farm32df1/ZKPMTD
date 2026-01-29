//! STARK Verifier - simulation layer (use IntegratedVerifier for production)
#![allow(deprecated)]

use crate::core::errors::{Result, ZKMTDError};
use crate::core::traits::Verifier;
use crate::core::types::{Proof, PublicInputs};
use crate::mtd::WarpingParams;
use crate::stark::prover::MTDVerifier as MTDVerifierInner;
use crate::utils::constants::DOMAIN_PROOF_VERIFICATION;
use crate::utils::hash::poseidon_hash;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

impl Verifier for MTDVerifierInner {
    fn verify(&self, proof: &Proof, public_inputs: &PublicInputs) -> Result<bool> {
        if proof.epoch != self.current_epoch.value() {
            return Err(ZKMTDError::InvalidProof);
        }
        if proof.size() < 64 {
            return Err(ZKMTDError::InvalidProof);
        }
        self.verify_internal(proof, public_inputs)
    }

    #[cfg(feature = "alloc")]
    fn verify_batch(&self, proofs: &[Proof], public_inputs: &[PublicInputs]) -> Result<Vec<bool>> {
        if proofs.len() != public_inputs.len() {
            return Err(ZKMTDError::InvalidPublicInputs {
                reason: alloc::format!(
                    "Mismatch: {} proofs, {} inputs",
                    proofs.len(),
                    public_inputs.len()
                ),
            });
        }
        proofs
            .iter()
            .zip(public_inputs.iter())
            .map(|(p, i)| self.verify(p, i))
            .collect()
    }
}

impl MTDVerifierInner {
    fn verify_internal(&self, proof: &Proof, public_inputs: &PublicInputs) -> Result<bool> {
        if !self.verify_integrity_hash(proof)? {
            return Ok(false);
        }
        if proof.data.len() < 64 {
            return Ok(false);
        }

        let mut trace_commitment = [0u8; 32];
        trace_commitment.copy_from_slice(&proof.data[0..32]);

        if !self.verify_fri_proof(proof, &trace_commitment)? {
            return Ok(false);
        }
        if !self.verify_public_inputs(proof, public_inputs)? {
            return Ok(false);
        }
        if !self.verify_params_consistency(&trace_commitment)? {
            return Ok(false);
        }

        Ok(true)
    }

    fn verify_integrity_hash(&self, proof: &Proof) -> Result<bool> {
        if proof.data.len() < 64 {
            return Ok(false);
        }
        let hash_start = proof.data.len() - 32;
        let claimed_hash = &proof.data[hash_start..];
        let computed_hash = poseidon_hash(&proof.data[..hash_start], crate::utils::constants::DOMAIN_PROOF_INTEGRITY);
        Ok(crate::utils::hash::constant_time_eq(
            claimed_hash,
            &computed_hash,
        ))
    }

    fn verify_fri_proof(&self, proof: &Proof, trace_commitment: &[u8; 32]) -> Result<bool> {
        let fri_start = 32;
        let fri_seed_end = fri_start + 32;
        let queries_end = fri_seed_end + self.config.fri_queries;

        if proof.data.len() < queries_end {
            return Ok(false);
        }
        if proof.data[fri_start..fri_seed_end] != self.current_params.fri_seed {
            return Ok(false);
        }

        for i in 0..self.config.fri_queries {
            if proof.data[fri_seed_end + i] != self.current_params.salt[i % 32] {
                return Ok(false);
            }
        }

        #[cfg(feature = "alloc")]
        {
            let mut binding_data = Vec::new();
            binding_data.extend_from_slice(trace_commitment);
            binding_data.extend_from_slice(&proof.data[fri_start..fri_seed_end]);
            let _ = poseidon_hash(&binding_data, DOMAIN_PROOF_VERIFICATION);
        }
        Ok(true)
    }

    fn verify_public_inputs(&self, proof: &Proof, public_inputs: &PublicInputs) -> Result<bool> {
        let start = 32 + 32 + self.config.fri_queries;
        if proof.data.len() < start + (public_inputs.len() * 8) {
            return Ok(false);
        }

        for (i, &expected) in public_inputs.data.iter().enumerate() {
            let offset = start + (i * 8);
            if offset + 8 > proof.data.len() {
                return Ok(false);
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&proof.data[offset..offset + 8]);
            if u64::from_le_bytes(bytes) != expected {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn verify_params_consistency(&self, trace_commitment: &[u8; 32]) -> Result<bool> {
        if trace_commitment.iter().all(|&b| b == 0) {
            return Ok(false);
        }
        if self.current_params.domain_separator.iter().all(|&b| b == 0) {
            return Ok(false);
        }

        #[cfg(feature = "alloc")]
        {
            let mut binding_data = Vec::new();
            binding_data.extend_from_slice(trace_commitment);
            binding_data.extend_from_slice(&self.current_params.domain_separator);
            let binding_hash = poseidon_hash(&binding_data, DOMAIN_PROOF_VERIFICATION);
            if binding_hash.iter().all(|&b| b == 0) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn verify_with_params(
        &self,
        proof: &Proof,
        public_inputs: &PublicInputs,
        params: &WarpingParams,
    ) -> Result<bool> {
        if proof.epoch != params.epoch.value() {
            return Err(ZKMTDError::InvalidEpoch {
                current: params.epoch.value(),
                reason: "Epoch mismatch".into(),
            });
        }
        let temp = MTDVerifierInner {
            config: self.config.clone(),
            current_epoch: params.epoch,
            current_params: params.clone(),
        };
        temp.verify(proof, public_inputs)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::core::traits::Prover;
    use crate::core::types::{Proof, PublicInputs, Witness};
    use crate::mtd::Epoch;
    use crate::stark::{prover::MTDProver, StarkConfig};
    use alloc::vec;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_verifier_valid_proof() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
        let verifier = prover.get_verifier();

        let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let public_inputs = PublicInputs::new(vec![42]);

        let proof = prover.prove(&witness, &public_inputs).unwrap();
        let is_valid = verifier.verify(&proof, &public_inputs).unwrap();

        assert!(is_valid, "Valid proof was rejected");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_verifier_wrong_epoch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();

        let prover = MTDProver::with_epoch(seed, config.clone(), Epoch::new(100)).unwrap();
        let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let public_inputs = PublicInputs::new(vec![42]);
        let proof = prover.prove(&witness, &public_inputs).unwrap();

        // Verifier with different epoch
        let wrong_verifier = MTDProver::with_epoch(seed, config, Epoch::new(200))
            .unwrap()
            .get_verifier();

        let result = wrong_verifier.verify(&proof, &public_inputs);
        assert!(result.is_err(), "Proof with different epoch was accepted");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_verifier_invalid_proof() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
        let verifier = prover.get_verifier();

        // Invalid proof (empty data)
        let invalid_proof = Proof::default();
        let public_inputs = PublicInputs::new(vec![42]);

        let result = verifier.verify(&invalid_proof, &public_inputs);
        assert!(result.is_err(), "Invalid proof was accepted");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_verifier_batch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
        let verifier = prover.get_verifier();

        // Generate multiple proofs
        let mut proofs = Vec::new();
        let mut inputs = Vec::new();

        for i in 1..=5 {
            let witness = Witness::new(vec![i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7]);
            let public_input = PublicInputs::new(vec![i * 10]);
            let proof = prover.prove(&witness, &public_input).unwrap();
            proofs.push(proof);
            inputs.push(public_input);
        }

        let results = verifier.verify_batch(&proofs, &inputs).unwrap();
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|&r| r), "All proofs should be valid");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_verify_with_params() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
        let params = prover.current_params().clone();
        let verifier = prover.get_verifier();

        let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let public_inputs = PublicInputs::new(vec![42]);
        let proof = prover.prove(&witness, &public_inputs).unwrap();

        let is_valid = verifier
            .verify_with_params(&proof, &public_inputs, &params)
            .unwrap();
        assert!(is_valid);
    }
}
