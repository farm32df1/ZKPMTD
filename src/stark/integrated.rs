//! Integrated ZKMTD - real Plonky3 STARK + MTD (recommended for production)

use crate::core::errors::Result;
use crate::mtd::{Epoch, MTDManager, WarpingParams};
use crate::stark::air::SimpleAir;
use crate::stark::real_stark::{RealProof, RealStarkProver, RealStarkVerifier};
use crate::utils::hash::poseidon_hash;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[derive(Debug)]
pub struct IntegratedProver {
    mtd_manager: MTDManager,
    stark_prover: RealStarkProver,
}

impl IntegratedProver {
    pub fn new(seed: &[u8], epoch: Epoch) -> Result<Self> {
        let mtd_manager = MTDManager::with_epoch(seed, epoch)?;
        let stark_prover = RealStarkProver::new(SimpleAir::fibonacci())?;
        Ok(Self {
            mtd_manager,
            stark_prover,
        })
    }

    pub fn with_entropy<E: crate::core::traits::EntropySource>(
        seed: &[u8],
        entropy: &mut E,
    ) -> Result<Self> {
        let mtd_manager = MTDManager::new(seed, entropy)?;
        let stark_prover = RealStarkProver::new(SimpleAir::fibonacci())?;
        Ok(Self {
            mtd_manager,
            stark_prover,
        })
    }

    pub fn current_epoch(&self) -> Epoch {
        self.mtd_manager.current_epoch()
    }
    pub fn current_params(&self) -> &WarpingParams {
        self.mtd_manager.current_params()
    }
    pub fn advance_epoch(&mut self) -> Result<()> {
        self.mtd_manager.advance()?;
        Ok(())
    }

    pub fn prove_fibonacci(&self, num_rows: usize) -> Result<IntegratedProof> {
        let stark_proof = self.stark_prover.prove_fibonacci(num_rows)?;
        let epoch = self.mtd_manager.current_epoch();
        let params = self.mtd_manager.current_params().clone();
        let binding_hash = self.compute_binding_hash(&stark_proof, &params);

        Ok(IntegratedProof {
            stark_proof,
            epoch,
            params,
            binding_hash,
        })
    }

    pub fn get_verifier(&self) -> IntegratedVerifier {
        IntegratedVerifier {
            stark_verifier: self.stark_prover.get_verifier(),
            current_epoch: self.mtd_manager.current_epoch(),
            current_params: self.mtd_manager.current_params().clone(),
        }
    }

    fn compute_binding_hash(&self, proof: &RealProof, params: &WarpingParams) -> [u8; 32] {
        let mut data = Vec::new();
        for &pv in &proof.public_values {
            data.extend_from_slice(&pv.to_le_bytes());
        }
        data.extend_from_slice(&params.epoch.value().to_le_bytes());
        data.extend_from_slice(&params.domain_separator);
        data.extend_from_slice(&params.fri_seed);
        data.extend_from_slice(&params.salt);
        poseidon_hash(&data, b"ZKMTD_BINDING")
    }
}

#[derive(Debug)]
pub struct IntegratedVerifier {
    stark_verifier: RealStarkVerifier,
    current_epoch: Epoch,
    current_params: WarpingParams,
}

impl IntegratedVerifier {
    pub fn new(seed: &[u8], epoch: Epoch) -> Result<Self> {
        let mtd_manager = MTDManager::with_epoch(seed, epoch)?;
        let stark_verifier = RealStarkVerifier::new(SimpleAir::fibonacci())?;
        Ok(Self {
            stark_verifier,
            current_epoch: mtd_manager.current_epoch(),
            current_params: mtd_manager.current_params().clone(),
        })
    }

    pub fn current_epoch(&self) -> Epoch {
        self.current_epoch
    }
    pub fn current_params(&self) -> &WarpingParams {
        &self.current_params
    }

    pub fn verify(&self, proof: &IntegratedProof) -> Result<bool> {
        if proof.epoch != self.current_epoch {
            return Ok(false);
        }
        if !self.verify_params_match(&proof.params) {
            return Ok(false);
        }

        let expected_binding = self.compute_binding_hash(&proof.stark_proof, &proof.params);
        if proof.binding_hash != expected_binding {
            return Ok(false);
        }

        self.stark_verifier.verify_fibonacci(&proof.stark_proof)
    }

    pub fn verify_with_params(
        &self,
        proof: &IntegratedProof,
        expected_epoch: Epoch,
        expected_params: &WarpingParams,
    ) -> Result<bool> {
        if proof.epoch != expected_epoch {
            return Ok(false);
        }
        if proof.params.domain_separator != expected_params.domain_separator
            || proof.params.fri_seed != expected_params.fri_seed
            || proof.params.salt != expected_params.salt
        {
            return Ok(false);
        }

        let expected_binding = self.compute_binding_hash(&proof.stark_proof, &proof.params);
        if proof.binding_hash != expected_binding {
            return Ok(false);
        }

        self.stark_verifier.verify_fibonacci(&proof.stark_proof)
    }

    fn verify_params_match(&self, proof_params: &WarpingParams) -> bool {
        proof_params.epoch == self.current_epoch
            && proof_params.domain_separator == self.current_params.domain_separator
            && proof_params.fri_seed == self.current_params.fri_seed
            && proof_params.salt == self.current_params.salt
    }

    fn compute_binding_hash(&self, proof: &RealProof, params: &WarpingParams) -> [u8; 32] {
        let mut data = Vec::new();
        for &pv in &proof.public_values {
            data.extend_from_slice(&pv.to_le_bytes());
        }
        data.extend_from_slice(&params.epoch.value().to_le_bytes());
        data.extend_from_slice(&params.domain_separator);
        data.extend_from_slice(&params.fri_seed);
        data.extend_from_slice(&params.salt);
        poseidon_hash(&data, b"ZKMTD_BINDING")
    }
}

#[derive(Debug)]
pub struct IntegratedProof {
    pub stark_proof: RealProof,
    pub epoch: Epoch,
    pub params: WarpingParams,
    pub binding_hash: [u8; 32],
}

impl IntegratedProof {
    pub fn public_values(&self) -> &[u64] {
        &self.stark_proof.public_values
    }
    pub fn num_rows(&self) -> usize {
        self.stark_proof.num_rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrated_prover_creation() {
        let seed = b"test-seed-for-integrated";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch);
        assert!(prover.is_ok(), "Integrated prover creation failed");

        let prover = prover.unwrap();
        assert_eq!(prover.current_epoch(), epoch);
    }

    #[test]
    fn test_integrated_prove_and_verify() {
        let seed = b"test-seed-for-integrated";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let proof = prover.prove_fibonacci(8).unwrap();

        // Check public values
        assert_eq!(proof.public_values().len(), 4);
        assert_eq!(proof.public_values()[0], 0); // F(0)
        assert_eq!(proof.public_values()[1], 1); // F(1)

        // Verify
        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        assert!(is_valid, "Valid proof was rejected");
    }

    #[test]
    fn test_integrated_soundness_tampered_binding() {
        let seed = b"test-seed-for-soundness";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let mut proof = prover.prove_fibonacci(8).unwrap();

        // Tamper with binding hash
        proof.binding_hash[0] ^= 0xFF;

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        assert!(!is_valid, "Tampered binding hash was accepted");
    }

    #[test]
    fn test_integrated_soundness_wrong_epoch() {
        let seed = b"test-seed-for-epoch";

        // Generate proof at epoch 100
        let prover = IntegratedProver::new(seed, Epoch::new(100)).unwrap();
        let proof = prover.prove_fibonacci(8).unwrap();

        // Try to verify with epoch 200 verifier
        let wrong_verifier = IntegratedVerifier::new(seed, Epoch::new(200)).unwrap();
        let is_valid = wrong_verifier.verify(&proof).unwrap();
        assert!(!is_valid, "Proof from different epoch was accepted");
    }

    #[test]
    fn test_integrated_soundness_wrong_seed() {
        // Generate proof with seed-A
        let prover = IntegratedProver::new(b"seed-A", Epoch::new(100)).unwrap();
        let proof = prover.prove_fibonacci(8).unwrap();

        // Try to verify with seed-B verifier
        let wrong_verifier = IntegratedVerifier::new(b"seed-B", Epoch::new(100)).unwrap();
        let is_valid = wrong_verifier.verify(&proof).unwrap();
        assert!(!is_valid, "Proof from different seed was accepted");
    }

    #[test]
    fn test_integrated_soundness_tampered_public_values() {
        let seed = b"test-seed-tamper-pv";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let mut proof = prover.prove_fibonacci(8).unwrap();

        // Tamper with public values (inside STARK proof)
        proof.stark_proof.public_values[2] = 999;

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        assert!(!is_valid, "Tampered public values were accepted");
    }

    #[test]
    fn test_integrated_epoch_advancement() {
        let seed = b"test-seed-advance";
        let epoch = Epoch::new(100);

        let mut prover = IntegratedProver::new(seed, epoch).unwrap();

        // Generate proof at epoch 100
        let proof_100 = prover.prove_fibonacci(8).unwrap();
        let verifier_100 = prover.get_verifier();
        assert!(verifier_100.verify(&proof_100).unwrap());

        // Advance epoch
        prover.advance_epoch().unwrap();
        assert_eq!(prover.current_epoch().value(), 101);

        // Previous proof should be rejected in new epoch
        let verifier_101 = prover.get_verifier();
        assert!(
            !verifier_101.verify(&proof_100).unwrap(),
            "Previous epoch proof accepted in new epoch"
        );

        // Generate and verify new proof in new epoch
        let proof_101 = prover.prove_fibonacci(8).unwrap();
        assert!(verifier_101.verify(&proof_101).unwrap());
    }

    #[test]
    fn test_integrated_independent_verifier() {
        let seed = b"test-seed-independent";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let proof = prover.prove_fibonacci(8).unwrap();

        // Create completely independent verifier
        let independent_verifier = IntegratedVerifier::new(seed, epoch).unwrap();
        let is_valid = independent_verifier.verify(&proof).unwrap();
        assert!(is_valid, "Independent verifier rejected valid proof");
    }

    #[test]
    fn test_integrated_various_trace_sizes() {
        let seed = b"test-seed-sizes";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let verifier = prover.get_verifier();

        // Test various trace sizes
        for &size in &[2, 4, 8, 16, 32, 64] {
            let proof = prover.prove_fibonacci(size).unwrap();
            assert_eq!(proof.num_rows(), size);

            let is_valid = verifier.verify(&proof).unwrap();
            assert!(is_valid, "Proof of size {} was rejected", size);
        }
    }

    #[test]
    fn test_integrated_invalid_trace_size() {
        let seed = b"test-seed-invalid";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();

        // Non-power-of-two size
        let result = prover.prove_fibonacci(7);
        assert!(result.is_err(), "Invalid size trace was accepted");

        // Too small size
        let result = prover.prove_fibonacci(1);
        assert!(result.is_err(), "Too small trace was accepted");
    }

    #[test]
    fn test_integrated_fibonacci_correctness() {
        let seed = b"test-seed-fib";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();

        // 8-row Fibonacci: last row [F(7), F(8)] = [13, 21]
        let proof = prover.prove_fibonacci(8).unwrap();
        assert_eq!(proof.public_values()[2], 13, "F(7) != 13");
        assert_eq!(proof.public_values()[3], 21, "F(8) != 21");

        // 16-row Fibonacci: last row [F(15), F(16)] = [610, 987]
        let proof = prover.prove_fibonacci(16).unwrap();
        assert_eq!(proof.public_values()[2], 610, "F(15) != 610");
        assert_eq!(proof.public_values()[3], 987, "F(16) != 987");
    }

    #[test]
    fn test_integrated_multiple_verifications() {
        let seed = b"test-seed-multi";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let proof = prover.prove_fibonacci(8).unwrap();
        let verifier = prover.get_verifier();

        // Same proof verified multiple times should always return same result
        for i in 0..10 {
            let is_valid = verifier.verify(&proof).unwrap();
            assert!(is_valid, "Verification {} failed", i + 1);
        }
    }
}
