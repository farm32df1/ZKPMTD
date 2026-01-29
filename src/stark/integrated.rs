//! Integrated ZKMTD - real Plonky3 STARK + MTD (recommended for production)
//!
//! All proofs commit public values with a salt (privacy-by-default).
//! No standard/privacy mode distinction — every proof is privacy-preserving.

use crate::core::errors::Result;
use crate::core::types::CommittedPublicInputs;
use crate::mtd::{Epoch, MTDManager, WarpingParams};
use crate::stark::air::SimpleAir;
use crate::stark::real_stark::{RealProof, RealStarkProver, RealStarkVerifier};
use crate::utils::constants::DOMAIN_BINDING;
use crate::utils::hash::{constant_time_eq_fixed, poseidon_hash};
use zeroize::Zeroize;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Compute binding hash for a proof with committed public values.
/// Single implementation shared by prover and verifier — no duplication.
///
/// SECURITY: Includes air_type to prevent AIR type confusion attacks where
/// a proof generated for one AIR type is presented as another type.
fn compute_binding_hash(
    proof: &RealProof,
    params: &WarpingParams,
    committed: &CommittedPublicInputs,
) -> [u8; 32] {
    let mut data = Vec::new();
    // Include AIR type as first element to prevent type confusion attacks
    data.push(proof.air_type.as_u8());
    for &pv in &proof.public_values {
        data.extend_from_slice(&pv.to_le_bytes());
    }
    data.extend_from_slice(&committed.commitment);
    data.extend_from_slice(&committed.value_count.to_le_bytes());
    data.extend_from_slice(&params.epoch.value().to_le_bytes());
    data.extend_from_slice(&params.domain_separator);
    data.extend_from_slice(&params.fri_seed);
    data.extend_from_slice(&params.salt);
    poseidon_hash(&data, DOMAIN_BINDING)
}

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

    /// Generate a proof with committed public values.
    /// All proofs are privacy-preserving — public_values are committed with the given salt.
    pub fn prove_fibonacci(
        &self,
        num_rows: usize,
        pv_salt: [u8; 32],
    ) -> Result<IntegratedProof> {
        let stark_proof = self.stark_prover.prove_fibonacci(num_rows)?;
        let epoch = self.mtd_manager.current_epoch();
        let params = self.mtd_manager.current_params().clone();

        let committed_public_values =
            CommittedPublicInputs::commit(&stark_proof.public_values, &pv_salt);
        let binding_hash =
            compute_binding_hash(&stark_proof, &params, &committed_public_values);

        Ok(IntegratedProof {
            stark_proof,
            epoch,
            params,
            binding_hash,
            committed_public_values,
            pv_salt: Some(pv_salt),
        })
    }

    /// Prove `a[i] + b[i] = c[i]` for all rows, with committed public values.
    pub fn prove_sum(
        &self,
        a_values: &[u64],
        b_values: &[u64],
        pv_salt: [u8; 32],
    ) -> Result<IntegratedProof> {
        let stark_proof = self.stark_prover.prove_sum(a_values, b_values)?;
        let epoch = self.mtd_manager.current_epoch();
        let params = self.mtd_manager.current_params().clone();
        let committed_public_values =
            CommittedPublicInputs::commit(&stark_proof.public_values, &pv_salt);
        let binding_hash =
            compute_binding_hash(&stark_proof, &params, &committed_public_values);

        Ok(IntegratedProof {
            stark_proof,
            epoch,
            params,
            binding_hash,
            committed_public_values,
            pv_salt: Some(pv_salt),
        })
    }

    /// Prove `a[i] * b[i] = c[i]` for all rows, with committed public values.
    pub fn prove_multiplication(
        &self,
        a_values: &[u64],
        b_values: &[u64],
        pv_salt: [u8; 32],
    ) -> Result<IntegratedProof> {
        let stark_proof = self.stark_prover.prove_multiplication(a_values, b_values)?;
        let epoch = self.mtd_manager.current_epoch();
        let params = self.mtd_manager.current_params().clone();
        let committed_public_values =
            CommittedPublicInputs::commit(&stark_proof.public_values, &pv_salt);
        let binding_hash =
            compute_binding_hash(&stark_proof, &params, &committed_public_values);

        Ok(IntegratedProof {
            stark_proof,
            epoch,
            params,
            binding_hash,
            committed_public_values,
            pv_salt: Some(pv_salt),
        })
    }

    /// Prove value >= threshold via bit decomposition, with committed public values.
    pub fn prove_range(
        &self,
        value: u64,
        threshold: u64,
        pv_salt: [u8; 32],
    ) -> Result<IntegratedProof> {
        let stark_proof = self.stark_prover.prove_range(value, threshold)?;
        let epoch = self.mtd_manager.current_epoch();
        let params = self.mtd_manager.current_params().clone();
        let committed_public_values =
            CommittedPublicInputs::commit(&stark_proof.public_values, &pv_salt);
        let binding_hash =
            compute_binding_hash(&stark_proof, &params, &committed_public_values);

        Ok(IntegratedProof {
            stark_proof,
            epoch,
            params,
            binding_hash,
            committed_public_values,
            pv_salt: Some(pv_salt),
        })
    }

    pub fn get_verifier(&self) -> IntegratedVerifier {
        IntegratedVerifier {
            stark_verifier: self.stark_prover.get_verifier(),
            current_epoch: self.mtd_manager.current_epoch(),
            current_params: self.mtd_manager.current_params().clone(),
        }
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

        let expected_binding =
            compute_binding_hash(&proof.stark_proof, &proof.params, &proof.committed_public_values);

        // SECURITY: Use constant-time comparison to prevent timing side-channel attacks
        if !constant_time_eq_fixed(&proof.binding_hash, &expected_binding) {
            return Ok(false);
        }

        self.stark_verifier.verify_by_type(&proof.stark_proof)
    }

    /// Verify a proof with the original public values and salt.
    /// Re-derives the commitment and checks it matches the one in the proof.
    pub fn verify_with_salt(
        &self,
        proof: &IntegratedProof,
        public_values: &[u64],
        pv_salt: &[u8; 32],
    ) -> Result<bool> {
        if !proof.committed_public_values.verify(public_values, pv_salt) {
            return Ok(false);
        }

        self.verify(proof)
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

        let expected_binding =
            compute_binding_hash(&proof.stark_proof, &proof.params, &proof.committed_public_values);

        // SECURITY: Use constant-time comparison to prevent timing side-channel attacks
        if !constant_time_eq_fixed(&proof.binding_hash, &expected_binding) {
            return Ok(false);
        }

        self.stark_verifier.verify_by_type(&proof.stark_proof)
    }

    fn verify_params_match(&self, proof_params: &WarpingParams) -> bool {
        proof_params.epoch == self.current_epoch
            && proof_params.domain_separator == self.current_params.domain_separator
            && proof_params.fri_seed == self.current_params.fri_seed
            && proof_params.salt == self.current_params.salt
    }
}

pub struct IntegratedProof {
    pub stark_proof: RealProof,
    pub epoch: Epoch,
    pub params: WarpingParams,
    pub binding_hash: [u8; 32],
    /// Committed public values (always present — privacy-by-default)
    pub committed_public_values: CommittedPublicInputs,
    /// Salt used for commitment (erasable for GDPR compliance).
    /// Access via `erase_salt()` for secure deletion — do not set directly.
    pub(crate) pv_salt: Option<[u8; 32]>,
}

impl core::fmt::Debug for IntegratedProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntegratedProof")
            .field("stark_proof", &self.stark_proof)
            .field("epoch", &self.epoch)
            .field("params", &self.params)
            .field("binding_hash", &self.binding_hash)
            .field("committed_public_values", &self.committed_public_values)
            .field("pv_salt", &self.pv_salt.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl IntegratedProof {
    pub fn public_values(&self) -> &[u64] {
        &self.stark_proof.public_values
    }
    pub fn num_rows(&self) -> usize {
        self.stark_proof.num_rows
    }

    /// Returns the committed values hash (for on-chain submission).
    pub fn committed_values_hash(&self) -> &[u8; 32] {
        &self.committed_public_values.commitment
    }

    /// Erase the salt for GDPR compliance.
    /// After this, the commitment cannot be reversed.
    /// The proof remains verifiable without the salt.
    /// Uses `zeroize` to prevent compiler dead-store elimination.
    pub fn erase_salt(&mut self) {
        if let Some(ref mut salt) = self.pv_salt {
            salt.zeroize();
        }
        self.pv_salt = None;
    }

    /// Returns true if the salt is present (not yet erased).
    pub fn has_salt(&self) -> bool {
        self.pv_salt.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a deterministic test salt
    fn test_salt() -> [u8; 32] {
        [42u8; 32]
    }

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
        let proof = prover.prove_fibonacci(8, test_salt()).unwrap();

        // Check public values
        assert_eq!(proof.public_values().len(), 4);
        assert_eq!(proof.public_values()[0], 0); // F(0)
        assert_eq!(proof.public_values()[1], 1); // F(1)

        // All proofs have committed values
        assert_ne!(proof.committed_values_hash(), &[0u8; 32]);

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
        let mut proof = prover.prove_fibonacci(8, test_salt()).unwrap();

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
        let proof = prover.prove_fibonacci(8, test_salt()).unwrap();

        // Try to verify with epoch 200 verifier
        let wrong_verifier = IntegratedVerifier::new(seed, Epoch::new(200)).unwrap();
        let is_valid = wrong_verifier.verify(&proof).unwrap();
        assert!(!is_valid, "Proof from different epoch was accepted");
    }

    #[test]
    fn test_integrated_soundness_wrong_seed() {
        // Generate proof with seed-A
        let prover = IntegratedProver::new(b"seed-A", Epoch::new(100)).unwrap();
        let proof = prover.prove_fibonacci(8, test_salt()).unwrap();

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
        let mut proof = prover.prove_fibonacci(8, test_salt()).unwrap();

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
        let proof_100 = prover.prove_fibonacci(8, test_salt()).unwrap();
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
        let proof_101 = prover.prove_fibonacci(8, test_salt()).unwrap();
        assert!(verifier_101.verify(&proof_101).unwrap());
    }

    #[test]
    fn test_integrated_independent_verifier() {
        let seed = b"test-seed-independent";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let proof = prover.prove_fibonacci(8, test_salt()).unwrap();

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
            let proof = prover.prove_fibonacci(size, test_salt()).unwrap();
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
        let result = prover.prove_fibonacci(7, test_salt());
        assert!(result.is_err(), "Invalid size trace was accepted");

        // Too small size
        let result = prover.prove_fibonacci(1, test_salt());
        assert!(result.is_err(), "Too small trace was accepted");
    }

    #[test]
    fn test_integrated_fibonacci_correctness() {
        let seed = b"test-seed-fib";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();

        // 8-row Fibonacci: last row [F(7), F(8)] = [13, 21]
        let proof = prover.prove_fibonacci(8, test_salt()).unwrap();
        assert_eq!(proof.public_values()[2], 13, "F(7) != 13");
        assert_eq!(proof.public_values()[3], 21, "F(8) != 21");

        // 16-row Fibonacci: last row [F(15), F(16)] = [610, 987]
        let proof = prover.prove_fibonacci(16, test_salt()).unwrap();
        assert_eq!(proof.public_values()[2], 610, "F(15) != 610");
        assert_eq!(proof.public_values()[3], 987, "F(16) != 987");
    }

    #[test]
    fn test_integrated_multiple_verifications() {
        let seed = b"test-seed-multi";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let proof = prover.prove_fibonacci(8, test_salt()).unwrap();
        let verifier = prover.get_verifier();

        // Same proof verified multiple times should always return same result
        for i in 0..10 {
            let is_valid = verifier.verify(&proof).unwrap();
            assert!(is_valid, "Verification {} failed", i + 1);
        }
    }

    // ============================================================
    // Committed Public Values Tests
    // ============================================================

    #[test]
    fn test_committed_prove_and_verify() {
        let seed = b"test-seed-privacy";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let pv_salt = test_salt();
        let proof = prover.prove_fibonacci(8, pv_salt).unwrap();

        assert_ne!(proof.committed_values_hash(), &[0u8; 32]);
        assert_eq!(proof.pv_salt, Some(pv_salt));

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        assert!(is_valid, "Valid proof was rejected");
    }

    #[test]
    fn test_verify_with_salt() {
        let seed = b"test-seed-verify-salt";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let pv_salt = test_salt();
        let proof = prover.prove_fibonacci(8, pv_salt).unwrap();
        let public_values = proof.public_values().to_vec();

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify_with_salt(&proof, &public_values, &pv_salt).unwrap();
        assert!(is_valid, "verify_with_salt rejected valid proof");
    }

    #[test]
    fn test_tampered_commitment() {
        let seed = b"test-seed-tamper-commit";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let mut proof = prover.prove_fibonacci(8, test_salt()).unwrap();

        // Tamper with the commitment
        proof.committed_public_values.commitment[0] ^= 0xFF;

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        assert!(!is_valid, "Tampered commitment was accepted");
    }

    #[test]
    fn test_wrong_salt_verify_with_salt() {
        let seed = b"test-seed-wrong-salt";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let pv_salt = test_salt();
        let proof = prover.prove_fibonacci(8, pv_salt).unwrap();
        let public_values = proof.public_values().to_vec();

        let wrong_salt = [99u8; 32];
        let verifier = prover.get_verifier();
        let is_valid = verifier.verify_with_salt(&proof, &public_values, &wrong_salt).unwrap();
        assert!(!is_valid, "Wrong salt was accepted in verify_with_salt");
    }

    #[test]
    fn test_erase_salt_gdpr() {
        let seed = b"test-seed-gdpr";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let pv_salt = test_salt();
        let mut proof = prover.prove_fibonacci(8, pv_salt).unwrap();

        // Proof is valid before salt erasure
        let verifier = prover.get_verifier();
        assert!(verifier.verify(&proof).unwrap());

        // Erase salt (GDPR deletion)
        proof.erase_salt();
        assert!(proof.pv_salt.is_none());

        // Proof is still verifiable (without salt, just binding hash check)
        assert!(verifier.verify(&proof).unwrap());

        // But verify_with_salt fails (can't re-derive commitment without salt)
        let public_values = proof.public_values().to_vec();
        let is_valid = verifier.verify_with_salt(&proof, &public_values, &[0u8; 32]).unwrap();
        assert!(!is_valid, "verify_with_salt succeeded after salt erasure");
    }

    #[test]
    fn test_different_salts_different_binding_hashes() {
        let seed = b"test-seed-salt-diff";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();

        let proof_a = prover.prove_fibonacci(8, [1u8; 32]).unwrap();
        let proof_b = prover.prove_fibonacci(8, [2u8; 32]).unwrap();

        // Different salts produce different binding hashes
        assert_ne!(
            proof_a.binding_hash, proof_b.binding_hash,
            "Different salts should produce different binding hashes"
        );
    }

    // ============================================================
    // Sum/Mul/Range Integrated Tests
    // ============================================================

    #[test]
    fn test_integrated_sum_prove_and_verify() {
        let seed = b"test-seed-sum-integrated";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let a = vec![1u64, 2, 3, 4];
        let b = vec![10u64, 20, 30, 40];
        let proof = prover.prove_sum(&a, &b, test_salt()).unwrap();

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        assert!(is_valid, "Valid integrated sum proof was rejected");
    }

    #[test]
    fn test_integrated_mul_prove_and_verify() {
        let seed = b"test-seed-mul-integrated";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let a = vec![2u64, 3, 4, 5];
        let b = vec![10u64, 20, 30, 40];
        let proof = prover.prove_multiplication(&a, &b, test_salt()).unwrap();

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        assert!(is_valid, "Valid integrated multiplication proof was rejected");
    }

    #[test]
    fn test_integrated_range_prove_and_verify() {
        let seed = b"test-seed-range-integrated";
        let epoch = Epoch::new(100);

        let prover = IntegratedProver::new(seed, epoch).unwrap();
        let proof = prover.prove_range(1000, 500, test_salt()).unwrap();

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify(&proof).unwrap();
        assert!(is_valid, "Valid integrated range proof was rejected");
    }

    #[test]
    fn test_integrated_sum_wrong_epoch() {
        let seed = b"test-seed-sum-epoch";

        let prover = IntegratedProver::new(seed, Epoch::new(100)).unwrap();
        let a = vec![1u64, 2, 3, 4];
        let b = vec![10u64, 20, 30, 40];
        let proof = prover.prove_sum(&a, &b, test_salt()).unwrap();

        let wrong_verifier = IntegratedVerifier::new(seed, Epoch::new(200)).unwrap();
        let is_valid = wrong_verifier.verify(&proof).unwrap();
        assert!(!is_valid, "Sum proof from wrong epoch was accepted");
    }
}
