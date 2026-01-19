//! Real Plonky3 STARK (full-p3 feature required)

use crate::core::errors::{Result, ZKMTDError};

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// Plonky3 Core
use p3_field::{extension::BinomialExtensionField, AbstractField, PrimeField64};
use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};
use p3_matrix::dense::RowMajorMatrix;

// Plonky3 STARK Components
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};

// AIR
use crate::stark::air::SimpleAir;

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 16, 7>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = FieldMerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    MyHash,
    MyCompress,
    8,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Pcs = TwoAdicFriPcs<Val, p3_dft::Radix2DitParallel, ValMmcs, ChallengeMmcs>;
type MyChallenger = DuplexChallenger<Val, Perm, 16, 8>;
pub type MyStarkConfig = StarkConfig<Pcs, Challenge, MyChallenger>;

pub struct RealStarkProver {
    air: SimpleAir,
    perm: Perm,
}

impl Clone for RealStarkProver {
    fn clone(&self) -> Self {
        Self {
            air: self.air.clone(),
            perm: self.perm.clone(),
        }
    }
}

impl core::fmt::Debug for RealStarkProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealStarkProver")
            .field("air", &self.air)
            .field("perm", &"<Poseidon2>")
            .finish()
    }
}

impl RealStarkProver {
    pub fn new(air: SimpleAir) -> Result<Self> {
        let perm = create_poseidon2_perm();
        Ok(Self { air, perm })
    }

    pub fn prove_fibonacci(&self, num_rows: usize) -> Result<RealProof> {
        // 1. Generate trace
        let trace = build_fibonacci_trace(num_rows)?;

        // 2. Public values (initial + final values)
        let public_values = compute_public_values(num_rows);

        // 3. Compute log2(num_rows)
        let log_n = num_rows.trailing_zeros() as usize;

        // 4. Create STARK configuration
        let config = create_stark_config(&self.perm, log_n);

        // 5. Create challenger
        let mut challenger = MyChallenger::new(self.perm.clone());

        // 6. Generate actual STARK proof
        let proof = prove(&config, &self.air, &mut challenger, trace, &public_values);

        // 7. Wrap proof
        Ok(RealProof {
            num_rows,
            public_values: public_values.iter().map(|v| v.as_canonical_u64()).collect(),
            inner: proof,
            perm: self.perm.clone(),
        })
    }

    pub fn get_verifier(&self) -> RealStarkVerifier {
        RealStarkVerifier {
            air: self.air.clone(),
            perm: self.perm.clone(),
        }
    }
}

pub struct RealStarkVerifier {
    air: SimpleAir,
    perm: Perm,
}

impl Clone for RealStarkVerifier {
    fn clone(&self) -> Self {
        Self {
            air: self.air.clone(),
            perm: self.perm.clone(),
        }
    }
}

impl core::fmt::Debug for RealStarkVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealStarkVerifier")
            .field("air", &self.air)
            .field("perm", &"<Poseidon2>")
            .finish()
    }
}

impl RealStarkVerifier {
    pub fn new(air: SimpleAir) -> Result<Self> {
        let perm = create_poseidon2_perm();
        Ok(Self { air, perm })
    }

    pub fn verify_fibonacci(&self, proof: &RealProof) -> Result<bool> {
        // 0. Public values integrity verification (soundness guarantee)
        // Public values must match trace computation.
        if !verify_public_values_consistency(proof.num_rows, &proof.public_values) {
            return Ok(false);
        }

        // 1. Restore public values
        let public_values: Vec<Val> = proof
            .public_values
            .iter()
            .map(|&v| Val::from_canonical_u64(v))
            .collect();

        // 2. Compute log2(num_rows)
        let log_n = proof.num_rows.trailing_zeros() as usize;

        // 3. Create STARK configuration (using same perm)
        let config = create_stark_config(&proof.perm, log_n);

        // 4. Create challenger
        let mut challenger = MyChallenger::new(proof.perm.clone());

        // 5. Actual STARK verification
        match verify(
            &config,
            &self.air,
            &mut challenger,
            &proof.inner,
            &public_values,
        ) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

pub struct RealProof {
    pub num_rows: usize,
    pub public_values: Vec<u64>,
    inner: Proof<MyStarkConfig>,
    perm: Perm,
}

impl core::fmt::Debug for RealProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealProof")
            .field("num_rows", &self.num_rows)
            .field("public_values", &self.public_values)
            .field("inner", &"<Proof>")
            .finish()
    }
}

fn create_poseidon2_perm() -> Perm {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Use deterministic seed (ensures identical verification results)
    let mut rng = ChaCha20Rng::seed_from_u64(0x5A4B5D4C3B2A1908);

    Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks,
        &mut rng,
    )
}

fn create_stark_config(perm: &Perm, log_n: usize) -> MyStarkConfig {
    // Hash and compression functions
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());

    // Merkle Tree commitment
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone());
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    // FRI configuration (includes mmcs)
    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 28,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    // DFT (Discrete Fourier Transform)
    let dft = p3_dft::Radix2DitParallel;

    // PCS (Polynomial Commitment Scheme)
    // new(log_n, dft, mmcs, fri)
    let pcs = Pcs::new(log_n, dft, val_mmcs, fri_config);

    StarkConfig::new(pcs)
}

fn build_fibonacci_trace(num_rows: usize) -> Result<RowMajorMatrix<Val>> {
    if !num_rows.is_power_of_two() {
        return Err(ZKMTDError::InvalidWitness {
            reason: alloc::format!("Row count must be power of two: {}", num_rows),
        });
    }

    if num_rows < 2 {
        return Err(ZKMTDError::InvalidWitness {
            reason: alloc::format!("Minimum 2 rows required: {}", num_rows),
        });
    }

    let mut values = Vec::with_capacity(num_rows * 2);
    let mut a = Val::zero();
    let mut b = Val::one();

    for _ in 0..num_rows {
        values.push(a);
        values.push(b);
        let c = a + b;
        a = b;
        b = c;
    }

    Ok(RowMajorMatrix::new(values, 2))
}

fn compute_public_values(num_rows: usize) -> Vec<Val> {
    let mut a = Val::zero();
    let mut b = Val::one();

    for _ in 0..(num_rows - 1) {
        let c = a + b;
        a = b;
        b = c;
    }

    // [initial a, initial b, final a, final b]
    vec![Val::zero(), Val::one(), a, b]
}

fn verify_public_values_consistency(num_rows: usize, public_values: &[u64]) -> bool {
    // Verify public values count
    if public_values.len() != 4 {
        return false;
    }

    // num_rows must be power of two
    if !num_rows.is_power_of_two() || num_rows < 2 {
        return false;
    }

    // Verify initial values: [0, 1]
    if public_values[0] != 0 || public_values[1] != 1 {
        return false;
    }

    // Compute Fibonacci sequence in Goldilocks field
    let mut a = Val::zero();
    let mut b = Val::one();

    for _ in 0..(num_rows - 1) {
        let c = a + b;
        a = b;
        b = c;
    }

    // Compare final values (as Goldilocks field values)
    let expected_a = a.as_canonical_u64();
    let expected_b = b.as_canonical_u64();

    if public_values[2] != expected_a || public_values[3] != expected_b {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_matrix::Matrix;

    #[test]
    fn test_real_stark_prover_creation() {
        let air = SimpleAir::fibonacci();
        let prover = RealStarkProver::new(air);
        assert!(prover.is_ok(), "Prover creation failed");
    }

    #[test]
    fn test_build_fibonacci_trace() {
        let trace = build_fibonacci_trace(8);
        assert!(trace.is_ok());

        let trace = trace.unwrap();
        assert_eq!(trace.height(), 8);
        assert_eq!(trace.width(), 2);
    }

    #[test]
    fn test_compute_public_values() {
        let pv = compute_public_values(8);
        assert_eq!(pv.len(), 4);
        assert_eq!(pv[0], Val::zero()); // F(0) = 0
        assert_eq!(pv[1], Val::one()); // F(1) = 1
                                       // F(6) = 8, F(7) = 13 (last row)
    }

    #[test]
    fn test_real_stark_prove_and_verify() {
        let air = SimpleAir::fibonacci();
        let prover = RealStarkProver::new(air).unwrap();

        // Generate proof
        let proof = prover.prove_fibonacci(8).unwrap();
        assert_eq!(proof.num_rows, 8);
        assert_eq!(proof.public_values.len(), 4);

        // Verify
        let verifier = prover.get_verifier();
        let is_valid = verifier.verify_fibonacci(&proof).unwrap();
        assert!(is_valid, "Valid proof was rejected");
    }

    #[test]
    fn test_real_stark_invalid_trace_size() {
        let air = SimpleAir::fibonacci();
        let prover = RealStarkProver::new(air).unwrap();

        // Non-power-of-two size
        let result = prover.prove_fibonacci(7);
        assert!(result.is_err(), "Invalid size trace was accepted");
    }

    #[test]
    fn test_real_stark_larger_trace() {
        let air = SimpleAir::fibonacci();
        let prover = RealStarkProver::new(air).unwrap();

        // Larger trace
        let proof = prover.prove_fibonacci(64).unwrap();

        let verifier = prover.get_verifier();
        let is_valid = verifier.verify_fibonacci(&proof).unwrap();
        assert!(is_valid, "Large trace proof was rejected");
    }
}
