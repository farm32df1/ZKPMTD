//! Real Plonky3 STARK (full-p3 feature required)

use crate::core::errors::{Result, ZKMTDError};

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// Plonky3 Core
use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

// Plonky3 STARK Components
use p3_challenger::{CanObserve, DuplexChallenger};
use p3_commit::ExtensionMmcs;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};

// AIR
use crate::stark::air::SimpleAir;
use crate::stark::range_air::RangeAir;

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
type Perm = Poseidon2Goldilocks<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    MyHash,
    MyCompress,
    2,
    8,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Pcs = TwoAdicFriPcs<Val, p3_dft::Radix2DitParallel<Val>, ValMmcs, ChallengeMmcs>;
type MyChallenger = DuplexChallenger<Val, Perm, 16, 8>;
pub type MyStarkConfig = StarkConfig<Pcs, Challenge, MyChallenger>;

/// Identifies which AIR circuit was used to generate a proof
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAirType {
    Fibonacci = 0,
    Sum = 1,
    Multiplication = 2,
    Range = 3,
}

impl ProofAirType {
    /// Convert to a unique byte for binding hash inclusion.
    /// This ensures proofs cannot be reused across different AIR types.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

pub struct RealStarkProver {
    air: SimpleAir,
    perm: Perm,
    /// Per-epoch MTD seed observed into the Fiat-Shamir transcript (H-3).
    /// Zero for standalone use (epoch-independent).
    mtd_seed: [u8; 32],
}

impl Clone for RealStarkProver {
    fn clone(&self) -> Self {
        Self {
            air: self.air.clone(),
            perm: self.perm.clone(),
            mtd_seed: self.mtd_seed,
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
        Ok(Self { air, perm, mtd_seed: [0u8; 32] })
    }

    /// Bind a per-epoch MTD seed into the STARK Fiat-Shamir transcript (H-3),
    /// making proofs genuinely epoch-specific. Standalone provers use a zero
    /// seed; the MTD/integrated layer sets the current epoch's `fri_seed` here.
    pub fn set_mtd_seed(&mut self, mtd_seed: [u8; 32]) {
        self.mtd_seed = mtd_seed;
    }

    pub fn prove_fibonacci(&self, num_rows: usize) -> Result<RealProof> {
        // 1. Generate trace
        let trace = build_fibonacci_trace(num_rows)?;

        // 2. Public values (initial + final values)
        let public_values = compute_public_values(num_rows);

        // 3. Create STARK configuration (challenger embedded in config)
        let config = create_stark_config(&self.perm, &self.mtd_seed);

        // 4. Generate actual STARK proof
        let proof = prove(&config, &self.air, trace, &public_values);

        // 7. Wrap proof
        Ok(RealProof {
            num_rows,
            public_values: public_values.iter().map(|v| v.as_canonical_u64()).collect(),
            air_type: ProofAirType::Fibonacci,
            inner: proof,
            perm: self.perm.clone(),
        })
    }

    /// Prove `a[i] + b[i] = c[i]` for all rows
    pub fn prove_sum(&self, a_values: &[u64], b_values: &[u64]) -> Result<RealProof> {
        let air = SimpleAir::sum();
        let trace = build_sum_trace_p3(a_values, b_values)?;
        let num_rows = trace.height();
        let public_values = compute_sum_public_values(a_values, b_values);

        let config = create_stark_config(&self.perm, &self.mtd_seed);
        let proof = prove(&config, &air, trace, &public_values);

        Ok(RealProof {
            num_rows,
            public_values: public_values.iter().map(|v| v.as_canonical_u64()).collect(),
            air_type: ProofAirType::Sum,
            inner: proof,
            perm: self.perm.clone(),
        })
    }

    /// Prove `a[i] * b[i] = c[i]` for all rows
    pub fn prove_multiplication(&self, a_values: &[u64], b_values: &[u64]) -> Result<RealProof> {
        let air = SimpleAir::multiplication();
        let trace = build_mul_trace_p3(a_values, b_values)?;
        let num_rows = trace.height();
        let public_values = compute_mul_public_values(a_values, b_values);

        let config = create_stark_config(&self.perm, &self.mtd_seed);
        let proof = prove(&config, &air, trace, &public_values);

        Ok(RealProof {
            num_rows,
            public_values: public_values.iter().map(|v| v.as_canonical_u64()).collect(),
            air_type: ProofAirType::Multiplication,
            inner: proof,
            perm: self.perm.clone(),
        })
    }

    /// Prove value >= threshold via bit decomposition
    pub fn prove_range(&self, value: u64, threshold: u64) -> Result<RealProof> {
        let air = RangeAir::new();
        let trace = crate::stark::range_air::trace_builder::build_range_proof_trace(value, threshold)?;
        let num_rows = trace.height();
        let public_values = vec![Val::from_u64(threshold)];

        let config = create_stark_config(&self.perm, &self.mtd_seed);
        let proof = prove(&config, &air, trace, &public_values);

        Ok(RealProof {
            num_rows,
            public_values: public_values.iter().map(|v| v.as_canonical_u64()).collect(),
            air_type: ProofAirType::Range,
            inner: proof,
            perm: self.perm.clone(),
        })
    }

    pub fn get_verifier(&self) -> RealStarkVerifier {
        RealStarkVerifier {
            air: self.air.clone(),
            perm: self.perm.clone(),
            mtd_seed: self.mtd_seed,
        }
    }
}

pub struct RealStarkVerifier {
    air: SimpleAir,
    perm: Perm,
    /// Per-epoch MTD seed observed into the Fiat-Shamir transcript (H-3).
    mtd_seed: [u8; 32],
}

impl Clone for RealStarkVerifier {
    fn clone(&self) -> Self {
        Self {
            air: self.air.clone(),
            perm: self.perm.clone(),
            mtd_seed: self.mtd_seed,
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
        Ok(Self { air, perm, mtd_seed: [0u8; 32] })
    }

    /// Bind the per-epoch MTD seed used to verify (H-3). Must match the seed the
    /// prover used (i.e. the same epoch's `fri_seed`) or verification fails.
    pub fn set_mtd_seed(&mut self, mtd_seed: [u8; 32]) {
        self.mtd_seed = mtd_seed;
    }

    /// Dispatch verification based on proof's AIR type
    pub fn verify_by_type(&self, proof: &RealProof) -> Result<bool> {
        match proof.air_type {
            ProofAirType::Fibonacci => self.verify_fibonacci(proof),
            ProofAirType::Sum => self.verify_sum(proof),
            ProofAirType::Multiplication => self.verify_multiplication(proof),
            ProofAirType::Range => self.verify_range(proof),
        }
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
            .map(|&v| Val::from_u64(v))
            .collect();

        // 2. Create STARK configuration (using same perm, challenger embedded)
        let config = create_stark_config(&proof.perm, &self.mtd_seed);

        // 3. Actual STARK verification
        match verify(&config, &self.air, &proof.inner, &public_values) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn verify_sum(&self, proof: &RealProof) -> Result<bool> {
        // SOUNDNESS: Verify num_rows is power of 2 (STARK requirement)
        if !proof.num_rows.is_power_of_two()
            || !(2..=crate::utils::constants::MAX_TRACE_ROWS).contains(&proof.num_rows)
        {
            return Ok(false);
        }

        let air = SimpleAir::sum();
        let public_values: Vec<Val> = proof
            .public_values
            .iter()
            .map(|&v| Val::from_u64(v))
            .collect();

        let config = create_stark_config(&proof.perm, &self.mtd_seed);

        match verify(&config, &air, &proof.inner, &public_values) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn verify_multiplication(&self, proof: &RealProof) -> Result<bool> {
        // SOUNDNESS: Verify num_rows is power of 2 (STARK requirement)
        if !proof.num_rows.is_power_of_two()
            || !(2..=crate::utils::constants::MAX_TRACE_ROWS).contains(&proof.num_rows)
        {
            return Ok(false);
        }

        let air = SimpleAir::multiplication();
        let public_values: Vec<Val> = proof
            .public_values
            .iter()
            .map(|&v| Val::from_u64(v))
            .collect();

        let config = create_stark_config(&proof.perm, &self.mtd_seed);

        match verify(&config, &air, &proof.inner, &public_values) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn verify_range(&self, proof: &RealProof) -> Result<bool> {
        // SOUNDNESS: Verify num_rows is power of 2 (STARK requirement)
        if !proof.num_rows.is_power_of_two()
            || !(2..=crate::utils::constants::MAX_TRACE_ROWS).contains(&proof.num_rows)
        {
            return Ok(false);
        }

        let air = RangeAir::new();
        let public_values: Vec<Val> = proof
            .public_values
            .iter()
            .map(|&v| Val::from_u64(v))
            .collect();

        let config = create_stark_config(&proof.perm, &self.mtd_seed);

        match verify(&config, &air, &proof.inner, &public_values) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

pub struct RealProof {
    pub num_rows: usize,
    pub public_values: Vec<u64>,
    pub air_type: ProofAirType,
    inner: Proof<MyStarkConfig>,
    perm: Perm,
}

impl core::fmt::Debug for RealProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealProof")
            .field("num_rows", &self.num_rows)
            .field("public_values", &self.public_values)
            .field("air_type", &self.air_type)
            .field("inner", &"<Proof>")
            .finish()
    }
}

fn create_poseidon2_perm() -> Perm {
    use crate::utils::constants::ZKMTD_POSEIDON2_SEED;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Use deterministic seed from constants (ensures identical hash and proof results)
    let mut rng = ChaCha20Rng::seed_from_u64(ZKMTD_POSEIDON2_SEED);

    Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng)
}

fn create_stark_config(perm: &Perm, mtd_seed: &[u8; 32]) -> MyStarkConfig {
    // Hash and compression functions
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());

    // Merkle Tree commitment (p3 0.5.3: third arg is the number of sibling
    // layers to keep uncompressed; 0 = fully compressed Merkle cap)
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    // FRI parameters (p3 0.5.3+: FriConfig -> FriParameters, proof_of_work_bits
    // split into commit/query grinding).
    //
    // Security: 128-bit *CONJECTURED* soundness (ethSTARK Conjecture 7.3 /
    // [BCI+20] proximity-gap conjecture — the same basis Plonky2/3 and most
    // deployed STARKs use). This is what `FriParameters::conjectured_soundness_bits`
    // reports: log_blowup * num_queries + query_proof_of_work_bits = 2*60 + 8 = 128.
    // - log_blowup=2 → rate 1/4 → 2 bits/query (conjectured)
    // - num_queries=60 → 120 bits
    // - query_proof_of_work_bits=8 → 8 bits grinding
    //
    // PROVEN (unconditional, Johnson-bound) soundness with these parameters is
    // only ~half (~1 bit/query → ~60+8 ≈ 68 bits). Reaching 128-bit *proven*
    // soundness would require roughly doubling num_queries (~120). Acceptable
    // for most uses; tighten num_queries if proven 128-bit is required.
    let fri_params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 60,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    // DFT (Discrete Fourier Transform)
    let dft = p3_dft::Radix2DitParallel::<Val>::default();

    // PCS (Polynomial Commitment Scheme) — p3 0.5.3 dropped the log_n argument
    let pcs = Pcs::new(dft, val_mmcs, fri_params);

    // p3 0.5.3+: the challenger is now stored inside StarkConfig and the
    // prove/verify functions no longer take a challenger argument.
    let mut challenger = MyChallenger::new(perm.clone());

    // H-3: bind the per-epoch MTD seed into the Fiat-Shamir transcript so the
    // proof system is genuinely epoch-specific. A proof produced under one seed
    // yields a different challenge sequence and is rejected under another seed.
    // (Standalone provers/verifiers use an all-zero seed, so they stay mutually
    // consistent and epoch-independent.)
    for chunk in mtd_seed.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        challenger.observe(Val::from_u64(u64::from_le_bytes(buf)));
    }

    StarkConfig::new(pcs, challenger)
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

    if num_rows > crate::utils::constants::MAX_TRACE_ROWS {
        return Err(ZKMTDError::InvalidWitness {
            reason: alloc::format!(
                "Row count {} exceeds maximum {}",
                num_rows,
                crate::utils::constants::MAX_TRACE_ROWS
            ),
        });
    }

    let mut values = Vec::with_capacity(num_rows * 2);
    let mut a = Val::ZERO;
    let mut b = Val::ONE;

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
    let mut a = Val::ZERO;
    let mut b = Val::ONE;

    for _ in 0..(num_rows - 1) {
        let c = a + b;
        a = b;
        b = c;
    }

    // [initial a, initial b, final a, final b]
    vec![Val::ZERO, Val::ONE, a, b]
}

fn verify_public_values_consistency(num_rows: usize, public_values: &[u64]) -> bool {
    // Verify public values count
    if public_values.len() != 4 {
        return false;
    }

    // num_rows must be a bounded power of two. The upper bound prevents an
    // attacker-controlled num_rows from forcing the O(num_rows) recomputation
    // loop below into unbounded work (RT-3 DoS).
    if !num_rows.is_power_of_two()
        || !(2..=crate::utils::constants::MAX_TRACE_ROWS).contains(&num_rows)
    {
        return false;
    }

    // Verify initial values: [0, 1]
    if public_values[0] != 0 || public_values[1] != 1 {
        return false;
    }

    // Compute Fibonacci sequence in Goldilocks field
    let mut a = Val::ZERO;
    let mut b = Val::ONE;

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

/// Build p3 trace for Sum AIR: columns [a, b, c=a+b]
fn build_sum_trace_p3(a_values: &[u64], b_values: &[u64]) -> Result<RowMajorMatrix<Val>> {
    if a_values.len() != b_values.len() {
        return Err(ZKMTDError::InvalidWitness {
            reason: alloc::format!(
                "Array lengths do not match: a={}, b={}",
                a_values.len(),
                b_values.len()
            ),
        });
    }
    if a_values.is_empty() {
        return Err(ZKMTDError::InvalidWitness {
            reason: "Empty input arrays".into(),
        });
    }

    let len = a_values.len();
    // Minimum height 4: degree-2 AIR constraints on a height-2 trace can hit a
    // FRI commitment edge case (CapMismatch) with these parameters; 4 rows is
    // the smallest verified-safe height and keeps proofs tiny.
    let num_rows = len.next_power_of_two().max(4);
    let mut values = Vec::with_capacity(num_rows * 3);

    for i in 0..num_rows {
        // Pad by repeating the last real row so the final trace row matches the
        // public "last" values bound in the AIR (C-1). c = a + b still holds.
        let idx = if i < len { i } else { len - 1 };
        let a = Val::from_u64(a_values[idx]);
        let b = Val::from_u64(b_values[idx]);
        let c = a + b;
        values.push(a);
        values.push(b);
        values.push(c);
    }

    Ok(RowMajorMatrix::new(values, 3))
}

/// Compute public values for Sum AIR: first and last row values.
/// Format: [a_first, b_first, c_first, a_last, b_last, c_last]
/// This allows the verifier to confirm the computation on known inputs/outputs.
fn compute_sum_public_values(a_values: &[u64], b_values: &[u64]) -> Vec<Val> {
    if a_values.is_empty() || b_values.is_empty() {
        return vec![];
    }

    let len = a_values.len();
    let a_first = Val::from_u64(a_values[0]);
    let b_first = Val::from_u64(b_values[0]);
    let c_first = a_first + b_first;

    let a_last = Val::from_u64(a_values[len - 1]);
    let b_last = Val::from_u64(b_values[len - 1]);
    let c_last = a_last + b_last;

    vec![a_first, b_first, c_first, a_last, b_last, c_last]
}

/// Build p3 trace for Multiplication AIR: columns [a, b, c=a*b]
fn build_mul_trace_p3(a_values: &[u64], b_values: &[u64]) -> Result<RowMajorMatrix<Val>> {
    if a_values.len() != b_values.len() {
        return Err(ZKMTDError::InvalidWitness {
            reason: alloc::format!(
                "Array lengths do not match: a={}, b={}",
                a_values.len(),
                b_values.len()
            ),
        });
    }
    if a_values.is_empty() {
        return Err(ZKMTDError::InvalidWitness {
            reason: "Empty input arrays".into(),
        });
    }

    let len = a_values.len();
    // Minimum height 4: degree-2 AIR constraints on a height-2 trace can hit a
    // FRI commitment edge case (CapMismatch) with these parameters; 4 rows is
    // the smallest verified-safe height and keeps proofs tiny.
    let num_rows = len.next_power_of_two().max(4);
    let mut values = Vec::with_capacity(num_rows * 3);

    for i in 0..num_rows {
        // Pad by repeating the last real row so the final trace row matches the
        // public "last" values bound in the AIR (C-1). c = a * b still holds.
        let idx = if i < len { i } else { len - 1 };
        let a = Val::from_u64(a_values[idx]);
        let b = Val::from_u64(b_values[idx]);
        let c = a * b;
        values.push(a);
        values.push(b);
        values.push(c);
    }

    Ok(RowMajorMatrix::new(values, 3))
}

/// Compute public values for Multiplication AIR: first and last row values.
/// Format: [a_first, b_first, c_first, a_last, b_last, c_last]
/// This allows the verifier to confirm the computation on known inputs/outputs.
fn compute_mul_public_values(a_values: &[u64], b_values: &[u64]) -> Vec<Val> {
    if a_values.is_empty() || b_values.is_empty() {
        return vec![];
    }

    let len = a_values.len();
    let a_first = Val::from_u64(a_values[0]);
    let b_first = Val::from_u64(b_values[0]);
    let c_first = a_first * b_first;

    let a_last = Val::from_u64(a_values[len - 1]);
    let b_last = Val::from_u64(b_values[len - 1]);
    let c_last = a_last * b_last;

    vec![a_first, b_first, c_first, a_last, b_last, c_last]
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
        assert_eq!(pv[0], Val::ZERO); // F(0) = 0
        assert_eq!(pv[1], Val::ONE); // F(1) = 1
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

    // ============================================================
    // C-1 soundness: public values are now bound in-circuit, so a proof
    // carrying forged public values must be rejected by the STARK verifier.
    // (Before the public-value binding fix these forgeries verified.)
    // ============================================================

    #[test]
    fn test_c1_sum_rejects_forged_public_values() {
        let prover = RealStarkProver::new(SimpleAir::sum()).unwrap();
        let mut proof = prover.prove_sum(&[3, 5], &[4, 6]).unwrap();
        let verifier = prover.get_verifier();
        assert!(verifier.verify_sum(&proof).unwrap(), "valid Sum proof should verify");

        // Forge the claimed first-row output (c_first) to a false value.
        proof.public_values[2] = proof.public_values[2].wrapping_add(1);
        assert!(
            !verifier.verify_sum(&proof).unwrap(),
            "Sum proof with forged public values must be rejected"
        );
    }

    #[test]
    fn test_c1_multiplication_rejects_forged_public_values() {
        let prover = RealStarkProver::new(SimpleAir::multiplication()).unwrap();
        let mut proof = prover.prove_multiplication(&[3, 5], &[4, 6]).unwrap();
        let verifier = prover.get_verifier();
        assert!(verifier.verify_multiplication(&proof).unwrap());

        // Forge the claimed last-row output (c_last).
        proof.public_values[5] = proof.public_values[5].wrapping_add(1);
        assert!(
            !verifier.verify_multiplication(&proof).unwrap(),
            "Multiplication proof with forged public values must be rejected"
        );
    }

    #[test]
    fn test_c1_range_rejects_forged_threshold() {
        let prover = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
        let mut proof = prover.prove_range(100, 50).unwrap();
        let verifier = prover.get_verifier();
        assert!(verifier.verify_range(&proof).unwrap());

        // Claim a public threshold different from the one bound in the trace.
        proof.public_values[0] = 99_999;
        assert!(
            !verifier.verify_range(&proof).unwrap(),
            "Range proof with forged public threshold must be rejected"
        );
    }

    #[test]
    fn test_c1_fibonacci_rejects_forged_final_value() {
        let prover = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
        let mut proof = prover.prove_fibonacci(16).unwrap();
        let verifier = prover.get_verifier();
        assert!(verifier.verify_fibonacci(&proof).unwrap());

        // Forge the claimed final value (bound to the last trace row in-circuit).
        proof.public_values[3] = proof.public_values[3].wrapping_add(1);
        assert!(
            !verifier.verify_fibonacci(&proof).unwrap(),
            "Fibonacci proof with forged final value must be rejected"
        );
    }

    #[test]
    fn test_h3_mtd_seed_binds_stark_transcript() {
        // H-3: the per-epoch MTD seed is observed into the Fiat-Shamir transcript,
        // so a proof produced under one seed must be rejected by a verifier using
        // a different seed. The STARK itself is now seed/epoch-specific, not just
        // gated by an out-of-band epoch comparison.
        let mut prover = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
        prover.set_mtd_seed([7u8; 32]);
        let proof = prover.prove_fibonacci(8).unwrap();

        // Same seed verifies.
        assert!(prover.get_verifier().verify_fibonacci(&proof).unwrap());

        // Different MTD seed => different transcript => rejected.
        let mut other = RealStarkVerifier::new(SimpleAir::fibonacci()).unwrap();
        other.set_mtd_seed([8u8; 32]);
        assert!(
            !other.verify_fibonacci(&proof).unwrap(),
            "proof must be rejected under a different MTD seed"
        );
    }

    #[test]
    fn test_rt3_oversized_num_rows_rejected() {
        // RT-3: an attacker-controlled num_rows above MAX_TRACE_ROWS must be
        // rejected immediately, before the O(num_rows) consistency loop. If the
        // cap regressed, this test would hang instead of returning quickly.
        let prover = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
        let verifier = prover.get_verifier();
        let mut proof = prover.prove_fibonacci(8).unwrap();

        proof.num_rows = 1usize << 30; // power of two, far over MAX_TRACE_ROWS
        assert!(
            !verifier.verify_fibonacci(&proof).unwrap(),
            "oversized num_rows must be rejected without running the O(num_rows) loop"
        );
    }
}
