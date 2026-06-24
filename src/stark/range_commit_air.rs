//! RT-1 fix: range proof that binds the private `value` to a PUBLIC Poseidon2
//! commitment in-circuit.
//!
//! The plain `RangeAir` leaves `value` a free witness, so it only proves
//! "∃ value ≥ threshold". This AIR additionally computes `commitment =
//! Poseidon2([value, salt, 0..])[0]` inside the circuit and binds it to a public
//! input, so the proof attests "the COMMITTED value ≥ threshold". The verifier
//! (who holds the trusted `value_commitment`) is now convinced about a specific
//! committed value rather than an arbitrary existential one.

use crate::core::errors::{Result, ZKMTDError};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks, Goldilocks};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2_air::{generate_trace_rows, num_cols, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_uni_stark::SubAirBuilder;

// Goldilocks Poseidon2 parameters (must match p3-goldilocks' width-16 instance).
const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = 7;
const SBOX_REGISTERS: usize = 1; // x^7 via one committed x^3 -> max AIR degree 3
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 22;

type LinLayers = GenericPoseidon2LinearLayersGoldilocks;
type P2Air = Poseidon2Air<
    Goldilocks,
    LinLayers,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;
type P2Cols<T> =
    Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

/// Number of Poseidon2 columns.
pub const POSEIDON_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

const RANGE_BITS: usize = 32;
/// Range columns: [bit0..bit31, value, threshold, diff].
const RANGE_WIDTH: usize = RANGE_BITS + 3;
const VALUE_IDX: usize = RANGE_BITS;
const THRESHOLD_IDX: usize = RANGE_BITS + 1;
const DIFF_IDX: usize = RANGE_BITS + 2;

/// Combined trace width.
pub const TOTAL_WIDTH: usize = POSEIDON_COLS + RANGE_WIDTH;

/// Minimum trace height (degree-3 constraints on a tiny trace can hit FRI edge
/// cases; 4 is verified-safe — same rationale as the Sum/Mul builders).
const HEIGHT: usize = 4;

/// Maximum value/threshold (field-overflow protection, identical to RangeAir).
pub const MAX_RANGE_VALUE: u64 = 1u64 << RANGE_BITS;

/// Deterministic Poseidon2 round constants for the in-circuit commitment.
/// Both prover (trace generation) and verifier (AIR) derive the SAME constants,
/// and the public commitment is defined as this permutation's output — so the
/// commitment is self-consistent regardless of the library's sponge hash.
/// Domain-separation tweak for the in-circuit commitment Poseidon2 (XORed into
/// the sponge seed so the commitment hash is independent of `poseidon_hash`).
const COMMIT_SEED_DOMAIN_SEP: u64 = 0x52_4E_47_43_4D_54_31; // b"RNGCMT1"

fn commit_round_constants() -> RoundConstants<Goldilocks, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    // Distinct from the sponge seed so the two are domain-separated.
    let seed = crate::utils::constants::ZKMTD_POSEIDON2_SEED ^ COMMIT_SEED_DOMAIN_SEP;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    RoundConstants::from_rng(&mut rng)
}

pub struct RangeCommitAir {
    poseidon: P2Air,
}

impl core::fmt::Debug for RangeCommitAir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RangeCommitAir").finish()
    }
}

impl Default for RangeCommitAir {
    fn default() -> Self {
        Self::new()
    }
}

impl RangeCommitAir {
    pub fn new() -> Self {
        Self {
            poseidon: Poseidon2Air::new(commit_round_constants()),
        }
    }
}

impl BaseAir<Goldilocks> for RangeCommitAir {
    fn width(&self) -> usize {
        TOTAL_WIDTH
    }

    fn num_public_values(&self) -> usize {
        // [threshold, value_commitment]
        2
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for RangeCommitAir {
    fn eval(&self, builder: &mut AB) {
        // 1. Poseidon2 permutation constraints on the first POSEIDON_COLS columns.
        {
            let mut sub = SubAirBuilder::<AB, P2Air, Goldilocks>::new(builder, 0..POSEIDON_COLS);
            self.poseidon.eval(&mut sub);
        }

        let main = builder.main();
        let row = main.current_slice();
        let p_cols: &P2Cols<AB::Var> = row[0..POSEIDON_COLS].borrow();

        // Poseidon input[0] = the value being committed; input[1] = salt (blinding).
        let p_value = p_cols.inputs[0];
        // Poseidon output = post-state of the final ending full round.
        let p_commit = p_cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[0];

        // Range columns (offset by POSEIDON_COLS).
        let r_value = row[POSEIDON_COLS + VALUE_IDX];
        let r_threshold = row[POSEIDON_COLS + THRESHOLD_IDX];
        let r_diff = row[POSEIDON_COLS + DIFF_IDX];

        // Public values.
        let pis = builder.public_values();
        let pub_threshold = pis[0];
        let pub_commit = pis[1];

        // 2. Range constraints (identical to RangeAir).
        let mut reconstructed = AB::Expr::ZERO;
        let mut power_of_two = AB::Expr::ONE;
        for i in 0..RANGE_BITS {
            let bit = row[POSEIDON_COLS + i];
            builder.assert_zero(bit * (AB::Expr::ONE - bit)); // binary
            reconstructed += bit * power_of_two.clone();
            power_of_two *= AB::Expr::from_u64(2);
        }
        builder.assert_eq(r_diff, r_value - r_threshold); // diff = value - threshold
        builder.assert_eq(reconstructed, r_diff); // 32-bit decomposition

        // 3. Bind threshold to the public input (C-1).
        builder.assert_eq(r_threshold, pub_threshold);

        // 4. RT-1 LINK: the range `value` IS the committed value, and the
        //    Poseidon2 output IS the public commitment.
        builder.assert_eq(r_value, p_value);
        builder.assert_eq(p_commit, pub_commit);
    }
}

/// Build the combined trace and return it together with the public commitment
/// `Poseidon2([value, salt, 0..])[0]`.
#[cfg(feature = "alloc")]
pub fn build_range_commit_trace(
    value: u64,
    threshold: u64,
    salt: u64,
) -> Result<(RowMajorMatrix<Goldilocks>, Goldilocks)> {
    if value >= MAX_RANGE_VALUE {
        return Err(ZKMTDError::InvalidWitness {
            reason: alloc::format!("Value {} exceeds maximum {}", value, MAX_RANGE_VALUE - 1),
        });
    }
    if threshold >= MAX_RANGE_VALUE {
        return Err(ZKMTDError::InvalidWitness {
            reason: alloc::format!("Threshold {} exceeds maximum {}", threshold, MAX_RANGE_VALUE - 1),
        });
    }
    if value < threshold {
        return Err(ZKMTDError::InvalidWitness {
            reason: alloc::format!("Value {} is less than threshold {}", value, threshold),
        });
    }
    let diff = value - threshold;

    // Poseidon2 input state [value, salt, 0, ..., 0].
    let mut input = [Goldilocks::ZERO; WIDTH];
    input[0] = Goldilocks::from_u64(value);
    input[1] = Goldilocks::from_u64(salt);

    let constants = commit_round_constants();
    let inputs: Vec<[Goldilocks; WIDTH]> = alloc::vec![input; HEIGHT];
    let p_trace = generate_trace_rows::<
        Goldilocks,
        LinLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &constants, 0);

    // Extract the commitment from row 0's final post-state.
    let commitment = {
        let row0 = p_trace.row_slice(0).expect("trace has rows");
        let cols: &P2Cols<Goldilocks> = row0[0..POSEIDON_COLS].borrow();
        cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[0]
    };

    // Range columns: [bit0..bit31, value, threshold, diff].
    let mut range_row = Vec::with_capacity(RANGE_WIDTH);
    let mut rem = diff;
    for _ in 0..RANGE_BITS {
        range_row.push(Goldilocks::from_u64(rem & 1));
        rem >>= 1;
    }
    range_row.push(Goldilocks::from_u64(value));
    range_row.push(Goldilocks::from_u64(threshold));
    range_row.push(Goldilocks::from_u64(diff));

    // Combine per row: [poseidon cols | range cols].
    let mut values = Vec::with_capacity(HEIGHT * TOTAL_WIDTH);
    for i in 0..HEIGHT {
        let p_row = p_trace.row_slice(i).expect("trace row");
        values.extend_from_slice(&p_row[0..POSEIDON_COLS]);
        values.extend_from_slice(&range_row);
    }

    Ok((RowMajorMatrix::new(values, TOTAL_WIDTH), commitment))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::Field;
    use p3_goldilocks::Poseidon2Goldilocks;

    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_fri::{FriParameters, TwoAdicFriPcs};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_uni_stark::{prove, verify, StarkConfig};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 2>;
    type Perm = Poseidon2Goldilocks<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type ValMmcs =
        MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Pcs = TwoAdicFriPcs<Val, p3_dft::Radix2DitParallel<Val>, ValMmcs, ChallengeMmcs>;
    type MyChallenger = DuplexChallenger<Val, Perm, 16, 8>;
    type Cfg = StarkConfig<Pcs, Challenge, MyChallenger>;

    fn config() -> Cfg {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let perm = Perm::new_from_rng_128(&mut rng);
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = ValMmcs::new(hash, compress, 0);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri = FriParameters {
            log_blowup: 2,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: 28,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 8,
            mmcs: challenge_mmcs,
        };
        let dft = p3_dft::Radix2DitParallel::<Val>::default();
        let pcs = Pcs::new(dft, val_mmcs, fri);
        StarkConfig::new(pcs, MyChallenger::new(perm))
    }

    #[test]
    fn rt1_roundtrip() {
        let air = RangeCommitAir::new();
        let cfg = config();
        let (trace, commit) = build_range_commit_trace(100, 50, 12345).unwrap();
        let pubs = [Goldilocks::from_u64(50), commit];
        let proof = prove(&cfg, &air, trace, &pubs);
        assert!(
            verify(&cfg, &air, &proof, &pubs).is_ok(),
            "honest committed-range proof must verify"
        );
    }

    #[test]
    fn rt1_public_commitment_is_bound() {
        let air = RangeCommitAir::new();
        let cfg = config();
        let (trace, commit) = build_range_commit_trace(100, 50, 12345).unwrap();
        let proof = prove(&cfg, &air, trace, &[Goldilocks::from_u64(50), commit]);
        // A different public commitment must be rejected (value IS bound to it).
        let wrong = [Goldilocks::from_u64(50), commit + Goldilocks::ONE];
        assert!(
            verify(&cfg, &air, &proof, &wrong).is_err(),
            "wrong public commitment accepted"
        );
    }

    #[test]
    fn rt1_threshold_is_bound() {
        let air = RangeCommitAir::new();
        let cfg = config();
        let (trace, commit) = build_range_commit_trace(100, 50, 12345).unwrap();
        let proof = prove(&cfg, &air, trace, &[Goldilocks::from_u64(50), commit]);
        let wrong = [Goldilocks::from_u64(999), commit];
        assert!(
            verify(&cfg, &air, &proof, &wrong).is_err(),
            "wrong public threshold accepted"
        );
    }

    #[test]
    fn rt1_builder_rejects_value_below_threshold() {
        assert!(build_range_commit_trace(5, 10, 1).is_err());
        assert!(build_range_commit_trace(MAX_RANGE_VALUE, 1, 1).is_err());
    }

    #[test]
    fn rt1_commitment_depends_on_value_and_salt() {
        let (_, c1) = build_range_commit_trace(100, 50, 1).unwrap();
        let (_, c2) = build_range_commit_trace(200, 50, 1).unwrap();
        let (_, c3) = build_range_commit_trace(100, 50, 2).unwrap();
        assert_ne!(c1, c2, "commitment must depend on value");
        assert_ne!(c1, c3, "commitment must depend on salt");
    }
}
