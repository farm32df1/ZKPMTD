//! Range Proof AIR - proves value >= threshold without revealing value

use crate::core::errors::{Result, ZKMTDError};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use p3_air::Air as P3Air;
use p3_air::{AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

pub const RANGE_BITS: usize = 32;

#[derive(Debug, Clone)]
pub struct RangeAir {
    num_bits: usize,
}

impl RangeAir {
    pub fn new() -> Self {
        Self {
            num_bits: RANGE_BITS,
        }
    }

    pub fn with_bits(num_bits: usize) -> Self {
        Self { num_bits }
    }

    pub fn width(&self) -> usize {
        // bits + value + threshold + diff
        self.num_bits + 3
    }
}

impl Default for RangeAir {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseAir<Goldilocks> for RangeAir {
    fn width(&self) -> usize {
        self.num_bits + 3
    }
}

impl<AB: AirBuilder<F = Goldilocks>> P3Air<AB> for RangeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);

        // Column indices
        let bits_end = self.num_bits;
        let value_idx = bits_end;
        let threshold_idx = bits_end + 1;
        let diff_idx = bits_end + 2;

        // 1. Verify each bit is binary (0 or 1)
        // Constraint: bit * (1 - bit) = 0
        for i in 0..self.num_bits {
            let bit = local[i];
            builder.assert_zero(bit * (AB::Expr::one() - bit));
        }

        // 2. Verify diff = value - threshold
        let value = local[value_idx];
        let threshold = local[threshold_idx];
        let diff = local[diff_idx];
        builder.assert_eq(diff, value - threshold);

        // 3. Verify bit decomposition: sum(bit_i * 2^i) = diff
        let mut reconstructed = AB::Expr::zero();
        let mut power_of_two = AB::Expr::one();

        for i in 0..self.num_bits {
            reconstructed += local[i] * power_of_two.clone();
            power_of_two *= AB::Expr::from_canonical_u64(2);
        }

        builder.assert_eq(reconstructed, diff);
    }
}

#[cfg(feature = "alloc")]
pub mod trace_builder {
    use super::*;

    pub fn build_range_proof_trace(
        value: u64,
        threshold: u64,
    ) -> Result<RowMajorMatrix<Goldilocks>> {
        if value < threshold {
            return Err(ZKMTDError::InvalidWitness {
                reason: alloc::format!("Value {} is less than threshold {}", value, threshold),
            });
        }

        let diff = value - threshold;

        // Decompose diff into bits
        let mut bits = Vec::with_capacity(RANGE_BITS);
        let mut remaining = diff;
        for _ in 0..RANGE_BITS {
            bits.push(Goldilocks::from_canonical_u64(remaining & 1));
            remaining >>= 1;
        }

        // Build trace row: [bits..., value, threshold, diff]
        let mut row = bits;
        row.push(Goldilocks::from_canonical_u64(value));
        row.push(Goldilocks::from_canonical_u64(threshold));
        row.push(Goldilocks::from_canonical_u64(diff));

        // For STARK, we need power-of-two rows, so duplicate the row
        let width = RANGE_BITS + 3;
        let mut values = Vec::with_capacity(width * 2);
        values.extend_from_slice(&row);
        values.extend_from_slice(&row); // Duplicate for 2 rows

        Ok(RowMajorMatrix::new(values, width))
    }

    pub fn build_range_in_bounds_trace(
        value: u64,
        min: u64,
        max: u64,
    ) -> Result<(RowMajorMatrix<Goldilocks>, RowMajorMatrix<Goldilocks>)> {
        // Prove: value >= min AND value <= max
        // Second condition: max >= value, i.e., max - value >= 0

        let trace_lower = build_range_proof_trace(value, min)?;
        let trace_upper = build_range_proof_trace(max, value)?;

        Ok((trace_lower, trace_upper))
    }
}

#[derive(Debug, Clone)]
pub struct RangeProofPublicInputs {
    pub threshold: u64,
    pub value_commitment: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_matrix::Matrix;

    #[test]
    fn test_range_air_creation() {
        let air = RangeAir::new();
        assert_eq!(air.width(), RANGE_BITS + 3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_range_proof_trace_valid() {
        use trace_builder::build_range_proof_trace;

        // Prove: 25 >= 18
        let trace = build_range_proof_trace(25, 18).unwrap();
        assert_eq!(trace.height(), 2);
        assert_eq!(trace.width(), RANGE_BITS + 3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_range_proof_trace_invalid() {
        use trace_builder::build_range_proof_trace;

        // Try to prove: 15 >= 18 (should fail)
        let result = build_range_proof_trace(15, 18);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_bit_decomposition() {
        use p3_field::PrimeField64;
        use trace_builder::build_range_proof_trace;

        // Prove: 25 >= 18, diff = 7 = 0b111
        let trace = build_range_proof_trace(25, 18).unwrap();

        // Check bits of diff=7: [1, 1, 1, 0, 0, ...]
        let row: Vec<Goldilocks> = trace.row(0).collect();
        assert_eq!(row[0].as_canonical_u64(), 1); // bit 0
        assert_eq!(row[1].as_canonical_u64(), 1); // bit 1
        assert_eq!(row[2].as_canonical_u64(), 1); // bit 2
        assert_eq!(row[3].as_canonical_u64(), 0); // bit 3
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_range_in_bounds() {
        use trace_builder::build_range_in_bounds_trace;

        // Prove: 22 is in range [18, 65]
        let result = build_range_in_bounds_trace(22, 18, 65);
        assert!(result.is_ok());

        // Prove: 17 is in range [18, 65] (should fail - below min)
        let result = build_range_in_bounds_trace(17, 18, 65);
        assert!(result.is_err());
    }
}
