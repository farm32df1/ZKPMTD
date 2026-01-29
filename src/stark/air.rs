//! AIR (Algebraic Intermediate Representation) for STARK polynomial constraints

use crate::core::types::FieldElement;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// Plonky3 imports
use p3_air::Air as P3Air;
use p3_air::{AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

/// Simple AIR for Fibonacci, Sum, Multiplication
#[derive(Debug, Clone)]
pub struct SimpleAir {
    num_columns: usize,
    air_type: AirType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AirType {
    Fibonacci,
    Sum,
    Multiplication,
}

impl SimpleAir {
    pub fn fibonacci() -> Self {
        Self { num_columns: 2, air_type: AirType::Fibonacci }
    }

    pub fn sum() -> Self {
        Self { num_columns: 3, air_type: AirType::Sum }
    }

    pub fn multiplication() -> Self {
        Self { num_columns: 3, air_type: AirType::Multiplication }
    }

    pub fn num_columns(&self) -> usize {
        self.num_columns
    }

    pub fn num_constraints(&self) -> usize {
        1
    }

    pub fn constraint_degree(&self) -> usize {
        match self.air_type {
            AirType::Fibonacci | AirType::Sum => 1,
            AirType::Multiplication => 2,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn evaluate_constraints(&self, trace: &[Vec<FieldElement>], row: usize) -> Vec<FieldElement> {
        let mut constraints = Vec::new();

        match self.air_type {
            AirType::Fibonacci => {
                if row + 2 < trace[0].len() {
                    let expected = trace[0][row].wrapping_add(trace[0][row + 1]);
                    constraints.push(trace[0][row + 2].wrapping_sub(expected));
                }
            }
            AirType::Sum => {
                if trace.len() >= 3 && row < trace[0].len() {
                    let expected = trace[0][row].wrapping_add(trace[1][row]);
                    constraints.push(trace[2][row].wrapping_sub(expected));
                }
            }
            AirType::Multiplication => {
                if trace.len() >= 3 && row < trace[0].len() {
                    let expected = trace[0][row].wrapping_mul(trace[1][row]);
                    constraints.push(trace[2][row].wrapping_sub(expected));
                }
            }
        }

        constraints
    }
}

impl BaseAir<Goldilocks> for SimpleAir {
    fn width(&self) -> usize {
        self.num_columns
    }
}

impl<AB: AirBuilder<F = Goldilocks>> P3Air<AB> for SimpleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        match self.air_type {
            AirType::Fibonacci => {
                builder.when_first_row().assert_eq(local[0], AB::Expr::zero());
                builder.when_first_row().assert_eq(local[1], AB::Expr::one());
                builder.when_transition().assert_eq(next[0], local[1]);
                builder.when_transition().assert_eq(next[1], local[0] + local[1]);
            }
            AirType::Sum => {
                builder.assert_eq(local[2], local[0] + local[1]);
            }
            AirType::Multiplication => {
                builder.assert_eq(local[2], local[0] * local[1]);
            }
        }
    }
}

/// Trace generation helper functions
#[cfg(feature = "alloc")]
pub mod trace_builder {
    use super::*;
    use crate::core::errors::{Result, ZKMTDError};
    use alloc::vec;
    use alloc::vec::Vec;

    pub fn build_fibonacci_trace(
        length: usize,
        initial: [u64; 2],
    ) -> Result<Vec<Vec<FieldElement>>> {
        if !length.is_power_of_two() {
            return Err(ZKMTDError::InvalidWitness {
                reason: alloc::format!("Trace length must be a power of 2: {}", length),
            });
        }
        if length < 2 {
            return Err(ZKMTDError::InvalidWitness {
                reason: alloc::format!("Trace length must be at least 2: {}", length),
            });
        }

        let mut trace = vec![initial[0], initial[1]];

        for i in 2..length {
            let next = trace[i - 2].wrapping_add(trace[i - 1]);
            trace.push(next);
        }

        Ok(vec![trace])
    }

    pub fn build_fibonacci_trace_p3(num_rows: usize) -> Result<RowMajorMatrix<Goldilocks>> {
        use p3_field::AbstractField;

        if !num_rows.is_power_of_two() {
            return Err(ZKMTDError::InvalidWitness {
                reason: alloc::format!("Number of trace rows must be a power of 2: {}", num_rows),
            });
        }

        let mut values = Vec::with_capacity(num_rows * 2);
        let mut a = Goldilocks::zero();
        let mut b = Goldilocks::one();

        for _ in 0..num_rows {
            values.push(a);
            values.push(b);

            let c = a + b;
            a = b;
            b = c;
        }

        Ok(RowMajorMatrix::new(values, 2))
    }

    pub fn build_sum_trace(
        a_values: Vec<u64>,
        b_values: Vec<u64>,
    ) -> Result<Vec<Vec<FieldElement>>> {
        if a_values.len() != b_values.len() {
            return Err(ZKMTDError::InvalidWitness {
                reason: alloc::format!(
                    "Array lengths do not match: a={}, b={}",
                    a_values.len(),
                    b_values.len()
                ),
            });
        }

        let sum_values: Vec<FieldElement> = a_values
            .iter()
            .zip(b_values.iter())
            .map(|(&a, &b)| a.wrapping_add(b))
            .collect();

        Ok(vec![a_values, b_values, sum_values])
    }

    pub fn build_multiplication_trace(
        a_values: Vec<u64>,
        b_values: Vec<u64>,
    ) -> Result<Vec<Vec<FieldElement>>> {
        if a_values.len() != b_values.len() {
            return Err(ZKMTDError::InvalidWitness {
                reason: alloc::format!(
                    "Array lengths do not match: a={}, b={}",
                    a_values.len(),
                    b_values.len()
                ),
            });
        }

        let product_values: Vec<FieldElement> = a_values
            .iter()
            .zip(b_values.iter())
            .map(|(&a, &b)| a.wrapping_mul(b))
            .collect();

        Ok(vec![a_values, b_values, product_values])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use trace_builder::*;

    #[test]
    fn test_simple_air_fibonacci() {
        let air = SimpleAir::fibonacci();
        assert_eq!(air.num_columns(), 2);
        assert_eq!(air.num_constraints(), 1);
        assert_eq!(air.constraint_degree(), 1);
    }

    #[test]
    fn test_simple_air_sum() {
        let air = SimpleAir::sum();
        assert_eq!(air.num_columns(), 3);
        assert_eq!(air.num_constraints(), 1);
        assert_eq!(air.constraint_degree(), 1);
    }

    #[test]
    fn test_simple_air_multiplication() {
        let air = SimpleAir::multiplication();
        assert_eq!(air.num_columns(), 3);
        assert_eq!(air.num_constraints(), 1);
        assert_eq!(air.constraint_degree(), 2);
    }

    #[test]
    fn test_base_air_width() {
        let fib = SimpleAir::fibonacci();
        let sum = SimpleAir::sum();
        let mul = SimpleAir::multiplication();

        assert_eq!(BaseAir::<Goldilocks>::width(&fib), 2);
        assert_eq!(BaseAir::<Goldilocks>::width(&sum), 3);
        assert_eq!(BaseAir::<Goldilocks>::width(&mul), 3);
    }

    #[test]
    fn test_air_type_equality() {
        assert_eq!(AirType::Fibonacci, AirType::Fibonacci);
        assert_ne!(AirType::Fibonacci, AirType::Sum);
        assert_ne!(AirType::Sum, AirType::Multiplication);
    }

    #[test]
    fn test_air_type_debug() {
        let t = AirType::Fibonacci;
        let debug = alloc::format!("{:?}", t);
        assert!(debug.contains("Fibonacci"));
    }

    #[test]
    fn test_simple_air_clone() {
        let air = SimpleAir::fibonacci();
        let cloned = air.clone();
        assert_eq!(air.num_columns(), cloned.num_columns());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_fibonacci_trace() {
        let trace = build_fibonacci_trace(8, [0, 1]).unwrap();
        assert_eq!(trace[0].len(), 8);
        assert_eq!(trace[0][0], 0);
        assert_eq!(trace[0][1], 1);
        assert_eq!(trace[0][2], 1);
        assert_eq!(trace[0][3], 2);
        assert_eq!(trace[0][4], 3);
        assert_eq!(trace[0][5], 5);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_fibonacci_trace_not_power_of_two() {
        let result = build_fibonacci_trace(7, [0, 1]);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_fibonacci_trace_too_small() {
        let result = build_fibonacci_trace(1, [0, 1]);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_fibonacci_trace_p3() {
        let matrix = build_fibonacci_trace_p3(8).unwrap();
        assert_eq!(matrix.width(), 2);
        assert_eq!(matrix.height(), 8);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_fibonacci_trace_p3_not_power_of_two() {
        let result = build_fibonacci_trace_p3(7);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_fibonacci_constraints() {
        let air = SimpleAir::fibonacci();
        let trace = build_fibonacci_trace(8, [0, 1]).unwrap();

        for row in 0..(trace[0].len() - 2) {
            let constraints = air.evaluate_constraints(&trace, row);
            assert_eq!(constraints.len(), 1);
            assert_eq!(constraints[0], 0, "Constraint not satisfied at row {}", row);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_fibonacci_constraints_last_rows() {
        let air = SimpleAir::fibonacci();
        let trace = build_fibonacci_trace(8, [0, 1]).unwrap();

        // Last two rows should return empty constraints
        let constraints = air.evaluate_constraints(&trace, 6);
        assert!(constraints.is_empty());
        let constraints = air.evaluate_constraints(&trace, 7);
        assert!(constraints.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_sum_trace() {
        let a = vec![1, 2, 3, 4];
        let b = vec![5, 6, 7, 8];
        let trace = build_sum_trace(a, b).unwrap();

        assert_eq!(trace.len(), 3);
        assert_eq!(trace[2][0], 6);
        assert_eq!(trace[2][1], 8);
        assert_eq!(trace[2][2], 10);
        assert_eq!(trace[2][3], 12);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_sum_trace_mismatched() {
        let a = vec![1, 2, 3];
        let b = vec![4, 5];
        let result = build_sum_trace(a, b);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_sum_constraints() {
        let air = SimpleAir::sum();
        let trace = build_sum_trace(vec![1, 2], vec![3, 4]).unwrap();

        for row in 0..trace[0].len() {
            let constraints = air.evaluate_constraints(&trace, row);
            assert_eq!(constraints.len(), 1);
            assert_eq!(constraints[0], 0);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_multiplication_trace() {
        let a = vec![2, 3, 4, 5];
        let b = vec![3, 4, 5, 6];
        let trace = build_multiplication_trace(a, b).unwrap();

        assert_eq!(trace.len(), 3);
        assert_eq!(trace[2][0], 6);
        assert_eq!(trace[2][1], 12);
        assert_eq!(trace[2][2], 20);
        assert_eq!(trace[2][3], 30);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_multiplication_trace_mismatched() {
        let a = vec![1, 2, 3];
        let b = vec![4, 5];
        let result = build_multiplication_trace(a, b);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_multiplication_constraints() {
        let air = SimpleAir::multiplication();
        let trace = build_multiplication_trace(vec![2, 3], vec![4, 5]).unwrap();

        for row in 0..trace[0].len() {
            let constraints = air.evaluate_constraints(&trace, row);
            assert_eq!(constraints.len(), 1);
            assert_eq!(constraints[0], 0);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_evaluate_constraints_insufficient_trace() {
        let air = SimpleAir::sum();
        let trace: Vec<Vec<u64>> = vec![vec![1, 2]]; // Only 1 column, need 3

        let constraints = air.evaluate_constraints(&trace, 0);
        assert!(constraints.is_empty());
    }
}
