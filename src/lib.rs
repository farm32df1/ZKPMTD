//! ZKMTD - Post-Quantum ZK proof library with Moving Target Defense
//!
//! Plonky3 STARK backend, epoch-based parameter rotation, Solana-ready.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, unused_qualifications, missing_debug_implementations)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod adapters;
pub mod batching;
pub mod core;
pub mod mtd;
pub mod stark;
pub mod utils;

/// Solana on-chain module (lightweight verification)
#[cfg(feature = "solana-program")]
pub mod solana;

pub use crate::core::{
    errors::{Result, ZKMTDError},
    traits::{EntropySource, Prover, Verifier},
    types::{Proof, PublicInputs, Witness},
};

pub use crate::mtd::{Epoch, MTDManager};

#[cfg(feature = "std")]
pub use crate::mtd::entropy::SystemEntropy;

pub use crate::stark::{MTDProver, MTDVerifier, StarkConfig};

pub use crate::batching::{BatchProver, BatchVerifier, ProofBatch};

#[cfg(feature = "solana-program")]
pub use crate::solana::{LightweightProof, OnchainVerifier, ProofCommitment};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = "ZKMTD";

/// Prelude module for convenient re-exports
pub mod prelude {
    pub use crate::core::errors::{Result, ZKMTDError};
    pub use crate::core::traits::{EntropySource, Prover, Verifier};
    pub use crate::core::types::{Proof, PublicInputs, Witness};
    pub use crate::mtd::{Epoch, MTDManager};
    pub use crate::stark::{MTDProver, MTDVerifier};

    #[cfg(feature = "alloc")]
    pub use crate::utils::compression::{CompressedProof, CompressionAlgorithm};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_name() {
        assert_eq!(NAME, "ZKMTD");
    }
}
