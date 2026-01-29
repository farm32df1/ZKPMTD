//! STARK module - Plonky3-based post-quantum ZK proofs with MTD integration
//!
//! # Architecture
//!
//! ## Off-chain (Full STARK)
//! - [`IntegratedProver`] / [`IntegratedVerifier`]: Production API (STARK + MTD)
//! - [`RealStarkProver`] / [`RealStarkVerifier`]: Core Plonky3 STARK
//!
//! ## On-chain (Solana)
//! - [`crate::solana::LightweightProof`] + [`crate::solana::OnchainVerifier`]
//! - ~5K CU, fits Solana constraints
//!
//! ## Testing
//! - [`MTDProver`] / [`MTDVerifier`]: Hash-based simulation

pub mod air;
pub mod config;
pub mod prover;
pub mod verifier;

#[cfg(feature = "full-p3")]
pub mod real_stark;

#[cfg(feature = "full-p3")]
pub mod integrated;

#[cfg(feature = "full-p3")]
pub mod range_air;

pub use air::SimpleAir;
pub use config::StarkConfig;
#[allow(deprecated)]
pub use prover::{MTDProver, MTDVerifier};

#[cfg(feature = "full-p3")]
pub use real_stark::{ProofAirType, RealProof, RealStarkProver, RealStarkVerifier};

#[cfg(feature = "full-p3")]
pub use integrated::{IntegratedProof, IntegratedProver, IntegratedVerifier};

#[cfg(feature = "full-p3")]
pub use range_air::RangeAir;
