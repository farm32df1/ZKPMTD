//! Solana on-chain module - lightweight verification (~15K CU)

pub mod lightweight;
pub mod onchain_verifier;

pub use lightweight::{BatchLightweightProof, LightweightProof, ProofCommitment};
pub use onchain_verifier::OnchainVerifier;
