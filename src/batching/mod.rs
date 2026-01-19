//! Batching System - aggregate multiple proofs with Merkle tree verification

pub mod aggregator;
pub mod batch_verifier;
pub mod merkle;

pub use aggregator::{create_proof_batch, BatchProver};
pub use batch_verifier::BatchVerifier;
pub use merkle::{MerklePath, MerkleTree};

// Re-export
pub use crate::core::types::ProofBatch;
