//! Blockchain adapters for proof serialization

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(any(feature = "solana-adapter", feature = "solana-program"))]
pub mod solana;

#[cfg(any(feature = "solana-adapter", feature = "solana-program"))]
pub use solana::SolanaAdapter;

/// Solana chain adapter trait
pub trait SolanaChainAdapter {
    fn name(&self) -> &str;

    #[cfg(feature = "alloc")]
    fn serialize_proof(
        &self,
        proof: &crate::core::types::Proof,
    ) -> crate::core::errors::Result<Vec<u8>>;

    #[cfg(feature = "alloc")]
    fn deserialize_proof(
        &self,
        data: &[u8],
    ) -> crate::core::errors::Result<crate::core::types::Proof>;

    fn estimate_compute_units(&self, proof_size: usize) -> u32;
}
