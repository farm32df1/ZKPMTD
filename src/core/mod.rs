//! Core types and traits (Proof, Witness, PublicInputs, Prover, Verifier)

pub mod errors;
pub mod traits;
pub mod types;

// Re-exports
pub use errors::{Result, ZKMTDError};
pub use traits::{EntropySource, Prover, Verifier};
pub use types::{Proof, PublicInputs, Witness};
