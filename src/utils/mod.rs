//! Utility functions - hash, compression, constants

pub mod compression;
pub mod constants;
pub mod hash;

pub use compression::{select_compression_algorithm, CompressedProof, CompressionAlgorithm};
pub use constants::*;
pub use hash::{hash_to_field, poseidon_hash};
