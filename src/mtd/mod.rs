//! MTD (Moving Target Defense) - epoch-based parameter rotation for replay prevention

pub mod entropy;
pub mod epoch;
pub mod manager;
pub mod warping;

#[cfg(any(feature = "solana-adapter", feature = "solana-program"))]
pub use entropy::SolanaEntropy;
#[cfg(feature = "std")]
pub use entropy::SystemEntropy;
pub use epoch::Epoch;
pub use manager::MTDManager;
pub use warping::WarpingParams;
