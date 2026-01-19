//! Error types for ZKMTD library

#[cfg(feature = "alloc")]
use alloc::string::String;

use core::fmt;

pub type Result<T> = core::result::Result<T, ZKMTDError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZKMTDError {
    ProofGenerationFailed {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    VerificationFailed {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    InvalidProof,
    InvalidWitness {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    InvalidPublicInputs {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    MTDError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    InvalidEpoch {
        current: u64,
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    EntropyError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    BatchError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    MerkleError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    ConfigurationError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    SerializationError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    UnsupportedFeature {
        #[cfg(feature = "alloc")]
        feature: String,
        #[cfg(not(feature = "alloc"))]
        feature: &'static str,
    },
    ResourceExhausted {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    ResourceLimitExceeded {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    InternalError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
}

impl fmt::Display for ZKMTDError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZKMTDError::ProofGenerationFailed { reason } => {
                write!(f, "Proof generation failed: {}", reason)
            }
            ZKMTDError::VerificationFailed { reason } => {
                write!(f, "Proof verification failed: {}", reason)
            }
            ZKMTDError::InvalidProof => {
                write!(f, "Invalid proof")
            }
            ZKMTDError::InvalidWitness { reason } => {
                write!(f, "Invalid witness data: {}", reason)
            }
            ZKMTDError::InvalidPublicInputs { reason } => {
                write!(f, "Invalid public inputs: {}", reason)
            }
            ZKMTDError::MTDError { reason } => {
                write!(f, "MTD error: {}", reason)
            }
            ZKMTDError::InvalidEpoch { current, reason } => {
                write!(f, "Invalid epoch (current: {}): {}", current, reason)
            }
            ZKMTDError::EntropyError { reason } => {
                write!(f, "Entropy error: {}", reason)
            }
            ZKMTDError::BatchError { reason } => {
                write!(f, "Batch processing error: {}", reason)
            }
            ZKMTDError::MerkleError { reason } => {
                write!(f, "Merkle tree error: {}", reason)
            }
            ZKMTDError::ConfigurationError { reason } => {
                write!(f, "Configuration error: {}", reason)
            }
            ZKMTDError::SerializationError { reason } => {
                write!(f, "Serialization error: {}", reason)
            }
            ZKMTDError::UnsupportedFeature { feature } => {
                write!(f, "Unsupported feature: {}", feature)
            }
            ZKMTDError::ResourceExhausted { reason } => {
                write!(f, "Resource exhausted: {}", reason)
            }
            ZKMTDError::ResourceLimitExceeded { reason } => {
                write!(f, "Resource limit exceeded: {}", reason)
            }
            ZKMTDError::InternalError { reason } => {
                write!(f, "Internal error: {}", reason)
            }
        }
    }
}

// Implement Error trait in std environment
#[cfg(feature = "std")]
impl std::error::Error for ZKMTDError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_error_display() {
        let err = ZKMTDError::InvalidProof;
        assert_eq!(format!("{}", err), "Invalid proof");
    }

    #[test]
    fn test_error_with_reason() {
        let err = ZKMTDError::ProofGenerationFailed {
            reason: "test error".into(),
        };
        assert!(format!("{}", err).contains("test error"));
    }

    #[test]
    fn test_invalid_epoch() {
        let err = ZKMTDError::InvalidEpoch {
            current: 12345,
            reason: "expired".into(),
        };
        assert!(format!("{}", err).contains("12345"));
        assert!(format!("{}", err).contains("expired"));
    }
}
