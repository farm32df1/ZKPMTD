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
    fn test_error_display_invalid_proof() {
        let err = ZKMTDError::InvalidProof;
        assert_eq!(format!("{}", err), "Invalid proof");
    }

    #[test]
    fn test_error_display_proof_generation_failed() {
        let err = ZKMTDError::ProofGenerationFailed {
            reason: "test error".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Proof generation failed"));
        assert!(msg.contains("test error"));
    }

    #[test]
    fn test_error_display_verification_failed() {
        let err = ZKMTDError::VerificationFailed {
            reason: "invalid signature".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("verification failed"));
        assert!(msg.contains("invalid signature"));
    }

    #[test]
    fn test_error_display_invalid_witness() {
        let err = ZKMTDError::InvalidWitness {
            reason: "too small".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid witness"));
        assert!(msg.contains("too small"));
    }

    #[test]
    fn test_error_display_invalid_public_inputs() {
        let err = ZKMTDError::InvalidPublicInputs {
            reason: "mismatch".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid public inputs"));
        assert!(msg.contains("mismatch"));
    }

    #[test]
    fn test_error_display_mtd_error() {
        let err = ZKMTDError::MTDError {
            reason: "param error".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("MTD error"));
        assert!(msg.contains("param error"));
    }

    #[test]
    fn test_error_display_invalid_epoch() {
        let err = ZKMTDError::InvalidEpoch {
            current: 12345,
            reason: "expired".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid epoch"));
        assert!(msg.contains("12345"));
        assert!(msg.contains("expired"));
    }

    #[test]
    fn test_error_display_entropy_error() {
        let err = ZKMTDError::EntropyError {
            reason: "insufficient".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Entropy error"));
        assert!(msg.contains("insufficient"));
    }

    #[test]
    fn test_error_display_batch_error() {
        let err = ZKMTDError::BatchError {
            reason: "empty batch".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Batch processing error"));
        assert!(msg.contains("empty batch"));
    }

    #[test]
    fn test_error_display_merkle_error() {
        let err = ZKMTDError::MerkleError {
            reason: "invalid path".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Merkle tree error"));
        assert!(msg.contains("invalid path"));
    }

    #[test]
    fn test_error_display_configuration_error() {
        let err = ZKMTDError::ConfigurationError {
            reason: "invalid config".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Configuration error"));
        assert!(msg.contains("invalid config"));
    }

    #[test]
    fn test_error_display_serialization_error() {
        let err = ZKMTDError::SerializationError {
            reason: "parse failed".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Serialization error"));
        assert!(msg.contains("parse failed"));
    }

    #[test]
    fn test_error_display_unsupported_feature() {
        let err = ZKMTDError::UnsupportedFeature {
            feature: "fancy_crypto".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Unsupported feature"));
        assert!(msg.contains("fancy_crypto"));
    }

    #[test]
    fn test_error_display_resource_limit() {
        let err = ZKMTDError::ResourceLimitExceeded {
            reason: "out of memory".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Resource limit exceeded"));
        assert!(msg.contains("out of memory"));
    }

    #[test]
    fn test_error_display_internal_error() {
        let err = ZKMTDError::InternalError {
            reason: "unexpected state".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Internal error"));
        assert!(msg.contains("unexpected state"));
    }

    #[test]
    fn test_error_debug() {
        let err = ZKMTDError::InvalidProof;
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidProof"));
    }

    #[test]
    fn test_error_clone() {
        let err = ZKMTDError::InvalidProof;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_error_equality() {
        let err1 = ZKMTDError::InvalidProof;
        let err2 = ZKMTDError::InvalidProof;
        let err3 = ZKMTDError::VerificationFailed {
            reason: "test".into(),
        };

        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }
}
