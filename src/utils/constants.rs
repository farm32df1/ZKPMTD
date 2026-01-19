//! Constants - cryptographic parameters, limits, and domain separation tags

pub const LIBRARY_VERSION: u8 = 1;
pub const MIN_PROOF_SIZE: usize = 1024;
pub const MAX_PROOF_SIZE: usize = 1024 * 1024;
pub const MIN_WITNESS_SIZE: usize = 4;
pub const MAX_WITNESS_SIZE: usize = 1024 * 1024;
pub const MIN_PUBLIC_INPUTS_SIZE: usize = 1;
pub const MAX_PUBLIC_INPUTS_SIZE: usize = 256;
pub const EPOCH_DURATION_SECS: u64 = 3600;
pub const MAX_EPOCH: u64 = u64::MAX - 1;
pub const SYSTEM_SALT: &[u8] = b"ZKMTD-v1-system-salt-2024";

// Domain separation tags
pub const DOMAIN_PROOF_GENERATION: &[u8] = b"ZKMTD::ProofGeneration";
pub const DOMAIN_PROOF_VERIFICATION: &[u8] = b"ZKMTD::ProofVerification";
pub const DOMAIN_MTD_PARAMS: &[u8] = b"ZKMTD::MTD::Parameters";
pub const DOMAIN_ENTROPY: &[u8] = b"ZKMTD::Entropy";
pub const DOMAIN_MERKLE: &[u8] = b"ZKMTD::Merkle";
pub const DOMAIN_COMMITMENT: &[u8] = b"ZKMTD::Commitment";

// Privacy domains
pub const DOMAIN_IDENTITY: &[u8] = b"ZKMTD::Privacy::Identity";
pub const DOMAIN_FINANCIAL: &[u8] = b"ZKMTD::Privacy::Financial";
pub const DOMAIN_MEDICAL: &[u8] = b"ZKMTD::Privacy::Medical";
pub const DOMAIN_LOCATION: &[u8] = b"ZKMTD::Privacy::Location";
pub const DOMAIN_BIOMETRIC: &[u8] = b"ZKMTD::Privacy::Biometric";
pub const DOMAIN_CREDENTIAL: &[u8] = b"ZKMTD::Privacy::Credential";
pub const DOMAIN_COMMUNICATION: &[u8] = b"ZKMTD::Privacy::Communication";

// Solana constants
pub const SOLANA_MAX_TX_SIZE: usize = 1000;
pub const SOLANA_MAX_COMPUTE_UNITS: u32 = 200_000;
pub const SOLANA_TARGET_PROOF_SIZE: usize = 500;
pub const SOLANA_BASE_CU: u32 = 5_000;
pub const SOLANA_PER_BYTE_CU: u32 = 10;
pub const SOLANA_HASH_CU: u32 = 100;

// Cryptographic parameters
pub const MIN_ENTROPY_BITS: usize = 128;
pub const RECOMMENDED_ENTROPY_BITS: usize = 256;
pub const MAX_BATCH_SIZE: usize = 1000;
pub const FRI_FOLDING_FACTOR: usize = 4;
pub const FRI_NUM_QUERIES: usize = 100;
pub const POSEIDON_OUTPUT_SIZE: usize = 32;
pub const MTD_PARAM_CACHE_SIZE: usize = 16;
pub const TIMESTAMP_TOLERANCE_SECS: u64 = 300;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_validity() {
        // Compile-time verified constants (Clippy lint-compliant)
        const _: () = assert!(MIN_PROOF_SIZE < MAX_PROOF_SIZE);
        const _: () = assert!(MIN_WITNESS_SIZE < MAX_WITNESS_SIZE);
        const _: () = assert!(MIN_PUBLIC_INPUTS_SIZE < MAX_PUBLIC_INPUTS_SIZE);
        const _: () = assert!(MIN_ENTROPY_BITS < RECOMMENDED_ENTROPY_BITS);
        const _: () = assert!(EPOCH_DURATION_SECS > 0);

        // Runtime check for test confirmation
        assert_ne!(SYSTEM_SALT.len(), 0);
    }

    #[test]
    fn test_domain_tags_uniqueness() {
        // Verify domain separation tags are unique
        let tags = [
            DOMAIN_PROOF_GENERATION,
            DOMAIN_PROOF_VERIFICATION,
            DOMAIN_MTD_PARAMS,
            DOMAIN_ENTROPY,
            DOMAIN_MERKLE,
        ];

        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "Domain tags are duplicated");
            }
        }
    }
}
