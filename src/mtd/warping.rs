//! WarpingParams - epoch-based dynamic cryptographic parameters for MTD

use crate::core::errors::{Result, ZKMTDError};
use crate::core::types::HashDigest;
use crate::mtd::Epoch;
use crate::utils::constants::SYSTEM_SALT;
use crate::utils::hash::{derive_mtd_params, poseidon_hash};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WarpingParams {
    pub epoch: Epoch,
    pub domain_separator: HashDigest,
    pub salt: HashDigest,
    pub fri_seed: HashDigest,
}

impl WarpingParams {
    pub fn generate(seed: &[u8], epoch: Epoch) -> Result<Self> {
        if seed.is_empty() {
            return Err(ZKMTDError::MTDError {
                reason: "Seed is empty".into(),
            });
        }

        // 1. Derive base parameters
        let base_params = derive_mtd_params(seed, epoch.value(), SYSTEM_SALT)?;

        // 2. Generate domain separator
        // Domain_Sep = Hash(base_params ∥ "DOMAIN")
        #[cfg(feature = "alloc")]
        let mut domain_data = Vec::new();
        #[cfg(not(feature = "alloc"))]
        let mut domain_data = [0u8; 128];

        #[cfg(feature = "alloc")]
        {
            domain_data.extend_from_slice(&base_params);
            domain_data.extend_from_slice(b"DOMAIN");
        }
        #[cfg(not(feature = "alloc"))]
        {
            domain_data[..32].copy_from_slice(&base_params);
            domain_data[32..38].copy_from_slice(b"DOMAIN");
        }

        let domain_separator = poseidon_hash(
            #[cfg(feature = "alloc")]
            &domain_data,
            #[cfg(not(feature = "alloc"))]
            &domain_data[..38],
            b"MTD_DOMAIN_SEP",
        );

        // 3. Generate Salt
        // Salt = Hash(base_params ∥ "SALT")
        #[cfg(feature = "alloc")]
        {
            domain_data.clear();
            domain_data.extend_from_slice(&base_params);
            domain_data.extend_from_slice(b"SALT");
        }
        #[cfg(not(feature = "alloc"))]
        {
            domain_data[32..36].copy_from_slice(b"SALT");
        }

        let salt = poseidon_hash(
            #[cfg(feature = "alloc")]
            &domain_data,
            #[cfg(not(feature = "alloc"))]
            &domain_data[..36],
            b"MTD_SALT",
        );

        // 4. Generate FRI seed
        // FRI_Seed = Hash(base_params ∥ "FRI")
        #[cfg(feature = "alloc")]
        {
            domain_data.clear();
            domain_data.extend_from_slice(&base_params);
            domain_data.extend_from_slice(b"FRI");
        }
        #[cfg(not(feature = "alloc"))]
        {
            domain_data[32..35].copy_from_slice(b"FRI");
        }

        let fri_seed = poseidon_hash(
            #[cfg(feature = "alloc")]
            &domain_data,
            #[cfg(not(feature = "alloc"))]
            &domain_data[..35],
            b"MTD_FRI_SEED",
        );

        Ok(Self {
            epoch,
            domain_separator,
            salt,
            fri_seed,
        })
    }

    pub fn next(&self, seed: &[u8]) -> Result<Self> {
        let next_epoch = self.epoch.next()?;
        Self::generate(seed, next_epoch)
    }

    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(104);
        bytes.extend_from_slice(&self.epoch.to_bytes());
        bytes.extend_from_slice(&self.domain_separator);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.fri_seed);
        bytes
    }

    #[cfg(feature = "alloc")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 104 {
            return Err(ZKMTDError::SerializationError {
                reason: alloc::format!("Invalid byte length: {} (expected: 104)", bytes.len()),
            });
        }

        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&bytes[0..8]);
        let epoch = Epoch::from_bytes(epoch_bytes);

        let mut domain_separator = [0u8; 32];
        domain_separator.copy_from_slice(&bytes[8..40]);

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[40..72]);

        let mut fri_seed = [0u8; 32];
        fri_seed.copy_from_slice(&bytes[72..104]);

        Ok(Self {
            epoch,
            domain_separator,
            salt,
            fri_seed,
        })
    }

    pub fn verify(&self, seed: &[u8]) -> Result<bool> {
        let expected = Self::generate(seed, self.epoch)?;
        Ok(self == &expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_warping_params_generation() {
        let seed = b"test-seed";
        let epoch = Epoch::new(12345);

        let params = WarpingParams::generate(seed, epoch).unwrap();
        assert_eq!(params.epoch, epoch);
    }

    #[test]
    fn test_warping_params_deterministic() {
        let seed = b"test-seed";
        let epoch = Epoch::new(100);

        let params1 = WarpingParams::generate(seed, epoch).unwrap();
        let params2 = WarpingParams::generate(seed, epoch).unwrap();

        assert_eq!(
            params1, params2,
            "Same seed and Epoch should generate same parameters"
        );
    }

    #[test]
    fn test_warping_params_different_epoch() {
        let seed = b"test-seed";

        let params1 = WarpingParams::generate(seed, Epoch::new(100)).unwrap();
        let params2 = WarpingParams::generate(seed, Epoch::new(200)).unwrap();

        assert_ne!(params1.domain_separator, params2.domain_separator);
        assert_ne!(params1.salt, params2.salt);
        assert_ne!(params1.fri_seed, params2.fri_seed);
    }

    #[test]
    fn test_warping_params_different_seed() {
        let epoch = Epoch::new(100);

        let params1 = WarpingParams::generate(b"seed1", epoch).unwrap();
        let params2 = WarpingParams::generate(b"seed2", epoch).unwrap();

        assert_ne!(params1.domain_separator, params2.domain_separator);
        assert_ne!(params1.salt, params2.salt);
        assert_ne!(params1.fri_seed, params2.fri_seed);
    }

    #[test]
    fn test_warping_params_empty_seed() {
        let epoch = Epoch::new(100);
        let result = WarpingParams::generate(b"", epoch);
        assert!(result.is_err());
    }

    #[test]
    fn test_warping_params_next() {
        let seed = b"test-seed";
        let params1 = WarpingParams::generate(seed, Epoch::new(10)).unwrap();
        let params2 = params1.next(seed).unwrap();

        assert_eq!(params2.epoch.value(), 11);
        assert_ne!(params1, params2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_warping_params_serialization() {
        let seed = b"test-seed";
        let epoch = Epoch::new(12345);
        let params = WarpingParams::generate(seed, epoch).unwrap();

        let bytes = params.to_bytes();
        assert_eq!(bytes.len(), 104);

        let recovered = WarpingParams::from_bytes(&bytes).unwrap();
        assert_eq!(params, recovered);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_warping_params_invalid_bytes() {
        let invalid_bytes = vec![0u8; 50]; // Invalid length
        let result = WarpingParams::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_warping_params_verify() {
        let seed = b"test-seed";
        let epoch = Epoch::new(100);
        let params = WarpingParams::generate(seed, epoch).unwrap();

        assert!(params.verify(seed).unwrap());
        assert!(!params.verify(b"wrong-seed").unwrap());
    }

    #[test]
    fn test_warping_params_uniqueness() {
        let seed = b"test-seed";
        let params = WarpingParams::generate(seed, Epoch::new(100)).unwrap();

        // Verify that each parameter is different from the others
        assert_ne!(params.domain_separator, params.salt);
        assert_ne!(params.domain_separator, params.fri_seed);
        assert_ne!(params.salt, params.fri_seed);
    }

    #[test]
    fn test_warping_params_cross_validation() {
        // Cross validation: verify uniqueness across multiple seed and epoch combinations
        use alloc::vec;

        let seeds = vec![
            b"seed1".as_slice(),
            b"seed2".as_slice(),
            b"very-long-seed-for-testing-purposes-12345".as_slice(),
        ];

        let epochs = vec![Epoch::new(0), Epoch::new(100), Epoch::new(999999)];

        for seed in &seeds {
            for &epoch in &epochs {
                let params = WarpingParams::generate(seed, epoch).unwrap();

                // Verify that each parameter is different from the others
                assert_ne!(
                    params.domain_separator,
                    params.salt,
                    "domain_separator and salt are identical: seed={:?}, epoch={}",
                    seed,
                    epoch.value()
                );
                assert_ne!(
                    params.domain_separator,
                    params.fri_seed,
                    "domain_separator and fri_seed are identical: seed={:?}, epoch={}",
                    seed,
                    epoch.value()
                );
                assert_ne!(
                    params.salt,
                    params.fri_seed,
                    "salt and fri_seed are identical: seed={:?}, epoch={}",
                    seed,
                    epoch.value()
                );
            }
        }
    }

    #[test]
    fn test_warping_params_statistical_uniqueness() {
        // Statistical verification: check that generated parameters are sufficiently distributed
        use alloc::vec;

        let seed = b"statistical-test-seed";
        let mut all_hashes = vec![];

        // Generate parameters for 10 different epochs
        for i in 0..10 {
            let params = WarpingParams::generate(seed, Epoch::new(i * 1000)).unwrap();
            all_hashes.push(params.domain_separator);
            all_hashes.push(params.salt);
            all_hashes.push(params.fri_seed);
        }

        // Verify all hashes are unique (30 = 10 epochs * 3 params)
        for i in 0..all_hashes.len() {
            for j in (i + 1)..all_hashes.len() {
                assert_ne!(
                    all_hashes[i], all_hashes[j],
                    "Collision found: same hash at index {} and {}",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_warping_params_domain_separation() {
        // Domain separation verification: confirm different parameters are generated from the same base_params
        let seed = b"domain-separation-test";
        let epoch = Epoch::new(12345);

        let params1 = WarpingParams::generate(seed, epoch).unwrap();
        let params2 = WarpingParams::generate(seed, epoch).unwrap();

        // Same input should generate same parameters (deterministic)
        assert_eq!(params1, params2, "Deterministic generation failed");

        // But each parameter should be different from the others
        assert_ne!(params1.domain_separator, params1.salt);
        assert_ne!(params1.domain_separator, params1.fri_seed);
        assert_ne!(params1.salt, params1.fri_seed);
    }
}
