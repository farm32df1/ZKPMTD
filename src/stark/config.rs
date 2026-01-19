//! StarkConfig - STARK proof system cryptographic parameters

use crate::core::errors::{Result, ZKMTDError};
use crate::utils::constants::{FRI_FOLDING_FACTOR, FRI_NUM_QUERIES};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StarkConfig {
    pub security_bits: usize,
    pub fri_folding_factor: usize,
    pub fri_queries: usize,
    pub grinding_bits: usize,
    pub blowup_factor: usize,
    pub trace_height: usize,
}

impl Default for StarkConfig {
    fn default() -> Self {
        Self {
            security_bits: 100,
            fri_folding_factor: FRI_FOLDING_FACTOR,
            fri_queries: FRI_NUM_QUERIES,
            grinding_bits: 10,
            blowup_factor: 4,
            trace_height: 1024,
        }
    }
}

impl StarkConfig {
    pub fn for_testing() -> Self {
        Self {
            security_bits: 80,
            fri_folding_factor: 2,
            fri_queries: 50,
            grinding_bits: 0,
            blowup_factor: 2,
            trace_height: 256,
        }
    }

    pub fn high_security() -> Self {
        Self {
            security_bits: 128,
            fri_folding_factor: 8,
            fri_queries: 128,
            grinding_bits: 15,
            blowup_factor: 8,
            trace_height: 2048,
        }
    }

    pub fn builder() -> StarkConfigBuilder {
        StarkConfigBuilder::new()
    }

    pub fn validate(&self) -> Result<()> {
        // Validate security level
        if self.security_bits < 80 {
            return Err(ZKMTDError::ConfigurationError {
                reason: alloc::format!("Security level too low: {} < 80", self.security_bits),
            });
        }

        if self.security_bits > 256 {
            return Err(ZKMTDError::ConfigurationError {
                reason: alloc::format!("Security level too high: {} > 256", self.security_bits),
            });
        }

        // Validate FRI folding factor
        if !matches!(self.fri_folding_factor, 2 | 4 | 8 | 16) {
            return Err(ZKMTDError::ConfigurationError {
                reason: alloc::format!(
                    "Invalid FRI folding factor: {} (must be one of 2, 4, 8, 16)",
                    self.fri_folding_factor
                ),
            });
        }

        // Validate number of FRI queries
        if self.fri_queries < 20 {
            return Err(ZKMTDError::ConfigurationError {
                reason: alloc::format!("Too few FRI queries: {} < 20", self.fri_queries),
            });
        }

        if self.fri_queries > 500 {
            return Err(ZKMTDError::ConfigurationError {
                reason: alloc::format!("Too many FRI queries: {} > 500", self.fri_queries),
            });
        }

        // Validate grinding bits
        if self.grinding_bits > 30 {
            return Err(ZKMTDError::ConfigurationError {
                reason: alloc::format!("Too many grinding bits: {} > 30", self.grinding_bits),
            });
        }

        // Validate blowup factor
        if !matches!(self.blowup_factor, 2 | 4 | 8 | 16) {
            return Err(ZKMTDError::ConfigurationError {
                reason: alloc::format!(
                    "Invalid blowup factor: {} (must be one of 2, 4, 8, 16)",
                    self.blowup_factor
                ),
            });
        }

        // Check if trace height is a power of 2
        if !self.trace_height.is_power_of_two() {
            return Err(ZKMTDError::ConfigurationError {
                reason: alloc::format!("Trace height is not a power of 2: {}", self.trace_height),
            });
        }

        if self.trace_height < 64 {
            return Err(ZKMTDError::ConfigurationError {
                reason: alloc::format!("Trace height too small: {} < 64", self.trace_height),
            });
        }

        Ok(())
    }

    pub fn estimated_proof_size(&self) -> usize {
        let base_size = 1000;
        let fri_size = self.fri_queries * 32 * (self.fri_folding_factor.ilog2() as usize);
        let trace_commitment_size = 32;

        base_size + fri_size + trace_commitment_size
    }

    pub fn estimated_proving_time_ms(&self) -> u64 {
        let base_time = 50;
        let grinding_time = 2u64.pow(self.grinding_bits as u32) / 1000;
        let trace_time = self.trace_height as u64 / 10;

        base_time + grinding_time + trace_time
    }
}

#[derive(Debug, Clone)]
pub struct StarkConfigBuilder {
    config: StarkConfig,
}

impl StarkConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: StarkConfig::default(),
        }
    }

    pub fn security_bits(mut self, bits: usize) -> Self {
        self.config.security_bits = bits;
        self
    }

    pub fn fri_folding_factor(mut self, factor: usize) -> Self {
        self.config.fri_folding_factor = factor;
        self
    }

    pub fn fri_queries(mut self, queries: usize) -> Self {
        self.config.fri_queries = queries;
        self
    }

    pub fn grinding_bits(mut self, bits: usize) -> Self {
        self.config.grinding_bits = bits;
        self
    }

    pub fn blowup_factor(mut self, factor: usize) -> Self {
        self.config.blowup_factor = factor;
        self
    }

    pub fn trace_height(mut self, height: usize) -> Self {
        self.config.trace_height = height;
        self
    }

    pub fn build(self) -> Result<StarkConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for StarkConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = StarkConfig::default();
        assert_eq!(config.security_bits, 100);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_testing_config() {
        let config = StarkConfig::for_testing();
        assert_eq!(config.security_bits, 80);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_high_security_config() {
        let config = StarkConfig::high_security();
        assert_eq!(config.security_bits, 128);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_builder() {
        let config = StarkConfig::builder()
            .security_bits(128)
            .fri_queries(150)
            .build()
            .unwrap();

        assert_eq!(config.security_bits, 128);
        assert_eq!(config.fri_queries, 150);
    }

    #[test]
    fn test_invalid_security_bits() {
        let config = StarkConfig::builder().security_bits(50).build();
        assert!(config.is_err());
    }

    #[test]
    fn test_invalid_fri_folding() {
        let config = StarkConfig {
            fri_folding_factor: 3, // Invalid value
            ..StarkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_trace_height() {
        let config = StarkConfig {
            trace_height: 1000, // Not a power of 2
            ..StarkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_estimated_proof_size() {
        let config = StarkConfig::default();
        let size = config.estimated_proof_size();
        assert!(size > 0);
        assert!(size < 100_000); // Reasonable range
    }

    #[test]
    fn test_estimated_proving_time() {
        let config = StarkConfig::default();
        let time = config.estimated_proving_time_ms();
        assert!(time > 0);
        assert!(time < 10_000); // Less than 10 seconds
    }
}
