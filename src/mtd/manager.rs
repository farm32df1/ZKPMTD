//! MTDManager - epoch transitions, parameter generation, and caching

use crate::core::errors::{Result, ZKMTDError};
use crate::core::traits::EntropySource;
use crate::mtd::{Epoch, WarpingParams};
use crate::utils::constants::{MTD_PARAM_CACHE_SIZE, TIMESTAMP_TOLERANCE_SECS};

#[cfg(feature = "alloc")]
use alloc::{collections::VecDeque, vec::Vec};

#[derive(Debug)]
pub struct MTDManager {
    seed: Vec<u8>,
    current_epoch: Epoch,
    current_params: WarpingParams,
    #[cfg(feature = "alloc")]
    cache: VecDeque<WarpingParams>,
    auto_advance: bool,
}

impl MTDManager {
    pub fn new<E: EntropySource>(seed: &[u8], entropy: &mut E) -> Result<Self> {
        if seed.is_empty() {
            return Err(ZKMTDError::MTDError {
                reason: "Seed is empty".into(),
            });
        }

        // Entropy quality verification
        if !entropy.is_cryptographically_secure() {
            return Err(ZKMTDError::EntropyError {
                reason: "Entropy source is not cryptographically secure".into(),
            });
        }

        // Calculate current Epoch
        #[cfg(feature = "std")]
        let current_epoch = Epoch::current()?;

        #[cfg(not(feature = "std"))]
        let current_epoch = Epoch::new(0); // In no_std, must be set explicitly

        // Generate initial parameters
        let current_params = WarpingParams::generate(seed, current_epoch)?;

        Ok(Self {
            seed: seed.to_vec(),
            current_epoch,
            current_params,
            #[cfg(feature = "alloc")]
            cache: VecDeque::with_capacity(MTD_PARAM_CACHE_SIZE),
            auto_advance: true,
        })
    }

    pub fn with_epoch(seed: &[u8], epoch: Epoch) -> Result<Self> {
        if seed.is_empty() {
            return Err(ZKMTDError::MTDError {
                reason: "Seed is empty".into(),
            });
        }

        let current_params = WarpingParams::generate(seed, epoch)?;

        Ok(Self {
            seed: seed.to_vec(),
            current_epoch: epoch,
            current_params,
            #[cfg(feature = "alloc")]
            cache: VecDeque::with_capacity(MTD_PARAM_CACHE_SIZE),
            auto_advance: false, // Manual management mode
        })
    }

    pub fn current_epoch(&self) -> Epoch {
        self.current_epoch
    }

    pub fn current_params(&self) -> &WarpingParams {
        &self.current_params
    }

    pub fn get_params(&mut self, epoch: Epoch) -> Result<WarpingParams> {
        // If it's the current Epoch, return immediately
        if epoch == self.current_epoch {
            return Ok(self.current_params.clone());
        }

        // Search cache
        #[cfg(feature = "alloc")]
        {
            if let Some(cached) = self.cache.iter().find(|p| p.epoch == epoch) {
                return Ok(cached.clone());
            }
        }

        // Cache miss: regenerate
        let params = WarpingParams::generate(&self.seed, epoch)?;

        // Add to cache
        #[cfg(feature = "alloc")]
        {
            if self.cache.len() >= MTD_PARAM_CACHE_SIZE {
                self.cache.pop_front(); // Remove oldest entry
            }
            self.cache.push_back(params.clone());
        }

        Ok(params)
    }

    pub fn advance(&mut self) -> Result<&WarpingParams> {
        let next_epoch = self.current_epoch.next()?;

        // Save previous parameters to cache
        #[cfg(feature = "alloc")]
        {
            if self.cache.len() >= MTD_PARAM_CACHE_SIZE {
                self.cache.pop_front();
            }
            self.cache.push_back(self.current_params.clone());
        }

        // Generate new parameters
        self.current_epoch = next_epoch;
        self.current_params = WarpingParams::generate(&self.seed, next_epoch)?;

        Ok(&self.current_params)
    }

    #[cfg(feature = "std")]
    pub fn sync(&mut self) -> Result<bool> {
        if !self.auto_advance {
            return Ok(false);
        }

        let system_epoch = Epoch::current()?;

        if system_epoch > self.current_epoch {
            // Epoch is behind: synchronization needed
            self.current_epoch = system_epoch;
            self.current_params = WarpingParams::generate(&self.seed, system_epoch)?;

            // Clear cache (data is too old)
            #[cfg(feature = "alloc")]
            self.cache.clear();

            Ok(true)
        } else if system_epoch < self.current_epoch {
            // System time went backwards (clock manipulation or bug)
            Err(ZKMTDError::MTDError {
                reason: alloc::format!(
                    "System time moved to the past: current={}, system={}",
                    self.current_epoch.value(),
                    system_epoch.value()
                ),
            })
        } else {
            // Synchronized
            Ok(false)
        }
    }

    pub fn set_auto_advance(&mut self, enabled: bool) {
        self.auto_advance = enabled;
    }

    pub fn validate_timestamp(&self, timestamp_secs: u64) -> bool {
        let epoch_start = self.current_epoch.start_timestamp();
        let epoch_end = self.current_epoch.end_timestamp();

        let lower_bound = epoch_start.saturating_sub(TIMESTAMP_TOLERANCE_SECS);
        let upper_bound = epoch_end.saturating_add(TIMESTAMP_TOLERANCE_SECS);

        timestamp_secs >= lower_bound && timestamp_secs <= upper_bound
    }

    #[cfg(feature = "alloc")]
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            size: self.cache.len(),
            capacity: MTD_PARAM_CACHE_SIZE,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub size: usize,
    pub capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use crate::mtd::entropy::SystemEntropy;

    #[cfg(feature = "std")]
    #[test]
    fn test_mtd_manager_creation() {
        let seed = b"test-seed";
        let mut entropy = SystemEntropy::new();
        let manager = MTDManager::new(seed, &mut entropy).unwrap();

        assert!(manager.current_epoch().value() > 0);
    }

    #[test]
    fn test_mtd_manager_with_epoch() {
        let seed = b"test-seed";
        let epoch = Epoch::new(12345);
        let manager = MTDManager::with_epoch(seed, epoch).unwrap();

        assert_eq!(manager.current_epoch(), epoch);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_mtd_manager_empty_seed() {
        let mut entropy = SystemEntropy::new();
        let result = MTDManager::new(b"", &mut entropy);
        assert!(result.is_err());
    }

    #[test]
    fn test_mtd_manager_advance() {
        let seed = b"test-seed";
        let mut manager = MTDManager::with_epoch(seed, Epoch::new(100)).unwrap();

        let initial_epoch = manager.current_epoch();
        manager.advance().unwrap();

        assert_eq!(manager.current_epoch().value(), initial_epoch.value() + 1);
    }

    #[test]
    fn test_mtd_manager_get_params() {
        let seed = b"test-seed";
        let mut manager = MTDManager::with_epoch(seed, Epoch::new(100)).unwrap();

        let params1 = manager.get_params(Epoch::new(100)).unwrap();
        let params2 = manager.get_params(Epoch::new(101)).unwrap();

        assert_ne!(params1, params2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mtd_manager_cache() {
        let seed = b"test-seed";
        let mut manager = MTDManager::with_epoch(seed, Epoch::new(100)).unwrap();

        // Request parameters for multiple Epochs
        for i in 100..110 {
            let _params = manager.get_params(Epoch::new(i)).unwrap();
        }

        let stats = manager.cache_stats();
        assert!(stats.size > 0);
        assert!(stats.size <= MTD_PARAM_CACHE_SIZE);
    }

    #[test]
    fn test_mtd_manager_validate_timestamp() {
        let seed = b"test-seed";
        let epoch = Epoch::new(100);
        let manager = MTDManager::with_epoch(seed, epoch).unwrap();

        let valid_ts = epoch.start_timestamp() + 100;
        assert!(manager.validate_timestamp(valid_ts));

        let invalid_ts = epoch.end_timestamp() + 10000;
        assert!(!manager.validate_timestamp(invalid_ts));
    }

    #[test]
    fn test_mtd_manager_auto_advance() {
        let seed = b"test-seed";
        let mut manager = MTDManager::with_epoch(seed, Epoch::new(100)).unwrap();

        manager.set_auto_advance(false);
        manager.set_auto_advance(true);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mtd_manager_clear_cache() {
        let seed = b"test-seed";
        let mut manager = MTDManager::with_epoch(seed, Epoch::new(100)).unwrap();

        // Add data to cache
        for i in 100..110 {
            let _params = manager.get_params(Epoch::new(i)).unwrap();
        }

        assert!(manager.cache_stats().size > 0);

        manager.clear_cache();
        assert_eq!(manager.cache_stats().size, 0);
    }
}
