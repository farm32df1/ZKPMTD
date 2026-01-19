//! Epoch - MTD time unit. New parameters generated per epoch.

use crate::core::errors::{Result, ZKMTDError};
use crate::utils::constants::{EPOCH_DURATION_SECS, MAX_EPOCH};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Epoch = floor(timestamp / EPOCH_DURATION_SECS)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Epoch {
    /// Epoch value (starting from 0)
    value: u64,
}

impl Epoch {
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    pub fn from_timestamp(timestamp_secs: u64) -> Self {
        let value = timestamp_secs / EPOCH_DURATION_SECS;
        Self { value }
    }

    #[cfg(feature = "std")]
    pub fn current() -> Result<Self> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ZKMTDError::InternalError {
                reason: alloc::format!("System time error: {}", e),
            })?
            .as_secs();

        Ok(Self::from_timestamp(timestamp))
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn next(&self) -> Result<Self> {
        if self.value >= MAX_EPOCH {
            return Err(ZKMTDError::InvalidEpoch {
                current: self.value,
                reason: "Epoch has reached the maximum value".into(),
            });
        }
        Ok(Self::new(self.value + 1))
    }

    pub fn prev(&self) -> Result<Self> {
        if self.value == 0 {
            return Err(ZKMTDError::InvalidEpoch {
                current: self.value,
                reason: "Epoch is 0".into(),
            });
        }
        Ok(Self::new(self.value - 1))
    }

    pub fn advance(&self, count: u64) -> Result<Self> {
        let new_value = self
            .value
            .checked_add(count)
            .ok_or(ZKMTDError::InvalidEpoch {
                current: self.value,
                reason: "Epoch overflow".into(),
            })?;

        if new_value > MAX_EPOCH {
            return Err(ZKMTDError::InvalidEpoch {
                current: self.value,
                reason: "Epoch exceeded the maximum value".into(),
            });
        }

        Ok(Self::new(new_value))
    }

    pub fn start_timestamp(&self) -> u64 {
        self.value * EPOCH_DURATION_SECS
    }

    pub fn end_timestamp(&self) -> u64 {
        (self.value + 1) * EPOCH_DURATION_SECS - 1
    }

    pub fn contains_timestamp(&self, timestamp_secs: u64) -> bool {
        let epoch_from_ts = Self::from_timestamp(timestamp_secs);
        epoch_from_ts.value == self.value
    }

    pub fn distance(&self, other: &Epoch) -> u64 {
        self.value.abs_diff(other.value)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        self.value.to_le_bytes()
    }

    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        let value = u64::from_le_bytes(bytes);
        Self::new(value)
    }
}

impl Default for Epoch {
    fn default() -> Self {
        Self::new(0)
    }
}

impl core::fmt::Display for Epoch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Epoch({})", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_epoch_creation() {
        let epoch = Epoch::new(12345);
        assert_eq!(epoch.value(), 12345);
    }

    #[test]
    fn test_epoch_from_timestamp() {
        // EPOCH_DURATION_SECS = 3600 (1 hour)
        let epoch = Epoch::from_timestamp(7200); // 2 hours
        assert_eq!(epoch.value(), 2);
    }

    #[test]
    fn test_epoch_next() {
        let epoch = Epoch::new(10);
        let next = epoch.next().unwrap();
        assert_eq!(next.value(), 11);
    }

    #[test]
    fn test_epoch_prev() {
        let epoch = Epoch::new(10);
        let prev = epoch.prev().unwrap();
        assert_eq!(prev.value(), 9);
    }

    #[test]
    fn test_epoch_prev_at_zero() {
        let epoch = Epoch::new(0);
        assert!(epoch.prev().is_err());
    }

    #[test]
    fn test_epoch_advance() {
        let epoch = Epoch::new(10);
        let advanced = epoch.advance(5).unwrap();
        assert_eq!(advanced.value(), 15);
    }

    #[test]
    fn test_epoch_timestamps() {
        let epoch = Epoch::new(5);
        assert_eq!(epoch.start_timestamp(), 5 * EPOCH_DURATION_SECS);
        assert_eq!(epoch.end_timestamp(), 6 * EPOCH_DURATION_SECS - 1);
    }

    #[test]
    fn test_epoch_contains_timestamp() {
        let epoch = Epoch::new(2);
        assert!(epoch.contains_timestamp(7200)); // 2 * 3600
        assert!(epoch.contains_timestamp(9000)); // 2.5 * 3600
        assert!(!epoch.contains_timestamp(10800)); // 3 * 3600
    }

    #[test]
    fn test_epoch_distance() {
        let epoch1 = Epoch::new(10);
        let epoch2 = Epoch::new(15);
        assert_eq!(epoch1.distance(&epoch2), 5);
        assert_eq!(epoch2.distance(&epoch1), 5);
    }

    #[test]
    fn test_epoch_bytes_conversion() {
        let epoch = Epoch::new(12345);
        let bytes = epoch.to_bytes();
        let recovered = Epoch::from_bytes(bytes);
        assert_eq!(epoch, recovered);
    }

    #[test]
    fn test_epoch_display() {
        let epoch = Epoch::new(12345);
        assert_eq!(format!("{}", epoch), "Epoch(12345)");
    }

    #[test]
    fn test_epoch_ordering() {
        let epoch1 = Epoch::new(10);
        let epoch2 = Epoch::new(20);
        assert!(epoch1 < epoch2);
        assert!(epoch2 > epoch1);
    }
}
