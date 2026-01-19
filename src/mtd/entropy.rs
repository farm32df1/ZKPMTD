//! Entropy sources for MTD - OS CSPRNG (std) and Solana slot hash (no_std)

#[allow(unused_imports)]
use crate::core::errors::Result;
#[allow(unused_imports)]
use crate::core::traits::EntropySource;

#[cfg(any(
    feature = "std",
    all(
        any(feature = "solana-adapter", feature = "solana-program"),
        not(feature = "alloc")
    )
))]
use crate::core::errors::ZKMTDError;
#[cfg(feature = "std")]
use crate::utils::constants::{MIN_ENTROPY_BITS, RECOMMENDED_ENTROPY_BITS};

#[allow(unused_imports)]
#[cfg(feature = "alloc")]
use alloc::vec;
#[allow(unused_imports)]
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct SystemEntropy {
    entropy_bits: usize,
}

#[cfg(feature = "std")]
impl SystemEntropy {
    pub fn new() -> Self {
        Self {
            entropy_bits: RECOMMENDED_ENTROPY_BITS,
        }
    }

    pub fn with_entropy_bits(mut self, bits: usize) -> Result<Self> {
        if bits < MIN_ENTROPY_BITS {
            return Err(ZKMTDError::EntropyError {
                reason: alloc::format!("Entropy is too low: {} < {}", bits, MIN_ENTROPY_BITS),
            });
        }
        self.entropy_bits = bits;
        Ok(self)
    }
}

#[cfg(feature = "std")]
impl Default for SystemEntropy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl EntropySource for SystemEntropy {
    #[cfg(feature = "alloc")]
    fn generate(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        if num_bytes == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; num_bytes];
        self.fill_bytes(&mut buffer)?;
        Ok(buffer)
    }

    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<()> {
        if output.is_empty() {
            return Ok(());
        }

        // std environment: use getrandom crate (cryptographically secure)
        // getrandom uses the OS's CSPRNG:
        // - Linux: /dev/urandom
        // - macOS/BSD: arc4random_buf
        // - Windows: BCryptGenRandom
        use getrandom::getrandom;

        getrandom(output).map_err(|e| ZKMTDError::EntropyError {
            reason: alloc::format!("getrandom failed: {}", e),
        })?;

        Ok(())
    }

    fn entropy_bits(&self) -> usize {
        self.entropy_bits
    }

    fn is_cryptographically_secure(&self) -> bool {
        // getrandom provides cryptographically secure entropy in all environments
        // Uses the OS's CSPRNG (Cryptographically Secure PRNG)
        true
    }
}

#[cfg(any(feature = "solana-adapter", feature = "solana-program"))]
#[derive(Debug, Clone)]
pub struct SolanaEntropy {
    slot_hash: [u8; 32],
    program_id: [u8; 32],
    counter: u64,
}

#[cfg(any(feature = "solana-adapter", feature = "solana-program"))]
impl SolanaEntropy {
    pub fn from_slot_hash(slot_hash: [u8; 32], program_id: [u8; 32]) -> Self {
        Self {
            slot_hash,
            program_id,
            counter: 0,
        }
    }

    pub fn new_for_testing() -> Self {
        Self {
            slot_hash: [0u8; 32],
            program_id: [0u8; 32],
            counter: 0,
        }
    }
}

#[cfg(any(feature = "solana-adapter", feature = "solana-program"))]
impl EntropySource for SolanaEntropy {
    #[cfg(feature = "alloc")]
    fn generate(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; num_bytes];
        self.fill_bytes(&mut buffer)?;
        Ok(buffer)
    }

    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<()> {
        use crate::utils::hash::poseidon_hash;

        #[cfg(feature = "alloc")]
        {
            use alloc::vec::Vec;

            // Entropy input composition: slot_hash || program_id || counter
            let mut entropy_input = Vec::with_capacity(32 + 32 + 8);
            entropy_input.extend_from_slice(&self.slot_hash);
            entropy_input.extend_from_slice(&self.program_id);
            entropy_input.extend_from_slice(&self.counter.to_le_bytes());

            // Generate entropy with Poseidon2 hash
            let hash = poseidon_hash(&entropy_input, b"SOLANA_ENTROPY_V1");

            // Fill output buffer (hash multiple times if needed)
            let mut offset = 0;
            let mut local_counter = self.counter;

            while offset < output.len() {
                let chunk_size = (output.len() - offset).min(32);
                output[offset..offset + chunk_size].copy_from_slice(&hash[..chunk_size]);
                offset += chunk_size;

                // If more is needed, increment counter and rehash
                if offset < output.len() {
                    local_counter += 1;
                    let mut new_input = Vec::with_capacity(32 + 32 + 8);
                    new_input.extend_from_slice(&self.slot_hash);
                    new_input.extend_from_slice(&self.program_id);
                    new_input.extend_from_slice(&local_counter.to_le_bytes());

                    let new_hash = poseidon_hash(&new_input, b"SOLANA_ENTROPY_V1");
                    let remaining = output.len() - offset;
                    let copy_size = remaining.min(32);
                    output[offset..offset + copy_size].copy_from_slice(&new_hash[..copy_size]);
                    offset += copy_size;
                }
            }

            // Update counter (for next call)
            self.counter += 1;

            Ok(())
        }

        #[cfg(not(feature = "alloc"))]
        {
            Err(ZKMTDError::UnsupportedFeature {
                reason: "SolanaEntropy requires the alloc feature".into(),
            })
        }
    }

    fn entropy_bits(&self) -> usize {
        256 // Slot hash 256 bits + Poseidon2 mixing
    }

    fn is_cryptographically_secure(&self) -> bool {
        // Solana slot hashes are generated by validator consensus and are cryptographically secure
        true
    }
}

#[cfg(test)]
#[derive(Debug)]
pub struct DeterministicEntropy {
    state: u64,
}

#[cfg(test)]
impl DeterministicEntropy {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

#[cfg(test)]
impl EntropySource for DeterministicEntropy {
    #[cfg(feature = "alloc")]
    fn generate(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; num_bytes];
        self.fill_bytes(&mut buffer)?;
        Ok(buffer)
    }

    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<()> {
        // LCG (Linear Congruential Generator) - for testing
        for byte in output.iter_mut() {
            self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (self.state >> 32) as u8;
        }
        Ok(())
    }

    fn entropy_bits(&self) -> usize {
        64 // Low entropy for testing purposes
    }

    fn is_cryptographically_secure(&self) -> bool {
        false // Not secure as it's for testing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn test_system_entropy_creation() {
        let entropy = SystemEntropy::new();
        assert_eq!(entropy.entropy_bits(), RECOMMENDED_ENTROPY_BITS);
        assert!(entropy.is_cryptographically_secure());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_system_entropy_with_bits() {
        let entropy = SystemEntropy::new().with_entropy_bits(256).unwrap();
        assert_eq!(entropy.entropy_bits(), 256);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_system_entropy_min_bits() {
        let result = SystemEntropy::new().with_entropy_bits(64);
        assert!(result.is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_system_entropy_generate() {
        let mut entropy = SystemEntropy::new();
        let bytes = entropy.generate(32).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_system_entropy_fill_bytes() {
        let mut entropy = SystemEntropy::new();
        let mut buffer = [0u8; 16];
        entropy.fill_bytes(&mut buffer).unwrap();

        // Check that not all bytes are zero (extremely low probability)
        let all_zero = buffer.iter().all(|&b| b == 0);
        assert!(!all_zero, "All bytes cannot be zero");
    }

    #[test]
    fn test_deterministic_entropy() {
        let mut entropy1 = DeterministicEntropy::new(12345);
        let mut entropy2 = DeterministicEntropy::new(12345);

        let bytes1 = entropy1.generate(32).unwrap();
        let bytes2 = entropy2.generate(32).unwrap();

        assert_eq!(bytes1, bytes2, "Same seed should generate same output");
        assert!(!entropy1.is_cryptographically_secure());
    }

    #[test]
    fn test_deterministic_entropy_different_seeds() {
        let mut entropy1 = DeterministicEntropy::new(111);
        let mut entropy2 = DeterministicEntropy::new(222);

        let bytes1 = entropy1.generate(32).unwrap();
        let bytes2 = entropy2.generate(32).unwrap();

        assert_ne!(
            bytes1, bytes2,
            "Different seeds should generate different output"
        );
    }
}
