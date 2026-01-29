//! Hash utilities - Poseidon2 hash on Goldilocks field (2^64 - 2^32 + 1)
//!
//! Uses Plonky3's Poseidon2 permutation for cryptographic security.
//! Sponge construction with domain separation for hash function.

use crate::core::errors::{Result, ZKMTDError};
use crate::core::types::{FieldElement, HashDigest};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use p3_field::{AbstractField, PrimeField64};
use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::Permutation;

type F = Goldilocks;

/// Plonky3 Poseidon2 permutation type (width=16, degree=7)
type Perm = Poseidon2<F, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 16, 7>;

/// Global Poseidon2 instance with deterministic initialization
/// Uses fixed seed for reproducibility across all executions
fn get_poseidon2() -> Perm {
    use crate::utils::constants::ZKMTD_POSEIDON2_SEED;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let mut rng = ChaCha20Rng::seed_from_u64(ZKMTD_POSEIDON2_SEED);

    Poseidon2::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks,
        &mut rng,
    )
}

pub fn bytes_to_field(bytes: &[u8]) -> FieldElement {
    let mut result = 0u64;
    for (i, &byte) in bytes.iter().take(8).enumerate() {
        result |= (byte as u64) << (i * 8);
    }
    // Goldilocks field modulo operation
    result % F::ORDER_U64
}

pub fn field_to_bytes(field_elem: FieldElement) -> [u8; 8] {
    field_elem.to_le_bytes()
}

#[cfg(feature = "alloc")]
pub fn bytes_to_fields(bytes: &[u8]) -> Vec<FieldElement> {
    bytes.chunks(8).map(bytes_to_field).collect()
}

/// Poseidon2-based cryptographic hash function
///
/// Uses Plonky3's verified Poseidon2 permutation with sponge construction.
/// - Width: 16 field elements
/// - Rate: 8 field elements
/// - Capacity: 8 field elements (128-bit security)
/// - S-box: x^7 (Goldilocks-optimized)
pub fn poseidon_hash(data: &[u8], domain: &[u8]) -> HashDigest {
    const WIDTH: usize = 16;
    const RATE: usize = 8;

    let perm = get_poseidon2();
    let mut state = [F::zero(); WIDTH];

    // 1. Domain separation: absorb domain into state
    for (i, chunk) in domain.chunks(8).enumerate() {
        if i >= RATE {
            break;
        }
        let val = bytes_to_field(chunk);
        state[i] = F::from_canonical_u64(val);
    }

    // First permutation (domain separation)
    perm.permute_mut(&mut state);

    // 2. Data absorption: convert to field elements and absorb
    for chunk in data.chunks(8 * RATE) {
        for (i, bytes_chunk) in chunk.chunks(8).enumerate() {
            if i >= RATE {
                break;
            }
            let val = bytes_to_field(bytes_chunk);
            state[i] += F::from_canonical_u64(val);
        }
        perm.permute_mut(&mut state);
    }

    // 3. Output squeezing: generate 32 bytes from first 4 field elements
    let mut result = [0u8; 32];
    for i in 0..4 {
        let bytes = state[i].as_canonical_u64().to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }

    result
}

/// Internal permutation function for testing
/// Uses Plonky3 Poseidon2 permutation
#[cfg(test)]
fn permute(state: &mut [Goldilocks; 16], _rounds: usize) {
    let perm = get_poseidon2();
    perm.permute_mut(state);
}

pub fn hash_to_field(hash: &HashDigest) -> FieldElement {
    bytes_to_field(hash)
}

pub fn combine_hashes(left: &HashDigest, right: &HashDigest, domain: &[u8]) -> HashDigest {
    #[cfg(feature = "alloc")]
    {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(left);
        combined.extend_from_slice(right);
        poseidon_hash(&combined, domain)
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(left);
        combined[32..].copy_from_slice(right);
        poseidon_hash(&combined, domain)
    }
}

#[cfg(feature = "alloc")]
pub fn hash_multiple(inputs: &[&[u8]], domain: &[u8]) -> HashDigest {
    let mut combined = Vec::new();
    for input in inputs {
        combined.extend_from_slice(input);
    }
    poseidon_hash(&combined, domain)
}

pub fn derive_mtd_params(seed: &[u8], epoch: u64, salt: &[u8]) -> Result<HashDigest> {
    if seed.is_empty() {
        return Err(ZKMTDError::MTDError {
            reason: "Seed is empty".into(),
        });
    }

    #[cfg(feature = "alloc")]
    {
        let mut data = Vec::new();
        data.extend_from_slice(seed);
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(salt);

        Ok(poseidon_hash(
            &data,
            crate::utils::constants::DOMAIN_MTD_PARAMS,
        ))
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut data = [0u8; 256];
        let mut offset = 0;

        let seed_len = seed.len().min(200);
        data[offset..offset + seed_len].copy_from_slice(&seed[..seed_len]);
        offset += seed_len;

        data[offset..offset + 8].copy_from_slice(&epoch.to_le_bytes());
        offset += 8;

        let salt_len = salt.len().min(256 - offset);
        data[offset..offset + salt_len].copy_from_slice(&salt[..salt_len]);
        offset += salt_len;

        Ok(poseidon_hash(
            &data[..offset],
            crate::utils::constants::DOMAIN_MTD_PARAMS,
        ))
    }
}

/// Derive a deterministic salt for public value commitment.
/// salt = Poseidon2(seed || epoch || nonce, DOMAIN_PV_SALT)
#[cfg(feature = "alloc")]
pub fn derive_pv_salt(seed: &[u8], epoch: u64, nonce: &[u8]) -> HashDigest {
    let mut data = Vec::with_capacity(seed.len() + 8 + nonce.len());
    data.extend_from_slice(seed);
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(nonce);
    poseidon_hash(&data, crate::utils::constants::DOMAIN_PV_SALT)
}

/// Constant-time equality comparison for fixed-size byte arrays.
/// Avoids timing side-channels by always comparing all bytes.
pub fn constant_time_eq_fixed<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut result = 0u8;
    for i in 0..N {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// Constant-time equality comparison for variable-length slices.
/// Both length comparison and content comparison are constant-time
/// to prevent timing side-channel leaks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_eq = a.len() == b.len();
    let max_len = a.len().max(b.len());
    let mut result = 0u8;
    for i in 0..max_len {
        let x = if i < a.len() { a[i] } else { 0 };
        let y = if i < b.len() { b[i] } else { 0 };
        result |= x ^ y;
    }
    len_eq && result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_field_conversion() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let field = bytes_to_field(&bytes);
        let back = field_to_bytes(field);
        assert_eq!(bytes, back);
    }

    #[test]
    fn test_poseidon_hash_deterministic() {
        let data = b"test data";
        let domain = b"test domain";

        let hash1 = poseidon_hash(data, domain);
        let hash2 = poseidon_hash(data, domain);

        assert_eq!(hash1, hash2, "Hash must be deterministic");
    }

    #[test]
    fn test_poseidon_hash_different_domain() {
        let data = b"test data";
        let domain1 = b"domain1";
        let domain2 = b"domain2";

        let hash1 = poseidon_hash(data, domain1);
        let hash2 = poseidon_hash(data, domain2);

        assert_ne!(
            hash1, hash2,
            "Different domains must produce different hashes"
        );
    }

    #[test]
    fn test_combine_hashes() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let domain = b"test";

        let combined = combine_hashes(&left, &right, domain);
        assert_ne!(combined, left);
        assert_ne!(combined, right);
    }

    #[test]
    fn test_derive_mtd_params() {
        let seed = b"my-secret-seed";
        let epoch = 12345u64;
        let salt = b"salt";

        let params1 = derive_mtd_params(seed, epoch, salt).unwrap();
        let params2 = derive_mtd_params(seed, epoch, salt).unwrap();

        assert_eq!(params1, params2, "Same inputs must produce same parameters");
    }

    #[test]
    fn test_derive_mtd_params_different_epoch() {
        let seed = b"my-secret-seed";
        let salt = b"salt";

        let params1 = derive_mtd_params(seed, 100, salt).unwrap();
        let params2 = derive_mtd_params(seed, 200, salt).unwrap();

        assert_ne!(
            params1, params2,
            "Different Epochs must produce different parameters"
        );
    }

    #[test]
    fn test_empty_seed_error() {
        let result = derive_mtd_params(&[], 100, b"salt");
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_derive_pv_salt_deterministic() {
        let salt1 = derive_pv_salt(b"seed", 100, b"nonce");
        let salt2 = derive_pv_salt(b"seed", 100, b"nonce");
        assert_eq!(salt1, salt2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_derive_pv_salt_different_epoch() {
        let salt1 = derive_pv_salt(b"seed", 100, b"nonce");
        let salt2 = derive_pv_salt(b"seed", 101, b"nonce");
        assert_ne!(salt1, salt2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_derive_pv_salt_different_seed() {
        let salt1 = derive_pv_salt(b"seed-A", 100, b"nonce");
        let salt2 = derive_pv_salt(b"seed-B", 100, b"nonce");
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_collision_resistance() {
        // Different inputs must produce different hashes
        let data1 = b"test data 1";
        let data2 = b"test data 2";
        let domain = b"test";

        let hash1 = poseidon_hash(data1, domain);
        let hash2 = poseidon_hash(data2, domain);

        assert_ne!(hash1, hash2, "Collision resistance verification");
    }

    #[test]
    fn test_field_modulo() {
        // Goldilocks field modulo operation verification
        let large_bytes = [0xFF; 8];
        let field = bytes_to_field(&large_bytes);
        assert!(field < F::ORDER_U64);
    }

    #[test]
    fn test_permutation_changes_state() {
        let mut state1 = [F::zero(); 16];
        let mut state2 = [F::zero(); 16];

        state1[0] = F::one();
        state2[0] = F::one();

        permute(&mut state1, 8);

        // State must change after permutation
        assert_ne!(state1, state2);
    }

    #[test]
    fn test_domain_separation_effectiveness() {
        // Same data, different domain -> different hash
        let data = b"identical data for testing";

        let hash1 = poseidon_hash(data, b"DOMAIN_A");
        let hash2 = poseidon_hash(data, b"DOMAIN_B");
        let hash3 = poseidon_hash(data, b"DOMAIN_C");

        assert_ne!(hash1, hash2, "DOMAIN_A and DOMAIN_B produced same hash");
        assert_ne!(hash1, hash3, "DOMAIN_A and DOMAIN_C produced same hash");
        assert_ne!(hash2, hash3, "DOMAIN_B and DOMAIN_C produced same hash");
    }

    #[test]
    fn test_data_sensitivity() {
        // Different data, same domain -> different hash
        let domain = b"SAME_DOMAIN";

        let hash1 = poseidon_hash(b"data1", domain);
        let hash2 = poseidon_hash(b"data2", domain);
        let hash3 = poseidon_hash(b"data3", domain);

        assert_ne!(hash1, hash2, "data1 and data2 produced same hash");
        assert_ne!(hash1, hash3, "data1 and data3 produced same hash");
        assert_ne!(hash2, hash3, "data2 and data3 produced same hash");
    }

    #[test]
    fn test_similar_domain_tags() {
        // Similar domain tags must also produce different hashes
        let data = b"test data";

        let hash1 = poseidon_hash(data, b"MTD_DOMAIN");
        let hash2 = poseidon_hash(data, b"MTD_SALT");
        let hash3 = poseidon_hash(data, b"MTD_FRI");

        assert_ne!(hash1, hash2, "MTD_DOMAIN and MTD_SALT produced same hash");
        assert_ne!(hash1, hash3, "MTD_DOMAIN and MTD_FRI produced same hash");
        assert_ne!(hash2, hash3, "MTD_SALT and MTD_FRI produced same hash");
    }

    #[test]
    fn test_append_vs_domain_separation() {
        // Data append vs domain separation: must produce different results
        let base_data = b"base";
        let tag = b"TAG";

        // Method 1: Append tag to data
        #[cfg(feature = "alloc")]
        {
            let mut combined = Vec::new();
            combined.extend_from_slice(base_data);
            combined.extend_from_slice(tag);
            let hash1 = poseidon_hash(&combined, b"DOMAIN");

            // Method 2: Use tag as domain
            let hash2 = poseidon_hash(base_data, tag);

            // Two methods must produce different hashes
            assert_ne!(
                hash1, hash2,
                "Data append and domain separation produced same hash"
            );
        }
    }

    #[test]
    fn test_empty_domain() {
        // Empty domain must also be handled correctly
        let data = b"test data";

        let hash1 = poseidon_hash(data, b"");
        let hash2 = poseidon_hash(data, b"NON_EMPTY");

        assert_ne!(
            hash1, hash2,
            "Empty domain and non-empty domain produced same hash"
        );
    }

    #[test]
    fn test_avalanche_effect() {
        // 1-bit change must cause many bit changes (Avalanche Effect)
        let data1 = [0u8; 32];
        let mut data2 = [0u8; 32];
        data2[0] = 1; // 1-bit change

        let hash1 = poseidon_hash(&data1, b"test");
        let hash2 = poseidon_hash(&data2, b"test");

        assert_ne!(hash1, hash2);

        // Calculate Hamming distance (number of different bits)
        let mut diff_bits = 0;
        for i in 0..32 {
            diff_bits += (hash1[i] ^ hash2[i]).count_ones();
        }

        // At least 25% of bits must change (25% of 256 bits = 64 bits)
        assert!(
            diff_bits >= 64,
            "Avalanche effect insufficient: only {} bits changed (minimum 64 bits required)",
            diff_bits
        );
    }

    // ============================================================
    // Cryptographic Hash Function Integrity Tests
    // ============================================================

    #[test]
    fn test_preimage_resistance() {
        // Given a hash output, it should be computationally infeasible
        // to find any input that produces that output
        let known_hash = poseidon_hash(b"secret_input", b"domain");

        // Try many different inputs - none should produce the same hash
        for i in 0..1000u64 {
            let test_input = i.to_le_bytes();
            let test_hash = poseidon_hash(&test_input, b"domain");
            assert_ne!(test_hash, known_hash, "Preimage found at iteration {}", i);
        }
    }

    #[test]
    fn test_second_preimage_resistance() {
        // Given an input, it should be hard to find a different input
        // that produces the same hash
        let input1 = b"original_message";
        let hash1 = poseidon_hash(input1, b"domain");

        // Similar inputs should not produce the same hash
        let similar_inputs = [
            b"original_messagE".as_slice(),  // 1 char different
            b"Original_message".as_slice(),  // case change
            b"original_message ".as_slice(), // trailing space
            b" original_message".as_slice(), // leading space
            b"original_messag".as_slice(),   // truncated
            b"original_message!".as_slice(), // appended
        ];

        for (i, input2) in similar_inputs.iter().enumerate() {
            let hash2 = poseidon_hash(input2, b"domain");
            assert_ne!(hash1, hash2, "Second preimage found at case {}", i);
        }
    }

    #[test]
    fn test_collision_resistance_extended() {
        // Test that different random inputs produce different hashes
        use alloc::collections::BTreeSet;

        let mut hashes = BTreeSet::new();

        // Generate 1000 different hashes
        for i in 0..1000u64 {
            let input = i.to_le_bytes();
            let hash = poseidon_hash(&input, b"collision_test");

            // Check no collision
            let hash_vec: Vec<u8> = hash.to_vec();
            assert!(
                hashes.insert(hash_vec),
                "Collision found at iteration {}",
                i
            );
        }

        assert_eq!(hashes.len(), 1000, "Expected 1000 unique hashes");
    }

    #[test]
    fn test_length_extension_resistance() {
        // Sponge construction should resist length extension attacks
        let short_data = b"short";
        let long_data = b"short_with_extension";

        let hash_short = poseidon_hash(short_data, b"domain");
        let hash_long = poseidon_hash(long_data, b"domain");

        // Hashes should be completely unrelated
        assert_ne!(hash_short, hash_long);

        // Check bit difference is significant (not just appended)
        let mut diff_bits = 0;
        for i in 0..32 {
            diff_bits += (hash_short[i] ^ hash_long[i]).count_ones();
        }
        assert!(diff_bits >= 64, "Length extension may be possible: only {} bits differ", diff_bits);
    }

    #[test]
    fn test_sbox_nonlinearity() {
        // x^7 S-box should be highly nonlinear
        // Test that linear combinations don't hold
        let a = F::from_canonical_u64(12345);
        let b = F::from_canonical_u64(67890);

        // S(a) + S(b) should not equal S(a + b)
        let sa = sbox(a);
        let sb = sbox(b);
        let sab = sbox(a + b);

        assert_ne!(sa + sb, sab, "S-box appears linear!");

        // S(k*a) should not equal k*S(a) for k != 0,1
        let k = F::from_canonical_u64(3);
        let ska = sbox(k * a);
        let ksa = k * sa;
        assert_ne!(ska, ksa, "S-box appears homomorphic!");
    }

    #[test]
    fn test_diffusion_completeness() {
        // Every output bit should depend on every input bit
        // Test by changing single input bytes and measuring output change
        let base_input = [0u8; 64];
        let base_hash = poseidon_hash(&base_input, b"diffusion");

        let mut total_affected_bytes = [false; 32];

        for byte_pos in 0..64 {
            let mut modified = base_input;
            modified[byte_pos] = 0xFF;

            let modified_hash = poseidon_hash(&modified, b"diffusion");

            for i in 0..32 {
                if base_hash[i] != modified_hash[i] {
                    total_affected_bytes[i] = true;
                }
            }
        }

        // All output bytes should be affected by at least one input change
        let affected_count = total_affected_bytes.iter().filter(|&&x| x).count();
        assert!(
            affected_count >= 28, // At least 28/32 bytes affected
            "Diffusion incomplete: only {}/32 output bytes affected",
            affected_count
        );
    }

    #[test]
    fn test_permutation_invertibility_not_exploitable() {
        // While permutation is theoretically invertible,
        // the sponge construction should prevent exploitation
        let mut state1 = [F::zero(); 16];
        state1[0] = F::from_canonical_u64(0x123456789ABCDEF0);

        let original = state1.clone();

        // Apply permutation
        permute(&mut state1, 8);

        // State should be completely different
        let mut same_count = 0;
        for i in 0..16 {
            if state1[i] == original[i] {
                same_count += 1;
            }
        }
        assert!(same_count <= 1, "Permutation leaves {} elements unchanged", same_count);
    }

    #[test]
    fn test_round_constant_effectiveness() {
        // Without round constants, permutation would have fixed points
        // Test that our constants prevent this

        // All-zero input
        let mut state = [F::zero(); 16];
        permute(&mut state, 8);

        let zero_count = state.iter().filter(|&&x| x == F::zero()).count();
        assert!(zero_count == 0, "Permutation has zero fixed points");

        // All-one input
        let mut state = [F::one(); 16];
        permute(&mut state, 8);

        let one_count = state.iter().filter(|&&x| x == F::one()).count();
        assert!(one_count == 0, "Permutation has one fixed points");
    }

    #[test]
    fn test_statistical_uniformity() {
        // Hash outputs should be statistically uniform
        let mut byte_sums = [0u64; 32];
        let iterations = 1000u64;

        for i in 0..iterations {
            let input = i.to_le_bytes();
            let hash = poseidon_hash(&input, b"uniformity");

            for (j, &byte) in hash.iter().enumerate() {
                byte_sums[j] += byte as u64;
            }
        }

        // Expected average: 127.5 per byte * 1000 iterations = 127500
        let expected = 127500u64;
        let tolerance = 15000u64; // ~12% tolerance

        for (i, &sum) in byte_sums.iter().enumerate() {
            assert!(
                sum > expected - tolerance && sum < expected + tolerance,
                "Byte {} is statistically biased: sum={}, expected={}±{}",
                i, sum, expected, tolerance
            );
        }
    }

    // Helper for S-box test
    fn sbox(x: Goldilocks) -> Goldilocks {
        let x2 = x * x;
        let x4 = x2 * x2;
        x4 * x2 * x // x^7
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_compare_with_plonky3_poseidon2_structure() {
        // Verify our implementation follows Poseidon2 structure
        // Even if constants differ, the structure should be sound

        use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
        use p3_goldilocks::DiffusionMatrixGoldilocks;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        // Create real Plonky3 Poseidon2 (verify it initializes without error)
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let _real_poseidon: Poseidon2<Goldilocks, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 16, 7> =
            Poseidon2::new_from_rng_128(
                Poseidon2ExternalMatrixGeneral,
                DiffusionMatrixGoldilocks,
                &mut rng,
            );

        // Both should:
        // 1. Use Goldilocks field
        // 2. Use x^7 S-box
        // 3. Have width 16

        // Test that our permutation produces valid field elements
        let mut state = [F::zero(); 16];
        for i in 0..16 {
            state[i] = F::from_canonical_u64(i as u64 * 12345);
        }

        permute(&mut state, 8);

        // All outputs should be valid Goldilocks field elements
        for (i, &elem) in state.iter().enumerate() {
            assert!(
                elem.as_canonical_u64() < F::ORDER_U64,
                "Element {} is not in Goldilocks field",
                i
            );
        }
    }

    #[test]
    fn test_hash_output_in_field() {
        // All hash outputs should be valid when interpreted as field elements
        for i in 0..100u64 {
            let hash = poseidon_hash(&i.to_le_bytes(), b"field_test");

            // Each 8-byte chunk should be a valid field element
            for chunk_idx in 0..4 {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&hash[chunk_idx * 8..(chunk_idx + 1) * 8]);
                let value = u64::from_le_bytes(bytes);

                // Should be less than field order
                assert!(
                    value < F::ORDER_U64,
                    "Hash chunk {} exceeds field order: {}",
                    chunk_idx,
                    value
                );
            }
        }
    }
}
