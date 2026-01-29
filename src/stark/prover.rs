//! MTD STARK Prover - simulation layer (use IntegratedProver for production)
#![allow(deprecated)]

use crate::core::errors::{Result, ZKMTDError};
use crate::core::traits::Prover;
use crate::core::types::{Proof, PublicInputs, Witness};
use crate::mtd::{Epoch, MTDManager, WarpingParams};
use crate::stark::StarkConfig;
use crate::utils::constants::{DOMAIN_PROOF_GENERATION, MIN_WITNESS_SIZE};
use crate::utils::hash::poseidon_hash;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[deprecated(since = "0.2.0", note = "Use IntegratedProver for production")]
#[derive(Debug)]
pub struct MTDProver {
    config: StarkConfig,
    mtd_manager: MTDManager,
}

impl MTDProver {
    pub fn new<E: crate::core::traits::EntropySource>(
        seed: &[u8],
        config: StarkConfig,
        entropy: &mut E,
    ) -> Result<Self> {
        config.validate()?;
        let mtd_manager = MTDManager::new(seed, entropy)?;
        Ok(Self {
            config,
            mtd_manager,
        })
    }

    pub fn with_epoch(seed: &[u8], config: StarkConfig, epoch: Epoch) -> Result<Self> {
        config.validate()?;
        let mtd_manager = MTDManager::with_epoch(seed, epoch)?;
        Ok(Self {
            config,
            mtd_manager,
        })
    }

    pub fn current_epoch(&self) -> Epoch {
        self.mtd_manager.current_epoch()
    }
    pub fn current_params(&self) -> &WarpingParams {
        self.mtd_manager.current_params()
    }
    pub fn advance_epoch(&mut self) -> Result<()> {
        self.mtd_manager.advance()?;
        Ok(())
    }
    pub fn mtd_manager_mut(&mut self) -> &mut MTDManager {
        &mut self.mtd_manager
    }

    pub fn get_verifier(&self) -> MTDVerifier {
        MTDVerifier {
            config: self.config.clone(),
            current_epoch: self.current_epoch(),
            current_params: self.current_params().clone(),
        }
    }

    fn prove_internal(
        &self,
        witness: &Witness,
        public_inputs: &PublicInputs,
        params: &WarpingParams,
    ) -> Result<Vec<u8>> {
        // NOTE: This is a simulation layer. For production STARK proofs,
        // use IntegratedProver from src/stark/integrated.rs

        // 1. Validate witness
        if witness.len() < MIN_WITNESS_SIZE {
            return Err(ZKMTDError::InvalidWitness {
                reason: alloc::format!(
                    "Witness size too small: {} < {}",
                    witness.len(),
                    MIN_WITNESS_SIZE
                ),
            });
        }

        // 2. Generate trace commitment (simulation)
        let trace_commitment = self.commit_trace(&witness.data, params)?;

        // 3. Generate FRI proof (simulation)
        let fri_proof = self.generate_fri_proof(&witness.data, params)?;

        // 4. Serialize proof
        #[cfg(feature = "alloc")]
        {
            let mut proof_data = Vec::new();
            proof_data.extend_from_slice(&trace_commitment);
            proof_data.extend_from_slice(&fri_proof);

            // Include public inputs
            for &input in &public_inputs.data {
                proof_data.extend_from_slice(&input.to_le_bytes());
            }

            // 5. Add integrity hash (for tamper detection)
            let integrity_hash = poseidon_hash(&proof_data, crate::utils::constants::DOMAIN_PROOF_INTEGRITY);
            proof_data.extend_from_slice(&integrity_hash);

            Ok(proof_data)
        }

        #[cfg(not(feature = "alloc"))]
        {
            Err(ZKMTDError::UnsupportedFeature {
                reason: "no_std environment requires fixed-size buffers".into(),
            })
        }
    }

    fn commit_trace(&self, witness_data: &[u64], params: &WarpingParams) -> Result<[u8; 32]> {
        // In production, this would use Merkle tree commitment
        // Current implementation uses simple hash

        #[cfg(feature = "alloc")]
        {
            let mut data = Vec::new();
            for &w in witness_data {
                data.extend_from_slice(&w.to_le_bytes());
            }
            data.extend_from_slice(&params.domain_separator);

            Ok(poseidon_hash(&data, DOMAIN_PROOF_GENERATION))
        }

        #[cfg(not(feature = "alloc"))]
        {
            let mut data = [0u8; 256];
            let mut offset = 0;

            for &w in witness_data.iter().take(20) {
                data[offset..offset + 8].copy_from_slice(&w.to_le_bytes());
                offset += 8;
            }

            Ok(poseidon_hash(&data[..offset], DOMAIN_PROOF_GENERATION))
        }
    }

    fn generate_fri_proof(&self, _witness_data: &[u64], params: &WarpingParams) -> Result<Vec<u8>> {
        // NOTE: This is a simulation layer. For real FRI proofs,
        // use IntegratedProver from src/stark/integrated.rs

        #[cfg(feature = "alloc")]
        {
            let mut fri_data = Vec::new();
            fri_data.extend_from_slice(&params.fri_seed);

            // Add query responses (simulation)
            for i in 0..self.config.fri_queries {
                let query_response = params.salt[i % 32];
                fri_data.push(query_response);
            }

            Ok(fri_data)
        }

        #[cfg(not(feature = "alloc"))]
        {
            Err(ZKMTDError::UnsupportedFeature {
                reason: "no_std FRI not yet implemented".into(),
            })
        }
    }
}

impl Prover for MTDProver {
    fn prove(&self, witness: &Witness, public_inputs: &PublicInputs) -> Result<Proof> {
        let params = self.current_params();
        let proof_data = self.prove_internal(witness, public_inputs, params)?;
        Ok(Proof::new(proof_data, params.epoch.value()))
    }

    fn min_witness_size(&self) -> usize {
        MIN_WITNESS_SIZE
    }
    fn min_public_inputs_size(&self) -> usize {
        1
    }
}

#[deprecated(since = "0.2.0", note = "Use IntegratedVerifier for production")]
#[derive(Debug, Clone)]
pub struct MTDVerifier {
    pub(crate) config: StarkConfig,
    pub(crate) current_epoch: Epoch,
    pub(crate) current_params: WarpingParams,
}

impl MTDVerifier {
    pub fn current_epoch(&self) -> Epoch {
        self.current_epoch
    }
    pub fn current_params(&self) -> &WarpingParams {
        &self.current_params
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::core::types::Witness;
    use crate::mtd::Epoch;
    use crate::stark::StarkConfig;
    use alloc::vec;

    #[cfg(feature = "std")]
    use crate::mtd::entropy::SystemEntropy;

    #[cfg(feature = "std")]
    #[test]
    fn test_mtd_prover_creation() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let mut entropy = SystemEntropy::new();

        let prover = MTDProver::new(seed, config, &mut entropy).unwrap();
        assert_eq!(prover.min_witness_size(), 4);
    }

    #[test]
    fn test_mtd_prover_with_epoch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(12345);

        let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
        assert_eq!(prover.current_epoch(), epoch);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mtd_prover_prove() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();

        let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let public_inputs = PublicInputs::new(vec![42]);

        let proof = prover.prove(&witness, &public_inputs).unwrap();
        assert!(!proof.is_empty());
        assert_eq!(proof.epoch, epoch.value());
    }

    #[test]
    fn test_mtd_prover_min_witness_size() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
        let witness = Witness::new(vec![1, 2]); // Too small
        let public_inputs = PublicInputs::new(vec![42]);

        let result = prover.prove(&witness, &public_inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_mtd_prover_advance_epoch() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let mut prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
        let initial_epoch = prover.current_epoch();

        prover.advance_epoch().unwrap();
        assert_eq!(prover.current_epoch().value(), initial_epoch.value() + 1);
    }

    #[test]
    fn test_mtd_prover_get_verifier() {
        let seed = b"test-seed";
        let config = StarkConfig::for_testing();
        let epoch = Epoch::new(100);

        let prover = MTDProver::with_epoch(seed, config, epoch).unwrap();
        let verifier = prover.get_verifier();

        assert_eq!(verifier.current_epoch(), prover.current_epoch());
    }
}
