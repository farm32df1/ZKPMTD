//! Integration tests for ZKMTD library

use zkmtd::batching::{create_proof_batch, BatchVerifier};
use zkmtd::core::traits::BatchProver as BatchProverTrait;
#[cfg(feature = "std")]
use zkmtd::SystemEntropy;
use zkmtd::{BatchProver, Epoch, MTDProver, Prover, PublicInputs, StarkConfig, Verifier, Witness};

#[cfg(feature = "std")]
#[test]
fn test_end_to_end_proof_workflow() {
    let seed = b"integration-test-seed";
    let mut entropy = SystemEntropy::new();
    let config = StarkConfig::for_testing();

    // Create prover
    let prover = MTDProver::new(seed, config, &mut entropy).unwrap();

    // Generate proof
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);
    let proof = prover.prove(&witness, &public_inputs).unwrap();

    // Verify
    let verifier = prover.get_verifier();
    assert!(verifier.verify(&proof, &public_inputs).unwrap());
}

#[test]
fn test_mtd_epoch_advancement() {
    let seed = b"epoch-test-seed";
    let config = StarkConfig::for_testing();
    let mut prover = MTDProver::with_epoch(seed, config, Epoch::new(100)).unwrap();

    let initial_epoch = prover.current_epoch();

    // Epoch transition
    prover.advance_epoch().unwrap();

    assert_eq!(prover.current_epoch().value(), initial_epoch.value() + 1);
}

#[test]
fn test_batch_proof_workflow() {
    let seed = b"batch-test-seed";
    let config = StarkConfig::for_testing();
    let epoch = Epoch::new(500);

    // Create batch prover
    let prover = BatchProver::with_epoch(seed, config, epoch).unwrap();

    // Generate multiple proofs
    let witnesses = vec![
        Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        Witness::new(vec![9, 10, 11, 12, 13, 14, 15, 16]),
        Witness::new(vec![17, 18, 19, 20, 21, 22, 23, 24]),
    ];

    let inputs = vec![
        PublicInputs::new(vec![100]),
        PublicInputs::new(vec![200]),
        PublicInputs::new(vec![300]),
    ];

    let proofs = prover.prove_batch(&witnesses, &inputs).unwrap();
    let batch = create_proof_batch(proofs, epoch.value()).unwrap();

    // Batch verification
    let verifier = BatchVerifier::new(prover.inner_prover().get_verifier());
    assert!(verifier.verify_batch(&batch, &inputs).unwrap());
}

#[test]
fn test_cross_epoch_verification_fails() {
    let seed = b"cross-epoch-test";
    let config = StarkConfig::for_testing();

    // Generate proof in epoch 100
    let prover1 = MTDProver::with_epoch(seed, config.clone(), Epoch::new(100)).unwrap();
    let witness = Witness::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let public_inputs = PublicInputs::new(vec![42]);
    let proof = prover1.prove(&witness, &public_inputs).unwrap();

    // Attempt verification with epoch 200 verifier (should fail)
    let prover2 = MTDProver::with_epoch(seed, config, Epoch::new(200)).unwrap();
    let verifier2 = prover2.get_verifier();

    let result = verifier2.verify(&proof, &public_inputs);
    assert!(result.is_err(), "Proof from different epoch was accepted");
}

#[cfg(feature = "std")]
#[test]
fn test_invalid_witness_size() {
    let seed = b"invalid-witness-test";
    let mut entropy = SystemEntropy::new();
    let config = StarkConfig::for_testing();

    let prover = MTDProver::new(seed, config, &mut entropy).unwrap();

    // Witness too small
    let invalid_witness = Witness::new(vec![1, 2]);
    let public_inputs = PublicInputs::new(vec![42]);

    let result = prover.prove(&invalid_witness, &public_inputs);
    assert!(result.is_err(), "Invalid witness was accepted");
}

#[test]
fn test_merkle_tree_integrity() {
    use zkmtd::batching::merkle::MerkleTree;

    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

    let tree = MerkleTree::new(leaves.clone()).unwrap();

    // Verify proof for all leaves
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.get_proof(i).unwrap();
        assert!(
            proof.verify(leaf),
            "Merkle proof verification failed: index {}",
            i
        );
    }
}

#[test]
fn test_deterministic_params() {
    use zkmtd::mtd::WarpingParams;

    let seed = b"deterministic-test";
    let epoch = Epoch::new(12345);

    // Generate twice with same seed and epoch
    let params1 = WarpingParams::generate(seed, epoch).unwrap();
    let params2 = WarpingParams::generate(seed, epoch).unwrap();

    // Must be exactly equal
    assert_eq!(params1.domain_separator, params2.domain_separator);
    assert_eq!(params1.salt, params2.salt);
    assert_eq!(params1.fri_seed, params2.fri_seed);
}

#[test]
fn test_proof_serialization() {
    #[cfg(feature = "solana-adapter")]
    {
        use zkmtd::adapters::{solana::SolanaAdapter, SolanaChainAdapter};
        use zkmtd::Proof;

        let adapter = SolanaAdapter::new();
        let original = Proof::new(vec![1, 2, 3, 4, 5], 12345);

        let serialized = adapter.serialize_proof(&original).unwrap();
        let deserialized = adapter.deserialize_proof(&serialized).unwrap();

        assert_eq!(original.version, deserialized.version);
        assert_eq!(original.epoch, deserialized.epoch);
        assert_eq!(original.data, deserialized.data);
    }
}
