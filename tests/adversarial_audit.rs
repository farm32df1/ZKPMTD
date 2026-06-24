//! Adversarial re-attack suite. Each test ATTEMPTS an exploit and asserts the
//! system DEFENDS (rejects it). A failing test = a real finding / regression.
//! Run repeatedly (loop) to also catch nondeterminism.
//! `cargo test --test adversarial_audit --features "std,full-p3,solana-adapter,borsh"`

use zkmtd::batching::MerkleTree;
use zkmtd::stark::air::SimpleAir;
use zkmtd::stark::{ProofAirType, RealStarkProver, RealStarkVerifier};
use zkmtd::utils::hash::{bytes_to_field, hash_to_field, poseidon_hash};
use zkmtd::Epoch;

const MAX_RANGE_VALUE: u64 = 1u64 << 32;
const GOLDILOCKS_ORDER: u64 = 0xFFFF_FFFF_0000_0001;

// ---- proof forgery (C-1: public values bound in-circuit) ----

#[test]
fn atk_forge_sum_public_values() {
    let p = RealStarkProver::new(SimpleAir::sum()).unwrap();
    let v = p.get_verifier();
    let mut proof = p.prove_sum(&[3, 5, 7, 9], &[2, 4, 6, 8]).unwrap();
    assert!(v.verify_sum(&proof).unwrap());
    proof.public_values[2] = proof.public_values[2].wrapping_add(1); // forge c_first
    assert!(!v.verify_sum(&proof).unwrap(), "forged Sum public value accepted");
}

#[test]
fn atk_forge_mul_public_values() {
    let p = RealStarkProver::new(SimpleAir::multiplication()).unwrap();
    let v = p.get_verifier();
    let mut proof = p.prove_multiplication(&[3, 5, 7, 9], &[2, 4, 6, 8]).unwrap();
    assert!(v.verify_multiplication(&proof).unwrap());
    proof.public_values[5] = proof.public_values[5].wrapping_add(1); // forge c_last
    assert!(!v.verify_multiplication(&proof).unwrap(), "forged Mul public value accepted");
}

#[test]
fn atk_forge_range_threshold() {
    let p = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
    let v = p.get_verifier();
    let mut proof = p.prove_range(100, 50).unwrap();
    assert!(v.verify_range(&proof).unwrap());
    proof.public_values[0] = 99_999; // claim a different public threshold
    assert!(!v.verify_range(&proof).unwrap(), "forged Range threshold accepted");
}

#[test]
fn atk_forge_fibonacci_final() {
    let p = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
    let v = p.get_verifier();
    let mut proof = p.prove_fibonacci(16).unwrap();
    assert!(v.verify_fibonacci(&proof).unwrap());
    proof.public_values[3] = proof.public_values[3].wrapping_add(1);
    assert!(!v.verify_fibonacci(&proof).unwrap(), "forged Fibonacci final accepted");
}

// ---- cross-AIR type confusion (RT-4) ----

#[test]
fn atk_cross_air_type_confusion() {
    let p = RealStarkProver::new(SimpleAir::sum()).unwrap();
    let v = p.get_verifier();
    let mut proof = p.prove_sum(&[3, 5, 7, 9], &[2, 4, 6, 8]).unwrap();
    proof.air_type = ProofAirType::Multiplication;
    assert!(!v.verify_by_type(&proof).unwrap(), "Sum-relabeled-as-Mul accepted");
}

// ---- verifier DoS via attacker num_rows (RT-3) ----

#[test]
fn atk_dos_oversized_num_rows() {
    let p = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
    let v = p.get_verifier();
    let mut proof = p.prove_fibonacci(8).unwrap();
    proof.num_rows = 1usize << 34; // power of two, far over MAX_TRACE_ROWS
    // Must return (rejected) quickly; a regression would hang on the O(num_rows) loop.
    assert!(!v.verify_fibonacci(&proof).unwrap(), "oversized num_rows not rejected");
}

// ---- Merkle malleability (RT-2 / H-4) ----

#[test]
fn atk_merkle_size_ambiguity() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    let t3 = MerkleTree::new(vec![a, b, c]).unwrap();
    let t4 = MerkleTree::new(vec![a, b, c, c]).unwrap();
    assert_ne!(t3.root(), t4.root(), "3-leaf and 4-leaf(dup) trees collide on root");
}

#[test]
fn atk_merkle_tampered_proof() {
    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let tree = MerkleTree::new(leaves.clone()).unwrap();
    let proof = tree.get_proof(0).unwrap();
    assert!(proof.verify(&leaves[0]), "valid inclusion rejected");
    assert!(!proof.verify(&[99u8; 32]), "wrong leaf accepted by inclusion proof");
}

// ---- Range soundness bounds ----

#[test]
fn atk_range_value_below_threshold() {
    let p = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
    assert!(p.prove_range(5, 10).is_err(), "value < threshold produced a proof");
}

#[test]
fn atk_range_field_overflow() {
    let p = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
    assert!(p.prove_range(MAX_RANGE_VALUE, 5).is_err(), "value == MAX_RANGE_VALUE accepted");
    assert!(p.prove_range(MAX_RANGE_VALUE + 1000, 5).is_err(), "value > MAX_RANGE_VALUE accepted");
    assert!(p.prove_range(1000, MAX_RANGE_VALUE + 1).is_err(), "threshold > MAX accepted");
}

// ---- hash collision resistance (C-3 / C-4) ----

#[test]
fn atk_bytes_to_field_wraparound_collision() {
    // Old bug: 0 and ORDER_U64 both reduced to field 0.
    assert_ne!(
        bytes_to_field(&[0u8; 8]),
        bytes_to_field(&GOLDILOCKS_ORDER.to_le_bytes()),
        "byte->field wraparound collision"
    );
}

#[test]
fn atk_sponge_trailing_zero_collision() {
    assert_ne!(
        poseidon_hash(b"abc", b"dom"),
        poseidon_hash(b"abc\x00", b"dom"),
        "trailing-zero sponge collision"
    );
}

// ---- epoch deserialization panic (H-1) ----

#[test]
fn atk_epoch_overflow_no_panic() {
    // Must return Err, never panic (reachable from untrusted bytes).
    assert!(Epoch::from_bytes(u64::MAX.to_le_bytes()).is_err(), "u64::MAX epoch not rejected");
}

// ---- MTD epoch/seed binding (H-3) ----

#[test]
fn atk_mtd_cross_seed_replay() {
    let mut prover = RealStarkProver::new(SimpleAir::fibonacci()).unwrap();
    prover.set_mtd_seed([7u8; 32]);
    let proof = prover.prove_fibonacci(8).unwrap();
    assert!(prover.get_verifier().verify_fibonacci(&proof).unwrap());

    let mut other = RealStarkVerifier::new(SimpleAir::fibonacci()).unwrap();
    other.set_mtd_seed([8u8; 32]);
    assert!(!other.verify_fibonacci(&proof).unwrap(), "proof verified under a different MTD seed");
}

// ---- determinism (no hidden nondeterminism across runs) ----

#[test]
fn atk_determinism() {
    let p = RealStarkProver::new(SimpleAir::sum()).unwrap();
    let v = p.get_verifier();
    let a = p.prove_sum(&[1, 2, 3, 4], &[5, 6, 7, 8]).unwrap();
    let b = p.prove_sum(&[1, 2, 3, 4], &[5, 6, 7, 8]).unwrap();
    assert_eq!(a.public_values, b.public_values, "public values nondeterministic");
    assert!(v.verify_sum(&a).unwrap() && v.verify_sum(&b).unwrap());
    assert_eq!(poseidon_hash(b"x", b"y"), poseidon_hash(b"x", b"y"), "hash nondeterministic");
}

// ---- C-A: on-chain batch verification requires a TRUSTED external root ----

#[cfg(feature = "solana-adapter")]
#[test]
fn atk_ca_onchain_batch_requires_trusted_root() {
    use zkmtd::solana::onchain_verifier::VerificationStatus;
    use zkmtd::solana::{BatchLightweightProof, OnchainVerifier};

    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let tree = MerkleTree::new(leaves.clone()).unwrap();
    let path = tree.get_proof(0).unwrap();
    let trusted_root = *tree.root();

    let proof = BatchLightweightProof {
        merkle_root: trusted_root,
        proof_count: 4,
        epoch: 100,
        merkle_path: path.siblings.clone(),
        leaf_index: 0,
        leaf_commitment: leaves[0],
    };

    // Legit proof against the correct TRUSTED root -> Valid.
    let v_ok = OnchainVerifier::new(100, [0u8; 32]).with_expected_merkle_root(trusted_root);
    assert_eq!(v_ok.verify_batch(&proof), VerificationStatus::Valid);

    // C-A: no trusted root configured -> rejected (must not trust the proof's own root).
    let v_none = OnchainVerifier::new(100, [0u8; 32]);
    assert_ne!(v_none.verify_batch(&proof), VerificationStatus::Valid, "self-rooted batch accepted");

    // Forged leaf (never in the tree) -> rejected against the trusted root.
    let mut forged = proof.clone();
    forged.leaf_commitment = [0x41u8; 32];
    assert_ne!(v_ok.verify_batch(&forged), VerificationStatus::Valid, "forged leaf accepted");
}

// ---- H-A: leaf index must be bound (within tree, full-depth path) ----

#[cfg(feature = "solana-adapter")]
#[test]
fn atk_ha_leaf_index_bound() {
    use zkmtd::solana::BatchLightweightProof;

    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let tree = MerkleTree::new(leaves.clone()).unwrap();
    let path = tree.get_proof(0).unwrap();
    let trusted = *tree.root();

    let mk = |idx: u32| BatchLightweightProof {
        merkle_root: trusted,
        proof_count: 4,
        epoch: 1,
        merkle_path: path.siblings.clone(),
        leaf_index: idx,
        leaf_commitment: leaves[0],
    };

    assert!(mk(0).verify_inclusion_against(&trusted), "legit index-0 proof rejected");
    assert!(!mk(4).verify_inclusion_against(&trusted), "leaf_index >= proof_count accepted");
    assert!(!mk(0x7FFF_FFFE).verify_inclusion_against(&trusted), "out-of-range leaf_index accepted");
}

// ---- H-B: hash_to_field must not be linearly collidable ----

#[test]
fn atk_hb_hash_to_field_no_linear_collision() {
    let mut a = [0u8; 32];
    a[0] = 1;
    let mut b = [0u8; 32];
    b[7] = 1; // same limb-sum as `a` under the old (buggy) additive folding
    assert_ne!(hash_to_field(&a), hash_to_field(&b), "hash_to_field linear collision");
}

// ---- M-A: poseidon_hash must absorb the FULL domain ----

#[test]
fn atk_ma_long_domain_no_prefix_collision() {
    let d1 = vec![0xAAu8; 100];
    let mut d2 = vec![0xAAu8; 100];
    d2[80] = 0xBB; // differ only past byte 56 (old code truncated the domain there)
    assert_ne!(
        poseidon_hash(b"data", &d1),
        poseidon_hash(b"data", &d2),
        "long-domain prefix collision"
    );
}
