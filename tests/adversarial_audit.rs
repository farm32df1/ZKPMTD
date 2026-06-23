//! Adversarial re-attack suite. Each test ATTEMPTS an exploit and asserts the
//! system DEFENDS (rejects it). A failing test = a real finding / regression.
//! Run repeatedly (loop) to also catch nondeterminism.
//! `cargo test --test adversarial_audit --features "std,full-p3,solana-adapter,borsh"`

use zkmtd::batching::MerkleTree;
use zkmtd::stark::air::SimpleAir;
use zkmtd::stark::{ProofAirType, RealStarkProver, RealStarkVerifier};
use zkmtd::utils::hash::{bytes_to_field, poseidon_hash};
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
