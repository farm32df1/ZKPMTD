//! Fuzz target for Merkle path verification
//! Tests: MerklePath::verify_against() with arbitrary paths
//! Goal: Ensure no panics, constant-time comparison, bounds checking

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zkmtd::batching::merkle::MerklePath;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    leaf_index: usize,
    siblings: Vec<[u8; 32]>,
    root: [u8; 32],
    leaf: [u8; 32],
    expected_root: [u8; 32],
}

fuzz_target!(|input: FuzzInput| {
    // Limit siblings to reasonable depth (prevent OOM)
    if input.siblings.len() > 64 {
        return;
    }

    let path = MerklePath {
        leaf_index: input.leaf_index,
        siblings: input.siblings,
        root: input.root,
    };

    // Test compute_root - should never panic
    let _ = path.compute_root(&input.leaf);

    // Test verify_against - should never panic
    let _ = path.verify_against(&input.leaf, &input.expected_root);

    // Test verify (self-verification) - should never panic
    let _ = path.verify(&input.leaf);
});
