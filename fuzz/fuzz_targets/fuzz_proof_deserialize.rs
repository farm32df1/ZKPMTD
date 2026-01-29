//! Fuzz target for Solana proof deserialization
//! Tests: deserialize_proof() with arbitrary byte sequences
//! Goal: Ensure no panics, memory safety, bounds checking

#![no_main]

use libfuzzer_sys::fuzz_target;
use zkmtd::adapters::{SolanaAdapter, SolanaChainAdapter};

fuzz_target!(|data: &[u8]| {
    let adapter = SolanaAdapter::new();

    // Should never panic, only return Ok or Err
    let _ = adapter.deserialize_proof(data);
});
