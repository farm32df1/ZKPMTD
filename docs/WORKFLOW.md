# Privacy-Preserving Verification Workflow

## Problem

Web3 services often need to verify user attributes such as age, financial status, or medical records. Storing this personal data on-chain creates GDPR and CCPA compliance risks. Traditional approaches either expose sensitive data or require trusted third parties.

## Solution

ZKMTD enables verification of user attributes without revealing the underlying data. The user generates a zero-knowledge proof on their device proving a statement like "age is at least 18" without revealing their actual age. Only the proof result is submitted on-chain.

## Off-Chain Phase

The user holds sensitive data locally on their device. This could be their birthdate, bank balance, vaccination record, or any private information.

The user generates a zero-knowledge proof. For example, if the requirement is "age >= 18" and the user is 25 years old, the proof demonstrates the requirement is satisfied without revealing that the age is 25.

The proof is bound to the current epoch. This binding ensures the proof cannot be replayed in future epochs. The Moving Target Defense system rotates cryptographic parameters each epoch.

A lightweight proof is created containing only the commitment hash and public result. The original sensitive data never leaves the user device.

## On-Chain Phase

The lightweight proof is submitted to Solana. This consumes approximately 5000 compute units.

The smart contract verifies the commitment binding and checks epoch validity. It does not and cannot access the original sensitive data.

The contract stores only the verification result such as proof valid equals true and the epoch number. No personal data is written to the blockchain.

The service can now trust that the user meets the requirement without ever seeing their private information.

## Security Properties

Replay attacks are prevented by epoch binding. A proof valid in epoch 100 becomes invalid in epoch 101. This protects against attackers capturing and reusing old proofs.

High latency networks are supported. The epoch tolerance system allows proofs to remain valid across reasonable network delays. This works for VPN connections, satellite links, and other delayed environments.

Post-quantum security is provided by hash-based STARK proofs. No elliptic curve cryptography is used, making the system immune to quantum attacks using Shor's algorithm.

## Example Use Cases

Age verification allows services to confirm users are above a minimum age without collecting birthdates.

Financial compliance enables proof of sufficient balance or income without exposing exact amounts.

Medical records can prove vaccination status or health conditions without revealing full medical history.

Identity verification confirms credential validity without transmitting personally identifiable information.

## Data Flow Summary

User device holds sensitive data. User device generates ZK proof. User device creates lightweight commitment. Lightweight commitment travels to blockchain. Blockchain verifies commitment only. Blockchain stores result only. Sensitive data never leaves user device.
