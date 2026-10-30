# Architecture Decisions for the X.509 + ZK Prototype

Several roadmap items depend on choices that change what the circuit proves, what the CA must do, or which proof system is used. Making these choices before building those items avoids work that a later decision would throw away. This document lays out the options; each decision is **open** until recorded here.

| # | Decision | Blocks roadmap items | Status |
|---|----------|----------------------|--------|
| D1 | What the CA must do (trust model) | 7, 8 | Open |
| D2 | Proof system | 10, and most circuit work | Open |
| D3 | Curve | 10 | Open (follows D2) |
| D4 | Where the issuing CA chain lives | 4 | Open |
| D5 | How key possession is proved | 5 | Open (follows D2) |

## D1. Trust model: what the CA must do

Today the circuit verifies a standard X.509 certificate: the CA's ECDSA signature over the TBSCertificate, with in-circuit SHA-256 and DER parsing. That is what lets this approach "work with existing PKI", its main advantage over BBS in the [top-level comparison](../README.md#comparison).

| Option | What the CA does | Circuit cost | Revocation | Certificate validation |
|--------|------------------|--------------|------------|------------------------|
| **A. Existing PKI only** (current) | Nothing new | ~4.8M constraints; CA ECDSA, SHA-256, and DER parsing in-circuit | Needs a separate mechanism (short-lived certs, or an accumulator anyway) | Must be done in-circuit (roadmap item 7) |
| **B. CA-published accumulator** | Periodically publishes a signed Merkle root over currently valid subject public keys | Removes the CA ECDSA, SHA-256, and TBS binding (more than half the circuit); adds a Merkle path | Built in: drop the leaf from the next root | Done by the CA when building the root, so item 7 is largely unnecessary |
| **C. Twin SNARK-friendly signature** | Also signs each subject key with a SNARK-friendly scheme (for example EdDSA over Baby Jubjub) | Order-of-magnitude reduction; no non-native ECDSA for issuance | Still needs a separate mechanism | Done by the CA at issuance |

Trade-offs:

- A keeps the "no change to existing PKI" property but carries the full cost, and still needs a revocation answer.
- B and C require CA cooperation, which weakens the main argument for this approach over BBS: if the CA must issue something new, the BBS comparison becomes closer.
- B's anonymity set is "keys valid at the time of the root" rather than "every certificate ever issued", and verifiers must fetch fresh roots.
- B and A are not exclusive: A could remain the baseline, with B as an optional fast path for cooperating CAs, at the cost of maintaining two circuits.

## D2. Proof system

The current Groth16/circom stack gives ~1 KB proofs and millisecond verification, but needs ~12 GB of RAM and ~10 minutes to prove (a 61% constraint reduction only halved proving time, so WASM witness generation is a large share of it), and a circuit-specific trusted setup that must be redone (and redistributed) after every circuit change.

| Option | Setup | Proof size / verification | Proving cost for P-256 + SHA-256 | Notes |
|--------|-------|---------------------------|----------------------------------|-------|
| **Groth16 + circom** (current) | Per-circuit trusted setup | ~128 B SNARK (~1 KB with current encoding) / ms | Highest: P-256 arithmetic emulated over BN254 | Mature tooling; setup and key distribution are an ongoing burden (roadmap item 13) |
| **PLONKish (for example Halo2)** | Universal setup (KZG) or none (IPA) | A few KB / still well under a second | 5-20x faster in published ECDSA benchmarks, thanks to lookups | Requires rewriting the circuit; can be wrapped in Groth16 for small proofs |
| **Folding (Nova family) + Groth16 wrapper** | Wrapper needs a setup | Small (wrapped) | Linear, FFT-free folding; best when amortized over many proofs | Most useful if a signer anonymizes many assets |
| **Proof systems designed for ECDSA credentials** (for example Google's Longfellow ZK, used for ECDSA-signed mobile driving licences) | None | Larger proofs than Groth16 | Designed specifically for P-256 ECDSA + SHA-256 workloads | Worth evaluating: this prototype's workload (P-256 signatures over SHA-256 hashes of structured data) closely matches its target use case |

Trade-offs:

- Every option other than Groth16 means rewriting the circuit, so circuit work done in circom before this decision is at risk. Changes that only reduce cost without altering the proof statement (such as roadmap item 2) remain worthwhile either way.
- Removing the per-circuit trusted setup also removes the key-distribution problem in roadmap item 13.
- The verifying side matters for C2PA: verifiers must ship the verification logic. A standardized or widely implemented proof system is easier to adopt than a bespoke one.

## D3. Curve

Applies only to pairing-based systems (Groth16, KZG-based PLONK).

- **BN254** (current): fastest tooling support, but conjectured security is about 100 bits after the Kim-Barbulescu attacks.
- **BLS12-381**: about 120 bits or more, slightly slower proving and slightly larger proofs (~192 B for Groth16).

For a production privacy system, BN254's margin is hard to justify. This decision follows D2: it is moot for proof systems that are not pairing-based.

## D4. Where the issuing CA chain lives

Roadmap item 4 adds the issuing CA's chain (intermediates, never the signer's certificate) to the anonymized asset so verifiers can validate it to a trust anchor.

- **CA-only `x5chain`**: reuses the standard header, but `x5chain` defines its first certificate as the signer's end-entity certificate, and `c2pa-rs` rejects a CA certificate in that position (`check_end_entity_certificate_profile`). Tools would misreport the CA as the signer.
- **A dedicated field in the `c2pa-x509-zk` header map**: no conflict with `x5chain` semantics; tools that don't understand the extension already must reject the signature because the extension is marked critical. Requires our verifier, and eventually a spec proposal, to define the field.

Related: `c2pa-rs` currently aborts reading when no signing certificate chain is present (roadmap item 1). Either option may need an upstream change for `c2patool` to display these assets in validating mode.

## D5. How key possession is proved

Today a second in-circuit P-256 ECDSA verification (~2M constraints) proves that the prover holds the certificate's private key, by verifying a fresh signature over the asset digest.

- **In-circuit ECDSA** (current): one self-contained proof.
- **Sigma protocol outside the SNARK**: the SNARK outputs a commitment to the subject public key; the signer adds a Schnorr-style proof of knowledge of the matching secret key, bound to the claim hash with Fiat-Shamir. Removes ~2M constraints, at the cost of a second, small proof and a commitment scheme that must be secure across both proof systems.

This interacts with roadmap item 5 (binding the proof to the C2PA claim): whichever proof carries possession is the one that must bind to the claim. If D2 selects a proof system with cheap ECDSA, the case for the Sigma protocol weakens.
