# Architecture Decisions for the X.509 + ZK Prototype

## Goals

This prototype is a feasibility study of using zero-knowledge proofs to anonymize the signer of a C2PA asset. It has two goals:

1. **Prove the technology and compare the options.** Each decision below is prototyped and measured rather than settled up front. Experiments may use efficient choices (P-256, a test trust setup that mimics C2PA's) as long as the cost of moving to real deployments (P-384 and RSA CAs, the C2PA trust list, a stronger proof-system curve) is measured or prototyped.
2. **Determine which options could work today** given current C2PA deployments.

Designs target the official [C2PA trust list](https://github.com/c2pa-org/conformance-public/tree/main/trust-list). The earlier interim trust list is not a design target, but much existing content relies on it, so goal 2 accounts for it. Both lists, and real signed samples, are analysed in [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md).

## Decisions

| # | Decision | Status | Roadmap |
|---|----------|--------|---------|
| D1 | Trust model: what the circuit proves about issuance | Prototype and compare A, B, C | [E3](README.md#e3-trust-model-b-merkle-membership), [E4](README.md#e4-trust-model-c-snark-friendly-credential) (A is the current baseline) |
| D2 | Proof system | Prototype and compare | [E6](README.md#e6-proof-systems) |
| D3 | Curve | Compare BN254 and BLS12-381 | [E7](README.md#e7-curve-bn254-vs-bls12-381) |
| D4 | Where the issuing CA chain lives | **Decided:** in `x5chain`, without the signer's certificate | [F1](README.md#f1-c2pa-like-test-pki-and-trust-lists) |
| D5 | How key possession is proved | Prototype and compare | [E5](README.md#e5-key-possession) |
| D6 | Who anonymizes: signer-side or third-party | Prototype and compare | [E2](README.md#e2-anonymization-mode-signer-side-vs-third-party) |

## D1. Trust model: what the circuit proves about issuance

Today the circuit verifies a standard X.509 certificate: the CA's ECDSA signature over the TBSCertificate, with in-circuit SHA-256 and DER parsing. That is what lets this approach "work with existing PKI", its main advantage over BBS in the [top-level comparison](../README.md#comparison).

| Option | Who does what | Circuit cost | Revocation | Certificate validation |
|--------|---------------|--------------|------------|------------------------|
| **A. Existing PKI only** (current) | Nothing new | ~4.8M constraints with a P-256 CA; real CAs need P-384, P-521, or RSA in-circuit (see [E1](README.md#e1-cost-of-reality-p-384-sha-384-and-rsa-in-circuit)) | Needs a separate mechanism (short-lived certs, or an accumulator anyway) | Must be done in-circuit ([H2](README.md#h2-full-certificate-validation-in-the-circuit)) |
| **B. Merkle membership** | An entity publishes a signed Merkle root over valid signer public keys | Removes the CA signature, SHA-256, and TBS binding (more than half the circuit); adds a Merkle path | Built in: drop the leaf from the next root | Done by the entity when building the root |
| **C. SNARK-friendly credential** | An entity signs each valid signer key with a SNARK-friendly scheme (for example EdDSA over Baby Jubjub) | Order-of-magnitude reduction; no non-native ECDSA for issuance | Still needs a separate mechanism | Done by the entity at issuance |

**Who can run B and C.** Neither requires the CAs to change anything. A single entity (for example the C2PA conformance program, or a dedicated anonymity service) can operate either under a **registration model**: a signer submits their X.509 chain and proves possession of the key; the entity validates the chain against the trust list, then adds the key to the Merkle tree (B) or issues a SNARK-friendly credential over it and chosen attributes such as the issuing CA or validity period (C). A CA-run variant of B would instead need every CA to publish roots, since no one else knows the full set of issued certificates.

Trade-offs:

- A keeps the "no change to existing PKI" property but must verify each CA's actual signature algorithm in-circuit, and still needs a revocation answer.
- With a registration entity, B and C make the circuit independent of the CA's key type, and the anonymity set can span every CA on the trust list (see [H4](README.md#h4-hiding-the-issuing-ca)). In exchange, the entity becomes a trust anchor (its key compromise allows forgery), learns who registered (but not what they later sign), and the anonymity set is limited to registered signers.
- B's anonymity set is "keys valid at the time of the root", and verifiers must fetch fresh roots. Short-lived signer certificates (Pixel's last about 90 days and appear to be issued per capture or session) mean frequent registrations.
- The interim trust list's directly trusted end-entity certificates map naturally onto B: membership in a published set of keys, buildable by anyone from the public list ([R3](README.md#r3-interim-list-allowed-signers-via-merkle-membership)).

## D2. Proof system

The current Groth16/circom stack gives ~1 KB proofs and millisecond verification, but needs ~12 GB of RAM and ~10 minutes to prove (a 61% constraint reduction only halved proving time, so WASM witness generation is a large share of it), and a circuit-specific trusted setup that must be redone (and redistributed) after every circuit change.

| Option | Setup | Proof size / verification | Proving cost for P-256 + SHA-256 | Notes |
|--------|-------|---------------------------|----------------------------------|-------|
| **Groth16 + circom** (current) | Per-circuit trusted setup | ~128 B SNARK (~1 KB with current encoding) / ms | Highest: P-256 arithmetic emulated over BN254 | Mature tooling; setup and key distribution are an ongoing burden ([H7](README.md#h7-build-setup-and-test-infrastructure)) |
| **Groth16 + circom, native witness generation** | Same | Same | Same constraints; avoids the WASM witness generator | Cheapest experiment: same circuit, targets the measured bottleneck |
| **PLONK family on the same R1CS** (for example snarkjs PLONK/FFLONK) | Universal setup | Larger / slower than Groth16 | Same circuit; usually slower to prove | Shows the cost of dropping the per-circuit setup without a rewrite |
| **PLONKish with lookups (for example Halo2)** | Universal setup (KZG) or none (IPA) | A few KB / still well under a second | 5-20x faster in published ECDSA benchmarks, thanks to lookups | Requires rewriting the circuit; can be wrapped in Groth16 for small proofs |
| **gnark (Go)** | Groth16 or PLONK | Groth16 or PLONK sizes | Emulated-field ECDSA gadgets | One codebase could cover D2, D3, and P-384 CAs; gadget coverage (for example SHA-384) to be confirmed |
| **Folding (Nova family) + Groth16 wrapper** | Wrapper needs a setup | Small (wrapped) | Linear, FFT-free folding; best when amortized over many proofs | Most useful if a signer anonymizes many assets |
| **Proof systems designed for ECDSA credentials** (for example Google's Longfellow ZK, used for ECDSA-signed mobile driving licences) | None | Larger proofs than Groth16 | Designed for P-256 ECDSA + SHA-256 workloads | Matches the signer-key side of this workload; fit for P-384 CA signatures unclear |

Trade-offs:

- Every option other than the first three means rewriting the circuit. Changes that only reduce cost without altering the proof statement remain worthwhile either way.
- Removing the per-circuit trusted setup also removes the key-distribution problem in [H7](README.md#h7-build-setup-and-test-infrastructure).
- The verifying side matters for C2PA: verifiers must ship the verification logic. A standardized or widely implemented proof system is easier to adopt than a bespoke one.

## D3. Curve

Applies only to pairing-based systems (Groth16, KZG-based PLONK).

- **BN254** (current): fastest tooling support, but conjectured security is about 100 bits after the Kim-Barbulescu attacks.
- **BLS12-381**: about 120 bits or more, slightly slower proving and slightly larger proofs (~192 B for Groth16). `circom` can compile for its scalar field and arkworks supports it.

For a production privacy system, BN254's margin is hard to justify. Moot for proof systems that are not pairing-based.

## D4. Where the issuing CA chain lives: decided

**Decision:** the anonymized asset's `x5chain` carries the issuing CA chain (intermediates up to, but excluding, the trust anchor) and never the signer's certificate. When the issuing CA is itself a trust anchor, as for Pixel, the chain may be just that certificate.

This follows `x5chain`'s purpose but departs from C2PA's requirements for it:

- RFC 9360 §2: the certificates "are to be ordered starting with the certificate containing the end-entity key followed by the certificate that signed it", and the header proposes a candidate path ("There is no requirement for the entire chain to be present").
- C2PA 2.5 §13.5: "the claim generator shall include the signer's certificate and all intermediate certificate authorities in the header's value. The trust anchor's certificate (also called the root certificate) should not be included", and "The `subjectPublicKeyInfo` element of the first or only certificate will be the public key used to validate the signature." §13.5.1.1: "Only end entity certificates shall be used to sign C2PA Claims".

The departure is scoped by the prototype's private-use COSE algorithm, which is marked critical: verifiers that do not understand it must reject the signature anyway. Consequence: stock `c2pa-rs` reads the first certificate as the signer's and fails its end-entity profile check, and already treats a missing signing certificate as fatal. Displaying or verifying anonymized assets in `c2patool` needs changes ([H8](README.md#h8-c2patool-support)).

## D5. How key possession is proved

Today a second in-circuit P-256 ECDSA verification (~2M constraints) proves that the prover holds the certificate's private key, by verifying a fresh signature over the asset digest.

- **In-circuit ECDSA** (current): one self-contained proof.
- **Commitment plus a proof outside the SNARK**: the SNARK outputs a commitment to the signer's public key, and the signer adds a Schnorr-style proof of knowledge of the matching secret key, bound to the claim with Fiat-Shamir. The commitment must be in a group where that proof is possible: committing on a SNARK-friendly curve such as Baby Jubjub would require a proof linking two different curves, which is complex. The straightforward variant commits on P-256 itself (`C = pk + r·H`) and proves knowledge of `(sk, r)` with `C = sk·G + r·H` outside the circuit, which is standard and cheap; the circuit then still computes one P-256 fixed-base multiplication (`r·H`). Expected saving: roughly half of one in-circuit ECDSA verification, not all of it.

Whichever proof carries possession is the one that must bind to the claim. In third-party mode (D6) there is no possession step: the original signature is verified instead. If D2 selects a proof system with cheap ECDSA, the case for the commitment variant weakens.

## D6. Who anonymizes: signer-side or third-party

- **Signer-side** (current): the anonymizer re-signs the asset with the signer's private key, and the circuit verifies that fresh signature. Only the original signer can anonymize, and only while they hold the key.
- **Third-party**: the circuit verifies the **original** COSE signature over the **original** claim, under a certificate chaining to the trust list. No private key is needed, so anyone holding the asset (a newsroom receiving it, for example) can anonymize it, and the proof covers the original claim and all its assertions.

Why it matters: device keys are often not exportable (Pixel keys are generated in the Titan M2 chip and appear to be short-lived), and keys for existing content are generally unavailable. For goal 2, third-party mode is likely the only way to anonymize content that already exists. Its costs: hashing the serialized claim in-circuit, and verifying the original signature with whatever algorithm the signer used (ES256 for Pixel; PS256 for many interim-list signers). It also lets parties other than the signer anonymize content, which may or may not be desirable.
