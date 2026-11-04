# Architecture Decisions for the X.509 + ZK Prototype

## Goals

This prototype is a feasibility study of using zero-knowledge proofs to anonymize the signer of a C2PA asset. It has two goals:

1. **Prove the technology and compare the options.** Each decision below is prototyped and measured rather than settled up front. Experiments may use efficient choices (P-256, a test trust setup that mimics C2PA's) as long as the cost of moving to real deployments (P-384 and RSA CAs, the C2PA trust list, a stronger proof-system curve) is measured or prototyped.
2. **Determine which options could work today** given current C2PA deployments.

### Method

- **Settle what is proved before comparing how fast.** Each variant is described by the statement it proves, what it discloses, and what it assumes (registration, freshness, historical validity). Variants are compared only against others that establish equivalent guarantees; otherwise the fastest one may simply prove less.
- **Label shortcuts.** Every result records which guarantees are established and which are experimental shortcuts (for example, partial certificate validation). Primitive benchmarks may omit validation; an end-to-end demonstration must say what it does not check.
- **Measure, then narrow.** The comparison matrix ([R1](README.md#r1-feasibility-matrix)) is kept up to date as experiments land, with explicit success and stop criteria, so the work does not turn into an exhaustive sweep of every combination.

Designs target the official [C2PA trust list](https://github.com/c2pa-org/conformance-public/tree/main/trust-list). The earlier interim trust list is not a design target, but much existing content relies on it, so goal 2 accounts for it. Both lists, and real signed samples, are analysed in [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md).

## Decisions

| # | Decision | Status | Roadmap |
|---|----------|--------|---------|
| D1 | Trust model: what the circuit proves about issuance | Prototype and compare A, B, C | [E3](README.md#e3-trust-model-b-merkle-membership), [E4](README.md#e4-trust-model-c-snark-friendly-credential) (A is the current baseline) |
| D2 | Proof system | Prototype and compare | [E6](README.md#e6-proof-systems) |
| D3 | Curve | Compare BN254 and BLS12-381 | [E7](README.md#e7-curve-bn254-vs-bls12-381) |
| D4 | Where the issuing CA chain lives | **Decided:** in `x5chain`, without the signer's certificate | [F1](README.md#test-pki-and-trust-lists) |
| D5 | How key possession is proved | Prototype and compare | [E5](README.md#e5-key-possession) |
| D6 | Who anonymizes: signer-side or third-party | Statement **adopted** in [THIRD-PARTY-STATEMENT.md](THIRD-PARTY-STATEMENT.md); being prototyped in E2b | [E2a](README.md#e2a-third-party-proof-statement-and-privacy-design), [E2b](README.md#e2b-third-party-anonymization) |
| D7 | Time policy: when must the certificate have been valid, and on what evidence | **Adopted** in [THIRD-PARTY-STATEMENT.md](THIRD-PARTY-STATEMENT.md#q6-time-policy): a trusted time stamp is required | [E2a](README.md#e2a-third-party-proof-statement-and-privacy-design) |

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
- B's anonymity set is "keys valid at the time of the root", and verifiers must fetch fresh roots. Short-lived signer certificates (some deployments use ~90-day certificates that appear to be issued per capture or session) mean frequent registrations.
- The interim trust list's directly trusted end-entity certificates map naturally onto B: membership in a published set of keys, buildable by anyone from the public list ([R3](README.md#r3-interim-list-allowed-signers-via-merkle-membership)). Building the tree publicly removes registration, but not the need to authenticate the source list and its interpretation: neither the official nor the interim list is signed today.
- B and C replace the proof of *issuance*, not the proof that the asset was signed. In third-party mode (D6) the original signature must still be verified, so B and C must be compared with A on the same overall statement.
- B and C need lifecycle semantics before they can be compared: whether a leaf or credential represents a key, a certificate, or an authorization with validity and policy attributes; how verifiers authenticate roots and reject stale ones; whether membership means "authorized now" or "authorized when signed"; and how renewal, revocation, and historical proofs behave. Dropping a leaf revokes only if verifiers stop accepting older roots, and short-lived certificates bound exposure but do not revoke immediately.

## D2. Proof system

The current Groth16/circom stack gives ~1 KB proofs and millisecond verification, but needs ~11 GiB of RAM and ~10 minutes per asset, and a circuit-specific trusted setup that must be redone (and redistributed) after every circuit change. The [baseline measurement](FEASIBILITY.md#observations) shows the Groth16 proof itself takes ~32 s; loading the 1 GB proving key (57% of the time) and WASM witness generation (37%) dominate, so the cheapest gains are engineering ones within this stack (key format, native witness generation) before any change of proof system.

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

**Decision:** the anonymized asset's `x5chain` carries the issuing CA chain (intermediates up to, but excluding, the trust anchor) and never the signer's certificate. When the issuing CA is itself a trust anchor, as is common on the C2PA trust list, the chain may be just that certificate. Implemented in F1.

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

The statement is adopted in [THIRD-PARTY-STATEMENT.md](THIRD-PARTY-STATEMENT.md), including making signer-side mode use the same statement ([Q2](THIRD-PARTY-STATEMENT.md#q2-one-statement-for-both-modes)). What third-party mode must prove is a complete connection: trusted issuer → authorized signer → original COSE signature → original claim → asset binding → anonymized output. Points that make this more than "verify the signature over the claim":

- COSE signs its `Sig_structure`, which includes the protected header. C2PA places `x5chain` in the protected header, so the signed bytes contain the signer's certificate: the circuit must hash them with the certificate as a private input.
- The claim's hard binding (`c2pa.hash.data`) excludes the manifest's byte range. If the anonymized output carries a different manifest, the original binding no longer matches the output bytes; the statement must say whether the output keeps the original claim or the proof bridges the original binding to the new bytes.
- Authenticating the original claim does not authenticate a rewritten one. If assertions are removed or changed for privacy (the original claim carries device and software details, instance identifiers, and possibly identity assertions), the statement must say which original assertions remain authenticated and how; C2PA's redaction mechanism references assertions by hash, which leaks low-entropy assertions unless they are salted.
- Nothing identifying (the original signature, certificate, or references to them) may be disclosed just to make verification easier.

Key possession (D5) does not apply here: there is no private key, only the original signature.

Why it matters: device keys are often not exportable (they are typically generated in secure hardware and may be short-lived), and keys for existing content are generally unavailable. For goal 2, third-party mode is likely the only way to anonymize content that already exists. Its costs: hashing the serialized claim in-circuit, and verifying the original signature with whatever algorithm the signer used (ES256 with P-256 signer keys is common on devices; PS256 for many interim-list signers). It also lets parties other than the signer anonymize content, which may or may not be desirable.

## D7. Time policy

The circuit checks the signer certificate's validity against a timestamp. Which timestamp, and what evidence backs it, is a policy decision with two separate questions:

- **Was the certificate valid when the original signature was made?** Requiring validity at anonymization time would exclude legitimate historical content; accepting an arbitrary historical timestamp would allow backdating.
- **Is it acceptable to anonymize, or to verify, that content now?** For example, whether a certificate revoked after signing should still count.

Evidence differs in strength. A date inside the claim is self-reported by the signer, even though it is signed. An RFC 3161 time-stamp token from a TSA on the C2PA TSA trust list is independent evidence; real assets carry them (see [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#time-stamping)).

**What a C2PA time stamp covers** ([C2PA 2.5 §10.3.2.5.2–10.3.2.5.4](https://spec.c2pa.org/specifications/specifications/2.5/specs/C2PA_Specification.html#_choosing_the_payload)). The TSA receives a message imprint: a hash of a COSE `Sig_structure` with context `CounterSignature`, whose other elements follow the claim signature's own (so it includes the claim signature's protected header, which carries the signer's certificate). Its payload depends on the version:

- **v1, `sigTst` (deprecated):** the claim signature's payload, i.e. the claim. Validators must still process it.
- **v2, `sigTst2`:** the serialized `signature` byte string of the claim's `COSE_Sign1`, including the CBOR major-type and length bytes. Claim generators must use v2; the spec describes it as a countersignature on the entire signature structure, including the certificate.

Both are stored in the unprotected header; a manifest holds at most one time stamp. The versions in real assets differ (see [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#time-stamping)), so supporting both means two imprint constructions with different witnesses and hashing costs.

**Using the time stamp without breaking anonymity.** The token carries the imprint, not its preimage, so publishing it does not reveal the original signature or certificate. It does expose a stable fingerprint: anyone holding the original asset, or records of it, can recompute the imprint and match it. In particular the TSA operator saw the imprint when the signer's device requested the time stamp, and for device-signed content the TSA is often run by the same organization as the CA. Two designs, to be chosen against an explicit threat model:

1. **Public token plus ZK binding:** verify the TSA's signature on the token off-circuit, and prove in ZK that the authenticated imprint corresponds to the original signed material. Cheaper, but leaves the fingerprint.
2. **Hidden token:** verify the TSA evidence inside the proof as well, so no fingerprint is exposed, at the cost of another in-circuit signature verification and the imprint's hashing.

A third option, time-stamping the anonymized output, proves existence at anonymization time only, not signing time. The adopted policy and threat model are in [THIRD-PARTY-STATEMENT.md](THIRD-PARTY-STATEMENT.md#q6-time-policy) (Q6, Q7). Revocation semantics ([H3](README.md#h3-revocation)) follow the same signing-time vs now distinction.
