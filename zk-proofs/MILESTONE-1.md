# Milestone 1: Third-Party Anonymization of Real C2PA Content

**Status: reached** (November 12, 2026, at PR #44). This document summarizes what the prototype now does, what it proves and discloses, what was measured, on what assumptions, and what is postponed to a second phase. Details are in the documents it links to; the evolution is in [HISTORY.md](HISTORY.md).

## Goals

The prototype studies whether zero-knowledge proofs can remove a C2PA signer's identity from signed content while keeping the content verifiable ([README](README.md)). The project set two goals:

1. **Feasibility:** prove the idea works, and compare the options (statements, trust models, proof systems, curves) by cost and by what they disclose ([FEASIBILITY.md](FEASIBILITY.md)).
2. **Real deployments:** establish what works on content signed by real C2PA deployments today, under the official trust lists ([DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md)).

Milestone 1's goal: **a third party, without the signer's key, can anonymize content a real device signed under the official trust list, hiding the signer, its issuing CA, and its time-stamp authority, while a verifier still checks the claim, the hard binding, and a statement of trust under its own policy.**

## What was reached

A real device photo, signed under the official C2PA trust list and time-stamped by a TSA on the official TSA list, is anonymized by the prototype and verified against both lists. The output:

- **Discloses no certificate, signature, or time-stamp token:** neither the signer's certificate and key, the original signature, the issuing CA, the TSA's certificates, nor the token's serial number and imprint.
- **Proves:** *the claim in this asset was signed by the holder of a certificate that a CA among the official list's 28 eligible P-384 CAs issued for C2PA claim signing; a TSA certified by one of the TSA list's 19 eligible P-384 CAs time-stamped that signature on a given UTC day, while the certificate was valid.*
- **Keeps** the original claim and its hard binding, so the content's integrity is checked as for any C2PA asset; the file keeps its size; the signature is replaced in place.
- **Scrubs** the photo's EXIF and XMP (outside the hard binding), so that its only remaining mention of the device's maker is in the claim.

On a laptop, anonymizing the benchmark fixture (a test asset mirroring the real deployment's chain) takes about 70–90 seconds and 7–9 GB of memory, depending on what is hidden, measured in one session; the real photos, in single runs, took 75 seconds with the issuer hidden and 129–141 seconds with everything hidden. Verifying takes 30–50 ms (about 0.1 s with the full verifier).

## The modes

Three statements, each with its own keys; the first is the default, the others opt-in. Metadata scrubbing applies to all three.

| | **Disclosed** (V1) | **Hidden issuer** (H4) | **Hidden issuer and time stamp** (I6) |
|---|---|---|---|
| Proves | The original ES256 signature over the claim, by a key in a certificate the issuing CA signed (P-384, SHA-384), for C2PA claim signing, not a CA, valid at the time stamp's time; the time-stamp token binds that signature | The same, with the issuing CA a member of a verifier-approved tree of eligible CAs | The same, with the time-stamp token verified in the proof: its TSA certified by a CA in a verifier-approved tree, its time within a public window |
| Discloses | The issuing CA chain, the time-stamp token (TSA, exact time), the claim | The time-stamp token, the claim | The claim; the time as a window (a UTC day by default) |
| Anonymity set (official lists) | The issuing CA's certificate holders | 28 CAs, 18 organizations | Issuer as before; TSA among 19 CAs, 14 organizations |
| Verifier needs | Trust list, TSA trust list | An issuer policy (approved trust-list snapshots and their periods), and the TSA trust list: the token is still public, checked outside the proof | The policy, with TSA snapshots; no TSA trust list |
| Constraints | 4,710,820 | 4,718,946 (+0.17%) | 6,458,939 (+37%) |
| Per-asset anonymization, fixture (cold, BN254; harness, median of three; [one session](FEASIBILITY.md#milestone-1-every-mode-in-one-session)) | 71–81 s (first and last runs) | 71 s: within the disclosed range | 91 s (+28% over the hidden issuer) |
| Per-asset anonymization, real photos (single runs) | 133 s (first photo) | 75 s (second photo; page cache not controlled) | 141 s; 129 s with metadata scrubbing (second photo) |
| Peak memory | 6.7 GiB | 6.7 GiB | 8.5 GiB |
| Proving key | 1.15 GB | 1.15 GB | 1.49 GB |
| Verification (full verifier) | 32–48 ms (55–76 ms) | 31–50 ms (80–122 ms) | 31–32 ms (104–108 ms) |
| Output | A 196-byte proof in a ZK signature of the original's size | Same, no certificate | Same, no certificate and no token |

Further options, measured on the disclosed statement: loading the proving key without point checks, behind a hash recorded at setup, takes per-asset anonymization to 28 s in the single-session measurement (25–33 s across earlier ones; [E6](FEASIBILITY.md#e6-proving-key-loading-in-gnark)); BLS12-381 instead of BN254 raises the security estimate from about 100 to about 120 bits, at 88 s per asset with that key path ([E7](FEASIBILITY.md#e7-bls12-381-as-an-option)).

## From M0 to Milestone 1

| | **M0** (the starting point) | **Milestone 1** |
|---|---|---|
| Who anonymizes | The signer, with its key | Anyone, without the key (the signer can too) |
| What the proof covers | A digest of the asset, and possession of the key | The original signature over the original claim: the claim and its hard binding stay valid |
| Certificates | A P-256 test PKI | P-384 CAs, as on the official list; ES256 signers |
| Time | A prover-chosen timestamp | A trusted time stamp, bound in the proof, or verified in it |
| Real content | None | Real device photos, against the official lists |
| Hidden | The signer | The signer, its CA, its TSA, the exact time; EXIF and XMP |
| Proof system | circom, Groth16 | gnark, Groth16 (BN254, or BLS12-381) |
| Per-asset anonymization | 611 s, 11.1 GiB | 71–91 s, 6.7–8.5 GiB (28 s with the fast key path) |

M0, Milestone 0, is the prototype's starting point: the signer-side circom implementation. Earlier documents and the benchmark records call it V0, and the harness still selects it with `--variant v0`. It is kept frozen for comparison ([HISTORY.md](HISTORY.md#decisions)). V1, in the other documents, is Milestone 1's disclosed statement.

## Real content

Demonstrated on the private samples of one real C2PA deployment ([DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#r2-anonymizing-a-real-asset)):

- **Disclosed mode** on a first device photo; **hidden issuer**, and **hidden issuer and time stamp** (with and without metadata scrubbing), on a second. All verify against the official lists (`conformance-public` at `a95f2c4`), with the claim's hard binding matching.
- **The deployment's encodings match** what the prototype expects (ES256 over the claim's `Sig_structure`, the protected header's layout, `sigTst2` over the countersignature), and its time-stamp chain has the same shape as its signing chain (a P-256 end entity under a listed P-384 CA).
- **The issuing CAs are directly on the lists,** which the hidden modes require.
- **Hidden issuer alone**, on the second photo: it verifies, but the time-stamp token it keeps names the deployment's own TSA, and so the organization; only hiding the token too removes that ([findings](DEPLOYMENT-FINDINGS.md#with-the-issuer-hidden-h4)).
- Refused, by design: an edited photo with two manifests ([E8](README.md#e8-ingredient-manifests)), and a raw image (DNG), whose format c2pa-rs cannot rewrite at the same size.

## What stays visible

- **The claim and its assertions**, unchanged by design (they carry the hard binding). On the real samples, the claim generator names the signing software and its build, and the actions name the product ("Created by …") and whether the content is a capture or AI-generated. With the issuer and the TSA hidden, **the claim is the main disclosure left** ([CLAIM-PRIVACY.md](CLAIM-PRIVACY.md#what-the-claim-discloses)).
- **The content's hash** (in the hard binding): anyone holding the original links it to the anonymized asset.
- **Signed metadata**: metadata inside the hard binding cannot be scrubbed. The AI-generated sample signs XMP and IPTC naming the vendor.
- **The time window** (a UTC day by default), a correlation channel for the TSA operator; and the trust lists' snapshots, which the verifier's policy names.

## Assumptions and reduced profiles

- **Trust:** the trust lists are authentic, and the verifier approves the snapshots (and their periods) it accepts roots from; the real-asset runs approved the current lists retrospectively, which shows acceptance under that policy, not historical membership.
- **Setup:** Groth16 keys from a single-party setup on the developer's machine (no ceremony).
- **The anonymizer is honest** toward the signer: it could leak what it hides. Strict decoding rejects unspecified fields, trailing bytes, and nonzero padding, which closes those channels for extra data, but not every covert channel: a malicious anonymizer is not made safe, and the assumption remains necessary.
- **Not checked:** revocation of the signer's or the TSA's certificate.
- **Reduced profiles**, each stated, the rest refused: the signer certificate's checks (P-256 key, claim-signing EKU, not a CA, validity) without the full RFC 5280 profile ([H2](README.md#h2-full-certificate-validation-in-the-circuit)); the time-stamp token's checks ([T2](HIDING-THE-TIME-STAMP.md#t2-the-token-profile)); ES256 signatures under P-384 CAs; JPEG and PNG for in-place replacement, JPEG for scrubbing.

## Status of the roadmap

**Done in Milestone 1:**

| Item | What | Where |
|---|---|---|
| F1–F3 | Test PKIs and trust lists, the benchmark harness, correctness infrastructure | [README](README.md#foundation) |
| E1 | P-384, SHA-384, and RSA primitives measured; gnark chosen | [FEASIBILITY.md](FEASIBILITY.md#e1-p-384-and-sha-384-primitives) |
| E2a, E2b | The third-party statement, designed and implemented | [THIRD-PARTY-STATEMENT.md](THIRD-PARTY-STATEMENT.md) |
| E6 (first) | Proving-key loading: the fast path, behind a recorded hash | [FEASIBILITY.md](FEASIBILITY.md#e6-proving-key-loading-in-gnark) |
| E7 | BLS12-381 as an option | [FEASIBILITY.md](FEASIBILITY.md#e7-bls12-381-as-an-option) |
| E8 (first) | Ingredients: an anonymized asset survives an edit; multi-manifest assets refused | [README](README.md#e8-ingredient-manifests) |
| R1, R2 | The feasibility matrix; real content | [FEASIBILITY.md](FEASIBILITY.md), [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md) |
| H4 | The hidden issuer | [HIDING-THE-ISSUER.md](HIDING-THE-ISSUER.md) |
| I6 | The hidden time-stamp token | [HIDING-THE-TIME-STAMP.md](HIDING-THE-TIME-STAMP.md) |
| H6 (first) | Metadata scrubbing outside the hard binding | [CLAIM-PRIVACY.md](CLAIM-PRIVACY.md#metadata-outside-the-claim-h6) |

**Designed, with a measured spike, for phase 2:** the private claim ([CLAIM-PRIVACY.md](CLAIM-PRIVACY.md)): the original claim kept private, the proof showing it references the disclosed assertions. Redaction cannot do this (C2PA 2.5 forbids redacting a claim's own assertions and any actions); the spike's claim walk costs 510,920 constraints (+8%) and accepts the real claims.

**Postponed to phase 2:**

- **Claim privacy:** the private-claim statement, the output's claim, and disclosing part of an assertion (the digital source type without the product), after feedback on the design.
- **Trust models:** signer membership in a Merkle tree (E3), a SNARK-friendly credential (E4), the interim list's allowed signers (R3).
- **Production:** time-stamping operations (H1), revocation (H3), a setup ceremony or a proof system without one (H5, E6), the full certificate profile in the circuit (H2, with the signer certificate's calendar-date check), CI (H7), c2patool support (H8).
- **Coverage:** RSA and P-521 CAs and TSAs (9 certificates of the official lists), scrubbing other formats, anonymizing multi-manifest provenance (E8), key possession for the signer-side mode (E5).

## Questions for C2PA

1. **A private claim** ([P4](CLAIM-PRIVACY.md#p4-conformance)): hiding the claim generator and actions requires an output whose visible claim the original signer did not sign, with a proof that the signed claim referenced the disclosed assertions. Is that a direction C2PA would consider, and what should a validator report?
2. **The ZK signature:** it uses a private-use COSE algorithm, marked critical, so standard validators fail closed. Would C2PA register an algorithm, or define how a proof stands in for a claim signature?
3. **Trust-list history:** verifying content signed in the past needs list snapshots with evidenced effective periods. Could the trust lists publish their history (dates of addition and removal) in a verifiable form?
4. **Identifying metadata in signed regions:** some writers sign XMP and IPTC naming the vendor, which no anonymizer can remove. Should guidance keep such metadata outside the hard binding, or out of the asset?
5. **Time-stamp linkability:** a TSA operator can match exact times and imprints to its records. Is a coarse disclosed time (a day) acceptable to verifiers, and should TSAs be expected to support privacy-preserving requests?
6. **Digital source type:** the most useful disclosure (capture or AI-generated) sits in the same assertion as the product's name. Would a separate assertion for it be considered, so that it can be disclosed alone?

## Caveats on the numbers

- **One laptop,** 20 cores and 31 GB of memory, under WSL; its timings vary by 10–40% across sessions. Comparisons are made within one session, between adjacent runs; figures from different days are given as ranges.
- **Sessions are checked for suspends:** Windows kept awake and a heartbeat logged; a session spoiled by a sleep was discarded ([HISTORY.md](HISTORY.md#lessons)).
- **Cold runs:** the proving key and constraint system evicted from the page cache before each proof, the observed state recorded.
- **Real-asset runs are single runs,** reported as such.

## Where to find things

| | |
|---|---|
| The prototype, its roadmap, and quick starts | [README.md](README.md) |
| Measurements and the feasibility matrix | [FEASIBILITY.md](FEASIBILITY.md); records in [bench/results/](bench/results/) |
| The statement and its privacy analysis | [THIRD-PARTY-STATEMENT.md](THIRD-PARTY-STATEMENT.md) |
| Hiding the issuer, the time stamp, the claim | [HIDING-THE-ISSUER.md](HIDING-THE-ISSUER.md), [HIDING-THE-TIME-STAMP.md](HIDING-THE-TIME-STAMP.md), [CLAIM-PRIVACY.md](CLAIM-PRIVACY.md) |
| Real deployments | [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md) |
| Decisions and the project's evolution | [ARCHITECTURE-DECISIONS.md](ARCHITECTURE-DECISIONS.md), [HISTORY.md](HISTORY.md) |
