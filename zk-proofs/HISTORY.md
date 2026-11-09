# Project History

How the X.509 + ZK prototype evolved, for reporting. Details live in the pull requests, the [results records](bench/results/), and the design documents; this file links to them rather than repeating them. Git tags mark the milestones, so each stage can be checked out and re-run.

| Tag | Commit | State |
|---|---|---|
| `v0-original` | `3dac0e0` | The prototype as published with the blog post (after #5) |
| `v0-sound` | `1cd7620` | The same design with the known defects fixed through #13; still an experimental baseline (no claim binding or time policy, certificate fields pinned by pattern, single-party setup) |
| `foundation` | `538c2dc` | Test PKI, correctness checks, benchmark harness, first measured baseline (after #17) |
| `e2b-v1` | after #24 | Third-party anonymization end to end, measured |

## Timeline

| Phase | Dates | PRs | Outcome |
|---|---|---|---|
| Original prototype | Jan–May 2026 | #1–#5 | BBS and X.509 + ZK demonstrations; the ZK path re-signs with the signer's key and proves, in circom, that a trusted CA issued the signer's certificate |
| Soundness and privacy fixes | Oct 29 – Nov 3 | #7, #8, #10, #11, #13 | The defects below fixed; standards-conformant COSE; cheaper in-circuit byte reads (12.2M → 4.8M constraints) |
| Goals and plan | Oct 29 – Nov 3 | #9, #12, #15 | Two goals (prove and compare the options; find what works on today's deployments); decisions D1–D7; an analysis of real trust lists and signed assets ([DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md)); a roadmap ordered by guarantees first |
| Foundation | Nov 3–4 | #14, #16, #17 | A C2PA-like test PKI and trust lists, with off-circuit chain validation (F1); witness checking and forgery tests (F3); a benchmark harness and the feasibility matrix with the measured baseline (F2) |
| Third-party anonymization | Nov 4–5 | #18–#24 | The statement and time policy (E2a); the cost of P-384 and SHA-384 (E1); proving-key loading options; the statement in gnark, the anonymizer and verifier, and its benchmark (E2b) |
| Real content | Nov 6 | #26 | A real device-signed photo under the official trust list anonymized and verified with the unchanged tools ([R2](DEPLOYMENT-FINDINGS.md#r2-anonymizing-a-real-asset)) |

## Defects found in the original prototype

| Defect | Consequence | Found | Fixed |
|---|---|---|---|
| The signer's certificate stayed in the anonymized asset's `x5chain` | Anonymization revealed the signer | Issue #6 | #7 |
| Private-use COSE algorithm IDs in the wrong range, `crit` under the wrong label, padding as trailing bytes | Not conformant COSE; standard tools failed | Review of the COSE encoding | #8 |
| The circuit read the signer key and validity at unconstrained offsets | Anyone with any certificate from the CA could forge a proof for their own key (confirmed with a real proof) | Code review | #10 |
| The in-circuit date conversion was off by one month | New certificates could not be proved; certificates expired up to a month earlier were accepted | Moving the tests to freshly generated certificates (F1) | #13 |
| The prover produced proofs from witnesses that violate the constraints (ark-circom ignores failing assertions) | Rejected inputs produced proofs that only failed at verification, masking errors | The forgery test of #10 | #16 (F3) |

## Decisions

Recorded in [ARCHITECTURE-DECISIONS.md](ARCHITECTURE-DECISIONS.md) (D1–D7) and [THIRD-PARTY-STATEMENT.md](THIRD-PARTY-STATEMENT.md) (Q1–Q10). The ones that changed the project's direction:

- **Design against the official C2PA trust list** (#12); its CAs are P-384, which the original circuit could not verify.
- **Third-party mode** (D6, #18): prove the original signature, so existing content can be anonymized without the signer's key, and **one statement for both modes** (Q2), which made the key-possession experiment (E5) moot.
- **Replace the signature in place** (Q1): the original claim and its hard binding stay valid, with nothing added to the asset.
- **A trusted time stamp is required** (D7, Q6): validity at the time a TSA attested the signature, as C2PA defines it; the token is public, so the TSA operator can link the output to the original (Q7).
- **gnark for E2b** (#22), after E1 measured ECDSA at a thirteenth of circom's constraints and P-384 available.
- **V0 kept as a frozen baseline** rather than retired, so the comparison can be reproduced. Moving past it was a decision (Q2), not a dominance result: the two disclose different information and accept different inputs.

## Measurements over time

All on the same laptop ([reference machine](FEASIBILITY.md#reference-machine)); from F2 on, with the harness, each phase in its own process.

| Record | Statement | Per-asset anonymization | Peak memory | Notes |
|---|---|---|---|---|
| Original circuit, before #11 (informal) | Signer-side, P-256 CA, asset digest | ~20 min | ~28 GB | 12.2M constraints, most of them reading certificate bytes at variable offsets |
| After #11 (informal) | Same | ~10.5 min | ~11.8 GB | 4.78M constraints; proving key 2.5 GB → 1.0 GB |
| [V0 baseline](bench/results/2026-11-03-baseline.json) (#17) | Signer-side, P-256 CA, asset digest, no time policy | 611 s | 11.1 GiB | 57% loading the proving key, 37% WASM witness generation; the proof itself 32 s |
| [E1 primitives](bench/results/2026-11-04-e1-p384-gnark.json) (#19) | A P-384 CA signature over a 1.5 KB TBS, in gnark | 5 s (key resident; not comparable) | 3.7 GiB | P-384 and SHA-384 cost 1.3–1.5× P-256 and SHA-256 |
| [Proving-key loading](bench/results/2026-11-04-proving-key-load.json) (#21) | V0's key, loading only | 345 s → 7 s possible | — | Uncompressed key with a recorded hash; not adopted |
| [V1 third-party](bench/results/2026-11-05-third-party.json) (#24) | The E2a statement, P-384 CA, `sigTst2`, in gnark | **79 s** | 7.5 GiB | 74% loading the proving key (CPU-bound); the proof 19.5 s |
| [V1 on a real photo](bench/results/2026-11-06-r2-device-photo.json) (#26) | Same, on a real asset under the official lists | 133 s | 7.4 GiB | The fixture took 110 s in the same session: consistent with similar cost; the machine ran 40% slower that day |
| [V1, key loading variants](bench/results/2026-11-06-e6/) (E6) | Same as V1 | 77 s → **25–28 s** | 7.4 → 9.2 GiB | Raw or dumped proving key, points not validated on load, behind its setup hash. Adopted as an opt-in raw path with provenance records and streamed loading: 49 s against 97 s in a slower session, 6.7 GiB |
| [V1 on BLS12-381](bench/results/2026-11-09-e7/) (E7) | Same, on a ~120-bit curve (curve-level estimate; option, BN254 stays default) | 302 s; **88 s** with the raw key path | 8.5 GiB | BN254 in the same session: 72 s and 33 s; raw BLS12-381 keys parse slowly even unchecked |

## Lessons

- **Write the statement before optimizing it.** The original circuit was efficient at proving the wrong thing: an asset digest, an unchecked time, and byte patterns rather than certificate fields. Specifying the chain of trust first (E2a) surfaced what had to be proved.
- **Signed is not the same as parsed.** Two distinct problems: fields read from bytes outside the CA-signed TBS (the forgery fixed in #10, by pinning them inside it), and expected bytes found inside the wrong signed field, such as an extension (addressed by the structural DER walk, Q5, in E2b). Bind fields to the signed data, parse its structure, and make anything unrecognized fail.
- **Test what a check rejects, and why.** Proofs from bad witnesses and the forgery both hid behind checks that passed for the wrong reason. Negative tests now assert the reason for rejection, and positive controls show the check can pass.
- **Formats should leave no room for other data.** Strict decoding (exact fields, zero padding, fixed-length proof) closed places where identifying data could ride along (#23).
- **Measure the conditions, not just the time.** Record the cache state rather than assume it, repeat runs on a noisy machine (single runs here varied by 2×), compare only under the same accounting, and keep primitive timings apart from per-asset ones (#17, #19, #21, #24).
- **The proving key, not the proof, dominates.** In both stacks, loading and validating the 1 GB key costs more than proving; the cheapest remaining gain is there.
- **Real deployments decide feasibility.** P-384 CAs, `sigTst2` time stamps, and unauthenticated EXIF were found by examining real trust lists and signed assets, not from the specification alone; designing against a real sample made the first real asset work unchanged.
