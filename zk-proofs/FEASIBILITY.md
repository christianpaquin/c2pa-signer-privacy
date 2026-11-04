# Feasibility Matrix (R1)

A living comparison of the anonymization variants, updated after each experiment ([roadmap R1](README.md#r1-feasibility-matrix)). Each row states what the variant proves, discloses, and assumes, its measured cost, and which guarantees are established versus experimental shortcuts (see the [method](ARCHITECTURE-DECISIONS.md#method)). Variants are compared only against others with equivalent guarantees.

Measurements come from the benchmark harness ([F2](README.md#benchmarks)); each row links to its JSON record in [`bench/results/`](bench/results/). Costs are counted the same way for every variant:

- **Per-asset anonymization:** from a signed asset to an anonymized one: reading the manifest and validating the chain, witness generation, proving (including loading the proving key), and packaging the anonymized asset. One-time work is excluded.
- **One-time:** compiling the circuit and the Groth16 setup, per circuit and keys.
- **Verify:** loading and preparing the verifying key and verifying the proof; the full verifier (trust-list chain validation, assertion and digest checks, and the proof) is reported separately.
- **Peak RAM:** the largest peak RSS of any phase in the category, each phase being a separate process.

Generating the test PKI and signing the sample asset are measured but not counted.

## Reference machine

13th Gen Intel Core i7-13800H laptop (20 logical CPUs), 32 GB of RAM, Ubuntu 24.04.2 under WSL2 (kernel 6.18), rustc 1.93.0, circom 2.1.6. Other profiles (a desktop, a phone) can be added as separate columns later.

## Provisional targets

Stretch goals, not pass/fail gates: today's baseline misses most of them, and rows are kept and compared on progress and trade-offs. Targets are per scenario, because who runs the prover changes the budget by orders of magnitude.

| Criterion | Third-party anonymizer (server) | Signer-side, on device (phone) | Verifier (any C2PA validator) |
|---|---|---|---|
| Per-asset anonymization | ≤ 5 min | ≤ 30 s | — |
| Peak memory | ≤ 16 GB | ≤ 2 GB | — |
| Verification | — | — | ≤ 500 ms, including in a browser (WASM) |
| Verifying key | — | — | ≤ 64 KB |
| Added output size | Proof container ≤ 10 KB (hard limit 100 KB); total added to the manifest reported separately | same | — |
| Security level | ≥ ~120 bits | same | — |
| Setup | No per-circuit ceremony preferred | same | — |

## Stop rules

- **Dominance:** drop a variant once another one is at least as good on every axis, counting trust, privacy, compatibility, and setup assumptions as well as time, memory, and size, at equivalent guarantees.
- **Time-box:** each experiment gets its first PR plus at most one follow-up for optimization.
- **Far off target:** if a first spike lands more than 10× from a target on a primary axis, stop unless there is a concrete, known path to close most of the gap; record the measurement here either way.

## Matrix

| Variant | Mode | Trust model | Proves | Discloses | Assumptions | Deployment segments covered | Per-asset anonymization | Peak RAM | Verify | Proof container / manifest added | Security | Setup | Record |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **V0 baseline** | Signer-side | A (X.509 in-circuit) | Issuing CA (P-256, ECDSA-SHA256) signed a certificate whose P-256 key signed the manifest-stripped asset digest; key and validity pinned inside the signed TBS | Issuing CA (`x5chain`), asset digest, a prover-chosen timestamp | Signer holds its key; trust list authentic; single-party setup | Test PKI only. Not the official list (P-384 CAs); interim P-256 camera roots only if their intermediates are also P-256 (unverified); not the interim allowed list | **611 s** (witness 231 s + prove 381 s; prepare and package < 0.1 s) | 11.1 GiB (prove phase) | 13 ms (19 ms full verifier) | 668 B / 11.4 KB | ~100 bits (BN254) | Per-circuit, single party | [2026-11-03-baseline](bench/results/2026-11-03-baseline.json) |

**V0 shortcuts:** every item under [Current Limitations](README.md#current-limitations) applies, in particular no historical validity (the timestamp is unchecked), binding to the asset bytes rather than the claim, and partial in-circuit certificate validation.

E1's P-384/SHA-384 primitives are measured [below](#e1-p-384-and-sha-384-primitives); they are components of future rows rather than a variant of their own. Planned rows: E1 (RSA primitives, standalone), E2b (third-party mode), E3/E4 (trust models B and C, on the same statement), E5 (key possession, signer-side only), E6/E7 (proof systems and curves).

## V0 baseline: measured detail

4,776,263 constraints, 4,737,842 wires. Inputs: a 504-byte signer certificate (414-byte TBS), one issuing CA certificate in `x5chain`, a 1.9 MB image.

| Phase | Category | Wall time | Peak RSS | Steps |
|---|---|---|---|---|
| Fixtures | Test fixture (not counted) | 0.2 s | 0.02 GiB | Generate the test PKI 0.16 s; sign the sample asset 0.02 s |
| Compile (circom) | One-time | 206 s | 6.05 GiB | |
| Setup | One-time | 49 s | 9.95 GiB | Proving key 1.03 GB, verifying key 872 B |
| Prepare | Anonymization | 0.03 s | 0.02 GiB | Read the signed manifest 24 ms; load the trust list, validate the issuing chain, build and write the circuit inputs, under 1 ms each |
| Witness | Anonymization | 231 s | 4.00 GiB | Load circuit 4.1 s; **compute witness (WASM) 225 s**; check witness 0.9 s; write 0.1 s |
| Prove | Anonymization | 381 s | 11.06 GiB | Load R1CS 2.8 s; read witness 0.3 s; **load proving key 345 s**; **Groth16 proof 32 s** |
| Package | Anonymization | 0.03 s | 0.02 GiB | Rewrite the manifest 15 ms; check the digest 6 ms |
| Verify | Verification | 13 ms | 0.01 GiB | Load verifying key 3.7 ms; prepare it 1.1 ms; verify 1.7 ms |
| Verify (full CLI, anonymized asset) | Verification (full) | 19 ms | 0.01 GiB | Trust-list chain validation, assertion and digest checks, Groth16 |

Totals: **611 s per-asset anonymization** (witness plus prove 611.2 s), 255 s one-time, 13 ms verification.

Output: a 128-byte Groth16 proof and 19 public inputs, embedded as a 668-byte container (base64 of JSON); a 1,183-byte assertion; a 481-byte `x5chain`; 11,386 bytes of C2PA manifest store added to the asset in total, including about 8 KB of padding reserved for the COSE signature.

An earlier run on the same machine measured 657 s per asset (witness 261 s, prove 396 s): expect run-to-run variation of roughly 10% on this laptop.

### Observations

- **Proving is 5% of the per-asset time.** The Groth16 proof takes 32 s. Deserializing the 1 GB proving key takes 345 s (57%): it is stored compressed and fully validated on load, decompressing and checking every curve point. A key written by local setup could be stored uncompressed and loaded without re-validation, likely bringing this to seconds. A candidate quick win outside the experiment plan.
- **Witness generation in WASM takes 225 s (37%).** Loading the circuit and checking the witness are negligible, and so are preparing the inputs and packaging the anonymized asset (under 0.1 s together). Native (C++) witness generation is the first E6 experiment.
- **Memory peaks while loading the proving key** (11.06 GiB in the prove phase); witness generation peaks at 4.00 GiB.
- **Verification is already within target** (13 ms, or 19 ms for the full verifier; 872-byte verifying key), and so is the proof container (668 B). The total manifest store (11.4 KB) is dominated by reserved padding.
- **Against the third-party target** (≤ 5 min, ≤ 16 GB): about 2× over on time, within on memory, even before the two engineering fixes above. The signer-side device target (≤ 30 s, ≤ 2 GB) is about 20× off on time and 5× on memory. BN254 misses the security target.

## E1: P-384 and SHA-384 primitives

What the algorithms of the official trust list's CAs cost in a circuit, next to the P-256 and SHA-256 the current circuit uses ([E1](README.md#e1-cost-of-reality-p-384-sha-384-and-rsa-in-circuit); code and how to run it in [`experiments/e1-p384`](experiments/e1-p384/)). Both curves are measured in the same stack, gnark v0.16.4 with Groth16 on BN254, because the current circom ECDSA library is specific to P-256 and the project has no circom SHA-384: porting both would have been a substantial job, and gnark is the leading second-stack candidate for E6 anyway. Records: [2026-11-04-e1-p384-gnark](bench/results/2026-11-04-e1-p384-gnark.json) (all circuits) and [its repeat](bench/results/2026-11-04-e1-p384-gnark-repeat.json) (the two 1,500-byte CA circuits, measured twice more).

**Shortcuts:** standalone primitives. No certificate parsing, field extraction, or chain checks; hashes over a length fixed at compile time (a real circuit hashes a variable-length TBS up to a maximum, at about the cost of the maximum). Every circuit is tested to accept a real signature or digest and reject a tampered input, and the SHA-384 circuit is checked against Go's standard library around the padding boundaries.

| Circuit | R1CS constraints | PLONKish constraints | Setup | Solve | Prove, key resident (incl. solve) | Peak RSS, whole run | Proving key (compressed / raw) |
|---|---|---|---|---|---|---|---|
| ECDSA P-256 verify, digest given | 148,357 | 567,375 | 13 s | 0.08 s | 0.70 s | 0.5 GiB | 37 / 73 MB |
| ECDSA P-384 verify, digest given | 301,556 | 1,149,790 | 28 s | 0.17 s | 1.42 s | 1.0 GiB | 74 / 148 MB |
| SHA-256, 414 bytes | 377,133 | 1,131,206 | 36 s | 0.26 s | 1.48 s | 1.0 GiB | 93 / 184 MB |
| SHA-384, 414 bytes | 466,399 | 1,415,580 | 44 s | 0.23 s | 1.56 s | 1.1 GiB | 110 / 219 MB |
| SHA-256, 1,500 bytes | 976,699 | 2,931,038 | 85 s | 0.45 s | 3.55 s | 2.1 GiB | 222 / 441 MB |
| SHA-384, 1,500 bytes | 1,143,102 | 3,479,150 | 108 s | 0.60 s | 4.98 s | 3.1 GiB | 289 / 574 MB |
| CA signature, P-256 + SHA-256, 414-byte TBS | 556,754 | 1,893,233 | 61 s | 0.29 s | 2.47 s | 1.7 GiB | 147 / 292 MB |
| CA signature, P-384 + SHA-384, 414-byte TBS | 821,074 | 2,702,402 | 71 s | 0.40 s | 3.16 s | 2.2 GiB | 193 / 383 MB |
| CA signature, P-256 + SHA-256, 1,500-byte TBS | 1,156,320 | 3,693,065 | 95–145 s | 0.55 s | **4.3 s** (4.17–9.01) | 3.0–3.4 GiB | 293 / 583 MB |
| CA signature, P-384 + SHA-384, 1,500-byte TBS | 1,521,300 | 5,109,304 | 123–143 s | 0.65 s | **5.1 s** (4.98–5.75) | 3.4–3.7 GiB | 368 / 731 MB |

For the two 1,500-byte CA circuits, prove is the median of three runs with the range in brackets; the first run's 9.0 s for P-256 was an outlier (the repeats took 4.2 and 4.3 s), and setup varied by up to 50% between runs. Every proof is 196 bytes and verifies in 1.5–3 ms; verifying keys are 768 bytes (P-256 key as public input) and 896 bytes (P-384), and 1,520 and 2,032 bytes for the hash-only circuits (one public input per digest byte). **Accounting boundaries.** Prove is *resident-key primitive proving*: the proving key generated by setup stays in memory, so the time includes gnark's witness computation (solve, under a second throughout) but no key loading. Peak RSS is *whole-run memory* for the circuit's process, which also compiles the circuit, runs setup, and compiles the PLONKish count; it is not the memory of proving alone. Neither matches the per-asset accounting of the [V0 baseline](#v0-baseline-measured-detail) (separate processes, keys loaded from disk, the whole statement), so these times are compared only with each other.

### Observations

- **P-384 with SHA-384 costs 1.3–1.5× P-256 with SHA-256** for a CA signature over a TBS (1.47× at 414 bytes, 1.32× at 1,500 bytes, in constraints; ~1.2× in proving time at 1,500 bytes). ECDSA alone doubles (2.03×, from four to six 64-bit limbs per coordinate); SHA-384 is 1.17–1.24× SHA-256 for the same message, since its larger 128-byte blocks halve the block count.
- **The hash, not the signature, dominates for real certificate sizes.** Over a 1,500-byte TBS, hashing is about 85% of the P-256 circuit and 75% of the P-384 one. Real certificates are larger than the test PKI's, so the variable-length maximum chosen for the TBS matters as much as the curve.
- **Relation to the circom baseline.** The current circuit's P-256 ECDSA component is 1,972,905 constraints, 13× gnark's 148,357 (gnark uses non-native arithmetic with range checks by lookup); its SHA-256 over up to 1,536 bytes is 758,254 constraints, 0.78× gnark's 976,699 for 1,500 bytes (the same 24 blocks). A CA signature over a TBS of up to 1,536 bytes costs 2,731,159 constraints in circom with P-256; gnark needs 1,156,320 with P-256 and **1,521,300 with P-384, 0.56× the circom P-256 figure**. Constraint counts across stacks are only indicative: gnark's lookups use a commitment in the proof, and the costs per constraint differ. The times are not comparable with the circom baseline's ~10 minutes per asset: that figure covers the whole statement (two ECDSA verifications, hashing, parsing) in separate processes and is dominated by loading the proving key (57%) and witness generation (37%), whereas these are single primitives with the key resident. The closest circom counterpart of resident-key proving is the baseline's witness computation plus Groth16 proof (225 s + 32 s), still for the whole 4.8M-constraint statement rather than one primitive.
- **gnark's Groth16 setup is slow** (about 80–125 s per million constraints, single party) and its proving keys are large (~240 MB compressed per million constraints); both are one-time, but setup dominates each run. The 196-byte proof is Groth16 plus one commitment and its proof of knowledge (gnark's extension for lookups), so a verifier needs gnark-compatible verification rather than plain Groth16.
- **Stop-rule assessment (provisional):** no stop rule is triggered by the primitive. The verification a real CA forces (P-384 with SHA-384 over a 1–1.5 KB TBS) proves in ~5 s with the key resident. Whether a full third-party statement meets the 5-minute target in gnark is not established by these figures: it adds the signer's COSE signature verification, its hash, and parsing, and per-asset accounting adds loading the keys (gnark's proving key here is 0.4 GB compressed for this primitive alone). That needs the full statement measured under the same accounting as the baseline. The PLONKish counts are 3.2–3.8× the R1CS counts, relevant to E6.
- **Implication for E6:** P-384 CAs argue for measuring the full statement in gnark rather than porting P-384 and SHA-384 to circom. That comparison must use equivalent full statements and the same accounting boundaries, and report loading artifacts from disk (cold) separately from operation with resident keys (warm). Remaining E1 work: RSA (PKCS#1 v1.5 and PSS), and SHA-384 over a variable-length input.

