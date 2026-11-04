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

Planned rows: E1 (P-384/SHA-384 and RSA primitives, standalone), E2b (third-party mode), E3/E4 (trust models B and C, on the same statement), E5 (key possession, signer-side only), E6/E7 (proof systems and curves).

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

- **Proving is 5% of the per-asset time.** The Groth16 proof takes 32 s. Deserializing the 1 GB proving key takes 345 s (57%): it is stored compressed and fully validated on load, decompressing and checking every curve point. [Proving-key loading](#proving-key-loading) measures the options: an uncompressed key checked against its recorded hash loads in about 5 s.
- **Witness generation in WASM takes 225 s (37%).** Loading the circuit and checking the witness are negligible, and so are preparing the inputs and packaging the anonymized asset (under 0.1 s together). Native (C++) witness generation is the first E6 experiment.
- **Memory peaks in the prove phase** (11.06 GiB), during proving rather than key loading: loading the key alone peaks at 2.1–3.2 GiB, and the prove phase still peaks at 11.2 GiB with a 5-second key load ([Proving-key loading](#proving-key-loading)). Witness generation peaks at 4.00 GiB.
- **Verification is already within target** (13 ms, or 19 ms for the full verifier; 872-byte verifying key), and so is the proof container (668 B). The total manifest store (11.4 KB) is dominated by reserved padding.
- **Against the third-party target** (≤ 5 min, ≤ 16 GB): about 2× over on time, within on memory, even before the two engineering fixes above. The signer-side device target (≤ 30 s, ≤ 2 GB) is about 20× off on time and 5× on memory. BN254 misses the security target.

## Proving-key loading

Measured with `c2pa-x509-zk-bench pk-load` ([record](bench/results/2026-11-04-proving-key-load.json)) on the V0 proving key: 22.6 million G1 points and 4.74 million G2 points (4.14 million of them non-zero), 1.03 GB compressed, 2.05 GB uncompressed. Each load ran in its own process, once after requesting the key file's eviction from the Linux page cache and once warm. Eviction is advisory, so the residency measured just before each load is recorded, and the cold labels rest on it: none of the key file was resident before any of the 13 cold loads, and all of it before every warm one. (The harness now derives the label from that measurement, and reports a load whose pages stayed resident as `eviction-failed` rather than cold.) The loads in the table produce the same key; tests check that every loader reads back the key that was written.

What the checks cover: BN254's G1 has cofactor 1, so a G1 point on the curve is in the prime-order subgroup; G2 points also need a subgroup check, a scalar multiplication each. Decoding a compressed point solves the curve equation, so it is always on the curve, but not necessarily in G2's subgroup. An uncompressed point is taken as written unless checked. "Full" is what arkworks' `Validate::Yes` does today. The arkworks loader already runs its checks in parallel; it decompresses points one at a time. The parallel loader also decompresses in parallel.

| Encoding | Loader | Point checks | SHA-256 checked | Load, cold / warm | Peak RSS |
|---|---|---|---|---|---|
| Compressed | arkworks | Full (**today**) | No | 369 s / 365 s | 2.1 GiB |
| Compressed | arkworks | None (on the curve by construction) | No | 289 s / 310 s | 2.1 GiB |
| Compressed | parallel | Full | No | 124 s / 127 s | 2.8 GiB |
| Compressed | parallel | None (on the curve by construction) | No | 60 s / 58 s | 2.9 GiB |
| Uncompressed | arkworks | Full | No | 95 s / 109 s | 2.1 GiB |
| Uncompressed | parallel | Full | No | 131 s / 139 s | 3.1 GiB |
| Uncompressed | parallel | Full | Yes | 109 s / 86 s | 3.1 GiB |
| Uncompressed | parallel | On the curve | No | 6.4 s / 3.7 s | 3.2 GiB |
| **Uncompressed** | **parallel** | **On the curve** | **Yes** | **7.3 s / 6.7 s** (hash 2.4 / 1.8 s) | 3.2 GiB |
| Uncompressed | arkworks | None | No | 8.8 s / 6.7 s | 2.1 GiB |
| Uncompressed | arkworks | None | Yes | 9.9 s / 8.7 s | 2.1 GiB |
| Uncompressed | parallel | None | No | 5.0 s / 5.8 s | 3.1 GiB |
| Uncompressed | parallel | None | Yes | 6.9 s / 5.2 s | 3.1 GiB |

The parallel configurations were noisy. An earlier run of the same code on the same machine (record not kept) measured:

- 104–109 s for compressed, parallel, full checks;
- 37 s for compressed, parallel, no checks;
- 74–76 s for uncompressed, parallel, full checks;
- 3–5 s for the uncompressed configurations without the subgroup check;
- 350 s for today's configuration.

The ranking was the same. The heavy runs of a concurrent experiment were serialized with these, but other work on the machine was not, which most likely explains the slower second run.

Where the time goes:

- Decompressing the points one at a time costs about 290 s, or 40–60 s in parallel.
- G2's subgroup check costs 70–130 s, even in parallel.
- Reading an uncompressed key without the subgroup check takes 3–9 s; hashing the 2 GB file takes 1.6–3.3 s.
- At setup, writing the key takes 5.8 s uncompressed against 3.0 s compressed, plus 1.8 s to hash it.

**End to end** ([record](bench/results/2026-11-04-uncompressed-key.json)): setup wrote the key uncompressed, and the prover checked its SHA-256 against the build manifest and every point on the curve.

- The prove phase took **43 s** against 381 s in the baseline: load R1CS 2.9 s; check the key's SHA-256 2.0 s; load the key 3.2 s; Groth16 proof 34 s.
- Per-asset anonymization took **339 s** against 611 s.
- Witness generation was slower in this run (296 s against 231 s), and so was setup (83 s against 49 s, of which only about 4 s is the larger key and its hash). Both are unchanged code, so this is most likely load from other work on the machine.
- Peak memory did not change (11.2 GiB in the prove phase): it comes from proving, not from loading the key.

### What the checks protect against

Only the prover uses the proving key. Verifiers use the verifying key, and arkworks checks a proof's points when a verifier decodes it, so no proving key, however malformed, can make a verifier accept a false statement. A bad proving key affects the prover:

- **Corruption or mix-ups** (a truncated copy, a key from another circuit or another setup): proofs that never verify, after minutes of work, or, for malformed encodings, a crash. Point checks catch only some of these, since a key from another setup consists of valid points. A hash checked against the value recorded at setup catches all of them. The loader also refuses lengths the file cannot hold, truncated files, and trailing data.
- **A malicious key** from an untrusted source: Groth16's zero-knowledge assumes a correctly generated key, and a subverted one can weaken the randomization that hides the witness (the subversion zero-knowledge literature studies exactly this). Point checks do not help: a malicious key can consist entirely of valid subgroup points. A hash helps only if the expected value comes from somewhere the attacker cannot change. A hash recorded in the build manifest next to the key does not qualify against an attacker who can write to that directory, who could replace both, and likely the binaries too. Points outside G2's subgroup would put the proof's B element outside the subgroup; verifiers reject such a proof, but the prover has already produced it, and the anonymizer does not verify its own proof before embedding it.

Today, keys come only from local setup, and the prover loads them from the same directory, so the realistic threat is corruption or a mix-up, which a hash recorded at setup covers completely. For a key written by setup and unchanged since (matching hash), the point checks add nothing, because setup wrote points it computed itself. Keys from a ceremony ([H5](README.md#h5-production-proving-setup)) change this: the expected hash would have to be pinned outside the key's directory (for example, published with the verifying key), and only a check of the key's well-formedness (pairing equations over its elements) would protect zero-knowledge against a subverted key. Neither is in place, and neither is needed for local setup.

### Proposal (for decision)

- **Recommended:** setup writes the proving key uncompressed and records its SHA-256 in the build manifest (already done on this branch). The prover refuses a key whose hash does not match, then loads it in parallel with on-curve checks, skipping G2's subgroup check: about 5–7 s instead of 345 s, at twice the file size (2.05 GB). The on-curve check costs about a second, and also covers manifests that predate the recorded hash; a key without a recorded hash could fall back to full checks.
- **Alternatives:**
  - Keep the compressed format and decompress and check in parallel: 104–127 s, with no format change and no reliance on the manifest.
  - Uncompressed with full checks and the hash: 86–109 s, the most checking, still a 3–4× gain.
  - Uncompressed with the hash and no point checks: about 1 s faster than the recommendation.
- **Not recommended:** skipping both the hash and the checks. It saves a further 1–2 s, and nothing would detect a wrong or corrupted key until proofs fail to verify.
- **Separately:** the anonymizer could verify its own proof (13 ms) before embedding it, which would catch any key problem the checks miss.

**Guardrails for adopting the fast path** in the prover (not done here; production loading stays compressed and fully checked):

- The build manifest records the key's encoding next to its hash (`proving_key_encoding`, added here, so a hash is never ambiguous about the format it covers); a format version and an explicit migration of existing compressed keys come with adoption.
- Full validation whenever trusted provenance is unavailable: no hash recorded at setup, or a key from elsewhere. A hash recorded next to the key detects corruption and mix-ups; it does not authenticate the key against anyone who can write to its directory.
- Point validation does not establish that a key came from the intended setup; only a check of the key's structure against the verifying key would (see above).
- Verifying-key loading and validation are unchanged.

