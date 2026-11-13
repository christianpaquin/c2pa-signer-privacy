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
| **M0 baseline** | Signer-side | A (X.509 in-circuit) | Issuing CA (P-256, ECDSA-SHA256) signed a certificate whose P-256 key signed the manifest-stripped asset digest; key and validity pinned inside the signed TBS | Issuing CA (`x5chain`), asset digest, a prover-chosen timestamp | Signer holds its key; trust list authentic; single-party setup | Test PKI only. Not the official list (P-384 CAs); interim P-256 camera roots only if their intermediates are also P-256 (unverified); not the interim allowed list | **611 s** (witness 231 s + prove 381 s; prepare and package < 0.1 s) | 11.1 GiB (prove phase) | 13 ms (19 ms full verifier) | 668 B / 11.4 KB | ~100 bits (BN254) | Per-circuit, single party | [2026-11-03-baseline](bench/results/2026-11-03-baseline.json) |
| **V1 third-party** (E2b) | Third-party (also signer-side, Q2) | A (X.509 in-circuit) | The [E2a statement](THIRD-PARTY-STATEMENT.md#the-chain-of-trust): issuing CA (P-384, ECDSA-SHA384) signed a certificate that, by a structural DER walk, is for C2PA claim signing and not a CA, valid at `t`; its P-256 key made the original ES256 signature over the original claim; the `sigTst2` imprint is bound to that signature | Issuing CA (`x5chain`), the claim and its assertions, `t` and the time-stamp token (the TSA operator can link it) | Trust list and TSA trust list authentic; single-party setup; honest anonymizer | Mirror of an official-list device deployment (P-384 CA, ES256, `sigTst2`); not yet a real asset (R2); not RSA CAs or signers, `sigTst`, or the interim allowed list | **79.4 s** (prove 79.4 s: proving key load 58.5 s, solve 3.0 s, proof 16.5 s; prepare, self-verify, package < 0.1 s) | 7.5 GiB (prove phase) | 30 ms (50 ms full verifier) | 196 B proof in a same-size ZK signature / no change (replaced in place) | ~100 bits (BN254) | Per-circuit, single party | [2026-11-05-third-party](bench/results/2026-11-05-third-party.json) |
| **V1 on a real asset** (R2) | Third-party | A | As V1 | As V1; for this photo, the claim generator and actions ("Created by Pixel Camera.") and, outside the hard binding, EXIF and XMP | As V1 | **The official list, one real device photo** (P-384 issuing CA on the list, ES256, `sigTst2` from a TSA on the TSA list); [details](DEPLOYMENT-FINDINGS.md#r2-anonymizing-a-real-asset) | 133 s; the fixture measured 110 s in the same session (79 s the day before): consistent with similar cost under large machine variation ([below](#r2-a-real-device-photo)) | 7.4 GiB | 48 ms (76 ms full verifier, official lists) | 196 B proof in a same-size ZK signature (615 bytes to spare) / no change | ~100 bits (BN254) | Per-circuit, single party | [2026-11-06-r2-device-photo](bench/results/2026-11-06-r2-device-photo.json) |
| **V1 on BLS12-381** (E7, option) | Third-party | A | As V1 | As V1 | As V1 | As V1 | 302 s with full point checks; **88 s** with the raw key path (BN254 in the same session: 72 and 33 s) ([detail](#e7-bls12-381-as-an-option)) | 8.5 GiB | 37–40 ms (60 ms full verifier) | 292 B proof in a same-size ZK signature / no change | **~120 bits** (curve-level estimate) | Per-circuit, single party | [2026-11-09-e7](bench/results/2026-11-09-e7/) |
| **V1, hidden issuer** (H4, option) | Third-party | A | As V1, with the issuing CA one of the trust list's eligible CAs (a Merkle root, approved by the verifier, in place of the CA) | As V1, except the issuing CA: hidden among the eligible CAs of its key type (28 P-384 CAs from 18 organizations on the official list); the claim and the public time-stamp token may still name the organization | As V1, and the verifier's issuer policy (approved snapshots and their periods) | As V1; issuing CA directly on the list | 106.8 s, against 104.0 s for V1 in the same conditions (+2.7%, within noise) ([detail](#h4-hiding-the-issuing-ca)) | 6.7 GiB | 50 ms (122 ms full verifier, with the policy) | 196 B proof in a same-size ZK signature, no certificate / no change | ~100 bits (BN254) | Per-circuit, single party | [2026-11-11-h4](bench/results/2026-11-11-h4/) |
| **V1, hidden issuer and time stamp** (I6, option) | Third-party | A | As the hidden issuer, with the time-stamp token verified in the circuit: a TSA certified by a CA in a verifier-approved TSA tree time-stamped the signature at a time within a public window | As the hidden issuer, and the TSA (hidden among the TSA list's eligible CAs: 19 P-384 CAs from 14 organizations on the official list), the token's serial number, imprint, and policy, and the exact time (a UTC day is disclosed by default) | As the hidden issuer, with TSA snapshots in the policy; no TSA trust list | As the hidden issuer; the TSA's CA directly listed; the token in the real profile | 97.4 s, against 76.9 and 75.1 s for the hidden issuer in the same session (+28%) ([detail](#i6-hiding-the-time-stamp-token)) | 8.5 GiB | 32 ms (104 ms full verifier, with the policy) | 196 B proof in a same-size ZK signature, no certificate and no token / no change | ~100 bits (BN254) | Per-circuit, single party | [2026-11-12-i6](bench/results/2026-11-12-i6/) |

**M0 shortcuts:** every item under [Current Limitations](README.md#current-limitations) applies, in particular no historical validity (the timestamp is unchecked), binding to the asset bytes rather than the claim, and partial in-circuit certificate validation.

**V1 shortcuts** ([guarantees and shortcuts](THIRD-PARTY-STATEMENT.md#guarantees-and-shortcuts)): no revocation check; key usage, unknown critical extensions, name constraints, and policies not checked (H2); the issuing CA is disclosed (H4); metadata outside the hard binding is reported, not scrubbed (H6); one accepted encoding of the protected header (as both real assets and c2pa-rs produce it).

**M0 and V1 are not an equal-guarantee comparison.** V1 proves strictly more (claim binding, historical validity backed by a trusted time stamp, certificate purpose, a P-384 CA) and also changes the proof stack (circom/arkworks to gnark), so the difference cannot be split between statement and stack. Nor does V1 dominate M0: the two **disclose different information** (V1 the claim and its assertions, and a time-stamp token the TSA operator can link; M0 only an asset digest and a time the prover chose), **accept different inputs** (V1 needs a `sigTst2` time stamp and a P-384 CA; M0 takes a P-256 CA and no time stamp), and V1 costs more one-time setup (499 s against 255 s), verification time (30 ms against 13 ms), and verifying-key size (2.1 KB against 872 B). M0 is frozen by decision ([Q2](THIRD-PARTY-STATEMENT.md#q2-one-statement-for-both-modes): one, stronger statement for both modes, covering the official list's dominant CA algorithm), not by a dominance result; it stays reproducible but is no longer developed.

E1's primitives, [P-384 and SHA-384](#e1-p-384-and-sha-384-primitives) and [RSA](#e1-rsa-primitives), are measured below; they are components of future rows rather than variants of their own. Planned rows: E3/E4 (trust models B and C, on the same statement), E5 (key possession, signer-side only), E6/E7 (proof systems and curves), E8 (ingredient manifests).

## M0 baseline: measured detail

M0 (Milestone 0, the starting point; see [MILESTONE-1.md](MILESTONE-1.md#from-m0-to-milestone-1)) is called V0 in the benchmark records made before the rename, and the harness selects it with `--variant v0`.

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

## V1 third-party (E2b): measured detail

Measured with `c2pa-x509-zk-bench run --variant third-party` ([record](bench/results/2026-11-05-third-party.json)), under the same accounting as M0: every phase in its own process. 4,710,820 constraints and 50 public inputs at the E2a size limits (protected header 2 KB, claim 1 KB, TBS 1 KB). Inputs: the mirror fixture, signed by c2pa-rs with a local test TSA: a 486-byte claim, a 1,216-byte protected header, a 661-byte signer certificate (539-byte TBS), one issuing CA certificate in the validated path, and a 1.9 MB image.

| Phase | Category | Wall time | Peak RSS | Steps |
|---|---|---|---|---|
| Fixtures | Test fixture (not counted) | 0.5 s | 0.02 GiB | Mirror PKI 0.44 s; sign with the local TSA 0.06 s |
| Setup (gnark CLI) | One-time | 499 s | 11.26 GiB | Compile 17.7 s; Groth16 setup 436 s; proving key 1.15 GB, constraint system 0.30 GB, verifying key 2.1 KB |
| Prepare | Anonymization | 0.01 s | 0.01 GiB | Read the manifest, check the claim (Q9), build the inputs (parse the original signature, check the imprint, validate the path at `t`), check that the ZK signature fits; each under 5 ms |
| Prove, cold (median of 3) | Anonymization | 79.4 s | 7.47 GiB | Load constraint system 1.2 s; **load proving key 58.5 s**; prove 19.5 s, of which solving the witness 3.0 s |
| Self-verify | Anonymization | 0.03 s | 0.01 GiB | The anonymizer's check of its own proof |
| Package | Anonymization | 0.01 s | 0.01 GiB | Encode the ZK signature at the original's exact size; replace it in the manifest store |
| Verify (gnark CLI) | Verification | 0.03 s | 0.02 GiB | Process start, loading the verifying key, verifying |
| Verify (full CLI, anonymized asset) | Verification (full) | 0.05 s | 0.01 GiB | Time-stamp token against the TSA trust list (OpenSSL), issuing chain, c2pa claim checks, proof |
| Prove, warm (median of 3; in no total) | Supplementary | 77.8 s | 7.47 GiB | Load proving key 58.3 s; prove 18.1 s |

Totals: **79.4 s per-asset anonymization**, 499 s one-time, 30 ms verification (50 ms for the full verifier).

**Cache state.** Before each cold run, the constraint system and the proving key were synced and evicted, and the measured residency was 0.0 for both in all three runs; before each warm run, 1.0. (A first run of this harness, without the sync, could not evict the files setup had just written; its residency check labelled the run `eviction-failed`, and it was discarded.) The three cold runs took 78.6–79.5 s, the warm ones 77.4–79.3 s.

Output: a 196-byte proof (Groth16 with one commitment, compressed) in a ZK signature of exactly the original claim signature's size (16,324 bytes as c2pa-rs reserves it for this fixture; 14,251 bytes of padding left). The manifest store and the asset keep their sizes (17,529 and 1,905,087 bytes), and the claim is unchanged.

### Observations

- **Per-asset anonymization: 79 s against M0's 611 s (7.7× faster), for a stronger statement**, and within the third-party target (≤ 5 min, ≤ 16 GB). The device target (≤ 30 s, ≤ 2 GB) is 2.6× off on time and 3.7× on memory.
- **Loading the proving key is again most of the time (74%), and it is CPU-bound, not I/O-bound:** cold and warm loads take the same ~58 s. gnark validates every point on load (decompression and subgroup checks), as arkworks did for M0 ([Proving-key loading](#proving-key-loading)). The proof itself takes 19.5 s, including 3 s of witness solving (native Go, against M0's 225 s in WASM).
- **One-time setup is slower than M0's** (499 s against 255 s) and needs 11.3 GiB at its peak, comparable to M0.
- **Verification stays within target**: 30 ms for the gnark CLI, most of it process start and loading the 2.1 KB verifying key; 50 ms for the full verifier, which adds the time-stamp, chain, and c2pa checks.
- **Size is a non-issue in place**: the ZK signature fits in the space c2pa-rs reserves with 14 KB to spare; for the real device sample, the [computed fit](THIRD-PARTY-STATEMENT.md#the-zk-signatures-encoding) leaves 674 bytes with this proof size.
- **Variance.** The six prove runs here agree within 3% (77.4–79.5 s). The first run of this harness, with one repetition each, measured key loads of 52 s and 102 s; the cause is unknown (nothing else was scheduled on the machine), hence the three repetitions and the median.

## R2: a real device photo

The first Pixel photo from [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#r2-anonymizing-a-real-asset), anonymized and verified against the official trust list and TSA trust list with the unchanged tools, measured with `c2pa-x509-zk-bench run --variant third-party --asset … --trust-list … --tsa-trust-list … --keys …` ([record](bench/results/2026-11-06-r2-device-photo.json); the asset and lists identified by SHA-256, the photo not committed). Inputs: a 377-byte claim, a 1,528-byte protected header, a 783-byte signer certificate (661-byte TBS, 8 extensions), a 1.49 MB JPEG.

| | Real photo | Fixture, same session ([control](bench/results/2026-11-06-r2-control-fixture.json)) | Fixture, previous day |
|---|---|---|---|
| Per-asset anonymization (cold prove, median of 3) | 133.2 s | 110.6 s | 79.4 s |
| Cold prove runs | 112–134 s | 102–113 s | 79–80 s |
| Load proving key (median run) | 101 s | 81 s | 58 s |
| Prove (incl. solving) | 29.4 s | 27.3 s | 19.5 s |
| Peak memory | 7.4 GiB | 7.5 GiB | 7.5 GiB |

**Consistent with similar cost under large machine variation.** The circuit has a fixed size, so its constraint work does not depend on the asset; equal wall-clock cost is not demonstrated. Eight further proves alternating the two inputs in one session ([record](bench/results/2026-11-06-r2-paired-proves.json); not through the harness, cache state not controlled) took 90.6–119.7 s for the photo and 87.8–101.2 s for the fixture: the photo took 18%, 5%, and 3% longer in successive pairs as the machine's speed settled (one fixture run was excluded: 523 s of wall time against 114 s of measured work, a pause of the machine). The same unchanged fixture ran 40% slower on this day than the day before, for reasons outside the harness (power or thermal state are likely; neither is recorded). Per-asset figures on this laptop should therefore be read as 80–130 s, and compared only within a session.

(The control record lists two locally changed files, a document and a test, neither part of the measured binaries, which were built from commit `e87ef17`.)

Everything else matched the fixture: preparation, self-verification, and packaging under 0.1 s; proof verification 48 ms, and 76 ms for the full verifier against the official lists (the fixture: 50 and 85 ms in the same session); the ZK signature in place with 615 bytes to spare.

## E6: proving-key loading in gnark

The first E6 experiment ([roadmap](README.md#e6-proof-systems)): how the gnark prover stores and loads its 1.15 GB proving key, the step that took three quarters of V1's per-asset time. The statement, circuit, keys, and proof are unchanged; only the key's file format and whether its points are validated on load vary. `c2pa-zk-gnark convert-pk` writes the raw (uncompressed) and dump formats; every file's SHA-256 is checked against `keys.json` before parsing, in all configurations. Each configuration went through the harness in one session (mirror fixture, three cold and three warm proves, median reported); the baseline ran first and last, measuring 76.9 and 79.9 s, so drift was about 4%. Records: [`bench/results/2026-11-06-e6/`](bench/results/2026-11-06-e6/), clean commit `6469789`, every cold run confirmed cold.

| Proving key | Points validated on load | Per-asset anonymization | Load key: read + hash + parse | Peak RAM | Key file |
|---|---|---|---|---|---|
| Compressed (V1 today) | Full | 76.9 s (79.9 s at the end) | 56.5 s (parse 53.6) | 7.4 GiB | 1.15 GB |
| Compressed | None (subgroup) | 52.5 s | 32.5 s (parse 31.0) | 7.4 GiB | 1.15 GB |
| Raw | Full | 52.1 s | 32.2 s (parse 28.7) | 9.2 GiB | 2.29 GB |
| Raw | None (subgroup and on-curve) | 28.2 s | 8.7 s (parse 5.7) | 9.2 GiB | 2.29 GB |
| Dump (gnark's binary dump) | None (nothing) | **24.6 s** | **5.2 s** (parse 1.5) | 9.2 GiB | 2.29 GB |

The proof itself takes 17.8–18.7 s (solving the witness, about 3 s of it) in every configuration; warm runs are within a few seconds of cold ones, so loading is CPU-bound, not I/O-bound.

### Observations

- **Decompressing points and checking G2 subgroups each cost about 24 s**; skipping both brings per-asset anonymization from ~77 s to 25–28 s, **under 30 s on the reference laptop**. That is not phone performance, and memory (9.2 GiB here, 6.3 GiB with streamed loading) remains far above the device target of 2 GB: the result supports laptop- or server-side anonymization, not mobile feasibility.
- **What is skipped.** In gnark, validating a raw point is the subgroup check, which includes the on-curve check; with checks off, raw points are taken as written (only their coordinates must be canonical field elements). Compressed points are on the curve by construction, so with checks off only G2's subgroup check is skipped. A dump is not validated at all, and its format is gnark-internal: it is raw memory, starting with a marker that detects a dump written on a different architecture (byte order) but carrying no version, so a dump should be regenerated whenever gnark is upgraded.
- **Peak memory rises with the larger files** (9.2 against 7.4 GiB) because the CLI reads the whole key into memory to hash it before parsing; hashing while streaming would remove most of that increase.
- **The same trade-off as for M0's key** ([Proving-key loading](#proving-key-loading)): for a key written by local setup whose hash matches `keys.json`, the point checks add nothing; the hash, stored next to the key, detects corruption and mix-ups, not replacement by someone who can write to the key directory; and no point check would stop a malicious but well-formed key, which could weaken zero-knowledge.

### Proposal (for decision)

- **Recommended: raw keys loaded without point checks, behind the hash recorded at setup** (28.2 s per asset), adopted first as an opt-in path. Raw is preferred because it goes through gnark's supported serialization API, not because it is guaranteed stable: gnark states that its serialized formats may change between versions, so raw keys, like dumps, must record the gnark version that wrote them.
- **The dump is not recommended as a storage format**: it saves 3.6 s but is a native memory image, tied to the architecture and the gnark version; at most an explicitly experimental, disposable local cache.
- **Adoption guardrails:**
  - convert from a fully validated key of trusted provenance (local setup), keeping the existing verifying key;
  - verify the hash before any unchecked parsing, and make sure the file cannot change between hashing and parsing;
  - record versioned metadata (format, producing gnark version, the source key's hash) and handle migration explicitly;
  - never fall back silently to unchecked loading when provenance or metadata is missing: refuse instead;
  - leave verifying-key loading, proof verification, and the anonymizer's check of its own proof unchanged;
  - stream the hash and parse through a bounded buffer: an exploratory single run in review loaded, proved, and verified with a raw key at 6.30 GiB peak (against 9.18 GiB reading the whole file), in 27.3 s against 30.4 s.
- **What the hash does not establish.** Stored next to the key, it detects corruption and mix-ups, not replacement by someone who can write to the key directory; and neither point checks nor a successful verification show that an attacker-supplied, well-formed key preserves zero-knowledge.
- **Not adopted here**: `prove` still defaults to the compressed key with full checks.

### The opt-in fast path (adopted)

Following the review of the proposal, the raw path is available as an **opt-in** (`prove --pk-format raw --pk-check none`); the default stays the compressed key with full checks.

- **Provenance.** `keys.json` records each proving-key file's format, hash, the gnark version that wrote it, and its source: local setup, or `convert-pk` from the compressed key loaded with full point checks. Loading without point checks is refused unless that record exists, matches the file, comes from such a source, and names the running gnark version; there is no silent fallback, and full checks need no record.
- **Streaming.** Every key-directory file is read in two buffered passes: its SHA-256 is checked before any parsing, then it is parsed while the same bytes are hashed again, and the result is used only if that hash matches too and no bytes remain. A file changed between the passes, or with trailing bytes, is rejected, and no file is held whole in memory.

Measured on 2026-11-09 ([records](bench/results/2026-11-09-e6-streamed/), clean commit `5ac12b2`; the machine was slower than on 2026-11-06, and drifted 9% during the session):

| | Per-asset anonymization (cold prove, median of 3) | Peak RAM |
|---|---|---|
| Compressed, full checks (first / last) | 97.2 / 105.6 s | 6.7 GiB (7.4 GiB before streaming) |
| **Raw, no point checks, streamed** | **49.1 s** | **6.7 GiB** (9.2 GiB before streaming) |

Streaming's own cost, isolated by alternating the previous (in-memory) CLI and the streamed one on the same raw key in one session ([paired record](bench/results/2026-11-09-e6-streamed/paired-loads.json)): about 2.5 s more to load the key (one more SHA-256 pass over 2.29 GB), whole-process times within the machine's noise, and about 2.5 GiB less peak memory. Raw without checks thus halves per-asset time against the default, in the same session, at no memory cost; on 2026-11-06's faster machine state, that was 28 s against 77 s.

## E7: BLS12-381 as an option

The same statement on BLS12-381 ([roadmap E7](README.md#e7-curve-bn254-vs-bls12-381)), available as an option alongside BN254, which stays the default: the curve belongs to the key set (`c2pa-zk-gnark setup --curve bls12-381`, recorded in `keys.json`), the ZK signature records it when it is not BN254, and keys or proofs of one curve are refused as the other. The circuit is unchanged; compiled for BLS12-381's scalar field it has 4,710,835 constraints (BN254: 4,710,820). BLS12-381 is estimated at about 120 bits of security, BN254 at about 100: curve-level estimates, not an assessment of the prototype's overall security, which also rests on its single-party setup, partial certificate validation, and the other shortcuts listed for V1.

Measured in one session through the harness (mirror fixture, three cold and three warm proves, median reported; [records](bench/results/2026-11-09-e7/), clean commit `fae4f80`, every cold run confirmed cold). The BN254 baseline ran first and last, measuring 72.4 and 85.5 s: the machine drifted about 18% during the session.

| Curve | Proving key | Per-asset anonymization | Load key (parse) | Proof | Peak RAM | Proof / verifying key | Proving key file |
|---|---|---|---|---|---|---|---|
| BN254 (default) | Compressed, full checks | 72.4 s (85.5 s at the end) | 54.3 s (53.2) | 16.6 s | 6.7 GiB | 196 B / 2.1 KB | 1.15 GB |
| BN254 | Raw, no point checks | 33.2 s | 12.7 s (10.0) | 18.8 s | 6.7 GiB | 196 B / 2.1 KB | 2.29 GB |
| BLS12-381 | Compressed, full checks | **302.2 s** | 270.7 s (268.7) | 29.6 s | 8.5 GiB | 292 B / 3.2 KB | 1.72 GB |
| BLS12-381 | Raw, no point checks | **87.8 s** | 56.1 s (50.9) | 29.5 s | 8.5 GiB | 292 B / 3.2 KB | 3.43 GB |

One-time setup took 709 s on BLS12-381 (BN254: about 430–500 s); verification stays at 37–40 ms (60 ms for the full verifier); the ZK signature still fits in place, with 14.1 KB to spare on the fixture (for the real device sample, by computation: 3,754 bytes available and about 3,255 needed, the 96 bytes of larger proof and the curve field added to BN254's 3,139, so about 500 bytes to spare; not yet confirmed on the asset).

### Observations

- **The security margin costs time, mostly in loading the key.** The proof itself takes 1.6–1.8× longer on BLS12-381 (29.5 s against 16.6–18.8 s), as expected from its larger base field. Loading costs far more: with full point checks, 271 s against 54 s, making BLS12-381's default path 4× slower than BN254's and just over the 5-minute third-party target.
- **The raw fast path matters more on BLS12-381** (302 s → 88 s per asset), but **its raw keys parse slowly even unchecked**: 51 s against BN254's 10 s. Loaded back to back ([record](bench/results/2026-11-09-e7/bls12-381-raw-vs-dump.json)), the raw key parsed in 42–43 s and gnark's dump in 4.7 s, so the cost is in gnark's decoding of raw BLS12-381 points, not in validation; the cause was not established (converting coordinates to gnark's internal form, 6 limbs against BN254's 4, is plausible). On this curve the dump would save about 30 s per asset, against 3.6 s on BN254; the dump stays experimental, its drawbacks ([proposal](#proposal-for-decision)) unchanged, and the raw decoding cost should be investigated before accepting the dump's coupling to the native memory layout and the gnark version as a normal storage path.
- **Memory rises to 8.5 GiB**, still far above the device target.
- **Within the third-party target on both curves with the raw path** (88 s on BLS12-381); the default path on BLS12-381 is at the limit.

## H4: hiding the issuing CA

The hidden-issuer statement ([HIDING-THE-ISSUER.md](HIDING-THE-ISSUER.md), [roadmap H4](README.md#h4-hiding-the-issuing-ca)), an option alongside the disclosed one: the issuing CA's P-384 key is private and proven a leaf of a Poseidon2 Merkle tree (format 1, depth 8) over the trust list's eligible CAs, and the CA's validity, from its leaf, contains `t`; the root replaces the CA's key as a public input. The ZK signature carries the root and a list name instead of the issuing chain; the verifier accepts the root only if it built the same root from a trust-list snapshot its policy approves, whose period contains `t`. The circuit has 4,718,946 constraints, 8,126 more than the disclosed statement (+0.17%).

Measured in one session through the harness with existing keys (setup not measured; mirror fixture, three cold and three warm proves, median reported; [records](bench/results/2026-11-11-h4/), commit `da5d334` with only README.md changed, every cold run confirmed cold). Windows was kept from sleeping, and a heartbeat every 10 s showed no suspend (largest gap 11 s). The disclosed baseline ran first and last.

| Statement (run order) | Per-asset anonymization | Load key (parse) | Proof | Peak RAM | Verify (full verifier) | Verifying key | Spare bytes in the ZK signature |
|---|---|---|---|---|---|---|---|
| Disclosed (1st) | 74.1 s | 55.6 s | 17.0 s | 6.7 GiB | 35 ms (59 ms) | 2.1 KB | 14,250 |
| Hidden issuer (2nd) | **106.8 s** | 79.5 s | 24.9 s | 6.7 GiB | 50 ms (122 ms) | 1.7 KB | 14,679 |
| Disclosed (3rd) | **104.0 s** | 77.2 s | 24.6 s | 6.6 GiB | 46 ms (77 ms) | 2.1 KB | 14,248 |

### Observations

- **No measurable cost.** The machine slowed by about 40% during the first run (its warm proves, 108–117 s, came after cold ones of 72–74 s) and stayed slow; no suspend occurred, so a lower power state with the screen locked is the likely cause. Against the adjacent disclosed run in the same conditions, the hidden issuer costs +2.7% per asset, within the noise of single proves (101–107 s), as the +0.17% in constraints predicts. The proving key is the same size (1.15 GB).
- **Verification** adds the policy check: building each approved snapshot's tree (one CLI call) and the c2pa checks on a copy carrying the placeholder certificate, 122 ms in total against 59–77 ms. The verifying key shrinks (one root instead of the CA key's twelve limbs as public inputs).
- **The output** carries no certificate: the ZK signature replaces the original at the same size, with 431 more spare bytes than the disclosed form (the issuing chain is gone).
- **The anonymity set** on the official trust list (`conformance-public` at `a95f2c4`): all 33 certificates pass the eligibility check (CA checks; none carries name or policy constraints), and the 28 with P-384 keys form the tree, from 18 organizations. The circuit's key type limits the set: the 4 RSA-4096 and 1 P-521 CAs would need their own statements and trees.
- **What it does not hide:** the claim (its generator and assertions) and the public time-stamp token, whose TSA certificate names its operator; for vertically integrated pipelines these name the organization anyway ([What H4 can and cannot hide](HIDING-THE-ISSUER.md#what-h4-can-and-cannot-hide)).

## I6: hiding the time-stamp token

The statement hiding the issuer and the time-stamp token ([HIDING-THE-TIME-STAMP.md](HIDING-THE-TIME-STAMP.md)), an option beside the disclosed and hidden-issuer ones: the hidden-issuer statement, with the token verified in the circuit under a stated, reduced profile (T2): the signed attributes and the TSA's ES256 signature, `TSTInfo` and its imprint of the original signature, the TSA certificate's TBS and its TSA CA's ECDSA-SHA384 signature, the TSA CA's membership in a TSA tree (leaf tag 4), and `genTime` in a public half-open window. The ZK signature carries the two roots and the window, and neither certificates nor token; the verifier approves the issuer root from claim-signing snapshots and the TSA root from TSA snapshots, each containing the whole window. The circuit has 6,458,939 constraints, 1,739,993 more than the hidden-issuer statement (+37%).

Measured in one session through the harness with existing keys (setup not measured: 722 s in a separate CLI run; mirror fixture with the real token's profile, three cold and three warm proves, median reported; [records](bench/results/2026-11-12-i6/), clean commit `4f973e5`, every cold run confirmed cold). Windows was kept from sleeping, and a heartbeat every 10 s showed no suspend (largest gap 13 s). The hidden-issuer baseline ran first and last.

| Statement (run order) | Per-asset anonymization | Load key (parse) | Proof | Peak RAM | Verify (full verifier) | Proving key | Spare bytes in the ZK signature |
|---|---|---|---|---|---|---|---|
| Hidden issuer (1st) | 76.9 s | 56.3 s | 18.9 s | 6.7 GiB | 31 ms (83 ms) | 1.15 GB | 14,103 |
| **Hidden issuer and time stamp** (2nd) | **97.4 s** | 73.1 s | 21.8 s | 8.5 GiB | 32 ms (104 ms) | 1.49 GB | 15,749 |
| Hidden issuer (3rd) | 75.1 s | 56.5 s | 17.0 s | 6.7 GiB | 31 ms (80 ms) | 1.15 GB | 14,103 |

### Observations

- **+28% per asset** against the adjacent hidden-issuer runs, below the +37% in constraints: proving grows with the constraints, but most of the time is loading the proving key, which grows with its size (+29%). Single cold proves ranged 94–98 s, against 69–80 s for the hidden issuer, so the difference is well beyond the session's noise.
- **Peak memory** rises from 6.7 to 8.5 GiB, with the larger proving key and constraint system.
- **Verification** is unchanged in proof cost (a Groth16 verification, 32 ms); the full verifier takes 104 ms, building two trees from the policy's snapshots instead of one, and no longer checking a token off-circuit.
- **The output** carries no time-stamp token: the ZK signature replaces the original at the same size, with 1,646 more spare bytes than the hidden-issuer form (the ~2 KB token, less the TSA tree reference and the window).
- **The anonymity sets** on the official lists (`a95f2c4`): the issuer among 28 P-384 CAs from 18 organizations; the TSA among 19 P-384 CAs from 14 organizations, all eligible for time stamping.
- **What it does not hide:** the claim and its assertions, as before; and the window, by default the UTC day, which remains a correlation channel for the TSA operator, narrower for a TSA with few requests ([HIDING-THE-TIME-STAMP.md](HIDING-THE-TIME-STAMP.md#guarantees-and-shortcuts)).

## Milestone 1: every mode in one session

The four configurations of [Milestone 1](MILESTONE-1.md) measured back to back, so that they compare directly; the earlier figures came from separate sessions, between which this laptop varies by 10–40%. Through the harness with existing keys (setup not measured), on the mirror fixture, three cold and three warm proves each, median reported; [records](bench/results/2026-11-13-all-modes/), clean commit `dce2661`, every cold run confirmed cold. Windows was kept from sleeping, on AC power, and a heartbeat every 10 s showed no suspend (largest gap 12 s, 35 minutes in all). The disclosed baseline ran first and last.

| Mode (run order) | Per-asset anonymization | Single cold proves | Load key (parse) | Proof | Peak RAM | Verify (full verifier) | Proving key |
|---|---|---|---|---|---|---|---|
| Disclosed (1st) | 81.0 s | 73.6–81.9 s | 57.8 s | 18.1 s | 6.6 GiB | 32 ms (61 ms) | 1.15 GB |
| Hidden issuer (2nd) | 71.2 s | 69.8–71.4 s | 52.3 s | 16.3 s | 6.7 GiB | 32 ms (83 ms) | 1.15 GB |
| Hidden issuer and time stamp (3rd) | 91.3 s | 88.4–94.9 s | 66.9 s | 20.4 s | 8.5 GiB | 31 ms (108 ms) | 1.49 GB |
| Disclosed, fast key path (4th) | 28.1 s | 27.7–30.1 s | 7.8 s | 16.4 s | 6.7 GiB | 37 ms (48 ms) | 2.29 GB (raw) |
| Disclosed (5th) | 71.0 s | 70.3–71.4 s | 51.1 s | 17.2 s | 6.7 GiB | 32 ms (55 ms) | 1.15 GB |

### Observations

- **The baseline drifted by 12% within the session** (81.0 s first, 71.0 s last), mostly in loading the proving key (57.8 s against 51.1 s); comparisons below are with the adjacent runs and that range.
- **Hiding the issuer costs nothing measurable:** 71.2 s, within the disclosed runs' range (71.0–81.0 s), as in the H4 session.
- **Hiding the time stamp too costs +28%** over the adjacent hidden-issuer run (91.3 s against 71.2 s), the same as in the I6 session; +13–29% over the disclosed runs. Its fastest single prove exceeds every other configuration's slowest (88.4 s against 81.9 s).
- **The fast key path** brings the disclosed mode to 28.1 s, 60–65% less than the compressed key, by cutting the key's parse from 51–58 s to 7.8 s; the proof itself (16–18 s) is unchanged.
- **Peak memory** is 6.6–6.7 GiB for every mode but the hidden time stamp (8.5 GiB); verification costs 31–37 ms for the proof in every mode, and the full verifier 48–108 ms, the hidden modes building the trees from the policy's snapshots.
- **Consistent with the earlier sessions:** disclosed 72–77 s (H4 session), hidden issuer 75–77 s and hidden-all 97 s (I6 session), fast path 25–33 s (E6, E7): this session runs a few percent faster, and the ratios between modes are unchanged.

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

For the two 1,500-byte CA circuits, prove is the median of three runs with the range in brackets; the first run's 9.0 s for P-256 was an outlier (the repeats took 4.2 and 4.3 s), and setup varied by up to 50% between runs. Every proof is 196 bytes and verifies in 1.5–3 ms; verifying keys are 768 bytes (P-256 key as public input) and 896 bytes (P-384), and 1,520 and 2,032 bytes for the hash-only circuits (one public input per digest byte). **Accounting boundaries.** Prove is *resident-key primitive proving*: the proving key generated by setup stays in memory, so the time includes gnark's witness computation (solve, under a second throughout) but no key loading. Peak RSS is *whole-run memory* for the circuit's process, which also compiles the circuit, runs setup, and compiles the PLONKish count; it is not the memory of proving alone. Neither matches the per-asset accounting of the [M0 baseline](#m0-baseline-measured-detail) (separate processes, keys loaded from disk, the whole statement), so these times are compared only with each other.

### Observations

- **P-384 with SHA-384 costs 1.3–1.5× P-256 with SHA-256** for a CA signature over a TBS (1.47× at 414 bytes, 1.32× at 1,500 bytes, in constraints; ~1.2× in proving time at 1,500 bytes). ECDSA alone doubles (2.03×, from four to six 64-bit limbs per coordinate); SHA-384 is 1.17–1.24× SHA-256 for the same message, since its larger 128-byte blocks halve the block count.
- **The hash, not the signature, dominates for real certificate sizes.** Over a 1,500-byte TBS, hashing is about 85% of the P-256 circuit and 75% of the P-384 one. Real certificates are larger than the test PKI's, so the variable-length maximum chosen for the TBS matters as much as the curve.
- **Relation to the circom baseline.** The current circuit's P-256 ECDSA component is 1,972,905 constraints, 13× gnark's 148,357 (gnark uses non-native arithmetic with range checks by lookup); its SHA-256 over up to 1,536 bytes is 758,254 constraints, 0.78× gnark's 976,699 for 1,500 bytes (the same 24 blocks). A CA signature over a TBS of up to 1,536 bytes costs 2,731,159 constraints in circom with P-256; gnark needs 1,156,320 with P-256 and **1,521,300 with P-384, 0.56× the circom P-256 figure**. Constraint counts across stacks are only indicative: gnark's lookups use a commitment in the proof, and the costs per constraint differ. The times are not comparable with the circom baseline's ~10 minutes per asset: that figure covers the whole statement (two ECDSA verifications, hashing, parsing) in separate processes and is dominated by loading the proving key (57%) and witness generation (37%), whereas these are single primitives with the key resident. The closest circom counterpart of resident-key proving is the baseline's witness computation plus Groth16 proof (225 s + 32 s), still for the whole 4.8M-constraint statement rather than one primitive.
- **gnark's Groth16 setup is slow** (about 80–125 s per million constraints, single party) and its proving keys are large (~240 MB compressed per million constraints); both are one-time, but setup dominates each run. The 196-byte proof is Groth16 plus one commitment and its proof of knowledge (gnark's extension for lookups), so a verifier needs gnark-compatible verification rather than plain Groth16.
- **Stop-rule assessment (provisional):** no stop rule is triggered by the primitive. The verification a real CA forces (P-384 with SHA-384 over a 1–1.5 KB TBS) proves in ~5 s with the key resident. Whether a full third-party statement meets the 5-minute target in gnark is not established by these figures: it adds the signer's COSE signature verification, its hash, and parsing, and per-asset accounting adds loading the keys (gnark's proving key here is 0.4 GB compressed for this primitive alone). That needs the full statement measured under the same accounting as the baseline. The PLONKish counts are 3.2–3.8× the R1CS counts, relevant to E6.
- **Implication for E6:** P-384 CAs argue for measuring the full statement in gnark rather than porting P-384 and SHA-384 to circom. That comparison must use equivalent full statements and the same accounting boundaries, and report loading artifacts from disk (cold) separately from operation with resident keys (warm). RSA is measured [next](#e1-rsa-primitives). SHA-384 over a variable-length input was implemented with the statement in E2b ([`gnark/statement/sha384.go`](gnark/statement/sha384.go)) and is measured as part of V1, so no standalone benchmark is needed.

## E1: RSA primitives

What RSA signatures cost in a circuit, next to ECDSA: RSA CAs (RSA-4096 and RSA-2048, signing with SHA256-RSA or SHA384-RSA, which is PKCS#1 v1.5) appear on both trust lists, and RSA signer keys with PS256 are common among interim-list signers ([DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#what-this-means-for-the-prototype)). Same spike, stack, and accounting as [P-384](#e1-p-384-and-sha-384-primitives) (code in [`experiments/e1-p384`](experiments/e1-p384/)); the RSA circuits as reviewed, with the ECDSA ones for comparison, measured in one session: [2026-11-10-e1-rsa-gnark-review](bench/results/2026-11-10-e1-rsa-gnark-review.json), clean commit `b61a545`. The [first record](bench/results/2026-11-10-e1-rsa-gnark.json) (commit `ed2b899`, all 20 E1 circuits) predates the modulus-size and canonical-signature checks, which add 23k (RSA-2048), 35k, and 47k (RSA-4096) constraints, mostly bit decompositions of n and s.

**How RSA is verified.** gnark's variable-modulus emulated arithmetic, with exactly as many 64-bit limbs as the key (32, 48, or 64), so one circuit serves every key of its size. The circuit asserts that n has exactly the key size (its top bit set) and that the signature is below n (RSAVP1), so only the canonical signature, the bytes a time stamp covers, is accepted. With the public exponent 65537, verification is 16 squarings and one multiplication modulo n; the result is asserted below n, decomposed into bits, and checked against the encoding: for **PKCS#1 v1.5**, `00 01 FF…FF 00 || DigestInfo || digest`; for **PS256**, EMSA-PSS-VERIFY with SHA-256, MGF1-SHA-256, and a 32-byte salt (the hash length, as RFC 8230 sets for COSE), including MGF1 in the circuit. CA moduli are public inputs, like the ECDSA CA keys; the PS256 signer's modulus is private, as the signer's key is in the statement.

**Correctness.** Every circuit accepts a signature made by Go's `crypto/rsa` and rejects a tampered input. For RSA-2048, 23 cases are run through `crypto/rsa`, gnark's test engine, and the compiled R1CS (solved, without proving), and the verdicts agree: signatures from `crypto/rsa` and hand-built encodings are accepted; a tampered signature, digest, or modulus is rejected, and so is the signature plus the modulus (the same value modulo n), and so are, for PKCS#1 v1.5, a wrong block type, padding byte, separator, or hash algorithm identifier, and for PSS, a 20-byte or empty salt, a wrong trailer, the leftmost bit set, nonzero padding, or a wrong separator. One case is refused by design where `crypto/rsa` accepts: a 2047-bit key in the 2048-bit circuit. Without the size check, the circuits would accept that key's PKCS#1 v1.5 signatures, and its PS256 signatures about half the time (when a padding bit the circuit does not clear happens to be zero).

**Shortcuts,** beyond the primitive ones listed for P-384: the exponent is 65537 only; key sizes are 2048, 3072, or 4096 bits exactly (a key of another size needs its own circuit); PSS takes a 32-byte salt only (a signer using another salt length would be refused).

**Before integration** into the third-party statement: the modulus and exponent must be read from the certificate the CA signed (the structural DER walk extended to RSA keys, with the exponent checked to be 65537), and the signature bytes the circuit verifies must be the ones the time stamp's imprint covers, as for ES256 today. The size and canonical-signature checks above are already in the circuits.

| Circuit | R1CS constraints | PLONKish constraints | Setup | Solve | Prove, key resident (incl. solve) | Peak RSS, whole run | Proving key (compressed / raw) |
|---|---|---|---|---|---|---|---|
| RSA-2048 PKCS#1 v1.5 verify, digest given | 80,447 | 214,819 | 6.2 s | 0.03 s | 0.35 s | 0.24 GiB | 16 / 31 MB |
| RSA-3072 PKCS#1 v1.5 verify, digest given | 119,577 | 311,854 | 8.2 s | 0.06 s | 0.43 s | 0.32 GiB | 21 / 42 MB |
| ECDSA P-256 verify, digest given | 148,357 | 567,375 | 13 s | 0.07 s | 0.62 s | 0.49 GiB | 37 / 73 MB |
| RSA-4096 PKCS#1 v1.5 verify, digest given | 158,091 | 407,918 | 12 s | 0.09 s | 0.66 s | 0.43 GiB | 30 / 60 MB |
| ECDSA P-384 verify, digest given | 301,556 | 1,149,790 | 26 s | 0.14 s | 1.17 s | 0.97 GiB | 74 / 148 MB |
| RSA-2048 PS256 verify, digest given | 525,073 | 1,562,759 | 59 s | 0.34 s | 2.45 s | 1.61 GiB | 134 / 266 MB |
| RSA-3072 PS256 verify, digest given | 705,200 | 2,096,239 | 79 s | 0.42 s | 2.98 s | 2.03 GiB | 166 / 330 MB |
| RSA-4096 PS256 verify, digest given | 885,323 | 2,629,719 | 84 s | 0.33 s | 2.67 s | 2.30 GiB | 198 / 393 MB |
| CA signature, RSA-4096 + SHA-384, 414-byte TBS | 636,652 | 1,907,856 | 50 s | 0.31 s | 2.01 s | 2.04 GiB | 152 / 303 MB |
| CA signature, P-384 + SHA-384, 414-byte TBS | 821,074 | 2,702,402 | 68 s | 0.39 s | 2.96 s | 2.26 GiB | 193 / 383 MB |
| CA signature, RSA-4096 + SHA-256, 1,500-byte TBS | 1,146,825 | 3,423,074 | 93 s | 0.60 s | 4.07 s | 3.27 GiB | 281 / 559 MB |
| CA signature, RSA-2048 + SHA-384, 1,500-byte TBS | 1,228,303 | 3,725,090 | 97 s | 0.62 s | 4.25 s | 3.51 GiB | 301 / 599 MB |
| CA signature, RSA-4096 + SHA-384, 1,500-byte TBS | 1,313,355 | 3,971,426 | 114 s | 0.70 s | 4.64 s | 3.40 GiB | 314 / 625 MB |
| CA signature, P-384 + SHA-384, 1,500-byte TBS | 1,521,300 | 5,109,304 | 126 s | 0.68 s | 5.22 s | 3.88 GiB | 368 / 731 MB |

Single runs, so times are indicative (RSA-4096 PS256 proved faster than RSA-3072 here) and constraints are the comparison. The ECDSA circuits reproduce the [P-384 record](#e1-p-384-and-sha-384-primitives)'s constraint counts exactly. Every proof is 196 bytes and verifies in 1.5–2.5 ms; a public RSA modulus is 32 to 64 public inputs (one per limb), so verifying keys grow to 1.8 KB (RSA-2048) and 3.1 KB (RSA-4096), against 0.9 KB with a P-384 key.

### Observations

- **RSA verification costs no more than ECDSA in the circuit.** With exponent 65537 it is 17 modular multiplications, against an emulated elliptic-curve double scalar multiplication: RSA-4096 PKCS#1 v1.5 costs 158k constraints, 0.52× ECDSA P-384 and about the same as P-256 (1.07×); RSA-2048 costs 80k. Cost grows about linearly with key size (80k, 120k, 158k for 2048, 3072, 4096 bits), about 30% of it the modulus-size and canonical-signature checks.
- **RSA CAs cost less than P-384 CAs.** Over a 1,500-byte TBS, an RSA-4096 CA signing with SHA-384 costs 0.86× the P-384 circuit, and with SHA-256 0.75×; RSA adds 85k (2048) to 170k (4096) constraints to the hash, about 13% of the circuit. The hash dominates even more than with ECDSA.
- **PS256 is dominated by its hashing.** MGF1 hashes H with a counter once per 32 bytes of the mask (7, 11, and 15 SHA-256 blocks for 2048, 3072, and 4096 bits), plus two blocks for H′: 43–49k constraints per block, 82–85% of the circuit. A PS256 verification costs 3.5× (RSA-2048) to 6.0× (RSA-4096) an ES256 one.
- **What RSA would add to the third-party statement** (estimates from these primitives; not measured): an RSA CA in place of the P-384 CA saves 140–220k constraints. A PS256 signer in place of ES256 adds 375–740k for the signature (8–16% of V1's 4.7M), and more for its certificate: an RSA-2048 to RSA-4096 SubjectPublicKeyInfo is about 200–460 bytes longer than a P-256 one, which adds hash blocks over the TBS, and the structural DER walk must locate an RSA key. The rest of the statement (claim hashing, time stamp) is unchanged.
- **Stop-rule assessment:** none triggered. No algorithm found in the trust lists or samples is a cost obstacle for trust model A in gnark, apart from P-521 and Ed25519, which are not measured. Supporting RSA in the statement is an integration task (certificate parsing, one statement per algorithm combination or a selector, key sizes as compile-time limits), relevant to [R3](README.md#r3-interim-list-allowed-signers-via-merkle-membership) and RSA-signed content.

## Proving-key loading

Measured with `c2pa-x509-zk-bench pk-load` ([record](bench/results/2026-11-04-proving-key-load.json)) on the M0 proving key: 22.6 million G1 points and 4.74 million G2 points (4.14 million of them non-zero), 1.03 GB compressed, 2.05 GB uncompressed. Each load ran in its own process, once after requesting the key file's eviction from the Linux page cache and once warm. Eviction is advisory, so the residency measured just before each load is recorded, and the cold labels rest on it: none of the key file was resident before any of the 13 cold loads, and all of it before every warm one. (The harness now derives the label from that measurement, and reports a load whose pages stayed resident as `eviction-failed` rather than cold.) The loads in the table produce the same key; tests check that every loader reads back the key that was written.

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

