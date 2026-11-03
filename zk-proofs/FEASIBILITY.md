# Feasibility Matrix (R1)

A living comparison of the anonymization variants, updated after each experiment ([roadmap R1](README.md#r1-feasibility-matrix)). Each row states what the variant proves, discloses, and assumes, its measured cost, and which guarantees are established versus experimental shortcuts (see the [method](ARCHITECTURE-DECISIONS.md#method)). Variants are compared only against others with equivalent guarantees.

Measurements come from the benchmark harness ([F2](README.md#benchmarks)); each row links to its JSON record in [`bench/results/`](bench/results/).

## Reference machine

13th Gen Intel Core i7-13800H laptop (20 logical CPUs), 32 GB of RAM, Ubuntu 24.04.2 under WSL2 (kernel 6.18), rustc 1.93.0, circom 2.1.6. Other profiles (a desktop, a phone) can be added as separate columns later.

## Provisional targets

Stretch goals, not pass/fail gates: today's baseline misses most of them, and rows are kept and compared on progress and trade-offs. Targets are per scenario, because who runs the prover changes the budget by orders of magnitude.

| Criterion | Third-party anonymizer (server) | Signer-side, on device (phone) | Verifier (any C2PA validator) |
|---|---|---|---|
| Per-proof time | ≤ 5 min | ≤ 30 s | — |
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

| Variant | Mode | Trust model | Proves | Discloses | Assumptions | Deployment segments covered | Per-proof time | Peak RAM | Verify | Proof container / manifest added | Security | Setup | Record |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **V0 baseline** | Signer-side | A (X.509 in-circuit) | Issuing CA (P-256, ECDSA-SHA256) signed a certificate whose P-256 key signed the manifest-stripped asset digest; key and validity pinned inside the signed TBS | Issuing CA (`x5chain`), asset digest, a prover-chosen timestamp | Signer holds its key; trust list authentic; single-party setup | Test PKI only. Not the official list (P-384 CAs); interim P-256 camera roots only if their intermediates are also P-256 (unverified); not the interim allowed list | **608 s** (witness 229 s + prove 379 s) | 11.1 GiB (prove phase) | 10 ms | 668 B / 11.4 KB | ~100 bits (BN254) | Per-circuit, single party | [2026-11-03-baseline](bench/results/2026-11-03-baseline.json) |

**V0 shortcuts:** every item under [Current Limitations](README.md#current-limitations) applies, in particular no historical validity (the timestamp is unchecked), binding to the asset bytes rather than the claim, and partial in-circuit certificate validation.

Planned rows: E1 (P-384/SHA-384 and RSA primitives, standalone), E2b (third-party mode), E3/E4 (trust models B and C, on the same statement), E5 (key possession, signer-side only), E6/E7 (proof systems and curves).

## V0 baseline: measured detail

4,776,263 constraints, 4,737,842 wires. Inputs: a 505-byte signer certificate (414-byte TBS), one issuing CA certificate in `x5chain`, a 1.9 MB image.

| Phase | Wall time | Peak RSS (GiB/MiB) | Steps |
|---|---|---|---|
| Compile (circom) | 199 s | 6.0 GiB | One-time |
| Setup | 51 s | 9.9 GiB | One-time; proving key 1.03 GB, verifying key 872 B |
| Witness | 229 s | 4.0 GiB | Load circuit 4 s; **compute witness (WASM) 224 s**; check witness 0.9 s; write 0.1 s |
| Prove | 379 s | 11.1 GiB | Load R1CS 2.8 s; read witness 0.3 s; **load proving key 342 s**; **Groth16 proof 33 s** |
| Verify | 0.03 s | 19 MiB | Load verifying key 10 ms; verify 10 ms |
| Verify (full CLI, anonymized asset) | 0.02 s | 27 MiB | Trust-list chain validation, assertion and digest checks, Groth16 |

Output: a 128-byte Groth16 proof and 19 public inputs, embedded as a 668-byte container (base64 of JSON); a 1,183-byte assertion; a 481-byte `x5chain`; 11,385 bytes of C2PA manifest store added to the asset in total, including about 8 KB of padding reserved for the COSE signature.

### Observations

- **Proving is 5% of the per-proof time.** The Groth16 proof takes 33 s. Deserializing the 1 GB proving key takes 342 s (56%): it is stored compressed and fully validated on load, decompressing and checking every curve point. A key written by local setup could be stored uncompressed and loaded without re-validation, likely bringing this to seconds. A candidate quick win outside the experiment plan.
- **Witness generation in WASM takes 224 s (37%).** Loading the circuit and checking the witness are negligible. Native (C++) witness generation is the first E6 experiment.
- **Memory peaks while loading the proving key** (11.1 GiB in the prove phase); witness generation peaks at 4.0 GiB.
- **Verification is already within target** (10 ms; 872-byte verifying key), and so is the proof container (668 B). The total manifest store (11.4 KB) is dominated by reserved padding.
- **Against the third-party target** (≤ 5 min, ≤ 16 GB): about 2× over on time, within on memory, even before the two engineering fixes above. The signer-side device target (≤ 30 s, ≤ 2 GB) is about 20× off on time and 5× on memory. BN254 misses the security target.
