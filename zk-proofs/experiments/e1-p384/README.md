# E1 spike: P-384, SHA-384, and RSA in-circuit

Roadmap item [E1](../../README.md#e1-cost-of-reality-p-384-sha-384-and-rsa-in-circuit): what verifying the signature algorithms of real C2PA deployments costs in a circuit, next to the P-256 and SHA-256 the current circuit uses. First P-384 ECDSA with SHA-384, the algorithms the official trust list's CAs use ([results](../../FEASIBILITY.md#e1-p-384-and-sha-384-primitives)); then RSA, PKCS#1 v1.5 for RSA CAs and PS256 for RSA signers ([results](../../FEASIBILITY.md#e1-rsa-primitives)). The directory keeps its first name so that earlier records and links stay valid.

## What is measured

Standalone primitives, Groth16 on BN254 with [gnark](https://github.com/consensys/gnark) v0.16.4:

| Circuit | Statement |
|---|---|
| `ecdsa-p256`, `ecdsa-p384` | ECDSA verification of a given digest under a public key |
| `sha256-414`, `sha256-1500`, `sha384-414`, `sha384-1500` | A hash over a private message of 414 or 1,500 bytes equals a public digest |
| `ca-p256-sha256-*`, `ca-p384-sha384-*` | A CA signature over a TBS: hash the private TBS bytes, verify the CA's signature over the digest under the CA's public key |
| `rsa{2048,3072}-pkcs1-sha256`, `rsa4096-pkcs1-sha384` | RSASSA-PKCS1-v1_5 verification of a given digest under a public modulus, exponent 65537 |
| `rsa{2048,3072,4096}-pss-sha256` | PS256 verification (RSASSA-PSS, SHA-256, MGF1-SHA-256, 32-byte salt) of a given digest under a private modulus, as the signer's key is in the statement |
| `ca-rsa2048-sha384-1500`, `ca-rsa4096-sha256-1500`, `ca-rsa4096-sha384-*` | A CA signature over a TBS with RSA PKCS#1 v1.5, as above |

414 bytes is the test PKI's signer TBS; 1,500 bytes stands for a larger real certificate (the current circuit's maximum).

**Shortcuts** (these are primitive benchmarks): no certificate parsing or field extraction, no chain or validity checks; hashes run over a length fixed at compile time, whereas a real circuit hashes a variable-length TBS up to a maximum (at about the cost of the maximum). Fresh keys and signatures each run, deterministic stand-in messages; neither affects cost. RSA: exponent 65537, key sizes that are multiples of 8 bits, and a 32-byte PSS salt only; the signature is not asserted below the modulus. RSA uses gnark's variable-modulus emulated arithmetic ([rsa.go](gnark/rsa.go)), with as many 64-bit limbs as the key, so one circuit serves every key of its size.

## Why gnark

Both curves must be measured in the same stack for the comparison to mean anything. In circom, the current circuit's ECDSA library (circom-ecdsa-p256) is specific to P-256 (field parameters and precomputed tables), and no SHA-384 is among the project's dependencies, so a P-384 measurement would first need a substantial port. gnark provides emulated ECDSA for both P-256 and P-384 and a 64-bit word API on which SHA-384 is about a hundred lines ([sha384.go](gnark/sha384.go)); gnark is also the leading second-stack candidate for [E6](../../README.md#e6-proof-systems). The circom baseline is related through its measured component counts.

## Running

Requires Go 1.27.3 or later (set in `go.mod`); Go downloads gnark on first build.

```bash
cd zk-proofs/experiments/e1-p384/gnark
go test -short .   # SHA-384 vs crypto/sha512; RSA-2048 verdicts vs crypto/rsa; the two 414-byte ECDSA CA circuits
go test .          # also: every circuit accepts its fixture and rejects a tampered one (under a minute)
go build -o e1bench .
./e1bench list
./e1bench all -out ../../../bench/results/<date>-e1-gnark.json        # all 20 circuits, ~25 min
./e1bench all ecdsa-p384 sha384-414                                    # a subset, to stdout
```

Each circuit runs in its own process, so its peak RSS is its own, but it is whole-run memory: the same process compiles the circuit, runs setup, proves, verifies, and compiles the PLONKish count. Prove time is resident-key proving: the proving key from setup stays in memory, so the time includes witness computation (solve) but no key loading. Neither is comparable with the per-asset accounting of the [benchmark harness](../../README.md#benchmarks). The record holds the environment, the shortcuts, notes on each step, and per circuit: R1CS constraints (and the PLONKish count, for E6), times for compile, setup, witness, solve, prove, and verify, proving key size (compressed and raw), verifying key and proof sizes, and peak RSS.
