# M0: The Signer-Side Baseline (frozen)

**M0, Milestone 0,** is the prototype's starting point: the signer, holding its key, replaces its own claim signature with a Groth16 proof (circom, arkworks) that a P-256 issuing CA certified a key that signed the asset's digest. It is kept frozen, so its results can be reproduced and compared, but no longer developed. Earlier documents and the benchmark records call it V0; the anonymizer still runs it unless given `--third-party`, and the harness selects it with `--variant v0`.

The current prototype is Milestone 1 ([MILESTONE-1.md](MILESTONE-1.md)): third-party anonymization of real content, in gnark. How the project moved from one to the other: [HISTORY.md](HISTORY.md); the two compared: [FEASIBILITY.md](FEASIBILITY.md#m0-baseline-measured-detail).

This document holds M0's reproduction steps, its statement and circuit, its build, placeholder mode, and testing, moved here unchanged from the README on 2026-11-13.

## Reproduction

The signer-side M0 baseline, kept so its results can be reproduced; for current use, see [Quick Start](README.md#quick-start-third-party-mode) above.

> **Prerequisites**: Complete the [Building Circuits](#building-circuits) setup before running these commands — you need the compiled circuit and trusted setup keys. For testing without that setup, see [Placeholder Mode](#placeholder-mode).

```bash
# Build
cargo build --release

# Generate a test PKI and trust lists in fixtures/pki (see Test PKI)
./generate-test-pki.sh

# 1. Sign an asset with standard X.509/ECDSA (x5chain: signer + issuing CA)
cargo run --release --bin c2pa-x509-zk-sign -- \
  --input fixtures/cards.png \
  --output /tmp/signed.png \
  --cert fixtures/pki/signer.pem \
  --key fixtures/pki/signer.key \
  --ca fixtures/pki/issuing-ca.pem

# 2. Anonymize: Replace signature with a Groth16 ZK proof
# This step is slow: ~10 minutes and ~12 GB of RAM (see Performance).
# --cert supplies the original signer cert DER so the circuit sees the exact
# bytes the CA signed (c2pa-rs may alter encoding when storing in the manifest).
cargo run --release --bin c2pa-x509-zk-anonymizer -- \
  --input /tmp/signed.png \
  --output /tmp/anon.png \
  --trust-list fixtures/pki/trust-list.json \
  --signer-key fixtures/pki/signer.key \
  --cert fixtures/pki/signer.pem

# 3. Verify the anonymized asset against a trust list (PEM or JSON)
cargo run --release --bin c2pa-x509-zk-verify -- \
  --input /tmp/anon.png \
  --trust-list fixtures/pki/trust-list.pem
```

## Cryptographic Details

The ZK approach uses a Groth16 zkSNARK to prove that the signer possesses a valid certificate issued by a trusted CA, without revealing which certificate. The primary circuit performs two P-256 ECDSA signature verifications plus in-circuit SHA-256 and UTCTime parsing (~4.8M constraints total). The proof cryptographically binds the signer's private key to a CA-issued certificate, and proves that the certificate was valid when the asset was anonymized.

### ZK Proof Statement

**Public inputs:**
- `caPubKeyX[6]`, `caPubKeyY[6]`: Trusted CA's P-256 public key (X, Y, each as 6 × 43-bit registers)
- `claimHash[6]`: Manifest-stripped asset digest SHA-256 (6 × 43-bit registers)
- `photoTimestamp`: Unix timestamp of when the asset was anonymized/processed

**Private inputs (witness):**
- `certDer[1500]`: Raw DER-encoded signer certificate bytes (zero-padded to 1500 bytes)
- `certLen`: Actual byte count of the certificate
- `tbsOffset`, `tbsLen`: Byte offset and declared length of the TBSCertificate DER field
- `spkiXOffset`: Byte offset of the 32-byte SPKI X coordinate within certDer
- `notBeforeOffset`, `notAfterOffset`: Byte offsets of the UTCTime fields within certDer
- `tbsHashPaddedLen`: Padded byte length of the TBS slice for SHA-256 (multiple of 64)
- `tbsHashPaddedBytes[1536]`: TBS DER bytes with SHA-256 padding appended, zero-filled to 1536
- `certSigR[6]`, `certSigS[6]`: CA's ECDSA signature over the TBSCertificate
- `claimSigR[6]`, `claimSigS[6]`: Signer's ECDSA signature over the manifest-stripped asset digest carried in `claimHash`

**Relations proved:**
1. `x509_parse.circom` extracts the TBSCertificate hash, the subject public key, and the validity period from `certDer` in-circuit. The public key and validity fields must carry their exact DER encoding and lie inside the TBSCertificate, the bytes the CA signed (see [Certificate field binding](#certificate-field-binding))
2. `caPubKeyX/Y` verifies the CA signature over the parsed TBSCertificate — the cert was issued by the trusted CA
3. The parsed subject public key verifies the signer's signature over `claimHash` — the prover holds the corresponding private key
4. `parser.notBefore ≤ photoTimestamp ≤ parser.notAfter` — the cert was valid when the asset was anonymized/processed (timestamps parsed in-circuit from certDer)

**Pending (required for production soundness):**
- RFC 5280 field validation (version, algorithm OID, key-usage extensions)
- A full DER walk of the TBSCertificate (see [Certificate field binding](#certificate-field-binding))
- Optional: revocation check via short-lived certs or an accumulator commitment

### Certificate field binding

The prover supplies the whole certificate buffer (`certDer`, 1500 bytes) and the byte offsets of the fields the circuit reads. Only the TBSCertificate slice of that buffer is covered by the CA's signature; everything else, including the space after the certificate, is under the prover's control. Each field the circuit uses must therefore be pinned inside the signed slice:

- **Subject public key:** the 27 bytes before `spkiXOffset` must be the DER encoding of a P-256 SubjectPublicKeyInfo (`30 59 30 13 06 07 2A8648CE3D0201 06 08 2A8648CE3D030107 03 42 00 04`), and the whole 91-byte field must lie within `[tbsOffset + 4, tbsOffset + 4 + tbsLen)`.
- **Validity:** a `30 1E` SEQUENCE header must precede `notBefore`, `notAfter` must immediately follow it, both UTCTimes must end in `Z`, and the whole 32-byte field must lie within the same range.
- **Offsets** are range-checked to 11 bits so the comparisons cannot wrap around the field, and the TBSCertificate must end within `certLen ≤ 1500`.

Earlier versions checked only the local tags (a `0x04` before the key, `17 0D` before each date) without tying them to the signed slice. A prover with no certificate could then append their own key and arbitrary validity dates after any genuine certificate from the CA and produce a proof that verified. `forged_key_outside_signed_tbs_is_rejected` in the integration tests replays that attack.

Remaining limitation: this is not a full DER walk of the TBSCertificate. A byte sequence matching the SPKI or Validity encoding inside another TBS field (for example, an extension) would also be accepted; exploiting that requires the CA to have signed a certificate containing such content. A full walk is part of [H2](README.md#h2-full-certificate-validation-in-the-circuit).

The placement checks and the in-circuit date conversion (`UTCTimeToUnix`) have fast tests (a few seconds, needs `circom` and `node`):

```bash
python3 circuits/test/test_placement.py
```

The in-circuit SHA-256 is implemented via `Sha256Bytes(1536)` from `@zk-email/circuits`.  The prover supplies `tbsHashPaddedBytes[1536]` (the TBS DER bytes with standard SHA-256 padding) and the circuit verifies that the first `4+tbsLen` bytes match `certDer[tbsOffset..]`, then hashes the buffer in-circuit and feeds the result into the CA ECDSA check.

### Constraint Count

The compiled circuit has **4,776,263 constraints** (reported by `circom` and recorded in the `.r1cs` header). Each component below was measured by compiling it on its own:

| Component | Constraints |
|---|-----------|
| `ECDSAVerifyNoPubkeyCheck` × 2 (Steps 2 + 4) | 3,945,810 |
| `Sha256Bytes(1536)` | 758,254 |
| TBS view: `VarShiftLeft(1536, 1536)` | 16,907 |
| TBS binding: 1536 × `LessEqThan` + products | ~21,500 |
| SPKI window: `P256SpkiInRegion(1500)` | 16,547 |
| Validity window: `ValidityInRegion(1500)` | 16,547 |
| Register packing, UTCTime parsing, offset and validity range checks | ~760 |
| **Total** | **4,776,263** |

The two ECDSA verifications are now over 80% of the circuit; see [Efficient ECDSA](#efficient-ecdsa) and the [cryptographic improvements](#cryptographic-improvements) for ways to reduce them.

Variable-index byte reads use `VarShiftLeft` windows from `@zk-email/circuits`, which cost about log2(n) × n constraints for an n-byte buffer regardless of window size. An earlier version read each byte through a per-byte multiplexer (`SelectByte`, ~4,500 constraints per read); with 1,662 such reads, the circuit had 12,208,271 constraints.

For a production multi-party trusted setup (MPC ceremony) this circuit class would require a **2²³** (~8.4M) Powers of Tau file.  **For this demo no ptau download is needed** — `ark-groth16` performs a local single-party setup directly from the `.r1cs` file.

### Potential Optimisations

A note on proof size before listing the ideas: a Groth16 proof over BN254 is ~128 bytes (3 G1 + 1 G2, compressed) regardless of circuit size, so the headline "~1 KB" figure is dominated by serialization and public inputs rather than the SNARK itself. Shrinking the wire-format proof is mostly a public-input problem; shrinking proving time is where the cryptographic wins are.

The first two items below are circuit-level tweaks that keep the current proof statement intact (the first is done). The remaining items are deeper changes that restructure what is proved, switch the proof system, or compress public inputs.

#### TBS binding ✅

Done: the per-byte `SelectByte` reads (TBS binding, SPKI, and Validity) were replaced with `VarShiftLeft` windows from `@zk-email/circuits/utils/array.circom`, taking the circuit from 12,208,271 to 4,776,263 constraints (-61%). See [Cheaper byte reads](#the-cheaper-byte-reads-an-m0-optimization).

#### Efficient ECDSA

The **Efficient ECDSA** technique (sometimes called the "NOPE" circuit, from [Personae Labs](https://personaelabs.org/posts/efficient-ecdsa-1/)) eliminates the fixed-base G scalar multiplication from signature verification by computing it off-circuit and supplying the result as a witness T. This would reduce each `ECDSAVerifyNoPubkeyCheck` (~1.3M constraints) to roughly ~700K constraints.

#### Cryptographic improvements

These restructure the protocol rather than the circuit. They generally trade an assumption (CA cooperation, an out-of-band trust artefact, or a different proof system) for a substantially smaller and/or faster proof. Constraint savings below are relative to the 4,776,263-constraint circuit.

##### CA-published accumulator of issued SPKIs

Replace the in-circuit CA signature verification with a Merkle membership proof against a CA-published accumulator over currently-valid subject public keys. The CA periodically publishes a signed root; the ZK proof becomes "the committed SPKI is a leaf under that root, and the prover holds its private key." This eliminates the CA ECDSA verification (~1.97M), the SHA-256 over TBS (~760K), and the TBS view and binding (~40K) — together more than half the circuit. RFC 5280 field validity (`notBefore`, `notAfter`, EKU, key usage) is enforced by the CA at root-publication time rather than in-circuit, and revocation reduces to "drop the leaf from the next root." Trade-off: verifiers must fetch a fresh signed root, and the anonymity set becomes "valid at root time" rather than "ever issued."

##### Sigma-protocol key possession bound to the SNARK

Move part of the second P-256 ECDSA verification (the prover's "key possession" check, ~1.97M constraints) out of the SNARK. The SNARK outputs a commitment to the signer's public key, and outside the SNARK the signer proves knowledge of the matching secret key with a Schnorr-style proof, Fiat–Shamir-bound to the claim. The proof is ~64–96 bytes and verifies in microseconds.

The commitment must live in a group where that proof works. Committing on a SNARK-friendly curve such as Baby Jubjub would need a proof linking two different curves, which is complex. The straightforward variant commits on P-256 itself (`C = pk + r·H`) and proves knowledge of `(sk, r)` with `C = sk·G + r·H`, but the circuit then still computes one P-256 fixed-base multiplication. Expected saving: roughly half of one in-circuit ECDSA verification, not all of it (see [D5](ARCHITECTURE-DECISIONS.md#d5-how-key-possession-is-proved)). Composes with the accumulator approach above.

##### Issuer-side SNARK-friendly credential ("twin signature")

In addition to the standard X.509/ECDSA certificate, have the CA sign each issued SPKI under a SNARK-friendly scheme — for example EdDSA over Baby Jubjub (≈4K constraints to verify), or a Pointcheval–Sanders / BBS-style structure-preserving signature. The X.509 cert is preserved unchanged for C2PA compatibility; the ZK proof only verifies the SNARK-friendly credential. Trade-off: the CA publishes one extra signed blob per cert, but proving cost can drop by an order of magnitude or more because no in-circuit ECDSA-over-non-native-field is required.

##### PLONKish proof system with native-field P-256 chips

The dominant cost driver today is P-256 arithmetic emulated over BN254's scalar field — every multiplication is a non-native big-int operation. Migrating to a PLONKish system (e.g. Halo2 with the 0xPARC P-256 chip, or `halo2_ecc`) provides lookup-table-accelerated SHA-256 and field operations sized for ECDSA. Public benchmarks for ECDSA-in-Halo2 versus ECDSA-in-Circom/Groth16 typically report 5–20× proving-time improvements. Trade-off: proofs grow to a few KB, verification is slower (still well under a second), and the universal Groth16 verifier is replaced. Can be combined with a Groth16 wrapper to recover constant-size proofs.

##### Folding schemes with a final Groth16 wrapper

Fold per-step costs (each ECDSA scalar-multiplication round, or the verification across many photos) using Nova / HyperNova / ProtoStar, then compress the final IVC instance with a Groth16 wrapper to recover a constant-size SNARK proof. Proving is dominated by the folding step, which is linear and FFT-free; the wrapper proof remains small and verifier-friendly. Particularly attractive when a single signer expects to anonymize many photos and the cost amortizes across them.

##### Public-input compression

Today the public inputs are `caPubKeyX[6] + caPubKeyY[6] + claimHash[6] + photoTimestamp`. Hashing these in-circuit to a single field element and publishing only the digest (with the cleartext public inputs carried alongside the proof container) brings the on-wire proof close to the Groth16 floor of ~128 bytes. This is the single change that most affects the headline "~1 KB" figure.

##### Pairing-curve choice

Switching the proving curve from BN254 to BLS12-381 raises the conjectured security margin from ~100 bits (post Kim–Barbulescu) toward ~120 bits. Proof size grows modestly (~192 bytes) and proving slows somewhat. Not a performance win, but worth considering for production soundness.

### Circuit Architecture

```
circuits/
├── x509_issue_and_possession.circom  # Main proof circuit (used by Rust prover)
│   ├── x509_parse.circom             # X.509 DER parser (fully implemented)
│   └── circom-ecdsa-p256/            # P-256 ECDSA verification (×2)
│       ├── ecdsa.circom              # ECDSAVerifyNoPubkeyCheck
│       ├── p256.circom               # Curve operations
│       └── bigint arithmetic         # 256-bit register arithmetic
│
└── x509_parse.circom                 # X.509 DER parser — X509Parse, field-placement checks
```

`x509_issue_and_possession.circom` is the sole proof circuit. It accepts the raw DER
certificate bytes and parses them in-circuit via `x509_parse.circom`, which pins the
subject public key and the validity period inside the TBSCertificate the CA signed (see
[Certificate field binding](#certificate-field-binding)). This prevents a prover from
pairing someone else's CA-signed certificate with their own key pair.

### Circuit Statistics

| Metric | Value | Notes |
|--------|-------|-------|
| Constraints | **4,776,263** (measured) | Two ECDSA verifs (3.95M) + SHA-256 (758K) + TBS view/binding (~38K) + field windows (~33K) + parsing |
| Constraints (with Efficient ECDSA for Step 4) | ~4,180,000 (estimated) | See optimisation note above — soundness caveat applies |
| Proving key size | ~1.0 GB (measured) | Native Rust key generated by `ark-groth16` from `.r1cs` |
| Verifying key size | 872 bytes (measured) | Constant for Groth16 |
| Proof size | ~1 KB | Constant for Groth16 |
| Production ceremony class | pot23 (~8.4M constraints) | Not needed for this demo — `ark-groth16` runs local setup |

### Performance

Measured with the [benchmark harness](README.md#benchmarks) on a 13th Gen Intel Core i7-13800H laptop (20 logical CPUs, 32 GB of RAM, WSL2); full record in [`bench/results/2026-11-03-baseline.json`](bench/results/2026-11-03-baseline.json) and analysis in [FEASIBILITY.md](FEASIBILITY.md#m0-baseline-measured-detail). Each phase ran in its own process.

| Phase | Time | Peak RSS | Notes |
|-------|------|----------|-------|
| Circuit compilation | ~3.4 min | ~6.0 GiB | One-time (`circom`) |
| Trusted setup | ~49 s | ~9.9 GiB | One-time, native Rust |
| Preparation | ~0.03 s | ~19 MiB | Per asset: read the signed manifest, validate the issuing chain, build the circuit inputs |
| Witness generation | ~3.8 min | ~4.0 GiB | Per asset; almost all of it running the circuit's WASM witness generator |
| Proving | ~6.3 min | ~11.1 GiB | Per asset; **~5.8 min of it is loading the 1 GB proving key** (stored compressed and fully validated on load); the Groth16 proof itself takes ~32 s |
| Packaging | ~0.03 s | ~23 MiB | Per asset: build the assertion, rewrite the manifest, check the digest |
| Verification | ~0.01 s | ~9 MiB | Per asset; the full verifier CLI (with trust-list chain validation) takes ~0.02 s |

Anonymizing one asset takes ~10.2 minutes, of which the cryptographic proving is about 5%: key deserialization (57%) and WASM witness generation (37%) dominate. Peak memory is ~11 GiB, while loading the proving key, so a 16 GB machine should be enough (not tested). Use [Placeholder Mode](#placeholder-mode) on smaller machines.

### COSE Integration

- Custom algorithm: `alg = -65538`, in the COSE private-use range (below -65536)
- Critical header: `crit = ["c2pa-x509-zk"]` (COSE header label 2), so verifiers that don't understand the extension must reject the signature
- Extension map with circuit metadata
- Padding: a `pad` byte string in the unprotected header fills the space `c2pa-rs` reserves for the signature, as `c2pa-rs` does for its own signatures
- The `x509-zk-signer-proof` assertion (version 0.2) carries the issuer name and key ID, the asset digest, the proof, the circuit ID and backend, and the SHA-256 of the circuit and verifying key used (diagnostics; version 0.1 assertions without them are still accepted).
- `x5chain` (in the protected header) carries the issuing CA chain only: the issuing CA first, then any further intermediates, never the signer's certificate, which would reveal the identity the proof hides (decision [D4](ARCHITECTURE-DECISIONS.md#d4-where-the-issuing-ca-chain-lives-decided)). Thanks to Iman Attia (EBU) for reporting the earlier leak of the signer's certificate ([#6](https://github.com/christianpaquin/c2pa-signer-privacy/issues/6)).

## Building Circuits

### 1. Compile circuit and run trusted setup

```bash
# All commands run from the zk-proofs/ directory

# Initialize submodules (if not already done)
git submodule update --init --recursive

# Install circuit JS dependencies (circomlib, circom-ecdsa-p256 deps)
npm install --prefix circuits

# Compile circuit (will run for a while, produces .r1cs and .wasm)
mkdir -p circuits/build
circom circuits/x509_issue_and_possession.circom \
  --r1cs --wasm --sym \
  -l circuits \
  -l circuits/node_modules \
  -o circuits/build/

# Run trusted setup (~1 minute, ~10 GB RAM) — generates proving and verifying keys
# Must run from zk-proofs/, not circuits/
cargo run --release --bin c2pa-x509-zk-setup -- --circuits-dir circuits
```

This generates the proving and verifying keys in `circuits/build/`.

> **Note**: The native Rust prover (`ark-groth16`) generates its own circuit-specific keys
> directly from the compiled `.r1cs` + `.wasm` files using a local random seed.  No
> external Powers of Tau ceremony file is needed — `ark-groth16::generate_random_parameters_with_reduction`
> handles the setup in one pass.
>
> Setup writes a build manifest next to the keys (`*_native.build.json`: circuit name,
> SHA-256 of the `.r1cs`, SHA-256 of the verifying key). If the circuit has been
> recompiled since, setup refuses to reuse the keys and the anonymizer refuses to prove
> with them, instead of producing a proof that cannot verify. Re-run setup with
> `--force` to regenerate the keys.
>
> Keys are generated locally by setup and never committed (the verifying keys were until #47).
>
> Verification needs only the verifying key (`*_native.vk`), not the proving key or the
> `.r1cs`. The anonymizer records the circuit and verifying-key hashes in the assertion;
> the verifier compares them with its own keys as a diagnostic only, never selects keys
> from what the asset says, and Groth16 verification decides validity.

## Placeholder Mode

If you haven't completed the circuit setup, the anonymizer can embed a placeholder proof instead of a real ZK proof. This lets you exercise the full manifest pipeline — sign, anonymize, verify — immediately after `cargo build`, without circuit compilation (~4 min), trusted setup (~1 min), or ~10-minute proof generation, and without needing ~12 GB of RAM.

The verifier will detect a placeholder and exit with a non-zero status (exit code 2) along with a warning. This is intentional: placeholder mode is for development and structural testing only.

```bash
cargo build --release

# 1. Sign
./generate-test-pki.sh

cargo run --release --bin c2pa-x509-zk-sign -- \
  --input fixtures/cards.png \
  --output /tmp/signed.png \
  --cert fixtures/pki/signer.pem \
  --key fixtures/pki/signer.key \
  --ca fixtures/pki/issuing-ca.pem

# 2. Anonymize with placeholder proof (no circuit setup required)
cargo run --release --bin c2pa-x509-zk-anonymizer -- \
  --input /tmp/signed.png \
  --output /tmp/anon.png \
  --trust-list fixtures/pki/trust-list.json \
  --placeholder

# 3. Verify (will print a placeholder warning — expected)
cargo run --release --bin c2pa-x509-zk-verify -- \
  --input /tmp/anon.png \
  --trust-list fixtures/pki/trust-list.pem

# The integration test suite also runs in placeholder mode:
cargo test --release
```

## Testing (M0)

Tests run at three layers:

| Layer | Command | Needs | What it covers |
|---|---|---|---|
| Circuit templates | `python3 circuits/test/test_placement.py` | `circom`, `node` | Accept and reject cases for the certificate-placement and date-conversion templates, at the constraint level (seconds) |
| Rust unit and integration | `cargo test --release` | — | Trust lists and chain validation, COSE encoding, CLI flows in placeholder mode, the witness check and setup manifest on a one-constraint fixture circuit, privacy scans |
| Real proofs | `cargo test --release -- --ignored` | Built circuit and keys, ~12 GB of RAM | End-to-end proof and verification; the field-binding forgery, rejected both before proving and at verification |

Conventions:

- **Every statement ships with must-reject tests at two layers:** the constraint level (the forged input is rejected by the circuit's constraints, with the prover's witness check reporting `WitnessRejected`) and the proof level (with the witness check turned off, the forged proof fails verification, which is what a verifier relies on).
- **Assert the rejection category, not incidental wording:** a typed error or a stable diagnostic of our own, never a compiler- or library-generated message.
- **Fixes come with their reproduction as a regression test,** confirmed to fail without the fix.
- **Every anonymized output is privacy-scanned** (`assert_no_signer_identifiers` in the integration tests): no signer certificate, public key, serial number, or subject DN, and no trace of the original manifest. This catches regressions of known identifiers; it does not prove anonymity, since identifiers can be re-encoded or hashed and content can be correlated in other ways (see [E2a](README.md#e2a-third-party-proof-statement-and-privacy-design)).

The prover checks every witness against the circuit's R1CS constraints before proving, because ark-circom's witness generator does not stop on a failing `===` (its exception handler is a no-op, whether or not `sanity_check` is set). Without that check, an input the circuit rejects still yields a proof that only fails verification. The prover computes the witness without ark-circom's `CircomBuilder::build`, whose debug-build assertion would panic on a rejected input before the check can report it, so the behavior is the same in debug and release builds. The check evaluates constraints exactly as Arkworks does when proving (wire 0 is the constant one), and rejects a witness whose constant entry is not 1; tests compare its verdicts with Arkworks' own constraint system on adversarial witnesses.

## The cheaper byte reads (an M0 optimization)



Done. Measuring each component showed that per-byte `SelectByte` reads (1,662 of them, ~4,500 constraints each) made up ~7.5M of the 12.2M constraints, far more than the earlier estimates suggested. All of them (TBS binding, SPKI, and Validity) now read through `VarShiftLeft` windows, without changing what the circuit proves:

| | Before | After |
|---|---|---|
| Constraints | 12,208,271 | 4,776,263 (-61%) |
| Circuit compilation | ~15 min, ~25 GB | ~4 min, ~6.3 GB |
| Trusted setup | ~2.5-6.5 min, ~24 GB | ~1 min, ~10.4 GB |
| Anonymization | ~20 min, ~28 GB | ~10.5 min, ~11.8 GB |
| Proving key | 2.5 GB | 1.0 GB |

Setup now also records a hash of the `.r1cs` alongside the keys, and setup and the anonymizer refuse keys from an older circuit (see [Building Circuits](#building-circuits)).

## Benchmarks (M0)

The harness's default variant, `--variant v0`, measures M0 (`--reuse-build` links `circuits/build`'s compiled circuit instead of compiling it; compilation is then not measured). Every phase runs as a separate process, so its wall time and peak memory (`wait4`'s peak RSS for that process) are its own; steps within a phase, such as loading the proving key or serializing the witness, are timed separately so no cost falls between phases. Phases are grouped into categories, and the record carries their totals:

| Category | Phases | Total |
|---|---|---|
| Test fixture | Generate the test PKI, sign the sample asset | Not counted |
| One-time | Compile the circuit, Groth16 setup | `one_time` |
| Anonymization (per asset) | Prepare (read the signed manifest, validate the issuing chain, build circuit inputs), witness, prove, package (build the assertion, rewrite the manifest, check the digest) | `anonymization_per_asset`, with `anonymization_witness_plus_prove` as the proof-generation subtotal |
| Verification | Load and prepare the verifying key, verify the proof | `verification` |
| Full verification | The verifier CLI on the anonymized asset (trust-list chain validation, assertion and digest checks, the proof) | `verification_full` |

The harness works in a directory it creates itself, a new one under `target/bench` by default, with its own compiled circuit and keys; `circuits/build` is not touched. A requested `--work-dir` must not exist, and only the directory the run created is removed afterwards.

The record contains the variant and the exact statement proved, the accounting boundaries above, the environment at the start of the run (CPU, memory, OS, WSL, rustc, circom, git commit and any changed tracked files), artifact hashes and sizes, input sizes, per-phase and per-step measurements with category totals, and output sizes: the Groth16 proof, the embedded proof container, the assertion, `x5chain`, and the whole manifest store added to the asset. A full run takes ~15 minutes and ~11 GiB of RAM. Results are compared in [FEASIBILITY.md](FEASIBILITY.md).

`run --proving-key CONFIG` selects how setup writes the proving key and how the prove phase loads it (by default, compressed and fully checked by arkworks, as the prover does). `c2pa-x509-zk-bench pk-load [--key KEY] [--reps N] [--only CONFIG]...` compares these configurations on their own: it converts a setup key to both encodings, then loads each configuration in its own process, first with the key evicted from the page cache, then warm. Results and a proposal are in [FEASIBILITY.md](FEASIBILITY.md#proving-key-loading).

## Toolchain (M0)

| Component | Tool | Version |
|-----------|------|---------|
| Circuit language | Circom | 2.1+ |
| Proving system | Groth16 on BN254 | — |
| Rust prover | ark-circom + ark-groth16 | 0.5 |
| Powers of Tau | Not needed — `ark-groth16` generates keys locally | — |
