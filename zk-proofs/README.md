# X.509 Zero-Knowledge Anonymizer for C2PA

This project implements privacy-preserving signatures for C2PA manifests using zero-knowledge proofs. It replaces an existing X.509/COSE signature with a ZK proof that the asset was signed by a certificate issued by a trusted CA, without revealing the signer's identity.

## Overview

This approach keeps standard X.509/ECDSA-P256 signing, then adds a post-processing step that:
- Extracts the original signature and certificate chain
- Generates a Groth16 ZK proof demonstrating valid CA issuance
- Replaces the manifest signature with the proof

The verifier can confirm the asset was anonymized from an asset signed by *someone* with a certificate from the trusted CA, without learning *who*.

## Quick Start

> **Prerequisites**: Complete the [Building Circuits](#building-circuits) setup before running these commands — you need the compiled circuit and trusted setup keys. For testing without that setup, see [Placeholder Mode](#placeholder-mode).

```bash
# Build
cargo build --release

# 1. Sign an asset with standard X.509/ECDSA
cargo run --release --bin c2pa-x509-zk-sign -- \
  --input fixtures/cards.png \
  --output /tmp/signed.png \
  --cert fixtures/certs/signer-cert.pem \
  --key fixtures/certs/signer-key.pem \
  --ca fixtures/certs/ca-cert.pem

# 2. Anonymize: Replace signature with a Groth16 ZK proof
# This step is slow: ~10 minutes and ~12 GB of RAM (see Performance).
# --cert supplies the original signer cert DER so the circuit sees the exact
# bytes the CA signed (c2pa-rs may alter encoding when storing in the manifest).
cargo run --release --bin c2pa-x509-zk-anonymizer -- \
  --input /tmp/signed.png \
  --output /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem \
  --signer-key fixtures/certs/signer-key.pem \
  --cert fixtures/certs/signer-cert.pem

# 3. Verify the anonymized asset
cargo run --release --bin c2pa-x509-zk-verify -- \
  --input /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem
```

## CLI Tools

| Binary | Description |
|--------|-------------|
| `c2pa-x509-zk-sign` | Create standard C2PA signed assets (ES256/P-256) |
| `c2pa-x509-zk-anonymizer` | Anonymize signed assets by replacing COSE signature with ZK proof |
| `c2pa-x509-zk-verify` | Verify anonymized assets against trusted CA |

## Project Structure

```
zk-proofs/
├── circuits/                       # Circom ZK circuits
│   ├── x509_issue_and_possession.circom  # Main proof circuit
│   ├── x509_parse.circom           # X.509 DER parser (X509Parse, field-placement checks)
│   ├── circom-ecdsa-p256/          # P-256 ECDSA verification library
│   └── build/                      # Compiled circuits and keys
├── crates/
│   └── c2pa-x509-zk-demo/          # Rust library + CLIs
└── fixtures/
    ├── cards.png                   # Test input image
    └── certs/                      # Test certificates
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

Remaining limitation: this is not a full DER walk of the TBSCertificate. A byte sequence matching the SPKI or Validity encoding inside another TBS field (for example, an extension) would also be accepted; exploiting that requires the CA to have signed a certificate containing such content. A full walk is part of [H2](#h2-full-certificate-validation-in-the-circuit).

The placement checks have fast tests (a few seconds, needs `circom` and `node`):

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

Done: the per-byte `SelectByte` reads (TBS binding, SPKI, and Validity) were replaced with `VarShiftLeft` windows from `@zk-email/circuits/utils/array.circom`, taking the circuit from 12,208,271 to 4,776,263 constraints (-61%). See [Cheaper byte reads](#cheaper-byte-reads-).

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

Measured on a 20-core machine with 31 GB of RAM (WSL2). Expect different times on other hardware, but similar memory use.

| Phase | Time | Peak RAM | Notes |
|-------|------|----------|-------|
| Circuit compilation | ~4 min | ~6.3 GB | One-time (`circom`) |
| Trusted setup | ~1 min | ~10.4 GB | One-time, native Rust |
| Anonymization (witness + proof) | ~10.5 min | ~11.8 GB | Per asset; witness generation runs the circuit's WASM |
| Verification | ~0.02 s | ~13 MB | Per asset |

Peak memory for the real-proof flow is ~12 GB, so a 16 GB machine should be enough (not tested). Use [Placeholder Mode](#placeholder-mode) on smaller machines.

Constraints fell 61% with the switch to `VarShiftLeft` (see [Constraint Count](#constraint-count)), but anonymization time fell only ~50% (from ~20 minutes), which suggests WASM witness generation is a large share of proving time.

### COSE Integration

- Custom algorithm: `alg = -65538`, in the COSE private-use range (below -65536)
- Critical header: `crit = ["c2pa-x509-zk"]` (COSE header label 2), so verifiers that don't understand the extension must reject the signature
- Extension map with circuit metadata
- Padding: a `pad` byte string in the unprotected header fills the space `c2pa-rs` reserves for the signature, as `c2pa-rs` does for its own signatures
- No `x5chain`: the anonymized output carries no certificates. Embedding the signer's leaf certificate would reveal the identity the proof hides, and the verifier supplies the trusted CA certificate itself (`--ca`). Thanks to Iman Attia (EBU) for reporting the earlier leak ([#6](https://github.com/christianpaquin/c2pa-signer-privacy/issues/6)).

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
> Setup records a SHA-256 of the `.r1cs` next to the keys (`*_native.r1cs.sha256`).
> If the circuit has been recompiled since, setup refuses to reuse the keys and the
> anonymizer refuses to prove with them, instead of producing a proof that cannot
> verify. Re-run setup with `--force` to regenerate the keys.

## Certificate Requirements

Certificates must use:
- **P-256 ECDSA** (secp256r1 / prime256v1)
- **Document Signing EKU** (1.3.6.1.5.5.7.3.36) for C2PA compatibility

Production C2PA certificates use the C2PA claim-signing EKU (`1.3.6.1.4.1.62558.2.1`) instead, and real CAs sign with P-384 or RSA rather than P-256 (see [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md)). [F1](#f1-c2pa-like-test-pki-and-trust-lists) moves the test PKI closer to that.

Generate test certificates and a signed test asset:
```bash
./generate-test-assets.sh
```

> **Note**: To create a signed test asset, `c2patool` must be installed. See the [c2patool documentation](https://github.com/contentauth/c2pa-rs/blob/main/cli/README.md) for details.

## Placeholder Mode

If you haven't completed the circuit setup, the anonymizer can embed a placeholder proof instead of a real ZK proof. This lets you exercise the full manifest pipeline — sign, anonymize, verify — immediately after `cargo build`, without circuit compilation (~4 min), trusted setup (~1 min), or ~10-minute proof generation, and without needing ~12 GB of RAM.

The verifier will detect a placeholder and exit with a non-zero status (exit code 2) along with a warning. This is intentional: placeholder mode is for development and structural testing only.

```bash
cargo build --release

# 1. Sign
cargo run --release --bin c2pa-x509-zk-sign -- \
  --input fixtures/cards.png \
  --output /tmp/signed.png \
  --cert fixtures/certs/signer-cert.pem \
  --key fixtures/certs/signer-key.pem \
  --ca fixtures/certs/ca-cert.pem

# 2. Anonymize with placeholder proof (no circuit setup required)
cargo run --release --bin c2pa-x509-zk-anonymizer -- \
  --input /tmp/signed.png \
  --output /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem \
  --signer-key fixtures/certs/signer-key.pem \
  --placeholder

# 3. Verify (will print a placeholder warning — expected)
cargo run --release --bin c2pa-x509-zk-verify -- \
  --input /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem

# The integration test suite also runs in placeholder mode:
cargo test --release
```

## Roadmap

The prototype is a feasibility study with two goals, set out in [ARCHITECTURE-DECISIONS.md](ARCHITECTURE-DECISIONS.md#goals): (1) prove the technology and compare the options, and (2) determine which options could work today given current C2PA deployments ([DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md)). Items have stable IDs; each is planned as its own PR, roughly in the order listed.

### Done

- **Signer certificate removed from anonymized output** ([#6](https://github.com/christianpaquin/c2pa-signer-privacy/issues/6)).
- **Certificate field binding:** the circuit pins the signer key and validity period inside the CA-signed TBSCertificate; previously a prover with no certificate could forge a proof (see [Certificate field binding](#certificate-field-binding)).

#### Standards-conformant COSE encoding ✅


Done for both prototypes. The COSE structures previously could not be parsed by strict COSE parsers, including the one in `c2pa-rs`:

- The algorithm identifiers were not in the COSE private-use range: `-65534` is registered by IANA as `A128CTR`, and the BBS prototype's `-65535` as `RS1`. They are now `-65538` (ZK) and `-65537` (BBS).
- `crit` was written under the text label `"crit"` rather than COSE header label 2, so nothing was actually marked critical.
- The structure was padded with trailing zero bytes. Padding is now a `pad` field in the unprotected header, as `c2pa-rs` does.

Result: `c2patool` now displays BBS-signed assets and reports `algorithm.unsupported`, the correct outcome for a custom algorithm. ZK-anonymized assets still fail in `c2patool`'s default (validating) mode, now with "could not find signing certificate chain": `c2pa-rs` treats a missing signing certificate as a fatal error rather than a validation failure (`get_signing_cert_serial_num` in `claim_verify.rs`). With verification disabled, `c2patool` displays the manifest. See [H8](#h8-c2patool-support).

Both prototypes' manifests also lack a `c2pa.created` action, which `c2patool` reports as `assertion.action.malformed`; to be fixed with [E2](#e2-anonymization-mode-signer-side-vs-third-party).

#### Cheaper byte reads ✅


Done. Measuring each component showed that per-byte `SelectByte` reads (1,662 of them, ~4,500 constraints each) made up ~7.5M of the 12.2M constraints, far more than the earlier estimates suggested. All of them (TBS binding, SPKI, and Validity) now read through `VarShiftLeft` windows, without changing what the circuit proves:

| | Before | After |
|---|---|---|
| Constraints | 12,208,271 | 4,776,263 (-61%) |
| Circuit compilation | ~15 min, ~25 GB | ~4 min, ~6.3 GB |
| Trusted setup | ~2.5-6.5 min, ~24 GB | ~1 min, ~10.4 GB |
| Anonymization | ~20 min, ~28 GB | ~10.5 min, ~11.8 GB |
| Proving key | 2.5 GB | 1.0 GB |

Setup now also records a hash of the `.r1cs` alongside the keys, and setup and the anonymizer refuse keys from an older circuit (see [Building Circuits](#building-circuits)).

### Foundation

#### F1. C2PA-like test PKI and trust lists

A test setup that mimics a real C2PA deployment, kept on P-256 for speed, modelled on the Pixel chain ([DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#real-signed-assets)):

- Root → issuing CA (`pathlen:0`, itself a trust anchor) → signer certificate with the C2PA claim-signing EKU and a ~90-day lifetime, generated at test time rather than committed.
- Trust lists loaded in the official formats (PEM and the JSON list of trusted entities), with test anchors.
- Decision D4: the anonymized asset's `x5chain` carries the issuing chain, never the signer's certificate; the verifier validates it against the trust list and checks the issuing CA's key against the proof's public inputs.
- `issuer_key_id` becomes a stable identifier (hash of the CA's SPKI, or its Subject Key Identifier), so it survives CA certificate renewal.

Privacy note: the issuing CA is disclosed, so the anonymity set is everyone that CA has issued certificates to. A narrowly scoped CA can nearly identify the signer (see [H4](#h4-hiding-the-issuing-ca)).

#### F2. Benchmark harness

One command that records, for each variant, constraints, proving time, peak memory, proof size, and verifying-key size from a fixed set of inputs, so experiments are comparable.

### Goal 1: prove the technology and compare the options

#### E1. Cost of reality: P-384, SHA-384, and RSA in-circuit

Standalone benchmarks of the primitives real deployments use, next to today's P-256 + SHA-256: P-384 ECDSA with SHA-384 (the official list's CAs), RSA-2048 and RSA-4096 with PKCS#1 v1.5 and PSS (RSA CAs and PS256 signers), and optionally P-521. This prices trust model A against the real trust list without building every variant end to end, and feeds the choice of proof system (E6).

#### E2. Anonymization mode: signer-side vs third-party

Decision D6. Add third-party mode: the circuit verifies the original COSE signature over the original claim (hashing the serialized claim in-circuit), so no private key is needed and the proof covers every assertion in the original claim. Compare with today's signer-side mode, which re-signs a digest of the asset bytes only; that mode should also bind to a claim rather than the manifest-stripped asset digest, so the rest of the manifest is authenticated. Both prototypes' manifests also need a `c2pa.created` action.

#### E3. Trust model B: Merkle membership

Decision D1, option B, under the registration model: an entity validates a signer's chain against the trust list and adds the signer key to a Merkle tree with a signed, published root; the circuit proves membership instead of verifying a CA signature.

#### E4. Trust model C: SNARK-friendly credential

Decision D1, option C: the registration entity issues a SNARK-friendly credential (for example EdDSA over Baby Jubjub) over the signer key and chosen attributes; the circuit verifies that credential instead of the X.509 chain.

#### E5. Key possession

Decision D5: in-circuit ECDSA (today) against a P-256 commitment with a Schnorr-style proof outside the circuit.

#### E6. Proof systems

Decision D2, cheapest first: native (C++) witness generation for the current circuit; a PLONK-family prover on the same R1CS; then a rewrite in a second stack (gnark is the leading candidate, since it could also cover P-384 CAs; Halo2 and Longfellow ZK are alternatives).

#### E7. Curve: BN254 vs BLS12-381

Decision D3: the same circuit and prover on both curves, comparing proving time, memory, and proof size against the security margin (~100 vs ~120 bits).

### Goal 2: what works today

#### R1. Feasibility matrix

For each deployment segment (official trust list; interim anchors; interim allowed list), which options work, at what measured cost, who must run what, and what remains unknown.

#### R2. Anonymizing a real Pixel photo

Third-party anonymization (E2) of a real Pixel photo, proving issuance by Google's listed P-384 issuing CA (E1). An end-to-end demonstration that the approach works on content signed today.

#### R3. Interim-list allowed signers via Merkle membership

The interim list trusts specific end-entity certificates directly; trust model B (E3) over that published set needs no CA or registration step. Most of those signers use RSA keys with PS256, so this depends on the RSA costs from E1.

### Hardening

Applies to whichever options the experiments favour.

#### H1. Meaningful timestamps

The `photoTimestamp` public input is chosen by the prover and ignored by the verifier, so a proof shows only that the certificate was valid at *some* time the prover picked, which an expired certificate can satisfy. The verifier should enforce a policy (for example, "within N hours of now" at anonymization time), and the timestamp should be anchored to an RFC 3161 time-stamp authority rather than self-reported. In third-party mode, the original claim's timestamp could serve.

#### H2. Full certificate validation in the circuit

Complete the RFC 5280 / C2PA certificate-profile checks listed under [Pending](#zk-proof-statement): certificate version, signature algorithm OID, key usage, `CA:FALSE`, and an EKU from the set real certificates carry (C2PA claim signing, document signing, email protection, and others; see [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#interim-trust-list-pre-conformance)). This includes walking the TBSCertificate's DER structure in-circuit, so the public key and validity fields are located by structure rather than by matching their encoding (see [Certificate field binding](#certificate-field-binding)). Trust models B and C move most of this to the registration entity.

#### H3. Revocation

Support revoked or compromised signer keys, through short-lived certificates (as Pixel already uses) or through Merkle roots that drop revoked keys (trust model B).

#### H4. Hiding the issuing CA

As the blog post suggests, prove membership of the issuing CA's key in a published set of trusted CAs (for example, a Merkle root over a trust list) instead of disclosing which CA issued the certificate. Trust models B and C can achieve this directly by spanning every listed CA.

#### H5. Production proving setup

Replace the single-party local setup with a multi-party ceremony, or adopt a proof system without a circuit-specific trusted setup (E6). The remaining [optimisations](#potential-optimisations) (Efficient ECDSA, after a soundness review; folding; public-input compression) apply if the circom/Groth16 stack is kept.

#### H6. Metadata privacy beyond the signature


Removing the certificate is necessary but not sufficient. The anonymizer should also check or scrub other identifying data: the claim generator and manifest identifiers, ingredients, and the asset's own metadata (for example EXIF camera serial numbers and GPS). The regression test for [#6](https://github.com/christianpaquin/c2pa-signer-privacy/issues/6) (`anonymized_asset_does_not_reveal_signer`) should be extended as each source is addressed.

#### H7. Build, setup, and test infrastructure


- Run the placeholder-mode suite in CI, and periodically run the full real-proof end-to-end test (it needs ~12 GB of RAM).
- Fix key distribution. The committed `x509_issue_and_possession_native.vk` is not usable on its own: the matching proving key is not committed, so every user who runs setup generates new random keys and overwrites it. Either publish both keys from a single setup (the proving key is ~2.4 GB), or stop committing the verifying key.
- Enable ark-circom's `sanity_check` in the prover. It is off by default, so witness generation does not check constraints: an input the circuit rejects still produces a proof after ~20 minutes, which then fails verification. With it on, such inputs fail immediately with the failing assertion.
- Bring `circuits/build.sh` in line with the working steps above. It currently uses a snarkjs/pot20 flow that is too small for this circuit and omits the include paths.

#### H8. c2patool support

Displaying and verifying anonymized assets in `c2patool` (likely in a fork of `c2pa-rs`): `c2pa-rs` treats a missing signing certificate as fatal, and with decision D4 it will read the issuing CA as the signer's certificate and fail its end-entity profile check. Both need handling for the prototype's private-use algorithm, and eventually a verifier for its proofs.

## Toolchain

| Component | Tool | Version |
|-----------|------|---------|
| Circuit language | Circom | 2.1+ |
| Proving system | Groth16 on BN254 | — |
| Rust prover | ark-circom + ark-groth16 | 0.5 |
| Powers of Tau | Not needed — `ark-groth16` generates keys locally | — |

## References

- [Groth16 zkSNARK](https://eprint.iacr.org/2016/260)
- [ark-circom](https://github.com/arkworks-rs/circom-compat)
- [ark-groth16](https://github.com/arkworks-rs/groth16)
- [@zk-email/circuits](https://github.com/zkemail/zk-email-verify)
- [Efficient ECDSA — Personae Labs](https://personaelabs.org/posts/efficient-ecdsa-1/)
- [c2pa-rs](https://github.com/contentauth/c2pa-rs)

## Credits

### circom-ecdsa-p256

The P-256 ECDSA circuit templates (`ECDSAVerifyNoPubkeyCheck`, `ECDSAPrivToPub`, and the underlying
big-integer and elliptic-curve arithmetic) are taken from
[**circom-ecdsa-p256**](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256)
by 0xPARC / Privacy Scaling Explorations, licensed under ISC.
The library is included as a git submodule at `circuits/circom-ecdsa-p256/`.

### circom-pairing

The elliptic-curve pairing and field-arithmetic circuits used by circom-ecdsa-p256 come from
[**circom-pairing**](https://github.com/privacy-scaling-explorations/circom-pairing)
(a.k.a. zkPairing) by 0xPARC / Privacy Scaling Explorations, licensed under GPL-3.0.
It is bundled as a nested submodule at `circuits/circom-ecdsa-p256/circuits/circom-pairing/`.

### @zk-email/circuits

The `Sha256Bytes` and `Sha256General` templates (in-circuit SHA-256 over byte arrays) are adapted
from [**@zk-email/circuits**](https://github.com/zkemail/zk-email-verify)
by the ZK Email team, licensed under MIT.
Utility includes (`utils/array.circom`, `utils/functions.circom`) are also used.
The package is installed as an npm dependency.
