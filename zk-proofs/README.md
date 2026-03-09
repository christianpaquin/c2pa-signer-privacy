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

# 2. Anonymize: Replace signature with a real Groth16 ZK proof
# This step is slow on the current circuit and may take a long time.
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
│   ├── x509_parse.circom           # X.509 DER parser (SelectByte, BytesToRegisters, X509Parse)
│   ├── circom-ecdsa-p256/          # P-256 ECDSA verification library
│   └── build/                      # Compiled circuits and keys
├── crates/
│   └── c2pa-x509-zk-demo/          # Rust library + CLIs
└── fixtures/
    ├── cards.png                   # Test input image
    └── certs/                      # Test certificates
```

## Cryptographic Details

The ZK approach uses a Groth16 zkSNARK to prove that the signer possesses a valid certificate issued by a trusted CA, without revealing which certificate. The primary circuit performs two P-256 ECDSA signature verifications plus in-circuit SHA-256 and UTCTime parsing (~12M constraints total). The proof cryptographically binds the signer's private key to a CA-issued certificate, and proves that the certificate was valid when the asset was anonymized.

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
1. `x509_parse.circom` extracts the TBSCertificate hash and SPKI from `certDer` in-circuit — the certificate structure is enforced by the proof itself
2. `caPubKeyX/Y` verifies the CA signature over the parsed TBSCertificate — the cert was issued by the trusted CA
3. The parsed subject public key verifies the signer's signature over `claimHash` — the prover holds the corresponding private key
4. `parser.notBefore ≤ photoTimestamp ≤ parser.notAfter` — the cert was valid when the asset was anonymized/processed (timestamps parsed in-circuit from certDer)

**Pending (required for production soundness):**
- RFC 5280 field validation (version, algorithm OID, key-usage extensions)
- Optional: revocation check via short-lived certs or an accumulator commitment

**Why in-circuit cert parsing matters:**
Passing raw `certDer` bytes into the circuit and parsing them inside the ZK proof is the architecturally sound design. An alternative (pre-computing fields off-circuit) creates a key-mixing attack: a malicious prover could combine cert A's CA signature with an unrelated key pair B, bypassing issuance verification entirely. In-circuit parsing closes this soundness gap.

The in-circuit SHA-256 is implemented via `Sha256Bytes(1536)` from `@zk-email/circuits`.  The prover supplies `tbsHashPaddedBytes[1536]` (the TBS DER bytes with standard SHA-256 padding) and the circuit verifies that the first `4+tbsLen` bytes match `certDer[tbsOffset..]`, then hashes the buffer in-circuit and feeds the result into the CA ECDSA check.

### Constraint Count

Estimated for the updated circuit (in-circuit SHA-256 + UTCTime parsing added):

| Component | Constraints |
|---|-----------|
| `ECDSAVerifyNoPubkeyCheck` × 2 (Steps 2 + 4) | ~3,945,000 |
| `X509Parse` TBS binding (1536 × `SelectByte` + 1536 × `LessEqThan`) | ~4,320,000 |
| `Sha256Bytes(1536)` | ~720,000 |
| SPKI extraction (64 × `SelectByte`) | ~90,000 |
| UTCTime parsing (2 × `UTCTimeToUnix`) | ~500 |
| Validity period range checks (`Num2Bits(32)` × 2) | ~70 |
| **Total (estimated)** | **~9,076,000** |

> **Note:** The measured constraint count is **12,073,163** (see [Circuit Statistics](#circuit-statistics) below). The estimates above account for the dominant sub-circuits but undercount wiring overhead, `BytesToRegisters` conversions, and other glue logic. Use the measured value for capacity planning.

For a production multi-party trusted setup (MPC ceremony) this circuit class would require a **2²⁴** (~16.7M) Powers of Tau file.  **For this demo no ptau download is needed** — `ark-groth16` performs a local single-party setup directly from the `.r1cs` file.

**Future optimisation:** The `SelectByte` calls for TBS binding (the dominant cost) can be replaced with `VarShiftLeft` from `@zk-email/circuits/utils/array.circom`, reducing the TBS binding cost from ~4.3M constraints to ~500K constraints (~8.3M total based on measured baseline, still within the pot24 ceremony class).

### Potential Optimisation: Efficient ECDSA

The **Efficient ECDSA** technique (sometimes called the "NOPE" circuit, from [Personae Labs](https://personaelabs.org/posts/efficient-ecdsa-1/)) eliminates the fixed-base G scalar multiplication from signature verification by computing it off-circuit and supplying the result as a witness T.  This would reduce each `ECDSAVerifyNoPubkeyCheck` (~1.3M constraints) to roughly ~700K constraints.

**However, this optimisation is not straightforwardly applicable to Step 2 (CA signature verification).**  If T is an unconstrained private witness, a prover can forge a passing check by computing T = (r, y) − u₂·Q for any point (r, y) on P-256, without access to the CA's private key.  Making T a public commitment would fix the soundness issue but would allow a verifier to link multiple proofs that use the same certificate (T = (hash/s)·G is deterministic per cert+signature pair).

For Step 4 (claim signature), the soundness concern is managed at the system level — only legitimate key holders receive CA-signed certs — so efficient ECDSA could be applied there.  The saving (~600K constraints) would not change the pot24 ceremony class requirement for a production multi-party setup.

Applying this optimisation is left as future work when the soundness and privacy tradeoffs have been fully evaluated.

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
└── x509_parse.circom                 # X.509 DER parser — SelectByte, BytesToRegisters, X509Parse
```

`x509_issue_and_possession.circom` is the sole proof circuit. It accepts the raw DER
certificate bytes and parses them in-circuit via `x509_parse.circom`, ensuring that
the CA signature, the subject public key, and the validity period are all bound to the
same certificate — preventing key-mixing attacks that would otherwise be possible if
fields were pre-computed off-circuit.

### Circuit Statistics

| Metric | Value | Notes |
|--------|-------|-------|
| Constraints | **12,073,163** (measured) | Two ECDSA verifs (~3.9M) + TBS binding (~4.3M) + SHA-256 (~720K) + parsing + UTCTime |
| Constraints (with VarShiftLeft TBS binding) | ~8,250,000 | Replace 1536 × SelectByte with VarShiftLeft from @zk-email/circuits |
| Constraints (with Efficient ECDSA for Step 4) | ~11,470,000 | See optimisation note above — soundness caveat applies |
| Proving key size | ~2.3 GB (measured) | Native Rust key generated by `ark-groth16` from `.r1cs` |
| Verifying key size | 872 bytes (measured) | Constant for Groth16 |
| Proof size | ~1 KB | Constant for Groth16 |
| Production ceremony class | pot24 (~16.7M constraints) | Not needed for this demo — `ark-groth16` runs local setup |

### Performance

The figures below should be treated as rough guidance for this circuit class, not as tight guarantees for every machine. In local testing for this repository, circuit compilation and native setup completed successfully and the full real flow completed end-to-end, but the anonymizer's proof-generation step remained very slow.

| Phase | Time | Notes |
|-------|------|-------|
| Circuit compilation | ~10 min | One-time |
| Trusted setup | ~30 sec | One-time, native Rust |
| Witness generation | Slow and hardware-dependent | Per-proof |
| Proof generation | Slow and hardware-dependent | Per-proof |
| Verification | Fast once a real proof exists | Real flow has been exercised locally |

### COSE Integration

- Custom algorithm: `alg = -65534` (experimental range)
- Critical header: `crit = ["c2pa-x509-zk"]`
- Extension map with circuit metadata

## Building Circuits

### 1. Compile circuit and run trusted setup

```bash
# All commands run from the zk-proofs/ directory

# Initialize submodules (if not already done)
git submodule update --init --recursive

# Install circuit JS dependencies (circomlib, circom-ecdsa-p256 deps)
npm install --prefix circuits

# Compile circuit (~5-10 minutes, produces .r1cs and .wasm)
mkdir -p circuits/build
circom circuits/x509_issue_and_possession.circom \
  --r1cs --wasm --sym \
  -l circuits \
  -l circuits/node_modules \
  -o circuits/build/

# Run trusted setup (~36 seconds) — generates proving and verifying keys
# Must run from zk-proofs/, not circuits/
cargo run --release --bin c2pa-x509-zk-setup -- --circuits-dir circuits
```

This generates the proving and verifying keys in `circuits/build/`.

> **Note**: The native Rust prover (`ark-groth16`) generates its own circuit-specific keys
> directly from the compiled `.r1cs` + `.wasm` files using a local random seed.  No
> external Powers of Tau ceremony file is needed — `ark-groth16::generate_random_parameters_with_reduction`
> handles the setup in one ~36-second pass.

## Certificate Requirements

Certificates must use:
- **P-256 ECDSA** (secp256r1 / prime256v1)
- **Document Signing EKU** (1.3.6.1.5.5.7.3.36) for C2PA compatibility

Generate test certificates and a signed test asset:
```bash
./generate-test-assets.sh
```

> **Note**: To create a signed test asset, `c2patool` must be installed. See the [c2patool documentation](https://github.com/contentauth/c2pa-rs/blob/main/cli/README.md) for details.

## Placeholder Mode

If you haven't completed the circuit setup, the anonymizer can embed a placeholder proof instead of a real ZK proof. This lets you exercise the full manifest pipeline — sign, anonymize, verify — immediately after `cargo build`, without waiting for circuit compilation (~10 min) and trusted setup (~36 sec).

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
- [Efficient ECDSA — Personae Labs](https://personaelabs.org/posts/efficient-ecdsa-1/)

## Credits

### circom-ecdsa-p256

The P-256 ECDSA circuit templates (`ECDSAVerifyNoPubkeyCheck`, `ECDSAPrivToPub`, and the underlying
big-integer and elliptic-curve arithmetic) are taken from
[**circom-ecdsa-p256**](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256)
by 0xPARC / Privacy Scaling Explorations, licensed under ISC.
The library is included as a git submodule at `circuits/circom-ecdsa-p256/`.
