# X.509 Zero-Knowledge Anonymizer for C2PA

This project implements privacy-preserving signatures for C2PA manifests using zero-knowledge proofs. It replaces an existing X.509/COSE signature with a ZK proof that the asset was signed by a certificate issued by a trusted CA, without revealing the signer's identity.

## Overview

This approach keeps standard X.509/ECDSA-P256 signing, then adds a post-processing step that:
- Extracts the original signature and certificate chain
- Generates a Groth16 ZK proof demonstrating valid CA issuance
- Replaces the manifest signature with the proof

The verifier can confirm the asset was signed by *someone* with a certificate from the trusted CA, without learning *who*.

## Quick Start

> **Note**: The steps below use `--placeholder`, which generates valid manifest structures without running the ZK circuit. This works immediately after `cargo build`. To generate real ZK proofs, complete the [Building Circuits](#building-circuits) setup first, then drop the `--placeholder` flag from Step 2 (proof generation takes ~8–10 minutes).

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

# 2. Anonymize: Replace signature with ZK proof
#    Use --placeholder until the circuit setup is complete (see Building Circuits below)
cargo run --release --bin c2pa-x509-zk-editor -- \
  --input /tmp/signed.png \
  --output /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem \
  --signer-key fixtures/certs/signer-key.pem \
  --placeholder

# 3. Verify the anonymized asset
#    (will print a placeholder warning until a real proof is embedded)
cargo run --release --bin c2pa-x509-zk-verify -- \
  --input /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem

# Run all integration tests (also use placeholder mode internally)
cargo test --release
```

## CLI Tools

| Binary | Description |
|--------|-------------|
| `c2pa-x509-zk-sign` | Create standard C2PA signed assets (ES256/P-256) |
| `c2pa-x509-zk-editor` | Anonymize signed assets by replacing COSE signature with ZK proof |
| `c2pa-x509-zk-verify` | Verify anonymized assets against trusted CA |

## Project Structure

```
zk-proofs/
├── circuits/                       # Circom ZK circuits
│   ├── x509_issue_and_possession.circom  # Main proof circuit
│   ├── x509_parse.circom           # Certificate parsing (ASN.1 scaffold, TODO)
│   ├── circom-ecdsa-p256/          # P-256 ECDSA verification library
│   └── build/                      # Compiled circuits and keys
├── crates/
│   └── c2pa-x509-zk-demo/          # Rust library + CLIs
└── fixtures/
    ├── cards.png                   # Test input image
    └── certs/                      # Test certificates
```

## Cryptographic Details

The ZK approach uses a Groth16 zkSNARK to prove that the signer possesses a valid certificate issued by a trusted CA, without revealing which certificate. The primary circuit performs two P-256 ECDSA signature verifications (~2M constraints each, ~4M total), making proof generation slow (~5–10 minutes) but verification fast (11ms). The proof cryptographically binds the signer's private key to a CA-issued certificate, and proves that the certificate was valid when the photo was taken.

### ZK Proof Statement

**Public inputs:**
- `caPubKeyX[6]`, `caPubKeyY[6]`: Trusted CA's P-256 public key (X, Y, each as 6 × 43-bit registers)
- `claimHash[6]`: C2PA claim hash SHA-256 (6 × 43-bit registers)
- `photoTimestamp`: Unix timestamp of when the photo was captured

**Private inputs (witness):**
- `certDer[1500]`: Raw DER-encoded signer certificate bytes (zero-padded to 1500 bytes)
- `certLen`: Actual byte count of the certificate
- `certSigR[6]`, `certSigS[6]`: CA's ECDSA signature over the TBSCertificate
- `claimSigR[6]`, `claimSigS[6]`: Signer's ECDSA signature over `claimHash`
- `certNotBefore`, `certNotAfter`: Certificate validity bounds (Unix timestamps)

**Relations proved:**
1. `x509_parse.circom` extracts the TBSCertificate hash and SPKI from `certDer` in-circuit — the certificate structure is enforced by the proof itself
2. `caPubKeyX/Y` verifies the CA signature over the parsed TBSCertificate — the cert was issued by the trusted CA
3. The parsed subject public key verifies the signer's signature over `claimHash` — the prover holds the corresponding private key
4. `certNotBefore ≤ photoTimestamp ≤ certNotAfter` — the cert was valid when the photo was taken

**Pending (required for production soundness):**
- Full `x509_parse.circom` implementation (ASN.1 DER parsing in-circuit) — currently a scaffold
- RFC 5280 field validation (version, algorithm OID, key-usage extensions)
- Optional: revocation check via short-lived certs or an accumulator commitment

**Why in-circuit cert parsing matters:**
Passing raw `certDer` bytes into the circuit and parsing them inside the ZK proof is the architecturally sound design. An alternative (pre-computing `tbsCertHash` off-circuit) creates a key-mixing attack: a malicious prover could combine cert A's CA signature with an unrelated key pair B, bypassing issuance verification entirely. In-circuit parsing closes this soundness gap.

### Constraint Count Reduction (Efficient ECDSA)

The current circuit uses `ECDSAVerifyNoPubkeyCheck` twice, which performs two double-scalar-multiplications (u₁·G + u₂·Q) each with ~1M constraints, totalling ~2M for each signature verification.

The **Efficient ECDSA** technique (sometimes called the "NOPE" circuit) reformulates verification so that only one scalar multiplication is done inside the circuit.  A helper point T = (−s/r)·R + (hash/r)·G is computed off-circuit and handed in as an additional witness; the circuit then proves T + subjectPubkey·(r/s) equals the expected point.  This roughly halves the constraint count per signature — reducing the total from ~4M to ~2M.

Applying this optimisation is left as future work; see the [Efficient ECDSA write-up](https://personaelabs.org/posts/efficient-ecdsa-1/) by Personae Labs for details.

### Circuit Architecture

```
circuits/
├── x509_issue_and_possession.circom  # Main proof circuit (used by Rust prover)
│   ├── x509_parse.circom             # ASN.1 cert parser scaffold (TODO)
│   └── circom-ecdsa-p256/            # P-256 ECDSA verification (×2)
│       ├── ecdsa.circom              # ECDSAVerifyNoPubkeyCheck
│       ├── p256.circom               # Curve operations
│       └── bigint arithmetic         # 256-bit register arithmetic
│
└── x509_parse.circom                 # X.509 DER parser (ASN.1 scaffold, TODO)
```

`x509_issue_and_possession.circom` is the sole proof circuit. It accepts the raw DER
certificate bytes and parses them in-circuit via `x509_parse.circom`, ensuring that
the CA signature, the subject public key, and the validity period are all bound to the
same certificate — preventing key-mixing attacks that would otherwise be possible if
fields were pre-computed off-circuit.

### Circuit Statistics

| Metric | Value | Notes |
|--------|-------|-------|
| Constraints | ~4,000,000 | Two `ECDSAVerifyNoPubkeyCheck` calls (~2M each) |
| Constraints (with Efficient ECDSA) | ~2,000,000 | See optimisation note above |
| Proving key size | ~726 MB | Scales with constraint count |
| Verifying key size | 968 bytes | Constant for Groth16 |
| Proof size | ~1 KB | Constant for Groth16 |

### Performance

| Phase | Time | Notes |
|-------|------|-------|
| Circuit compilation | ~10 min | One-time |
| Trusted setup | ~36 sec | One-time, native Rust |
| Witness generation | ~2 sec | Per-proof |
| Proof generation | ~8-10 min | Per-proof (two ECDSA verifications) |
| Verification | **11 ms** | Fast |

### COSE Integration

- Custom algorithm: `alg = -65534` (experimental range)
- Critical header: `crit = ["c2pa-x509-zk"]`
- Extension map with circuit metadata

## Building Circuits

### 1. Compile the Circom circuit

```bash
# Initialize submodules (if not already done)
git submodule update --init --recursive

cd circuits

# Install dependencies
npm install

# Download Powers of Tau (1.4GB)
curl -O https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau
mv powersOfTau28_hez_final_21.ptau pot21_final.ptau

# Compile circuit (~5-10 minutes)
circom x509_issue_and_possession.circom --r1cs --wasm --sym -l . -l node_modules -o build/
```

### 2. Run trusted setup (native Rust)

The native setup using `ark-groth16` is much faster than snarkjs (~36 seconds vs 2-4 hours):

```bash
# from zk-proofs/
cargo run --release --bin c2pa-x509-zk-setup -- --circuits-dir circuits
```

This generates the proving and verifying keys in `circuits/build/`.

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

Before circuits are fully built, the editor generates placeholder proofs. The verifier detects these and prints a warning. This allows testing the manifest structure without running the circuit setup.

## Toolchain

| Component | Tool | Version |
|-----------|------|---------|
| Circuit language | Circom | 2.1+ |
| Proving system | Groth16 on BN254 | — |
| Rust prover | ark-circom + ark-groth16 | 0.5 |
| Powers of Tau | Hermez ptau | 2²¹ |

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
