# X.509 Zero-Knowledge Anonymizer for C2PA

This project implements privacy-preserving signatures for C2PA manifests using zero-knowledge proofs. It replaces an existing X.509/COSE signature with a ZK proof that the asset was signed by a certificate issued by a trusted CA, without revealing the signer's identity.

## Overview

This approach keeps standard X.509/ECDSA-P256 signing, then adds a post-processing step that:
- Extracts the original signature and certificate chain
- Generates a Groth16 ZK proof demonstrating valid CA issuance
- Replaces the manifest signature with the proof

The verifier can confirm the asset was signed by *someone* with a certificate from the trusted CA, without learning *who*.

## Quick Start

> **Note**: These commands work without building circuits first. The editor uses "placeholder mode" which generates valid manifest structures with placeholder proofs. To generate real ZK proofs, complete the [Building Circuits](#building-circuits) setup first.

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
cargo run --release --bin c2pa-x509-zk-editor -- \
  --input /tmp/signed.png \
  --output /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem \
  --signer-key fixtures/certs/signer-key.pem

# 3. Verify the anonymized asset
cargo run --release --bin c2pa-x509-zk-verify -- \
  --input /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem

# Run tests
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
│   ├── c2pa_signer_proof.circom    # Main proof circuit
│   ├── x509_parse.circom           # Certificate parsing
│   ├── x509_issue_and_possession.circom
│   ├── circom-ecdsa-p256/          # P-256 ECDSA verification library
│   └── build/                      # Compiled circuits and keys
├── crates/
│   └── c2pa-x509-zk-demo/          # Rust library + CLIs
└── fixtures/
    ├── cards.png                   # Test input image
    └── certs/                      # Test certificates
```

## Cryptographic Details

The ZK approach uses a Groth16 zkSNARK to prove that the signer possesses a valid certificate issued by a trusted CA, without revealing which certificate. The circuit performs full P-256 ECDSA signature verification (~2M constraints), making proof generation slow (~5 minutes) but verification fast (11ms). The proof binds the signer's public key to the CA via a hash commitment, and proves knowledge of a valid ECDSA signature over the C2PA claim hash.

### ZK Proof Statement

**Public inputs:**
- `issuerHash[4]`: SHA-256 hash of CA public key (4 × 64-bit limbs)
- `claimHash[6]`: C2PA claim hash (6 × 43-bit registers)
- `signerPubkey[2][6]`: Signer's P-256 public key (X, Y coordinates)

**Private inputs (witness):**
- `claimSigR[6]`, `claimSigS[6]`: ECDSA signature (r, s) over claim hash

**Relations proved:**
1. The signer's public key is bound to a certificate issued by the CA (via issuerHash)
2. A valid ECDSA signature exists over the claim hash using the signer's private key

### Circuit Architecture

```
c2pa_signer_proof.circom
├── x509_parse.circom              # Extract public key from DER certificate
├── x509_issue_and_possession.circom  # Verify CA signature + key possession
└── circom-ecdsa-p256/             # P-256 ECDSA signature verification
    ├── ecdsa.circom               # Main ECDSA verify
    ├── secp256r1.circom           # Curve operations
    └── bigint.circom              # 256-bit arithmetic
```

### Circuit Statistics

| Metric | Value |
|--------|-------|
| Constraints | ~2,000,000 |
| Proving key size | 363 MB |
| Verifying key size | 968 bytes |
| Proof size | ~1 KB |

### Performance

| Phase | Time | Notes |
|-------|------|-------|
| Circuit compilation | ~10 min | One-time |
| Trusted setup | ~36 sec | One-time, native Rust |
| Witness generation | ~2 sec | Per-proof |
| Proof generation | ~4-5 min | Per-proof |
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
circom c2pa_signer_proof.circom --r1cs --wasm --sym -l . -l node_modules -o build/
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
- [circom-ecdsa-p256](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256)
- [ark-circom](https://github.com/arkworks-rs/circom-compat)
- [ark-groth16](https://github.com/arkworks-rs/groth16)
