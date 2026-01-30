# C2PA Signer Privacy

This project explores privacy-preserving signature schemes for [C2PA](https://c2pa.org/) (Coalition for Content Provenance and Authenticity) manifests. The goal is to allow verification of content authenticity while protecting the identity of individual signers.

## Overview

Two strategies are implemented as proof-of-concept demonstrations:

| Strategy | Approach | Privacy Model | Performance |
|----------|----------|---------------|-------------|
| **BBS+ Signatures** | New signature scheme with selective disclosure | Hide chosen attributes, unlinkable proofs | Fast signing & verify (~3ms) |
| **X.509 + ZK Proofs** | Standard ECDSA + zero-knowledge anonymizer | Hide signer identity, reveal CA | Slower proof gen (~5min), fast verify (11ms) |

### Strategy 1: BBS+ Selective Disclosure

Replace ECDSA signatures with BBS+ signatures that support **selective disclosure** (reveal only chosen attributes) and **unlinkable proofs** (same signer, different verifications cannot be correlated).

**Location:** [`bbs-signatures/`](bbs-signatures/)

### Strategy 2: X.509 + ZK Anonymizing Editor

Keep standard X.509/ECDSA-P256 signing, add a post-processing step that replaces the signature with a **zero-knowledge proof** demonstrating the signer possessed a valid certificate from a trusted CA—without revealing which specific certificate.

**Location:** [`zk-proofs/`](zk-proofs/)

---

## Comparison

| Feature | Strategy 1 (BBS+) | Strategy 2 (X.509 + ZK) |
|---------|-------------------|-------------------------|
| **Signing algorithm** | BBS+ (new) | ECDSA P-256 (standard) |
| **PKI compatibility** | Requires new CA infrastructure | Works with existing X.509 |
| **Privacy model** | Selective attribute disclosure | Hide signer, reveal CA |
| **Signer identity hidden** | ✅ Yes | ✅ Yes |
| **Proof generation time** | ~2ms | ~4-5 minutes |
| **Verification time** | ~3ms | 11ms |
| **Setup required** | None | Trusted setup (one-time) |
| **Proof size** | ~500 bytes | ~1KB |
| **Randomized proofs** | ✅ Different bytes each time | ❌ Deterministic |

> **Note on unlinkability**: Both strategies hide the signer's identity from verifiers. The "randomized proofs" row refers to whether deriving a proof multiple times produces different bytes. BBS+ proofs are randomized (useful if you want to distribute the same content multiple times without correlation), while Groth16 proofs are deterministic (same inputs → same proof).

---

## Quick Start

### Strategy 1: BBS+ Signatures

```bash
cd bbs-signatures
cargo build --release
cargo test
```

### Strategy 2: X.509 + ZK Proofs

```bash
cd zk-proofs
cargo build --release

# One-time trusted setup (~36 seconds)
cargo run --release --bin c2pa-x509-zk-setup -- --circuits-dir circuits

# Run tests
cargo test --release
```

---

## CLI Tools

### Strategy 1: BBS+

```bash
# Sign an asset with BBS+
cargo run --release --bin c2pa-bbs-sign -- \
  --input fixtures/cards.png \
  --output signed.png

# Verify a BBS+ signed asset
cargo run --release --bin c2pa-bbs-verify -- \
  --input signed.png
```

### Strategy 2: X.509 + ZK

```bash
# 1. Sign an asset with standard X.509/ECDSA
cargo run --release --bin c2pa-x509-zk-sign -- \
  --input fixtures/cards.png \
  --output signed.png \
  --cert fixtures/certs/signer-cert.pem \
  --key fixtures/certs/signer-key.pem \
  --ca fixtures/certs/ca-cert.pem

# 2. Anonymize: Replace signature with ZK proof (~5 minutes)
cargo run --release --bin c2pa-x509-zk-editor -- \
  --input signed.png \
  --output anonymized.png \
  --ca fixtures/certs/ca-cert.pem \
  --signer-key fixtures/certs/signer-key.pem \
  --circuits-dir circuits

# 3. Verify the ZK proof
cargo run --release --bin c2pa-x509-zk-verify -- \
  --input anonymized.png \
  --ca fixtures/certs/ca-cert.pem \
  --circuits-dir circuits
```

---

## Project Structure

```
signer-privacy/
├── README.md                    # This file
├── bbs-signatures/              # Strategy 1: BBS+ implementation
│   ├── Cargo.toml
│   ├── crates/c2pa-bbs-demo/    # Demo CLI tools
│   ├── docs/bbs-c2pa-design.md  # BBS+ design details
│   └── fixtures/                # Test images
├── zk-proofs/                   # Strategy 2: X.509 + ZK implementation
│   ├── Cargo.toml
│   ├── circuits/                # Circom circuits
│   │   ├── c2pa_signer_proof.circom
│   │   ├── circom-ecdsa-p256/   # P-256 ECDSA circuit (submodule)
│   │   └── build/               # Compiled circuits and keys
│   ├── crates/c2pa-x509-zk-demo/ # Demo CLI tools
│   └── fixtures/                # Test certs and images
└── external/
    └── pairing_crypto/          # BBS+ crypto library (submodule)
```

---

## Cryptographic Details

The following sections provide deeper technical details for readers familiar with BBS+ signatures and zero-knowledge proof systems.

### BBS+ Signature Scheme

#### What is Signed

A BBS+ signature is created over a vector of messages (attributes). In this prototype:

| Message Slot | Attribute | Purpose |
|--------------|-----------|---------|
| 0 | `claim_hash` | SHA-256 hash of the C2PA claim (binding to content) |
| 1 | `issuer` | Organization name |
| 2 | `policy` | Trust policy identifier |
| 3 | `editor_id` | Individual editor identifier |
| 4 | `device_id` | Device/hardware identifier |

#### What is Presented (Selective Disclosure)

When deriving a proof for verification, the holder selects which messages to reveal:

- **Revealed**: `claim_hash`, `issuer`, `policy` (slots 0, 1, 2)
- **Hidden**: `editor_id`, `device_id` (slots 3, 4)

The derived proof cryptographically demonstrates that the hidden values were included in the original signature, without revealing them.

#### Proof Randomization

Each time a proof is derived, fresh randomness is used, producing different proof bytes. This prevents correlation even when the same signature is presented multiple times.

#### Identity Model Limitation

The prototype uses a self-asserted BBS key pair. A production system would anchor the BBS public key to a Verifiable Credential (VC) chain, binding the key to an issuer identity.

### ZK Proof System (Groth16)

#### Proof Statement

The zero-knowledge proof demonstrates the following without revealing the signer's certificate or private key:

**Public Inputs:**
- `ca_pubkey` — The trusted CA's P-256 public key (64 bytes)
- `claim_hash` — SHA-256 hash of the C2PA claim (32 bytes)

**Private Inputs (Witness):**
- `cert_der` — DER-encoded X.509 certificate (up to 512 bytes)
- `signer_privkey` — P-256 private key scalar (32 bytes)

**Relations Proved:**
1. The certificate's issuer signature verifies under `ca_pubkey`
2. The signer possesses the private key corresponding to the certificate's public key
3. The signer created a valid ECDSA signature over `claim_hash`

#### Circuit Architecture

```
c2pa_signer_proof.circom
├── x509_parse.circom          # Extract public key from DER certificate
├── x509_issue_and_possession.circom  # Verify CA signature + key possession
└── circom-ecdsa-p256/         # P-256 ECDSA signature verification
    ├── ecdsa.circom           # Main ECDSA verify
    ├── secp256r1.circom       # Curve operations
    └── bigint.circom          # 256-bit arithmetic
```

#### Circuit Statistics

| Metric | Value |
|--------|-------|
| Constraints | ~2,000,000 |
| Proving key size | 363 MB |
| Verifying key size | 968 bytes |
| Proof size | ~1 KB (256 bytes compressed) |

#### Toolchain

| Component | Tool | Version |
|-----------|------|---------|
| Circuit language | Circom | 2.1+ |
| Constraint compilation | circom compiler | 2.1+ |
| Proving system | Groth16 on BN254 | — |
| Rust prover | ark-circom | 0.5 |
| Groth16 implementation | ark-groth16 | 0.5 |
| Powers of Tau | Hermez ptau | 2²¹ |

#### Performance Breakdown

| Phase | Time | Notes |
|-------|------|-------|
| Circuit compilation | ~10 min | One-time, produces R1CS |
| Trusted setup | ~36 sec | One-time, produces pk/vk |
| Witness generation | ~2 sec | Per-proof |
| Proof generation | ~4-5 min | Per-proof (CPU-bound) |
| Verification | **11 ms** | Fast, suitable for validators |

---

## License

MIT

## References

- [C2PA Specification](https://c2pa.org/specifications/)
- [BBS+ Signatures (IETF Draft)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
- [MATTR pairing_crypto](https://github.com/mattrglobal/pairing_crypto) — BBS+ implementation used in Strategy 1
- [Groth16 zkSNARK](https://eprint.iacr.org/2016/260)
- [ark-circom](https://github.com/arkworks-rs/circom-compat) — Native Rust Circom prover used in Strategy 2
- [ark-groth16](https://github.com/arkworks-rs/groth16) — Groth16 proving system
- [circom-ecdsa-p256](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256) — P-256 ECDSA circuit
