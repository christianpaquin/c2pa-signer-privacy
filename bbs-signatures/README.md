# BBS Signatures for C2PA

This project implements privacy-preserving signatures for C2PA manifests using BBS signatures with selective disclosure. It allows verification of content authenticity while hiding the signer's identity.

## Overview

BBS signatures support **selective disclosure** (reveal only chosen attributes) and **unlinkable proofs** (same signer, different verifications cannot be correlated). This implementation:

- Signs C2PA manifests with a `bbs-signer-proof` assertion
- Reveals `issuer` and `policy` attributes while hiding `editor_id` and `device_id`
- Binds the C2PA claim hash into the proof

## Quick Start

```bash
# Build
cargo build --release

# Sign an asset
cargo run --release --bin c2pa-bbs-sign -- \
  --input fixtures/cards.png \
  --output /tmp/signed.png \
  --issuer "MyOrg" \
  --policy "trusted-editor-v1"

# Verify the signed asset
cargo run --release --bin c2pa-bbs-verify -- \
  --input /tmp/signed.png

# Run tests
cargo test --release
```

## CLI Tools

| Binary | Description |
|--------|-------------|
| `c2pa-bbs-sign` | Create C2PA manifest with BBS signer privacy |
| `c2pa-bbs-verify` | Verify BBS signed assets |

## Data Model

### Credential Attributes

| Attribute | Disclosed | Purpose |
|-----------|-----------|---------|
| `claim_hash` | ✅ Yes | SHA-256 hash of C2PA claim (binding to content) |
| `issuer` | ✅ Yes | Organization name |
| `policy` | ✅ Yes | Trust policy identifier |
| `editor_id` | ❌ No | Individual editor identifier (hidden) |
| `device_id` | ❌ No | Device/hardware identifier (hidden) |

### Manifest Assertion Format

```json
{
  "type": "bbs-signer-proof",
  "version": "0.1",
  "public_attributes": {
    "issuer": "ExampleOrg",
    "policy": "trusted-editor-v1"
  },
  "claim_hash": "<hex>",
  "proof": "<base64-bbs-proof>",
  "scheme": "bbs"
}
```

### COSE Integration

- Custom algorithm: `alg = -65535`
- Critical header: `crit = ["c2pa-bbs"]`
- BBS public key embedded in assertion for verifier self-sufficiency

## Cryptographic Details

The BBS approach replaces the standard COSE/ECDSA signature with a BBS signature that supports selective disclosure. A credential containing multiple attributes (issuer, policy, editor ID, device ID, claim hash) is signed once, then a derived proof reveals only the chosen attributes while cryptographically hiding the rest. Each proof derivation uses fresh randomness, making proofs unlinkable: the same credential can generate multiple proofs that cannot be correlated. This provides both attribute-level privacy and protection against tracking.

### How BBS Works

A BBS signature is created over a vector of messages (attributes). When deriving a proof:
- The holder selects which messages to reveal
- The derived proof cryptographically demonstrates that hidden values were included in the original signature
- Each proof derivation uses fresh randomness, producing different bytes (unlinkable)

### BBS Library

This implementation uses [MATTR's `pairing_crypto`](https://github.com/mattrglobal/pairing_crypto), which tracks the IRTF CFRG draft (`draft-irtf-cfrg-bbs-signatures-03`) and provides:
- BLS12-381 + SHA-256 ciphersuite
- Signature and proof derivation APIs
- Proof verification

### Limitations

The prototype uses a self-asserted BBS key pair. A production system would anchor the BBS public key to a Verifiable Credential (VC) chain, binding the key to an issuer identity.

## Test Assets

- `fixtures/cards.png` — Test image from [microsoft/c2pa-extension-validator](https://github.com/microsoft/c2pa-extension-validator)

## References

- [BBS Signatures (IETF Draft)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
- [MATTR pairing_crypto](https://github.com/mattrglobal/pairing_crypto)
- [Design Document](docs/bbs-c2pa-design.md)
