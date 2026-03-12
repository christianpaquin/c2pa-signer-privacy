# BBS Signatures for C2PA

This project implements privacy-preserving C2PA manifests using BBS selective-disclosure proofs. The toy flow models a Verifiable Credential-style separation between an issuer that signs a credential and a holder that later presents that credential over a C2PA asset hash.

## Overview

BBS signatures support **selective disclosure** (reveal only chosen attributes) and **unlinkable presentations** (the holder can derive fresh proofs from the same credential). This implementation:

- Issues a toy BBS credential signed by a demo issuer, encoding four attributes:
  - an `issuer` identifier
  - an issuance `policy` identifier
  - a `user_id`
  - a `device_id` 
- Lets the holder present that credential in a `bbs-signer-proof` assertion, while
  - Revealing the `issuer` and `policy` attributes and hiding the `user_id` and `device_id` ones
  - Binding the C2PA asset hash into the BBS presentation header
- Lets the verifier validate the presentation, learning the disclosed attributes, and matching the BBS presentation to the C2PA asset

## Quick Start

```bash
# Build
cargo build --release

# Issue a toy credential
cargo run --release --bin c2pa-bbs-issue -- \
  --output /tmp/credential.json \
  --issuer "MyOrg" \
  --policy "issuance-policy-v1"

# Present the credential over an asset
cargo run --release --bin c2pa-bbs-sign -- \
  --input fixtures/cards.png \
  --output /tmp/signed.png \
  --credential /tmp/credential.json

# Verify the signed asset
cargo run --release --bin c2pa-bbs-verify -- \
  --input /tmp/signed.png

# Run tests
cargo test --release
```

## CLI Tools

| Binary | Description |
|--------|-------------|
| `c2pa-bbs-issue` | Issue a toy BBS credential from the demo issuer |
| `c2pa-bbs-sign` | Present an issued credential over a C2PA asset hash |
| `c2pa-bbs-verify` | Verify BBS signed assets |

## Data Model

### Credential Attributes

| Attribute | Disclosed | Purpose |
|-----------|-----------|---------|
| `claim_hash` | ✅ Yes | SHA-256 hash of the asset with the manifest excluded |
| `issuer` | ✅ Yes | Organization name |
| `policy` | ✅ Yes | Trust policy identifier |
| `user_id` | ❌ No | Individual user identifier (hidden) |
| `device_id` | ❌ No | Device/hardware identifier (hidden) |

### Toy Credential Format

```json
{
  "version": "0.1",
  "issuer_public_key": "<base64-bbs-public-key>",
  "public_attributes": {
    "issuer": "ExampleOrg",
    "policy": "issuance-policy-v1"
  },
  "hidden_attributes": {
    "user_id": "user-1234",
    "device_id": "device-9876"
  },
  "signature": "<base64-bbs-signature>"
}
```

### Manifest Assertion Format

```json
{
  "type": "bbs-signer-proof",
  "version": "0.1",
  "public_attributes": {
    "issuer": "ExampleOrg",
    "policy": "issuance-policy-v1"
  },
  "claim_hash": "<hex>",
  "proof": "<base64-bbs-proof>",
  "scheme": "bbs",
  "issuer_public_key": "<base64-issuer-bbs-public-key>"
}
```

### COSE Integration

- Custom algorithm: `alg = -65535`
- Critical header: `crit = ["c2pa-bbs"]`
- Issuer BBS public key embedded in the assertion and COSE extension for verifier self-sufficiency

## Cryptographic Details

The BBS approach replaces the standard COSE/ECDSA signature with a BBS presentation derived from a previously issued credential. In this toy flow, an issuer signs a credential containing multiple attributes, and the holder later derives a proof that reveals only the chosen attributes while binding the presentation to a C2PA asset hash. Each proof derivation uses fresh randomness, so the holder can generate unlinkable presentations from the same credential while the verifier still learns the issuer public key and the disclosed attributes.

### C2PA Integration

This prototype keeps the usual C2PA manifest structure and replaces the conventional COSE claim signature with a private-use BBS-based COSE object.

- Claim structure is otherwise unchanged: the manifest still uses the standard `created_assertions`, content bindings, and claim generator metadata.
- The COSE envelope is retained as `c2pa.signature`, but it uses a private-use algorithm value because C2PA does not currently define a BBS signature algorithm.
- The verifier disables built-in COSE verification, extracts the custom assertion, recomputes the manifest-stripped asset hash, and verifies the BBS proof directly.

### Custom COSE Format

The demo signer emits a `COSE_Sign1_Tagged` object with:

- `alg = -65535` as a private-use BBS algorithm identifier
- `crit = ["c2pa-bbs"]` so verifiers know an extension is required
- `x5chain` carrying the demo X.509 certificate chain required by `c2pa-rs`
- a `c2pa-bbs` extension map containing:
  - `scheme = "bbs"`
  - `version = "0.1"`
  - `issuer_public_key = <raw BBS issuer public key bytes>`

The COSE signature field contains the BBS proof bytes. The payload is detached in the usual C2PA style.

### How BBS Works

A BBS credential is issued over a vector of messages (attributes). When deriving a proof:
- The issuer signs the full attribute set once
- The holder selects which messages to reveal
- The derived proof cryptographically demonstrates that hidden values were included in the original issuer signature
- The holder binds the C2PA asset hash into the presentation header, on which its private key is applied (effectively signing the C2PA asset using the BBS credential)
- Each proof derivation uses fresh randomness, producing different bytes (unlinkable)

The presentation header binding used by this demo is:

```text
"c2pa-bbs-claim-hash:" || hex_decode(claim_hash)
```

This ensures the BBS presentation is tied to the specific asset being certified.

### Signing And Verification Flow

Signing in the demo has two explicit steps:

1. The issuer creates a toy BBS credential over the holder attributes.
2. The holder computes the asset hash before manifest embedding, derives a selective-disclosure proof from the credential, and embeds that proof into the C2PA manifest.

Verification in the demo does the reverse:

1. Read the manifest and extract the `bbs-signer-proof` assertion.
2. Remove the embedded JUMBF from a temporary copy of the asset.
3. Recompute the asset hash on that manifest-stripped copy.
4. Reconstruct the presentation header and verify the BBS proof against the disclosed attributes and issuer public key.

This means the verifier now checks both the BBS disclosure proof and the integrity of the non-manifest asset bytes.

### Demo Certificate Chain

`c2pa-rs` still expects a valid X.509 chain when serializing a manifest, even though the proof payload is non-standard. To satisfy that requirement, the demo ships an in-repo CA/leaf pair and embeds the chain in the custom COSE object. This is purely to interoperate with the current library behavior; the privacy logic is carried by the BBS credential and presentation, not by the X.509 chain.

### BBS Library

This implementation uses [MATTR's `pairing_crypto`](https://github.com/mattrglobal/pairing_crypto) (`draft-latest` branch), which tracks the latest IRTF CFRG draft (`draft-irtf-cfrg-bbs-signatures-10`) and provides:
- BLS12-381 + SHA-256 ciphersuite
- Signature and proof derivation APIs
- Proof verification

### Limitations

The prototype uses a deterministic demo issuer key and stores the issued credential as a local JSON file. A production system would anchor the issuer key in a real trust framework, protect holder credentials at rest, and define how the holder obtains and manages credentials out of band.

Additional limitations of the current prototype:

- It uses a toy local credential file instead of a real wallet or credential exchange.
- It relies on a private-use COSE algorithm value rather than a standardized C2PA extension.
- It embeds a demo X.509 chain only to satisfy current `c2pa-rs` manifest-writing requirements.
- It does not yet model revocation, issuer policy discovery, or a production trust registry for BBS issuers.

## Test Assets

- `fixtures/cards.png` — Test image from [microsoft/c2pa-extension-validator](https://github.com/microsoft/c2pa-extension-validator)

## References

- [BBS Signatures (IETF Draft)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) specification
- [MATTR pairing_crypto](https://github.com/mattrglobal/pairing_crypto) BBS library 
- [c2pa-rs](https://github.com/contentauth/c2pa-rs) C2PA rust library
