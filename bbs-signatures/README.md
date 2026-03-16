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
  "holder_secret_key": "<base64-bls-secret-key>",
  "public_attributes": {
    "issuer": "ExampleOrg",
    "policy": "issuance-policy-v1"
  },
  "hidden_attributes": {
    "user_id": "user-1234",
    "device_id": "device-9876"
  },
  "signature": "<base64-bbs-bound-signature>"
}
```

The `holder_secret_key` is the holder's BLS secret key used for holder binding (see below). In the demo it is stored alongside the credential for convenience; a production system would manage holder keys separately in a secure wallet.

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

### Holder Binding

This demo uses **BBS bound signatures** (as defined in the [draft BBS spec](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)) to bind each credential and proof to a specific holder via a BLS key pair.

Without holder binding, anyone who obtains the credential file could derive valid proofs — the credential would be a **bearer token**. Holder binding prevents this: only the entity that holds the BLS secret key can produce valid presentations.

**How it works:**

1. **Key generation**: The holder generates a BLS12-381 key pair (secret key + public key).
2. **Issuance**: The holder sends the BLS _public key_ to the issuer. The issuer calls `bbs_bound::sign()`, which binds the credential to that public key. The issuer learns the holder's public key (needed to know who they're issuing to) but never the secret key.
3. **Proof generation**: The holder calls `bbs_bound::proof_gen()` with their BLS _secret key_. The secret key is used as an additional always-hidden message during proof derivation, cryptographically proving that the holder possesses the matching key.
4. **Verification**: The verifier calls `bbs_bound::proof_verify()` which succeeds only if the proof was generated with the correct secret key. The verifier does **not** learn the holder's BLS key — it remains hidden in the proof.

**Privacy properties:**

- The **verifier** does not learn the holder's identity or BLS public key — the holder binding is zero-knowledge.
- The **issuer** knows the holder's BLS public key (and thus can identify which holder they issued to), which is the standard Verifiable Credential model: issuers naturally verify holder identity before issuance.
- Presentations remain **unlinkable**: each proof derivation uses fresh randomness, so two proofs from the same credential cannot be correlated by the verifier.

**Note on issuer-privacy:** In this demo flow, the issuer sees the holder's BLS public key during issuance. An alternative approach could use BBS blind signing (where the holder commits to a secret value that the issuer signs without seeing), but the standard `bbs_bound` scheme is the simpler and more widely supported option. Since the issuer already knows who it is issuing credentials to (that's inherent to the issuance process), revealing the holder's public key to the issuer is not an additional privacy concern.

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
- The issuer signs the full attribute set once, binding the credential to the holder's BLS public key via `bbs_bound::sign()`
- The holder selects which messages to reveal
- The derived proof cryptographically demonstrates that hidden values were included in the original issuer signature, and that the prover holds the BLS secret key bound into the credential
- The holder binds the C2PA asset hash into the presentation header, on which its private key is applied (effectively signing the C2PA asset using the BBS credential)
- Each proof derivation uses fresh randomness, producing different bytes (unlinkable)

The presentation header binding used by this demo is:

```text
"c2pa-bbs-claim-hash:" || hex_decode(claim_hash)
```

This ensures the BBS presentation is tied to the specific asset being certified.

### Signing And Verification Flow

Signing in the demo has two explicit steps:

1. The issuer creates a toy BBS-bound credential over the holder attributes, binding it to the holder's BLS public key.
2. The holder computes the asset hash before manifest embedding, derives a holder-bound selective-disclosure proof from the credential using their BLS secret key, and embeds that proof into the C2PA manifest.

Verification in the demo does the reverse:

1. Read the manifest and extract the `bbs-signer-proof` assertion.
2. Remove the embedded JUMBF from a temporary copy of the asset.
3. Recompute the asset hash on that manifest-stripped copy.
4. Reconstruct the presentation header and verify the BBS-bound proof against the disclosed attributes and issuer public key.

This means the verifier now checks the BBS disclosure proof (including holder binding), and the integrity of the non-manifest asset bytes.

### Demo Certificate Chain

`c2pa-rs` still expects a valid X.509 chain when serializing a manifest, even though the proof payload is non-standard. To satisfy that requirement, the demo ships an in-repo CA/leaf pair and embeds the chain in the custom COSE object. This is purely to interoperate with the current library behavior; the privacy logic is carried by the BBS credential and presentation, not by the X.509 chain.

### BBS Library

This implementation uses [MATTR's `pairing_crypto`](https://github.com/mattrglobal/pairing_crypto) (`draft-latest` branch), which tracks the latest IRTF CFRG draft (`draft-irtf-cfrg-bbs-signatures-10`) and provides:
- BLS12-381 + SHA-256 ciphersuite
- Signature and proof derivation APIs
- Proof verification

### Limitations

The prototype uses deterministic demo keys for both the issuer (BBS key pair) and the holder (BLS key pair), and stores the issued credential as a local JSON file. A production system would anchor the issuer key in a real trust framework, protect holder keys and credentials at rest (e.g., in a secure wallet), and define how the holder obtains and manages credentials out of band.

Additional limitations of the current prototype:

- It uses a toy local credential file (with the holder's BLS secret key stored alongside) instead of a real wallet or credential exchange.
- It relies on a private-use COSE algorithm value rather than a standardized C2PA extension.
- It embeds a demo X.509 chain only to satisfy current `c2pa-rs` manifest-writing requirements.
- It does not yet model revocation, issuer policy discovery, or a production trust registry for BBS issuers.
- The holder BLS key pair is generated deterministically from a static seed; a real system would generate random holder keys.

## Test Assets

- `fixtures/cards.png` — Test image from [microsoft/c2pa-extension-validator](https://github.com/microsoft/c2pa-extension-validator)

## References

- [BBS Signatures (IETF Draft)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) specification
- [MATTR pairing_crypto](https://github.com/mattrglobal/pairing_crypto) BBS library 
- [c2pa-rs](https://github.com/contentauth/c2pa-rs) C2PA rust library
