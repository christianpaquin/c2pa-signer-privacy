# BBS Signatures Demo

This project implements **Strategy 1 – BBS-based signer privacy** from the v2 plan. It demonstrates how to build and verify C2PA manifests whose signatures are replaced by a selective-disclosure BBS/BBS+ proof over the C2PA claim hash.

**Status: ✅ Complete** — End-to-end sign/verify flow is fully functional with 4 passing integration tests.

## Components

- **Rust crate `c2pa-bbs-demo`** (workspace root)
  - `c2pa-bbs-sign`: CLI that builds C2PA manifests containing a `bbs-signer-proof` assertion.
  - `c2pa-bbs-verify`: CLI that validates the proof, the revealed attributes, and the claim hash binding.
- **Example assets** and scripts for running the sign/verify flow end-to-end.

## Quick Start

```bash
# Build everything
cargo build --workspace

# Sign an asset with BBS signer privacy
cargo run -p c2pa-bbs-demo --bin c2pa-bbs-sign -- \
  --input fixtures/cards.png \
  --output /tmp/signed.png \
  --issuer "MyOrg" \
  --policy "trusted-editor-v1"

# Verify the signed asset
cargo run -p c2pa-bbs-demo --bin c2pa-bbs-verify -- \
  --input /tmp/signed.png

# Run all integration tests
cargo test -p c2pa-bbs-demo --test integration
```

## Sample Asset

- `fixtures/cards.png` — test image copied from the [microsoft/c2pa-extension-validator](https://github.com/microsoft/c2pa-extension-validator) media fixtures (`test/media/cards.png`).
- Use it with the CLIs via `--input fixtures/cards.png` to verify the signing and verification flows without hunting for your own media.

## Data Model

BBS credential attributes:
- `issuer` and `policy` are revealed.
- `editor_id` and `device_id` remain hidden.
- `claim_hash` (from `c2pa-rs`) is bound inside the proof as an external message.

Manifest assertion prototype:

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
  "scheme": "bbs+"
}
```

## BBS Library Choice

We depend on [MATTR's `pairing_crypto`](external/pairing_crypto) (commit `5c35d52`) for all BBS/BBS+ primitives. That crate tracks the current IRTF CFRG draft (`draft-irtf-cfrg-bbs-signatures-03`) and gives us:
- Deterministic demo key material for rapid prototyping.
- A reference BLS12-381 + SHA-256 ciphersuite with signature + proof derivation APIs.
- Matching proof verification logic we can reuse in the `c2pa-bbs-verify` CLI once the manifest plumbing lands.

## Implementation Stages

1. **Workspace scaffolding**
   - Create a Cargo workspace with shared dependencies on `c2pa` and a BBS/BBS+ crate (e.g., `bbs` or `ursa`).
   - Define shared types for credential schemas, proofs, and manifest assertions.
2. **Signing flow (`c2pa-bbs-sign`)**
   - Compute the C2PA claim hash using `c2pa-rs`.
   - Generate or load a BBS credential + signature.
   - Produce a selective-disclosure proof revealing `issuer` and `policy` while binding `claim_hash`.
   - Embed the assertion and write the manifest.
3. **Verification flow (`c2pa-bbs-verify`)**
   - Recompute the claim hash for the asset.
   - Extract the `bbs-signer-proof` assertion and validate the proof against the known BBS public key.
   - Display the revealed attributes and verification status.
4. **Docs and demos**
   - Provide example assets and walkthroughs comparing the privacy-preserving flow to standard C2PA signatures.

## Completed Work

- ✅ Compute real C2PA claim hashes (via `c2pa-rs`) and wire them into the proof binding.
- ✅ Implement manifest embedding/extraction helpers that swap in the `bbs-signer-proof` assertion.
- ✅ Custom COSE algorithm (`alg = -65535`) with `crit = ["c2pa-bbs"]` header.
- ✅ BBS public key embedded in assertion for verifier self-sufficiency.
- ✅ Integration tests covering round-trip, attribute matching, and error cases.

## Future Work

- Replace the static demo key with a proper VC hierarchy (DID + credential subject).
- Engage with C2PA spec authors about a formal experimental algorithm registry.
- Parameterize the CLIs to accept custom BBS key material.
