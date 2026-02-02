# BBS Claim Signature Integration Design

_Last updated: 2026-01-12_

**Implementation Status: ✅ Complete**

## Context

Strategy 1 replaces the standard COSE claim signature (ECDSA, RSA, or EdDSA over an X.509 credential) with a selective-disclosure BBS proof while leaving the rest of the C2PA manifest pipeline intact. The goal is to show how signer identity/privacy can be decoupled from the manifest by hiding private attributes (e.g., device identifiers) yet revealing verifiable policy statements.

Authority references:
- C2PA v2.2 specification sections 10 (Claims), 11 (Manifests), 13 (Digital Signatures), 14 (Trust Model), and 15 (Validation).
- MATTR `pairing_crypto` BBS implementation targeting the CFRG draft (`draft-irtf-cfrg-bbs-signatures-03`).

## Constraints & Assumptions

1. **Claim structure untouched**: We still emit `c2pa.claim.v2` with the usual `created_assertions`, content bindings, and `claim_generator_info`. Hashing and CBOR serialization follow Section 10.3 exactly.
2. **COSE envelope retained**: The claim signature remains a `COSE_Sign1_Tagged` object stored in `c2pa.signature`. The only deviation is the algorithm and payload interpretation described below.
3. **Single unauthenticated BBS key**: For this demo the signer’s BBS key pair is static and local. It is _not_ anchored to a credential hierarchy yet. Future work will bind it into a Verifiable Credential (VC) or similar chain, but the manifest design should allow slotting that in without structural changes.
4. **Explicit deviation markers**: Because Section 13.2.1 only authorizes ES/PS/EdDSA, we must clearly mark our manifest as using an experimental algorithm so downstream validators fail fast instead of misinterpreting data.

## Demo Certificate Chain (Implementation Note)

`c2pa-rs` still insists on a valid X.509 chain before it will serialize a manifest, even when the signature payload is non-standard. To unblock local testing we now ship an in-repo CA/leaf pair generated on 2025-12-15:

- [crates/c2pa-bbs-demo/resources/demo-bbs-ca.pem](crates/c2pa-bbs-demo/resources/demo-bbs-ca.pem) / `.der`
  - Self-signed CA with `basicConstraints=critical,CA:true`, 4096-bit RSA, SHA-256, SKI and AKI present, and `keyCertSign` usage.
- [crates/c2pa-bbs-demo/resources/demo-bbs-leaf.pem](crates/c2pa-bbs-demo/resources/demo-bbs-leaf.pem) / `.der`
  - 3072-bit RSA, `keyUsage=critical,digitalSignature,nonRepudiation`, and `extendedKeyUsage=critical,1.3.6.1.5.5.7.3.36` (Document Signing OID that C2PA accepts by default).
- The OpenSSL CSR template lives at [crates/c2pa-bbs-demo/resources/demo-bbs-leaf.cnf](crates/c2pa-bbs-demo/resources/demo-bbs-leaf.cnf) so we can reissue the leaf quickly if parameters change.

`BbsProofSigner` returns the full `[leaf, CA]` chain via `certs()` and uses `direct_cose_handling() = true` to emit a complete COSE_Sign1 structure with the private-use algorithm identifier.

## Implemented Manifest Changes

### 1. Custom COSE Algorithm Identifier (Implemented)

The signer now builds a proper COSE_Sign1 structure with:
- `alg = -65535` (private-use value for BBS)
- `crit = ["c2pa-bbs"]` so conformant parsers know an extension is required
- `x5chain` containing the demo certificate chain (for c2pa-rs compatibility)
- `c2pa-bbs = <CBOR map>` with:
  - `scheme`: `"bbs"`
  - `version`: `"0.1"`  
  - `public_key`: raw bytes of the BBS public key (48 bytes BLS12-381 G1)

The signature field contains the BBS proof bytes. The payload is detached (nil) per C2PA Section 13.2.2.

**Verification note:** Standard c2pa validators reject the custom algorithm. The `c2pa-bbs-verify` CLI disables c2pa's built-in COSE validation via `settings::load_settings_from_str()` and performs BBS proof verification directly.

### 2. BBS Assertion Marker (Implemented)

Add a custom assertion referenced in `created_assertions`:

```json
{
  "type": "bbs-signer-proof",
  "version": "0.1",
  "scheme": "bbs",
  "public_attributes": {
    "issuer": "ExampleOrg",
    "policy": "trusted-editor-v1"
  },
  "claim_hash": "<hex SHA-256 of original asset>",
  "proof": "<base64 BBS proof bytes>",
  "public_key": "<base64 BBS public key, 48 bytes BLS12-381 G1>"
}
```

The `public_key` field allows any verifier to validate the proof without sharing the signer's IKM. This serves as a UX-level hint and gives validators a place to expose the revealed attributes without re-parsing the COSE structure.

### 3. Proof Binding

The BBS proof binds the C2PA claim hash via the presentation header:

```
presentation_header = "c2pa-bbs-claim-hash:" || hex_decode(claim_hash)
```

This is already implemented inside `generate_bbs_proof()` and used again in `verify_bbs_proof()`. Including that binding string spec in the design doc ensures the same format is used when the manifest is finalized.

## Signing Flow Impact

1. Build the claim and compute its hash (`compute_claim_hash()` placeholder becomes real once `c2pa-rs` integration lands).
2. Produce a BBS signature over all attributes, then derive a selective-disclosure proof revealing only issuer + policy and binding the presentation header to the claim hash.
3. Serialize the proof into the COSE `signature` slot along with the headers above.
4. Write the custom `c2pa.bbs.signature-info` assertion into the assertion store and reference it from `created_assertions`.

Everything else in the manifest store (hash assertions, thumbnails, ingredients, etc.) is unchanged, so standard validators will fail specifically at `algorithm.unsupported` (Section 15.7) yet still see the marker assertion explaining why.

## Verification Flow Impact

1. Parse the manifest and locate `c2pa.signature`. Detect `crit` includes `"c2pa-bbs"` with `alg = -65535`.
2. Recompute the claim hash, reconstruct the presentation header, and call `verify_bbs_proof()` using the proof bytes and message order from the header.
3. Compare revealed attributes against `c2pa.bbs.signature-info` for sanity.
4. If future credential binding is added, this is where the VC hierarchy would be checked before reporting trust status.

## Future Work

- Replace the static key with a proper VC hierarchy (e.g., DID + credential subject) and record a pointer to that VC inside `c2pa-bbs`.
- Decide how to expose issuer policy metadata in a standard assertion so other tools can consume it without custom logic.
- Engage with C2PA spec authors about a formal experimental algorithm registry to avoid relying on private `alg` values long-term.

## Completed Work Log

- ✅ Custom COSE algorithm (`alg = -65535`) with `crit` header and `c2pa-bbs` extension map.
- ✅ BBS public key embedded in both COSE header and assertion for verifier self-sufficiency.
- ✅ Claim hash preserved in assertion so verifier can validate proof binding without re-hashing modified asset.
- ✅ Integration tests (4 tests: round-trip, attribute matching, wrong issuer, wrong policy).
- ✅ Demo certificate chain with proper C2PA extensions (Document Signing EKU).
