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
# This step is slow: ~20 minutes and ~28 GB of RAM (see Performance).
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

The in-circuit SHA-256 is implemented via `Sha256Bytes(1536)` from `@zk-email/circuits`.  The prover supplies `tbsHashPaddedBytes[1536]` (the TBS DER bytes with standard SHA-256 padding) and the circuit verifies that the first `4+tbsLen` bytes match `certDer[tbsOffset..]`, then hashes the buffer in-circuit and feeds the result into the CA ECDSA check.

### Constraint Count

The compiled circuit has **12,073,163 constraints** (measured: reported by `circom` and recorded in the `.r1cs` header). Use this value for capacity planning.

The per-component figures below are estimates, not measurements:

| Component | Constraints (estimated) |
|---|-----------|
| `ECDSAVerifyNoPubkeyCheck` × 2 (Steps 2 + 4) | ~3,945,000 |
| `X509Parse` TBS binding (1536 × `SelectByte` + 1536 × `LessEqThan`) | ~4,320,000 |
| `Sha256Bytes(1536)` | ~720,000 |
| SPKI extraction (64 × `SelectByte`) | ~90,000 |
| UTCTime parsing (2 × `UTCTimeToUnix`) | ~500 |
| Validity period range checks (`Num2Bits(32)` × 2) | ~70 |
| Sum of estimates | ~9,076,000 |
| **Measured total** | **12,073,163** |

> **Note:** The estimates leave ~3M constraints (about a quarter of the circuit) unaccounted for. Wiring, `BytesToRegisters` conversions, and other glue logic explain some of the gap, but at least one component estimate is probably too low. Per-component measurements are planned as part of [roadmap item 2](#2-quick-circuit-win-cheaper-tbs-binding).

For a production multi-party trusted setup (MPC ceremony) this circuit class would require a **2²⁴** (~16.7M) Powers of Tau file.  **For this demo no ptau download is needed** — `ark-groth16` performs a local single-party setup directly from the `.r1cs` file.

### Potential Optimisations

A note on proof size before listing the ideas: a Groth16 proof over BN254 is ~128 bytes (3 G1 + 1 G2, compressed) regardless of circuit size, so the headline "~1 KB" figure is dominated by serialization and public inputs rather than the SNARK itself. Shrinking the wire-format proof is mostly a public-input problem; shrinking proving time is where the cryptographic wins are.

The first two items below are circuit-level tweaks that keep the current proof statement intact. The remaining items are deeper changes that restructure what is proved, switch the proof system, or compress public inputs.

#### TBS binding

The `SelectByte` calls for TBS binding (the dominant cost) can be replaced with `VarShiftLeft` from `@zk-email/circuits/utils/array.circom`, reducing the TBS binding cost from ~4.3M constraints to ~500K constraints (~8.3M total based on measured baseline, still within the pot24 ceremony class).

#### Efficient ECDSA

The **Efficient ECDSA** technique (sometimes called the "NOPE" circuit, from [Personae Labs](https://personaelabs.org/posts/efficient-ecdsa-1/)) eliminates the fixed-base G scalar multiplication from signature verification by computing it off-circuit and supplying the result as a witness T. This would reduce each `ECDSAVerifyNoPubkeyCheck` (~1.3M constraints) to roughly ~700K constraints.

#### Cryptographic improvements

These restructure the protocol rather than the circuit. They generally trade an assumption (CA cooperation, an out-of-band trust artefact, or a different proof system) for a substantially smaller and/or faster proof. Constraint savings below are relative to the ~12M measured baseline.

##### CA-published accumulator of issued SPKIs

Replace the in-circuit CA signature verification with a Merkle membership proof against a CA-published accumulator over currently-valid subject public keys. The CA periodically publishes a signed root; the ZK proof becomes "the committed SPKI is a leaf under that root, and the prover holds its private key." This eliminates the CA ECDSA verification (~1.97M), the SHA-256 over TBS (~720K), and the TBS-binding logic (~4.3M with `SelectByte`) — together more than half the circuit. RFC 5280 field validity (`notBefore`, `notAfter`, EKU, key usage) is enforced by the CA at root-publication time rather than in-circuit, and revocation reduces to "drop the leaf from the next root." Trade-off: verifiers must fetch a fresh signed root, and the anonymity set becomes "valid at root time" rather than "ever issued."

##### Sigma-protocol key possession bound to the SNARK

Move the second P-256 ECDSA verification (the prover's "key possession" check, ~1.97M constraints) out of the SNARK. The SNARK instead outputs a Pedersen commitment to the SPKI on a SNARK-friendly curve (e.g. Baby Jubjub, a few thousand constraints). Outside the SNARK the signer produces a Schnorr proof of knowledge of the secret key for the committed SPKI, with Fiat–Shamir bound to `claimHash`. The Schnorr proof is ~64–96 bytes and verifies in microseconds. Net effect: one fewer non-native ECDSA in-circuit, at the cost of a small Pedersen subcircuit and a short companion proof. Composes with the accumulator approach above.

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
| Constraints (with VarShiftLeft TBS binding) | ~8,250,000 (estimated) | Replace 1536 × SelectByte with VarShiftLeft from @zk-email/circuits; depends on the TBS-binding estimate above |
| Constraints (with Efficient ECDSA for Step 4) | ~11,470,000 (estimated) | See optimisation note above — soundness caveat applies |
| Proving key size | ~2.3 GB (measured) | Native Rust key generated by `ark-groth16` from `.r1cs` |
| Verifying key size | 872 bytes (measured) | Constant for Groth16 |
| Proof size | ~1 KB | Constant for Groth16 |
| Production ceremony class | pot24 (~16.7M constraints) | Not needed for this demo — `ark-groth16` runs local setup |

### Performance

Measured on a 20-core machine with 31 GB of RAM (WSL2). Expect different times on other hardware, but similar memory use.

| Phase | Time | Peak RAM | Notes |
|-------|------|----------|-------|
| Circuit compilation | ~15 min | ~23 GB | One-time (`circom`) |
| Trusted setup | ~6.5 min | ~24 GB | One-time, native Rust |
| Anonymization (witness + proof) | ~20 min | ~28 GB | Per asset; witness generation runs the circuit's WASM |
| Verification | ~0.03 s | ~13 MB | Per asset |

**A machine with at least 32 GB of RAM is required** for the real-proof flow; on 16 GB machines compilation, setup, and proving will fail. Use [Placeholder Mode](#placeholder-mode) on smaller machines.

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

# Run trusted setup (~6.5 minutes, ~24 GB RAM) — generates proving and verifying keys
# Must run from zk-proofs/, not circuits/
cargo run --release --bin c2pa-x509-zk-setup -- --circuits-dir circuits
```

This generates the proving and verifying keys in `circuits/build/`.

> **Note**: The native Rust prover (`ark-groth16`) generates its own circuit-specific keys
> directly from the compiled `.r1cs` + `.wasm` files using a local random seed.  No
> external Powers of Tau ceremony file is needed — `ark-groth16::generate_random_parameters_with_reduction`
> handles the setup in one pass.
>
> If keys already exist, setup does nothing, even if the circuit has changed. After
> recompiling a modified circuit, delete `circuits/build/x509_issue_and_possession_native.{pk,vk}`
> before re-running setup, or proofs will fail.

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

If you haven't completed the circuit setup, the anonymizer can embed a placeholder proof instead of a real ZK proof. This lets you exercise the full manifest pipeline — sign, anonymize, verify — immediately after `cargo build`, without circuit compilation (~15 min), trusted setup (~6.5 min), or ~20-minute proof generation, and without needing 32 GB of RAM.

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

The goal is to move this prototype from a demo toward something that works in realistic deployments, with stronger security and privacy guarantees. Each item below is planned as its own PR, roughly in this order.

### 1. Standards-conformant COSE encoding ✅

Done for both prototypes. The COSE structures previously could not be parsed by strict COSE parsers, including the one in `c2pa-rs`:

- The algorithm identifiers were not in the COSE private-use range: `-65534` is registered by IANA as `A128CTR`, and the BBS prototype's `-65535` as `RS1`. They are now `-65538` (ZK) and `-65537` (BBS).
- `crit` was written under the text label `"crit"` rather than COSE header label 2, so nothing was actually marked critical.
- The structure was padded with trailing zero bytes. Padding is now a `pad` field in the unprotected header, as `c2pa-rs` does.

Result: `c2patool` now displays BBS-signed assets and reports `algorithm.unsupported`, the correct outcome for a custom algorithm. ZK-anonymized assets still fail in `c2patool`'s default (validating) mode, now with "could not find signing certificate chain": `c2pa-rs` treats a missing signing certificate as a fatal error rather than a validation failure (`get_signing_cert_serial_num` in `claim_verify.rs`). With verification disabled, `c2patool` displays the manifest. Resolving this depends on item 4 and possibly an upstream `c2pa-rs` change.

Both prototypes' manifests also lack a `c2pa.created` action, which `c2patool` reports as `assertion.action.malformed`; this should be fixed alongside item 5.

### 2. Quick circuit win: cheaper TBS binding

Replace the 1536 `SelectByte` calls in the TBS binding with `VarShiftLeft` from `@zk-email/circuits` (see [TBS binding](#tbs-binding)): an estimated reduction from ~12M to ~8.3M constraints, without changing what the circuit proves. That estimate rests on the per-component estimates in [Constraint Count](#constraint-count), which leave ~3M constraints unexplained, so the first step is to measure each component by compiling it on its own, and to report the gain as measured before and after. This lowers the cost of every later real-proof test run, and stays worthwhile whatever the architecture decisions below conclude.

Because it changes the circuit, it also needs setup to detect a stale proving key (for example, by recording a hash of the `.r1cs` alongside the keys) instead of silently reusing keys from an older circuit.

### 3. Architecture decisions

Several items below depend on choices that change what the CA must do, what the circuit proves, or which proof system is used. These are laid out in [ARCHITECTURE-DECISIONS.md](ARCHITECTURE-DECISIONS.md), to be settled before the items that depend on them:

- **D1. Trust model:** existing PKI only, a CA-published accumulator, or a SNARK-friendly "twin" signature from the CA. Affects items 7 and 8.
- **D2. Proof system:** Groth16/circom, a PLONKish system, folding, or a proof system designed for ECDSA credentials. Affects item 10 and most circuit work.
- **D3. Curve:** BN254 (~100-bit security) or BLS12-381 (~120-bit). Follows D2.
- **D4. Where the issuing CA chain lives.** Affects item 4.
- **D5. How key possession is proved:** in-circuit ECDSA or an out-of-circuit Sigma protocol. Affects item 5.

Item 4 can proceed in parallel once D4 is settled.

### 4. Intermediate CAs and verifier trust lists

Real PKIs issue end-entity certificates from intermediate CAs, which verifiers often do not hold in advance. The circuit already proves issuance by whichever CA key is a public input, so no circuit change is needed:

- The anonymizer embeds the issuing CA's chain (intermediates up to, but excluding, the root). It never embeds the signer's certificate.
- The verifier validates that chain to a root in a trust list (a directory of anchors, or the C2PA trust list format) instead of a single `--ca` file, and checks that the issuing CA's key matches the proof's public inputs.
- `issuer_key_id` becomes a stable key identifier (hash of the CA's SPKI, or its Subject Key Identifier) rather than a hash of the whole CA certificate, so it survives CA certificate renewal.

Depends on decision D4 (where the chain lives): the standard `x5chain` header requires the first certificate to be the signer's end-entity certificate, and `c2pa-rs` rejects a CA certificate in that position.

Privacy note: the issuing CA is disclosed by design, so the anonymity set is everyone that CA has issued certificates to. A narrowly scoped intermediate can nearly identify the signer (see item 9).

### 5. Bind the proof to the C2PA claim

The proof currently binds to a digest of the asset bytes with the manifest stripped, so nothing authenticates the rest of the manifest: other assertions can be changed without detection. The proof's public input should instead be the hash of the new claim, which already covers every assertion, including the hard binding to the asset bytes. The verifier can then re-enable standard `c2pa-rs` assertion and hash validation and only substitute the signature check.

Related: decision D5 (an out-of-circuit Sigma protocol for key possession would carry this binding instead of the in-circuit signature), and the missing `c2pa.created` action noted under item 1.

### 6. Meaningful timestamps

The `photoTimestamp` public input is chosen by the prover and ignored by the verifier, so a proof shows only that the certificate was valid at *some* time the prover picked, which an expired certificate can satisfy. The verifier should enforce a policy (for example, "within N hours of now" at anonymization time), and the timestamp should be anchored to an RFC 3161 time-stamp authority rather than self-reported.

### 7. Full certificate validation in the circuit

Complete the RFC 5280 / C2PA certificate-profile checks listed under [Pending](#zk-proof-statement): certificate version, signature algorithm OID, key usage, `CA:FALSE`, and the C2PA / document-signing EKU. Without these, any certificate the CA has issued (including a CA certificate) can produce a valid proof.

Depends on decision D1: with a CA-published accumulator, the CA validates certificates when it builds the root, and most of this item becomes unnecessary.

### 8. Revocation

Support revoked or compromised signer keys, either through short-lived certificates or through a CA-published accumulator of valid keys (see [CA-published accumulator](#ca-published-accumulator-of-issued-spkis)). The accumulator approach also removes most of the circuit's cost. Depends on decision D1.

### 9. Hiding the issuing CA among a trusted set

As the blog post suggests, prove membership of the issuing CA's key in a published set of trusted CAs (for example, a Merkle root over a trust list) instead of disclosing which CA issued the certificate. This enlarges the anonymity set beyond a single, possibly small, intermediate.

### 10. Production proving setup and performance

Depends on decisions D2 and D3. Replace the single-party local setup with a multi-party ceremony, or adopt a proof system without a circuit-specific trusted setup, and bring proving time and memory to something a signer will accept. The remaining [optimisations](#potential-optimisations) (Efficient ECDSA, after a soundness review; folding; public-input compression) apply here if the circom/Groth16 stack is kept.

### 11. Anonymizing without the signer's private key

The anonymizer currently re-signs the asset digest with the signer's key, so it must run on the signer's side. Supporting a third-party anonymizer would require proving, in-circuit, the validity of the *original* COSE signature over the original claim. This is a research item: it involves hashing the full claim in-circuit and deciding what happens to the original claim's contents.

### 12. Metadata privacy beyond the signature

Removing the certificate is necessary but not sufficient. The anonymizer should also check or scrub other identifying data: the claim generator and manifest identifiers, ingredients, and the asset's own metadata (for example EXIF camera serial numbers and GPS). The regression test for [#6](https://github.com/christianpaquin/c2pa-signer-privacy/issues/6) (`anonymized_asset_does_not_reveal_signer`) should be extended as each source is addressed.

### 13. Build, setup, and test infrastructure

- Generate test PKI at test time rather than relying on committed certificates with short validity periods.
- Run the placeholder-mode suite in CI, and periodically run the full real-proof end-to-end test (it needs ~28 GB of RAM).
- Fix key distribution. The committed `x509_issue_and_possession_native.vk` is not usable on its own: the matching proving key is not committed, so every user who runs setup generates new random keys and overwrites it. Either publish both keys from a single setup (the proving key is ~2.4 GB), or stop committing the verifying key.
- Bring `circuits/build.sh` in line with the working steps above. It currently uses a snarkjs/pot20 flow that is too small for this circuit and omits the include paths.

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
