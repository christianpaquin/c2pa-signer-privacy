# X.509 Zero-Knowledge Anonymizer Demo

This project implements **Strategy 2 – X.509 + ZK anonymizing editor** from the v2 plan. It replaces an existing X.509/COSE signature in a C2PA manifest with a Circom-based ZK proof that the asset was signed by a certificate issued by a trusted CA, without revealing the signer's identity.

**Status: 🚧 In Progress** — Core components complete, awaiting Groth16 trusted setup completion.

## Project Structure

```
zk-proofs/
├── Cargo.toml                      # Rust workspace
├── README.md
├── generate-test-assets.sh         # Certificate generation script
├── circuits/                       # Circom ZK circuits
│   ├── c2pa_signer_proof.circom    # Main proof circuit
│   ├── circom-ecdsa-p256/          # P-256 ECDSA verification library
│   ├── pot21_final.ptau            # Powers of Tau (2^21 constraints)
│   ├── package.json                # snarkjs dependencies
│   └── build/                      # Compiled circuits and keys
├── crates/
│   └── c2pa-x509-zk-demo/          # Rust library + CLIs
│       ├── src/
│       │   ├── lib.rs              # Re-exports, X509ZkSignerProofAssertion
│       │   ├── circuit.rs          # CircuitInputs, snarkjs bridge
│       │   ├── manifest.rs         # ZkProofSigner, manifest rewriting
│       │   └── bin/
│       │       ├── sign.rs         # Standard X.509/ECDSA signer
│       │       ├── editor.rs       # Anonymizing editor CLI
│       │       └── verify.rs       # ZK proof verifier CLI
│       └── tests/
│           └── integration.rs      # End-to-end tests
└── fixtures/
    ├── cards.png                   # Test input image
    ├── cards-signed.png            # Test asset signed with ES256
    └── certs/
        ├── ca-cert.pem/.der        # P-256 CA certificate
        ├── ca-key.pem              # CA private key
        ├── signer-cert.pem/.der    # P-256 signer certificate
        └── signer-key.pem          # Signer private key
```

## Components

### Rust Crate (`c2pa-x509-zk-demo`)

| Binary | Description |
|--------|-------------|
| `c2pa-x509-zk-sign` | Create standard C2PA signed assets (ES256/P-256) |
| `c2pa-x509-zk-editor` | Anonymize signed assets by replacing COSE signature with ZK proof |
| `c2pa-x509-zk-verify` | Verify anonymized assets against trusted CA |

### Circom Circuits

| Circuit | Constraints | Description |
|---------|-------------|-------------|
| `c2pa_signer_proof.circom` | ~2M | Proves ECDSA signature over claim hash using P-256 key |

The circuit uses `circom-ecdsa-p256` for full P-256 ECDSA verification (~30s proving time expected).

### Custom COSE Format

Anonymized manifests use a custom COSE algorithm:
- `alg = -65534` (experimental range)
- `crit = ["c2pa-x509-zk"]`
- Extension map with circuit metadata

## Quick Start

### 1. Build the Rust workspace

```bash
cd zk-proofs
cargo build --workspace
```

### 2. Generate test certificates (optional, already included)

```bash
./generate-test-assets.sh
```

### 3. Sign an asset with standard X.509/ECDSA

```bash
cargo run --bin c2pa-x509-zk-sign -- \
  --input fixtures/cards.png \
  --output /tmp/signed.png \
  --cert fixtures/certs/signer-cert.pem \
  --key fixtures/certs/signer-key.pem \
  --ca fixtures/certs/ca-cert.pem
```

### 4. Anonymize the signed asset

```bash
cargo run --bin c2pa-x509-zk-editor -- \
  --input /tmp/signed.png \
  --output /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem
```

### 5. Verify the anonymized asset

```bash
cargo run --bin c2pa-x509-zk-verify -- \
  --input /tmp/anon.png \
  --ca fixtures/certs/ca-cert.pem
```

## ZK Proof Statement

**Public inputs:**
- `issuerHash[4]`: SHA-256 hash of CA public key (4 × 64-bit limbs)
- `claimHash[6]`: C2PA claim hash (6 × 43-bit registers)
- `signerPubkey[2][6]`: Signer's P-256 public key (X, Y coordinates)

**Private inputs (witness):**
- `claimSigR[6]`, `claimSigS[6]`: ECDSA signature (r, s) over claim hash

**Relations proved:**
1. The signer's public key is bound to a certificate issued by the CA (via issuerHash).
2. A valid ECDSA signature exists over the claim hash using the signer's private key.

The circuit does NOT verify the full X.509 chain in-circuit (for simplicity). Instead:
- The `issuerHash` is a commitment to the CA's public key.
- The verifier checks that `issuerHash` matches the trusted CA's key ID.
- This is sufficient for the demo to prove the concept.

## Building Circuits

> ⚠️ **Warning: Long Build Time**  
> The Groth16 trusted setup for this circuit takes **2-4+ hours** due to ~2M constraints (448MB r1cs).  
> The `snarkjs groth16 setup` command produces **no output** until completion — this is normal.  
> You can verify it's working by checking CPU usage: `top -p $(pgrep -f "node.*snarkjs")`

```bash
cd circuits

# Install dependencies
npm install

# Download Powers of Tau (1.4GB, supports 2^21 constraints)
curl -O https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau
mv powersOfTau28_hez_final_21.ptau pot21_final.ptau

# Compile circuit (~5-10 minutes)
circom c2pa_signer_proof.circom --r1cs --wasm --sym -o build/

# Groth16 trusted setup (⚠️ 2-4+ HOURS, no progress output)
# Verify it's running: CPU should be at ~100%
npx snarkjs groth16 setup build/c2pa_signer_proof.r1cs pot21_final.ptau build/c2pa_signer_proof_0000.zkey

# Contribute to ceremony and export keys
npx snarkjs zkey contribute build/c2pa_signer_proof_0000.zkey build/c2pa_signer_proof.zkey --name="Demo contribution" -e="some random entropy"
npx snarkjs zkey export verificationkey build/c2pa_signer_proof.zkey build/verification_key.json
```

**Why so long?** The circuit uses full P-256 ECDSA verification from `circom-ecdsa-p256`, which requires ~2M constraints. This is the trade-off for cryptographic soundness. Alternative approaches (simplified circuits, different curves) would be faster but less realistic.

## Running Tests

```bash
cargo test --package c2pa-x509-zk-demo
```

Tests include:
- `sign_creates_valid_asset`: Standard signing produces valid C2PA asset.
- `editor_creates_anonymized_asset_placeholder`: Editor rewrites manifest correctly.
- `verify_recognizes_placeholder_proof`: Verifier identifies placeholder proofs.
- `verify_fails_with_wrong_ca`: Wrong CA certificate correctly rejected.

## High-Level Flow

```
┌─────────────────────┐     ┌────────────────────┐     ┌──────────────────┐
│  Original Asset     │     │  Anonymizing       │     │  Anonymized      │
│  (X.509/COSE sig)   │ ──▶ │  Editor            │ ──▶ │  Asset           │
│                     │     │                    │     │  (ZK proof)      │
└─────────────────────┘     └────────────────────┘     └──────────────────┘
        │                           │                          │
        │                           │                          │
        ▼                           ▼                          ▼
  ┌──────────────┐           ┌──────────────┐           ┌──────────────┐
  │ Manifest     │           │ Generate ZK  │           │ x509-zk-     │
  │ - x5c chain  │           │ proof binding│           │ signer-proof │
  │ - COSE sig   │           │ claim hash   │           │ assertion    │
  │ - claim hash │           │ to CA        │           │ (no x5c)     │
  └──────────────┘           └──────────────┘           └──────────────┘
```

## Implementation Notes

### Certificate Requirements

Certificates must use:
- **P-256 ECDSA** (secp256r1 / prime256v1)
- **Document Signing EKU** (1.3.6.1.5.5.7.3.36) for C2PA compatibility

### Placeholder Mode

Before circuits are built, the editor generates placeholder proofs. The verifier detects these and prints a warning. This allows testing the full flow without waiting for the multi-hour trusted setup.

**To test without building circuits:**
```bash
cargo test --package c2pa-x509-zk-demo
```

All tests pass with placeholder proofs, validating the manifest structure, assertion format, and CA key ID verification.

### snarkjs Integration

The Rust code invokes `node` + `snarkjs` via subprocess for:
- Witness generation: `snarkjs wtns calculate`
- Proof generation: `snarkjs groth16 prove`
- Proof verification: `snarkjs groth16 verify`

This keeps the implementation simple while using battle-tested proving infrastructure.

## Future Enhancements

1. **Full X.509 chain verification in-circuit**: Use `asn1-parser-circom` to parse certificates and verify the CA signature.
2. **Attribute revelation**: Allow selective disclosure of certificate fields (e.g., organization name).
3. **Performance optimization**: Consider PLONK or recursive proofs for faster verification.
4. **Native Rust proving**: Replace snarkjs with `ark-groth16` for pure-Rust implementation.
