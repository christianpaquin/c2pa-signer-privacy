# C2PA Signer Privacy

This project explores privacy-preserving signature schemes for [C2PA](https://c2pa.org/) (Coalition for Content Provenance and Authenticity) manifests. The goal is to allow verification of content authenticity while protecting the identity of individual signers.

## Approaches

Two proof-of-concept implementations demonstrate different privacy strategies:

| Approach | Description | Documentation |
|----------|-------------|---------------|
| **BBS Signatures** | Replace ECDSA with BBS signatures supporting selective disclosure and unlinkable proofs | [bbs-signatures/](bbs-signatures/README.md) |
| **X.509 + ZK Proofs** | Keep standard X.509/ECDSA signing, add a post-processing step that replaces the signature with a zero-knowledge proof | [zk-proofs/](zk-proofs/README.md) |

## Comparison

| Feature | BBS Signatures | X.509 + ZK Proofs |
|---------|----------------|-------------------|
| **Signing algorithm** | BBS (new) | ECDSA P-256 (standard) |
| **PKI compatibility** | Requires new CA infrastructure | Works with existing X.509 |
| **Privacy model** | Selective attribute disclosure | Hide signer, reveal CA |
| **Signer identity hidden** | ✅ Yes | ✅ Yes |
| **Proof generation time** | ~2ms | ~4-5 minutes |
| **Verification time** | ~3ms | 11ms |
| **Setup required** | None | Trusted setup (one-time) |
| **Proof size** | ~500 bytes | ~1KB |
| **Randomized proofs** | ✅ Different bytes each time | ❌ Deterministic |

> **Note on unlinkability**: Both approaches hide the signer's identity from verifiers. BBS proofs are randomized (same content can be distributed multiple times without correlation), while Groth16 proofs are deterministic (same inputs → same proof).

## Project Structure

```
c2pa-signer-privacy/
├── README.md                    # This file
├── bbs-signatures/              # BBS implementation
│   ├── crates/c2pa-bbs-demo/    # CLI tools and library
│   ├── docs/bbs-c2pa-design.md  # Design details
│   └── fixtures/                # Test images
├── zk-proofs/                   # X.509 + ZK implementation  
│   ├── circuits/                # Circom circuits
│   ├── crates/c2pa-x509-zk-demo/ # CLI tools and library
│   └── fixtures/                # Test certs and images
└── external/
    └── pairing_crypto/          # BBS crypto library (submodule)
```

## License

MIT

## References

- [C2PA Specification](https://c2pa.org/specifications/)
- [BBS Signatures (IETF Draft)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
- [Groth16 zkSNARK](https://eprint.iacr.org/2016/260)
