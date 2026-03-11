# C2PA Signer Privacy

This project explores privacy-preserving signature schemes for [C2PA](https://c2pa.org/) (Coalition for Content Provenance and Authenticity) manifests, as described in this [blog post](https://christianpaquin.github.io/2026-03-13-privacy-for-c2pa-signers.html). The goal is to allow verification of content authenticity while protecting the identity of individual signers.

## Approaches

Two proof-of-concept implementations demonstrate different privacy strategies:

| Approach | Description | Documentation |
|----------|-------------|---------------|
| **BBS Signatures** | Toy issuer/holder flow using BBS credentials, selective disclosure, and C2PA hash-bound presentations | [bbs-signatures/](bbs-signatures/README.md) |
| **X.509 + ZK Proofs** | Keep standard X.509/ECDSA signing, add a post-processing step that replaces the signature with a zero-knowledge proof | [zk-proofs/](zk-proofs/README.md) |

## Comparison

| Feature | BBS Signatures | X.509 + ZK Proofs |
|---------|----------------|-------------------|
| **Signing algorithm** | BBS (new) | ECDSA P-256 (standard) |
| **PKI compatibility** | Requires new CA infrastructure | Works with existing X.509 |
| **Privacy model** | Selective attribute disclosure | Hide signer, reveal CA |
| **Signer identity hidden** | ✅ Yes | ✅ Yes |
| **Proof generation time** | ~2ms | Very slow, hardware-dependent |
| **Verification time** | ~3ms | Fast once a proof exists |
| **Setup required** | None | Trusted setup (one-time) |
| **Proof size** | ~500 bytes | ~1KB |
| **Randomized proofs** | ✅ Different bytes each time | ✅ Different bytes each time |

## Dependencies

Both subprojects depend on the [`c2pa` Rust library](https://github.com/contentauth/c2pa-rs) (v0.33) for C2PA manifest handling (reading, writing, and validating manifests).

## Project Structure

```
c2pa-signer-privacy/
├── README.md                    # This file
├── bbs-signatures/              # BBS implementation
│   ├── crates/c2pa-bbs-demo/    # CLI tools and library
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
