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
| **PKI compatibility** | Requires new CA infrastructure | Works with existing PKI |
| **Privacy model** | Selective attribute disclosure | Hide signer, reveal CA |
| **Signer identity hidden** | ✅ Yes | ✅ Yes |
| **Proof generation time** | Fast | Slow |
| **Verification time** | Fast | Fast |
| **Setup required** | None | Trusted setup (one-time) |
| **Proof size** | ~500 bytes | ~1KB |

## Project Structure

```
c2pa-signer-privacy/
├── README.md                     # This file
├── bbs-signatures/               # BBS implementation
│   ├── crates/c2pa-bbs-demo/     # CLI tools and library
│   └── fixtures/                 # Test images
├── zk-proofs/                    # X.509 + ZK implementation  
│   ├── circuits/                 # Circom circuits
│   ├── crates/c2pa-x509-zk-demo/ # CLI tools and library
│   └── fixtures/                 # Test certs and images
└── external/
    └── pairing_crypto/           # BBS crypto library (submodule)
```

## Acknowledgments

I'd like to thank my colleague Greg Zaverucha for his helpful feedback on the project.