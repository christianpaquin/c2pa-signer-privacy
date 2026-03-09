---
layout: post
title:  "Privacy for C2PA signers"
permalink: /:year-:month-:day-:title.html
---

TODO: delete me before release

We can't trust the images and videos we see online anymore. Recent generative AI improvements support the creation and modification of convincing digital media in quasi real time. We live in an era where these fakes are routinely shared online, sometimes for harmless fun, but increasingly to influence public opinion.

Fortunately, technologies exist to embed cryptographic signatures and watermarks in these digital assets, proving their origin. The [Coalition for Content Provenance and Authenticity (C2PA)](https://c2pa.org/) specification has become the leading mechanism to add cryptographic authenticity to digital media, and has been [adopted](https://c2pa.org/membership/) by many technology providers, camera manufacturers, and news media organizations.[^1] Major deployments have started in 2025 and will accelerate in 2026. We can soon imagine a world where assets with a verified origin can be positively flagged or prioritized by online platforms, versus those without (similar to the web transition from HTTP to HTTPS).

In many contexts however (e.g., conflict zones, protests, corruption reporting) asset creators might be reluctant to share certified images and videos that identify them for fear of retribution. Thankfully, there are ways to reconcile the need for authenticated assets and the privacy of their creators. This post explores strategies to achieve various levels of privacy for C2PA signers, ranging from pseudonymity to full anonymity.

Note that we only consider the signer’s (a person or organization) privacy here, not the ability to redact or modify the asset itself. This is possible using the [C2PA assertion redaction mechanism](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_redaction_of_assertions), or more advanced cryptographic mechanisms.[^2] 

## Example scenarios

Many scenarios require privacy for the signer, for example:

1. A reporter documenting human right abuses wants to remain anonymous to avoid retribution from a hostile government but would like to disclose their affiliation (to, e.g., a news organization). The news organizations publishing the images and videos doesn’t want the ability to identify the journalist to avoid the risk of being compelled to disclose their identity.

2. A news organization receives a signed video from a confidential source for a story, and wants to share it without disclosing the source's identity (or leaking identifiable attributes) while preserving the authenticity guarantees of the video. 

3. A whistle blower records some incriminating conversations using their phone and releases the audio files signed by their corporate identity. They want to remain anonymous without anyone (including the employer who issued the identity credential) being able to trace their identity.

4. A Banksy-style artist creates authenticated pictures and posts them at various online locations. They want to remain pseudonymous reusing the same signing credential, but without linking it to their real life identity.

## Linkability

In this [blog post](https://christianpaquin.github.io/2023-06-16-where's-waldo-been.html), I explain the subtle ways an identity credential can be tracked and traced by its issuer and various verifiers. The current [C2PA specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html) only supports X.509 certificates to generate (claim) signatures, which is an inescapably linkable credential type: an issuer (i.e., Certificate Authority) can always recognize the certificate it issued to a specific device or user. Other privacy-friendly credential types could be added to a C2PA manifest using, e.g., an [identity assertions](https://cawg.io/identity/1.3-draft+vc-vp+new-introduction/), but the claim signer's X.509-based signature remains an unavoidably linkable element. 

The following strategies will address this linkability, resulting in various levels of privacy. The strategies achieving the highest levels of privacy would require either updates to the specification, or post-processing on a C2PA asset. 

## Privacy strategies

Let's now explore some techniques to provide privacy to a C2PA claim signer. 

### Pseudonymous certificates

The simplest strategy compatible with the current specification is to generate a self-signed X.509 certificate and use it to sign digital assets (i.e., use it as the claim generator certificate). The certificate would then need to be obtained out-of-band by verifiers. This technique doesn't allow signers to prove attributes certified by a 3rd party (e.g., memberships, entitlements, etc.), it only demonstrates ownership of a public key; it is only useful for scenario #4. Retrieving the certificate from the signer's well-known web site would be a good way to convince verifiers that, e.g., "this image was signed by the owner of https://example.com". 

### One-use certificates

Re-using a X.509 certificate creates linkable signatures: even if a certificate doesn't identify its owner, all the resulting signatures can be associated to the same entity. 

To achieve unlinkability between multiple signed assets, a signer could obtain a new certificate for each signature, which is a heavy burden on the infrastructure. This is what [Google deployed](https://security.googleblog.com/2025/09/pixel-android-trusted-images-c2pa-content-credentials.html) for their Pixel 10 C2PA signing. This prevents a verifier from linking two images to the same signer; it does not prevent, however, the issuer to recognize and trace each individual certificate.

### Unlinkable signatures

Cryptographic unlinkable signatures allow creating privacy-supporting certified assets without disclosing the holder's full identity to verifiers. One of the leading algorithm candidates is [BBS](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html), undergoing standardization in the [IETF](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/). In a BBS credential flow, an issuer signs a credential containing holder attributes, and the holder later derives a selective-disclosure proof for a verifier. Augmenting the C2PA specification to support BBS-enabled presentations[^3] would allow a manifest to reveal only selected attributes, while binding the presentation to the asset being certified.


### Zero-knowledge proofs over X.509 certificates

A Zero-Knowledge Proof (ZKP) is a cryptographic mechanism allowing someone to prove properties about some data without disclosing the data itself. Given some data signed by a X.509 certificate, a user could prove that the signature and certificate are valid without disclosing the identifiable parts of the certificate (e.g., serial number, public key, issuer signature, validity period). A C2PA manifest could be redacted using a ZKP allowing anyone to verify that:
1. the digital asset hasn't been modified
2. the signer's cert was valid when the asset was processed/anonymized
3. the signer cert's CA is trusted (the CA cert would be visible, allowing validators to infer memberships)

This technique is very promising as it is compatible with the current C2PA specification and doesn't require changes to the key management infrastructure (to introduce new signing algorithms).

### Comparison

| Strategy | Unlinkable wrt verifiers | Unlinkable wrt the issuer | Supported by current spec |
|----------|:----------------------:|:-------------------:|:-------------------:|
| Pseudonymous certificates | ❌ | N/A (self-signed) | ✅ |
| One-use certificates | ✅ | ❌ | ✅ |
| Unlinkable signatures (BBS) | ✅ | ✅ | ❌ |
| ZKP over X.509 | ✅ | ✅ | ⚠️[^4] |

## A prototype

I've built prototypes for the most privacy-preserving options explored here: a BBS-based flow and a zero-knowledge approach on top of a conventional manifest. The BBS prototype now models a simple issuer/holder/verifier flow: a demo issuer signs a toy credential, the holder presents that credential over the C2PA asset hash, and the verifier checks both the disclosed attributes and the content binding. The zero-knowledge prototype keeps conventional X.509/ECDSA signing, then post-processes the asset into an anonymized variant whose proof is bound to the manifest-stripped asset bytes and to the signer's CA. The code is available in this GitHub [c2pa-signer-privacy](https://github.com/christianpaquin/c2pa-signer-privacy) project.

## Next steps

The emergence of provenance technologies is a welcome tool to help fight disinformation and help establish trust in online contents. It is however not too early to consider the negative privacy impact this might have, which could slow down adoption.

My hope is that the community will use simple prototypes like these to discuss concrete scenarios, compare privacy goals, and experiment with alternative trust models before the ecosystem hardens around only one approach. Which scenarios really need pseudonymity versus unlinkability? Which attributes should remain visible to verifiers? How much can be achieved within the current specification, and where are specification changes justified? These are design questions worth debating now, while experimentation is still cheap.

I hope these strategies can be explored, debated, and tested by the broader C2PA ecosystem.

Onward!

# Footnotes

[^1]: Notably, the International Press Telecommunications Council (IPTC) has created a list of [Verified News Publishers](https://iptc.org/verified-news-publishers-list/) to help the verifier ecosystem recognize known news media organizations.

[^2]: One such approach, the [VerITAS system](https://eprint.iacr.org/2024/1066.pdf), has been prototyped by Stanford researchers Trisha Datta, Binyi Chen, and Dan Boneh.

[^3]: This could be achieved by either specifying a X.509 profile supporting BBS signatures, or allowing other credential types supporting BBS (e.g., Verifiable Credentials) to natively sign a C2PA manifest.

[^4]: The initial signing step is fully spec-compliant (standard X.509/ECDSA), but the anonymized manifest uses a non-standard COSE algorithm and a custom assertion, which current verifiers cannot process without modifications.