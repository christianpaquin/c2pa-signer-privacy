# Deployment Findings: C2PA Trust Lists and Real Signed Assets

What real C2PA deployments look like, as input to [goal 2](ARCHITECTURE-DECISIONS.md#goals): which certificate types, key types, and signature algorithms an anonymizer would actually face. Collected on 2026-10-30.

## Official C2PA trust list

Source: [`c2pa-org/conformance-public/trust-list/C2PA-TRUST-LIST.pem`](https://github.com/c2pa-org/conformance-public/tree/main/trust-list) (last changed 2026-10-17; the JSON version is a "List of Trusted Entities" with 18 organizations, issued 2026-10-23, next update due 2027-01-21).

- **32 certificates: 20 self-signed roots and 12 intermediates.** Every intermediate has `pathlen:0`, so it can only issue end-entity certificates. Eleven chain to a root on the list; Adobe's issuing CA does not, so it is a trust anchor in its own right. In practice, a signer's certificate is often issued directly by a listed certificate.
- **CA keys: 27 × P-384, 4 × RSA-4096, 1 × P-521. None use P-256.** The current circuit verifies the CA's signature only for P-256 with SHA-256, so as built, trust model A cannot prove issuance by any CA on this list.

**The lists are not signed.** Neither the JSON files (official list and TSA list) nor the PEM files carry a signature element; they are files in a GitHub repository. Anything built from them (for example a Merkle tree of signer keys) needs to authenticate its source another way, at minimum by pinning the list's content hash.

## Time-stamping

The same repository publishes a **C2PA TSA trust list** (`C2PA-TSA-TRUST-LIST.pem` / `.json`, 23 certificates) for RFC 3161 time-stamp authorities. Real assets carry TSA tokens: both Pixel photos below include a token from "Google Pixel Time Stamping Authority", whose issuing CA ("Google C2PA Pixel Time-Stamping ICA G3") is on the TSA trust list. Validated time evidence therefore exists for real content, independent of any date the signer writes into the claim.

The samples use different time-stamp versions (from the header labels in their manifests; see [D7](ARCHITECTURE-DECISIONS.md#d7-time-policy) for what each covers):

| Sample | Time stamp |
|---|---|
| Both Pixel photos (official list) | v2, `sigTst2` |
| Microsoft image, Black Forest Labs image (interim list) | v1, `sigTst` (deprecated) |
| ChatGPT image via Truepic | none |

## Interim trust list (pre-conformance)

Source: [`contentauth/verify-site/static/trust`](https://github.com/contentauth/verify-site/tree/main/static/trust). The file header states it is frozen, that Content Credentials signed with these certificates remain valid, and that validators should distinguish them from those tracing to the official list. It is still used by verify.contentauthenticity.org.

**`anchors.pem`: 27 CA certificates (19 roots, 8 intermediates)**, trusted by chaining, like the official list:

| Key | Count | Organizations |
|---|---|---|
| P-256 | 5 roots | Canon, FUJIFILM, Leica, Nikon, Metaphysic |
| P-384 | 4 roots | Sony, Cybertrust Japan, ATOM, ContentSign (Nodle) |
| P-521 | 3 roots | Samsung, vivo, Bria |
| RSA-4096 | 6 roots, 8 intermediates | Adobe, Microsoft (3), Truepic, Pinterest; the intermediates are mostly timestamping CAs (DigiCert, GlobalSign, SSL.com) and two Microsoft C2PA PCAs |
| Ed25519 | 1 root | Trufo (expired 2025-08-12) |

**`allowed.pem`: 115 end-entity certificates trusted directly**, without a chain. Keys: 70 × RSA-2048, 22 × P-384 (15 of them AWS), 16 × P-256, 7 × RSA-4096. 78 distinct organization/key combinations, including the EBU, AFP, and WDR. 31 were still valid on 2026-10-30; 84 had expired.

**`store.cfg`: accepted EKUs**: email protection, document signing, time stamping, OCSP signing, Microsoft C2PA signing (`1.3.6.1.4.1.311.76.59.1.9`), and C2PA claim signing (`1.3.6.1.4.1.62558.2.1`).

## Real signed assets

Five real assets with intact manifests, analysed with `c2patool` and by extracting their certificate chains.

| Sample | Claim alg | Signer key | CA that signed the signer certificate | Signer cert validity | Trusted via |
|---|---|---|---|---|---|
| Pixel 10 Pro photo (Aug 2025) | ES256 | **P-256** | Google C2PA Mobile A 1P ICA G3 L1: P-384, ECDSA-SHA384 | 90 days | Official list (the ICA is listed) |
| Pixel photo (Oct 2025) | ES256 | **P-256** | same ICA: P-384, ECDSA-SHA384 | 89 days | Official list |
| ChatGPT image via Truepic (Jan 2025) | ES256 | **P-256** | Truepic WebClaimSigningCA: RSA-2048, SHA384-RSA | 1 year | Interim anchors (Truepic RootCA) |
| Microsoft image (May 2024) | PS256 | RSA-3072 | Microsoft SCD Claimants RSA CA: RSA-4096, SHA384-RSA | ~10 months | Interim anchors (Microsoft Supply Chain RSA Root CA 2022) |
| Black Forest Labs image (Jun 2025) | PS256 | RSA-2048 | GlobalSign GCC R6 SMIME CA 2023: RSA-4096, SHA256-RSA | 1 year | Interim allowed list (the signer certificate itself) |

Sources: the first Pixel photo is the original linked from [Hacker Factor's Pixel 10 analysis](https://hackerfactor.com/blog/index.php?/archives/1077-Google-Pixel-10-and-Massive-C2PA-Failures.html); the others are attachments to `c2pa-rs` issues [#1488](https://github.com/contentauth/c2pa-rs/issues/1488), [#1609](https://github.com/contentauth/c2pa-rs/issues/1609), and [#1590](https://github.com/contentauth/c2pa-rs/issues/1590).

Pixel signer certificate details: `CA:FALSE`; EKU C2PA claim signing plus email protection; issued hours before the photo's timestamp, with a different serial for each photo. This fits per-capture or per-session issuance; two samples cannot distinguish between them. Google states the keys are generated in StrongBox on the Titan M2 chip.

## Anatomy of a real manifest

What a third-party proof would have to hash, measured on the first Pixel photo by parsing its JUMBF manifest store (collected 2026-11-04 for [E2a](THIRD-PARTY-STATEMENT.md)).

| Part | Size | Contents |
|---|---|---|
| Manifest store | 4,912 B | One manifest |
| Claim (`c2pa.claim.v2`) | 377 B | `alg`, `claim_generator_info` ("Google C2PA SDK for Android" and a version), `instanceID`, `signature`, two created assertions; no gathered assertions or ingredients |
| Assertions | 243 B + 164 B | `c2pa.hash.data`; `c2pa.actions.v2` with one action: `c2pa.created`, "Created by Pixel Camera.", digital source type `computationalCapture`. Neither is salted |
| Claim signature (`COSE_Sign1`) | 3,754 B | Protected header 1,528 B: `alg` ES256 and `x5chain` with the signer certificate (783 B) and the issuing CA (733 B). Unprotected header: `sigTst2` (2,037 B), `pad` (97 B), `pad2`. Signature 64 B. No stapled OCSP (`rVals`) |
| Signer certificate TBS | 661 B | P-256 key; validity Aug 29 01:09:56 to Nov 26 01:09:55 2025 (the time stamp is 02:10:21 the same day); key usage digital signature and non-repudiation; EKU email protection and C2PA claim signing; `CA:FALSE`; an OCSP responder URL |
| Time stamp | — | SHA-256 message imprint |

**The hard binding excludes more than the manifest store.** `c2pa.hash.data` lists five exclusions: the EXIF segment (APP1, 11,574 B), the manifest store (APP11), and three XMP segments (APP1, about 74 KB in total). The EXIF holds make and model ("Google", "Pixel 10 Pro"), software, lens, capture time, and a GPS block. None of it is authenticated by the claim.



- **P-256 is realistic for signer keys**, especially on devices (both Pixel photos and the ChatGPT image), so the current key-possession check fits them. RSA signer keys (PS256) are common among interim-list signers.
- **CA signatures are where real deployments differ from the prototype.** The official list's CAs sign with P-384 (and RSA-4096, P-521); the interim list adds P-256 roots for four camera makers (whose issuing intermediates were not examined; no camera samples were available), plus P-384, P-521, RSA-4096, and Ed25519. Trust model A on real CAs needs P-384 + SHA-384 and RSA verification in-circuit ([E1](README.md#e1-cost-of-reality-p-384-sha-384-and-rsa-in-circuit)).
- **Device keys are typically not exportable** (Pixel: StrongBox, short-lived certificates), so anonymizing existing content needs third-party mode ([D6](ARCHITECTURE-DECISIONS.md#d6-who-anonymizes-signer-side-or-third-party)).
- **`x5chain` can be short**: the Pixel issuing CA is itself a trust anchor, so an anonymized Pixel asset's `x5chain` would hold one certificate.
- **The interim allowed list is a set-membership trust model**, which maps onto trust model B without any CA involvement.
- **Production certificates use the C2PA claim-signing EKU** (`1.3.6.1.4.1.62558.2.1`); the prototype's fixtures use document signing. In-circuit certificate checks must accept the EKUs real certificates carry.
- **Still unknown:** signer and issuing-CA key types for camera makers (Canon, Nikon, Leica, Sony, FUJIFILM) and for official-list signers other than Google. Samples from those deployments would close this gap.
