# I6: Hiding the Time-Stamp Token

**Status: adopted (PR #37); being implemented.** Done: the fixture's profile and eligibility by purpose (PR #38). This note designs the hidden time-stamp token ([HIDING-THE-ISSUER.md, I6](HIDING-THE-ISSUER.md#i6-the-time-stamp-token); [THIRD-PARTY-STATEMENT.md, Q7](THIRD-PARTY-STATEMENT.md#q7-time-stamp-threat-model), "hidden token") before any circuit work, as the H4 note did for the issuer. Each choice is listed under [Decisions for review](#decisions-for-review) with a proposed default.

## The problem

Third-party anonymization requires a trusted time stamp ([Q6](THIRD-PARTY-STATEMENT.md#q6-time-policy)), and today the output carries the original `sigTst2` token unchanged; the verifier checks it off-circuit, and the circuit binds its imprint to the original signature. The token discloses:

- **Its TSA**, in the certificates it embeds and in the TSA's policy OID in `TSTInfo`. For device-signed content, the TSA is often run by the organization that runs the CA, so the token names the organization even when the issuing CA is hidden ([What H4 can and cannot hide](HIDING-THE-ISSUER.md#what-h4-can-and-cannot-hide)).
- **A unique identifier**: `TSTInfo`'s serial number, and the imprint, which the TSA operator saw when the signer's device requested the time stamp. The operator can match either to its records and link the anonymized asset to the original request ([Q7](THIRD-PARTY-STATEMENT.md#q7-time-stamp-threat-model)).
- **The exact time**, to the second.

Hiding the token means verifying it in the circuit, so that the output carries no token, only what the verifier needs: a time, and the trust in the TSA.

## What a real token holds

The real device-signed photo's `sigTst2` token (2,015 bytes), and the official TSA trust list (`conformance-public` at `a95f2c4`):

| Part | Size | Content |
|---|---|---|
| `TSTInfo` (the signed content) | 98 B | Version, the TSA's policy OID, the SHA-256 imprint, an 8-byte serial number, `genTime` in whole seconds, accuracy 10 s |
| Signed attributes | 137 B | `contentType`, `messageDigest` (SHA-256 of `TSTInfo`), `signingCertificateV2` |
| TSA signature | — | ES256: the TSA certificate's key is P-256 |
| TSA certificate | 773 B (TBS 652 B) | P-256 key, `CA:FALSE`, EKU time stamping; issued with ECDSA-SHA384 by the next certificate |
| TSA's issuing CA | 725 B (TBS 603 B) | P-384 key, `CA:TRUE, pathlen:0`, EKU time stamping; **itself on the TSA trust list** |

| TSA trust list | |
|---|---|
| Certificates | 24, from 15 organizations: 19 P-384, 4 RSA-4096, 1 P-521 |
| P-384 certificates | 19, from 14 organizations; none carries name or policy constraints |

The time stamp's chain has the same shape as the signer's: a P-256 end-entity certificate issued, with ECDSA-SHA384, by a P-384 CA that is itself listed. The circuit's existing parts (P-384 CA signature over a TBS, P-256 ECDSA, the DER walk, the issuer tree) apply to it directly.

The mirror fixture reproduces this profile (`generate-test-pki.sh --mirror`: a P-256 TSA certificate issued by a listed P-384 TSA CA, both carried in the token; [plan](#proposed-plan), step 1, done).

## The statement with a hidden token

The chain of trust of [E2a](THIRD-PARTY-STATEMENT.md#the-chain-of-trust), with the time link moved into the circuit:

| Link | Today (E2b, H4) | With I6 |
|---|---|---|
| Time | Off-circuit: the token is valid and trusted, and `t` is its `genTime`. In-circuit: the token's imprint is the hash of the original signature's countersignature structure | **In-circuit:** a TSA CA listed in a tree whose root `R_TSA` is public signed the TSA certificate's TBS (ECDSA P-384, SHA-384); walking that TBS, its key is P-256, it is not a CA, its only EKU is time stamping, and its validity contains `genTime`; that key signed (ES256) the signed attributes; their `messageDigest` is the SHA-256 of `TSTInfo`; `TSTInfo`'s imprint is the hash of the countersignature structure (as today, now private), and its `genTime` lies in the public window `[t₁, t₂)` |
| Signer and issuing CA validity | At the public `t` | At the private `genTime` |
| Everything else | Unchanged | Unchanged |

What the verifier learns: *the claim in this asset was signed by the holder of a certificate that a CA in the verifier-approved set `R` issued for claim signing; a TSA certified by a CA in the verifier-approved set `R_TSA` time-stamped that signature at a time within `[t₁, t₂)`, when the certificate was valid*.

| Public | Private (new) |
|---|---|
| The claim, the issuer root `R` | `TSTInfo`, its serial number, policy OID, imprint, and `genTime` |
| The TSA tree's root `R_TSA` | The signed attributes and the TSA's signature |
| The time window `[t₁, t₂)` (replaces `t` and the imprint) | The TSA certificate, its issuing CA's key, validity, and Merkle path |

## Decisions for review

### T1. One statement, hiding both

- **Proposed: a single new statement hiding both the issuer and the token**, opt-in, beside the disclosed and hidden-issuer statements. Each statement is its own key set (about 6.7 GiB to prove, ~1.2 GB proving key, ~7–10 min setup); hiding the token while disclosing the CA, or the reverse, are both possible, but the TSA and the CA usually belong to the same organization, so hiding one without the other rarely helps.
- **Alternative:** a token-only statement too, for verifiers that want the CA disclosed but the TSA operator unable to link. Worth adding only if asked.

### T2. The token profile

The circuit fixes the layouts it parses, as it does for the protected header ([Q4](THIRD-PARTY-STATEMENT.md#q4-circuit-size-limits)).

- **Proposed:** the real token's profile: CMS `SignedData` with one `SignerInfo`; signed attributes holding `contentType` (`id-ct-TSTInfo`) and `messageDigest`, other attributes allowed and ignored; the TSA certificate supplied by the anonymizer (from the token's `certificates`, which the output does not keep). Size limits: `TSTInfo` ≤ 256 B, signed attributes ≤ 256 B, TSA certificate TBS ≤ 1 KB; larger tokens are refused.

**The verification contract.** Moving the token's checks from OpenSSL into the circuit needs the accepted profile stated exactly. The circuit enforces:

- **Structural parsing:** every field is read by walking the DER structure within the authenticated objects' boundaries (the signed attributes, `TSTInfo`, the TSA certificate's TBS), never by searching for byte patterns or trusting prover-supplied offsets, as for the signer certificate ([Q5](THIRD-PARTY-STATEMENT.md#q5-in-circuit-certificate-checks)).
- **Attributes:** exactly one `contentType` attribute, with exactly one value, `id-ct-TSTInfo`; exactly one `messageDigest` attribute, with exactly one value, the SHA-256 of the exact `TSTInfo` encoding (RFC 5652, §11.1–11.2).
- **One object:** the imprint and `genTime` are fields of that same authenticated `TSTInfo`, located by its structure.
- **Algorithms, fixed and checked:** SHA-256 as `TSTInfo`'s imprint algorithm, ES256 (ECDSA P-256 with SHA-256) as the TSA's signature, ECDSA-SHA384 as the TSA CA's.
- **The signature preimage:** the signed attributes are hashed with the DER `SET OF` tag (`31`), not the `[0]` tag (`A0`) they carry inside the `SignerInfo` (RFC 5652, §5.4).
- **The TSA certificate:** a v3 certificate with a P-256 key, not a CA, validity containing `genTime`, and exactly one extended key usage extension, critical, whose only purpose is time stamping (RFC 3161, §2.3).

This is a **reduced verification profile**, not equivalent to everything OpenSSL checks. Deliberately not checked:

- `signingCertificateV2`: it protects a CMS verifier from a substituted certificate, but the circuit verifies the signature with the certificate whose TBS the CA signed.
- The TSA certificate's other extensions and fields (key usage, policies, names), revocation, and the token's `accuracy`, `ordering`, and `nonce` fields.

### T3. The public time

Hiding the token does not stop the TSA operator from linking if `genTime` stays exact: its records show which requests it time-stamped in that second. The anonymity set against the operator is the operator's requests within the published window.

- **Proposed: a window aligned to fixed boundaries, one UTC day by default**: `t₁` is `genTime` rounded down to the granularity and `t₂ = t₁ +` the granularity, and the circuit proves `t₁ ≤ genTime < t₂`. The window is **half-open**, `[t₁, t₂)`, so each time belongs to exactly one window: midnight starts a day, and a `1s` window holds one second. Certificate validity is still checked at the exact, private `genTime`, so a certificate issued an hour before the photo (as in the real sample) still verifies.
- **Aligned, never centered:** a window centered on `genTime` would reveal it as its midpoint. Alignment also makes every asset time-stamped the same day publish the same window.
- **Easy to change:** the window's bounds are public inputs, not part of the circuit, so any granularity works with the same keys. The anonymizer takes it as an option (`--time-window`, default `1d`; also `1h`, `1s` for today's precision); the verifier accepts any aligned window and its policy may set a maximum (`max_time_window`), for verifiers that need finer times. The verifier checks the alignment, so an anonymizer cannot publish an unaligned, more revealing window by mistake.
- The verifier's snapshot periods apply to the whole window, consistently with their own half-open periods (`from ≤ t < until`): a snapshot is used only if `from ≤ t₁` and, when it has an end, `t₂ ≤ until`. The rule applies independently to the issuer snapshot and the TSA snapshot. A window straddling a trust-list change is refused (the anonymizer can choose a finer one).
- The time the proof discloses is the window: by default, the date. This says nothing of other times the asset may show (metadata, for example). Assets in the same window cannot be ordered within it.

### T4. Trust in the TSA

- **Proposed: as H4 for the issuer**: the TSA certificate's issuing CA must itself be on the TSA trust list (as in the real token) and be eligible, and the circuit proves its membership in a second tree (format 1) over the TSA list's eligible P-384 CAs.
- **Eligibility for its purpose.** The issuer trees' check (`eligible_issuers`) requires an extended key usage allowing C2PA claim signing, so it would refuse a time-stamping-only CA and admit a claim-signing-only one. The CA checks become parameterized by purpose: the common checks unchanged (a CA, key usage allowing certificate signing, no unrecognized critical extension, path length, no name or policy constraints); for signer issuers, an EKU, if any, allowing claim signing, as today; for TSA issuers, an EKU, if any, including time stamping or `anyExtendedKeyUsage`.
- On the official TSA list, with this rule, all 19 P-384 certificates are eligible, from 14 organizations; 7 of them carry a time-stamping-only EKU, which the claim-signing rule would have refused. The verifier's policy gains TSA snapshots, approved and checked as issuer snapshots are ([I4](HIDING-THE-ISSUER.md#i4-tree-shape-and-verifier-policy)).
- The TSA CA's validity, from its leaf, must contain `genTime`.
- Not checked, as today: revocation of the TSA certificate.

### T5. TSA algorithms

- **Proposed:** an ES256 TSA certificate under a P-384 CA with ECDSA-SHA384, the real profile. RSA TSAs (4 RSA-4096 CAs on the list) would need the RSA CA circuit ([E1](FEASIBILITY.md#e1-rsa-primitives)) and their own tree; as for the issuer, the algorithm is disclosed by the choice of statement, and splits the anonymity set.

### T6. The output format

- The ZK signature carries no token: the statement `third-party-hidden/1`, the issuer tree reference (as H4), a TSA tree reference `{format, root, list}`, and the window `[t₁, t₂)`. Its unprotected header loses the `c2pa-x509-zk-tst` label; the 2 KB token's space becomes padding.
- c2pa-rs's validation of the copy carrying the placeholder certificate ([I5](HIDING-THE-ISSUER.md#i5-the-output-format)) does not need a time stamp; to be confirmed when implemented.

## Estimated cost

Estimated from E1 and E2b, not measured. The countersignature hash that binds the imprint is already in the circuit (about 1.0M constraints) and stays.

| Part | Constraints (estimate) | Basis |
|---|---|---|
| TSA CA's signature over the TSA certificate's TBS (P-384, SHA-384, ≤ 1 KB) | ~1.2M | E1: 0.82M at 414 B, 1.52M at 1,500 B |
| Walking the TSA certificate's TBS (key, validity, EKU, basic constraints) | ~0.1–0.2M | The signer certificate's walk |
| TSA's signature (ES256) and SHA-256 of the signed attributes (≤ 256 B) | ~0.4M | E1: P-256 verify 0.15M, SHA-256 0.38M at 414 B |
| SHA-256 of `TSTInfo` (≤ 256 B), parsing it | ~0.3M | E1 |
| TSA tree membership, window and validity comparisons | Under 20k | H4 |
| **I6, as proposed** | **~2.0–2.1M, about +45% on V1** | |

Expect per-asset anonymization of about 1.4× V1's (proving scales with constraints, and the proving key with it, to about 1.7 GB); verification is unchanged in cost.

## Proposed plan

1. **Mirror the real token's profile in the fixture:** `generate-test-pki.sh --mirror` issues a P-256 TSA certificate from a listed P-384 TSA CA (the existing tests keep passing: off-circuit token checks do not depend on the profile).
2. **Circuit (Go):** the combined statement, `TSTInfo` and signed-attribute parsing, the TSA certificate's walk and signatures, the TSA tree, the window; measured constraint count. Tests:
   - forgery: a TSA certificate not issued by a listed CA, a CA certificate as TSA, a changed `TSTInfo`, signed attributes, or TSA signature, an imprint of another signature;
   - the contract ([T2](#t2-the-token-profile)): a missing, duplicated, or multi-valued `contentType` or `messageDigest`; a `messageDigest` of other bytes; an imprint or `genTime` outside `TSTInfo`'s structure; another imprint algorithm; signed attributes hashed with the `[0]` tag; an EKU that is not critical, has another purpose besides time stamping, or is duplicated;
   - time ([T3](#t3-the-public-time)): a time stamp exactly at midnight, `genTime = t₂` (refused), a one-second window, `genTime` outside the certificates' validity.
3. **Anonymizer and verifier (Rust):** `--hide-time-stamp` (implies `--hide-issuer`) with `--time-window` (default `1d`), the alignment check and `max_time_window` in the verifier, the format, TSA snapshots in the policy, eligibility by purpose. Tests: time-stamping-only, claim-signing-only, unrestricted, and unrelated-purpose CAs, for each purpose; a window ending exactly at a snapshot's expiry (accepted) and one crossing a replacement boundary (refused); end to end, that no token, TSA certificate, or serial number remains in the output. Measured with the harness.

## Guarantees and shortcuts

Unchanged from [HIDING-THE-ISSUER.md](HIDING-THE-ISSUER.md#guarantees-and-shortcuts), except:

- **Gained:** the TSA is hidden among the TSA list's eligible CAs of its key type, and the token's direct request identifiers (its serial number, policy OID, and imprint) are no longer disclosed. The public window remains a correlation channel for the TSA operator; public claims, metadata, auxiliary records, and possession of the original asset can also enable linking.
- **Not gained:** the claim's content still discloses what it discloses; a narrow window, or a TSA with few requests, still lets its operator link. The time is published only to within the window.
- **Trust moves into the circuit:** the token's checks that OpenSSL performs today (signature, certificate profile, chain) become circuit constraints, so their correctness depends on the circuit's parsing, as the signer certificate's already does; and they form a reduced profile ([T2](#t2-the-token-profile)), not all of OpenSSL's checks.
