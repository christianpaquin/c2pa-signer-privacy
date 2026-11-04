# E2a: Third-Party Proof Statement and Privacy Design

**Status: adopted** (reviewed and merged in PR #18; implemented in [E2b](#implementation-e2b)). This document specifies what third-party anonymization proves ([D6](ARCHITECTURE-DECISIONS.md#d6-who-anonymizes-signer-side-or-third-party)) and the time policy ([D7](ARCHITECTURE-DECISIONS.md#d7-time-policy)), before any circuit work ([roadmap E2a](README.md#e2a-third-party-proof-statement-and-privacy-design)). Each open choice is listed under [Decisions for review](#decisions-for-review) with its default, as reviewed; E2b implements the defaults.

Section references are to the [C2PA 2.5 specification](https://spec.c2pa.org/specifications/specifications/2.5/specs/C2PA_Specification.html). Sizes come from a real device-signed photo on the official trust list (a P-256 signer certificate issued by a P-384 CA, an ES256 claim signature, and a `sigTst2` time stamp); its anatomy is in [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#anatomy-of-a-real-manifest).

## Summary of proposed defaults

| # | Decision | Proposed default |
|---|---|---|
| [Q1](#q1-output-form) | Output form | Replace the original claim signature in place with a ZK signature in a defined compact encoding; keep the original claim and assertions unchanged, and keep the manifest store's size; fail before proving if it does not fit |
| [Q2](#q2-one-statement-for-both-modes) | Signer-side mode | Same statement: the signer signs normally, then runs the third-party prover. Retire the asset-digest circuit after E2b; deprioritize E5 |
| [Q3](#q3-how-the-claim-enters-the-proof) | How the claim enters the proof | Claim bytes as packed public inputs (31 bytes per field element), derived by the verifier from the claim box and never stored in the output |
| [Q4](#q4-circuit-size-limits) | Size limits | Protected header ≤ 2 KB, claim ≤ 1 KB, signer TBS ≤ 1 KB; refuse larger inputs; revisit with R2 samples |
| [Q5](#q5-in-circuit-certificate-checks) | In-circuit certificate checks | Walk the TBS's DER structure; read the key, validity, EKU (must include claim signing), and basic constraints (must not be a CA) from their parsed fields |
| [Q6](#q6-time-policy) | Time policy | Require a trusted time stamp, and apply C2PA semantics (validity at the attested time); token checked off-circuit and bound in-circuit. Refuse assets without one, except in an explicitly selected research mode |
| [Q7](#q7-time-stamp-threat-model) | Time-stamp threat model | Public token for E2b; the TSA operator can link the output to the request. Hidden token measured later |
| [Q8](#q8-revocation) | Revocation | Strip stapled OCSP responses; no revocation check of the hidden signer; report it |
| [Q9](#q9-assertions-and-metadata) | Assertions and metadata | All original assertions stay visible; refuse identity assertions; report unbound metadata (EXIF, XMP) and scrub it in H6 |
| [Q10](#q10-first-algorithms) | First algorithms | ES256 claim signatures, `sigTst2` time stamps; then `sigTst`, then PS256 |

## The chain of trust

Third-party mode must establish each link from a trusted issuer to the anonymized output, without disclosing the signer's certificate, key, or original signature. The table states how each link is established under the defaults.

| Link | Established by | How |
|---|---|---|
| Trusted issuer | Off-circuit | The output's `x5chain` holds the issuing CA chain ([D4](ARCHITECTURE-DECISIONS.md#d4-where-the-issuing-ca-chain-lives-decided)); the verifier validates it against the C2PA trust list at the proof's time `t`, and checks that the issuing CA's key equals the proof's public input |
| → Authorized signer | In-circuit | The issuing CA's key signed the signer certificate's TBS; the circuit walks that TBS's DER structure and reads the signer key, validity period, extended key usage (must include claim signing), and basic constraints (must not be a CA) from the parsed fields ([Q5](#q5-in-circuit-certificate-checks)); `notBefore ≤ t ≤ notAfter` |
| → Original COSE signature | In-circuit | The signer key verifies the original signature over `SHA-256(Sig_structure)`, where `Sig_structure = ["Signature1", P, external_aad, claim]` (§10.3.2.4) and `P` is the original protected header (private: it contains the signer's certificate) |
| → Signer certificate is the one in the header | In-circuit | The certificate verified above is the first entry of `P`'s `x5chain` (§13.5: the first certificate's key validates the signature), and `P`'s `alg` is the one verified |
| → Original claim | In-circuit, public input | The `claim` in the `Sig_structure` is a public input equal to the claim box's bytes in the output ([Q3](#q3-how-the-claim-enters-the-proof)) |
| → Asset binding | Off-circuit, standard C2PA | The original claim's assertions, including its hard binding, are validated as usual against the output. Nothing in the binding changes, because the asset's bytes and the claim are kept ([Q1](#q1-output-form)) |
| → Anonymized output | Off-circuit | The output's claim signature box holds the ZK signature (private-use `alg`, critical), the issuing chain, the proof, and the time-stamp token if any |
| Time | Both | Off-circuit: the token is valid and issued by a TSA on the C2PA TSA trust list, and `t` is its attested time. In-circuit: the token's message imprint is the hash of the original signature's countersignature structure (v2) or claim (v1), see [Q6](#q6-time-policy) |

What the verifier learns in total, if every check passes: *the claim in this asset, unchanged, was signed by the holder of a certificate that a trusted issuing CA issued for claim signing, valid at time `t`; when a time stamp is present, `t` is when a trusted TSA attested that signature*. This is the same statement C2PA validation makes about a signed claim, minus the signer's identity and revocation status.

### Public and private inputs

| Public (in the output, or derived by the verifier) | Private (witness) |
|---|---|
| The claim bytes, packed (derived by the verifier from the claim box) | The original protected header `P` (alg, `x5chain` with the signer certificate and intermediates) |
| The issuing CA's public key | The original signature `(r, s)` |
| The time `t` | The signer certificate's position in `P`, and field positions in its TBS |
| The time-stamp message imprint, when a token is used | The CA's signature over the signer certificate |

The verifier never sees `P`, so it cannot recompute any hash over the signed bytes; every hash that covers `P` is computed in the circuit.

## Privacy

### What the output discloses

| Item | Disclosed? | Notes |
|---|---|---|
| Signer certificate, key, serial, subject, exact validity | No | Private inputs. The exact validity period would be a fingerprint: the real sample's certificate was issued an hour before the photo |
| Original signature | No | With the claim and `P`, it would allow recovering the signer's key |
| Issuing CA chain | Yes | [D4](ARCHITECTURE-DECISIONS.md#d4-where-the-issuing-ca-chain-lives-decided); the anonymity set is that CA's certificate holders ([H4](README.md#h4-hiding-the-issuing-ca)) |
| The claim and its assertions | Yes | Unchanged, including `claim_generator_info` (software name and version), `instanceID`, and the actions (for example, "Created by" a named camera app) ([Q9](#q9-assertions-and-metadata)) |
| Time `t` and the time-stamp token | Yes, with a token | The token reveals the TSA and the attested time; its imprint is a hash over private data, but the TSA operator can match it ([Q7](#q7-time-stamp-threat-model)) |
| Stapled OCSP responses | No | Removed: they identify the signer certificate ([Q8](#q8-revocation)) |
| Signature algorithm family | Yes | The verifier needs the matching circuit (for example ES256) |
| Metadata outside the hard binding (EXIF, XMP) | Unchanged in E2b | Not authenticated by the claim and not covered by the proof; reported, scrubbed in H6 ([Q9](#q9-assertions-and-metadata)) |

### Linkability

- **Two anonymized assets from the same signer** are not linkable through the proof: Groth16 proofs are zero-knowledge, and no per-signer value is public. They can still be correlated through disclosed content (the issuing CA, software version, metadata).
- **Anyone holding the original signed asset** can link it to the anonymized one: the claim is identical. Anonymization protects the signer only if the original signed manifest is not published elsewhere. This is inherent to keeping the original claim, and the reason the output is otherwise unchanged.
- **The TSA operator**, with a public token, can match the imprint to the original time-stamp request ([Q7](#q7-time-stamp-threat-model)).
- **Assets without salted assertions:** any assertion hash in the claim can be checked against guesses. This matters only for assertions that are hidden (redacted); under the default nothing is hidden.

## Decisions for review

### Q1. Output form

How the anonymized asset carries the original claim and the proof.

- **O1. Replace the signature in place (proposed).** Keep the original manifest, claim, and assertion boxes byte for byte; replace only the claim signature box's `COSE_Sign1` with the ZK signature, and pad it so the manifest store keeps its exact size. The claim's hard binding then still matches the output: with `c2pa.hash.data` the store's byte range is fixed in the claim (§16.3.1.2), and with BMFF hashes root boxes cannot move (§16.3.2.2). The original assertions remain authenticated by the claim, and the proof authenticates the claim. If the ZK signature does not fit in the original signature's space, anonymization fails rather than changing the binding; the anonymizer checks this before proving. The encoding and the real sample's sizes are below.
- **O2. Add an update manifest.** Do O1, then add an update manifest (§11.3.3) that takes the original as its `parentOf` ingredient. Only an update manifest can redact the original's assertions (§8.8), and update manifests may change the store's length. It must be signed with a normal C2PA credential, so the anonymizer (for example a newsroom) is identified. C2PA forbids redacting `c2pa.actions`, so the action descriptions stay visible regardless. Needed only if real claims carry identifying assertions ([Q9](#q9-assertions-and-metadata)).
- **O3. A new manifest signed by the anonymizer**, with the proof about the original claim as one of its assertions and the original manifest removed. Standard validators would accept the anonymizer's signature, but the original claim's authenticity and its hard binding would then exist only inside the proof, so this is a different statement. Not proposed.

Under every option, standard C2PA validators reject the ZK signature (unknown critical algorithm); display in standard tools is [H8](README.md#h8-c2patool-support).

#### The ZK signature's encoding

The output carries only what the verifier cannot derive. Every public input of the proof is recomputed by the verifier from the output: the claim from the claim box, the issuing CA's key from `x5chain`, and `t` and the message imprint from the time-stamp token. None is stored with the proof. (Today's container, base64 of JSON with the public inputs, is replaced.)

| Field | Contents |
|---|---|
| Tag | `COSE_Sign1_Tagged` (18) |
| Protected header | `alg` −65538; `crit` `["c2pa-x509-zk"]`; `x5chain` with the issuing CA chain ([D4](ARCHITECTURE-DECISIONS.md#d4-where-the-issuing-ca-chain-lives-decided)); `"c2pa-x509-zk"`: a map with the format version and the verifying key's SHA-256, identifying the circuit (diagnostic, as in today's build manifest) |
| Unprotected header | `"c2pa-x509-zk-tst"`: the original time-stamp structure, unchanged (a private label, because the token covers the original signature, not this one, and a validator reading it as `sigTst2` would report it invalid); `pad` and `pad2` to reach the exact size |
| Payload | `nil` (detached, as in C2PA) |
| Signature | A format version byte followed by the compressed proof |

Sizes for the real sample, computed by encoding this structure with its issuing CA certificate and time-stamp token:

| | Bytes |
|---|---|
| Original `COSE_Sign1` (the space available) | 3,754 |
| ZK `COSE_Sign1` before padding, with a 128-byte Groth16 proof (current stack) | 3,012 (742 to spare) |
| Same, with a 196-byte gnark Groth16 proof with its commitment ([E1](FEASIBILITY.md)) | 3,080 (674 to spare) |
| Same, without the time-stamp token | 958 |

**Exact fit.** The padding must bring the encoding to exactly the original length. A single padding field cannot reach every length, because a CBOR byte string's length header grows from one to two bytes at 24 bytes and to three at 256, skipping some totals (3,036 and 3,269 with the current stack); with both `pad` and `pad2` present (6 bytes more than `pad` alone, so 3,018 bytes for the sample), every larger total is reachable (checked over the next 1,000 sizes); totals between the two use `pad` alone where its encoding allows. E2b tests an exact fit, one byte short (refused before proving), and totals at each length-header boundary.

### Q2. One statement for both modes

Signer-side mode today proves a fresh signature over a manifest-stripped asset digest, which leaves the rest of the manifest unauthenticated. **Proposed:** signer-side mode uses the same statement as third-party mode. The signer signs a standard C2PA claim with its certificate, as any claim generator does, and runs the third-party prover on its own output before publishing. Then:

- the two modes prove the same thing and differ only in who runs the prover, so the comparison in R1 is about deployment, not guarantees;
- the claim, its assertions, and the hard binding are authenticated in both modes;
- key possession (D5) no longer arises: the original signature takes its place. E5 would compare only an alternative way to prove the same signature, so it is deprioritized;
- the current asset-digest circuit stays as the V0 baseline row in [FEASIBILITY.md](FEASIBILITY.md) and is retired from the tools after E2b.

### Q3. How the claim enters the proof

The verifier has the claim; the circuit must hash exactly those bytes inside the `Sig_structure`.

- **Packed public input (proposed).** The claim bytes, up to the maximum length, packed 31 bytes per field element, plus the length. The verifier packs the claim box's bytes itself, so the packed values are never stored in the output and do not affect its size ([encoding](#the-zk-signatures-encoding)). A 1 KB maximum is 34 public inputs; Groth16 verification grows by one scalar multiplication per public input, well under a millisecond each.
- **A public hash of the claim.** One public input, but the circuit hashes the claim twice (once alone, once in the `Sig_structure`), adding roughly 30k constraints per 64-byte block.

### Q4. Circuit size limits

Circom circuits hash up to a fixed maximum length, and the cost follows the maximum, not the actual length. Approximate SHA-256 cost: 30k constraints per 64-byte block.

| Input | Real sample | Proposed maximum | Hashing cost at the maximum |
|---|---|---|---|
| Protected header `P` | 1,528 B | 2 KB | — |
| Claim | 377 B | 1 KB | — |
| `Sig_structure` (`P`, claim, framing) | about 1.9 KB | about 3 KB | ~1.5M constraints |
| Countersignature structure, v2 (`P`, the signature) | about 1.6 KB | about 2.1 KB | ~1.0M constraints |
| Signer certificate TBS | 661 B | 1 KB | SHA-384 for a P-384 CA; measured in E1 |

Inputs over a limit are refused with a clear error. The limits are revisited when R2 measures more real claims (claims with ingredients or more assertions are larger), and per-limit costs go into R1.

### Q5. In-circuit certificate checks

Today the circuit reads the signer key and validity period at prover-supplied positions, checking only that the expected DER encoding appears there, inside the signed TBS. That shows the bytes were signed, not that they are the field they claim to be: the same bytes inside another field (an extension, for example) would also be accepted ([Certificate field binding](README.md#certificate-field-binding)). For the key and validity, exploiting this needs a CA to have signed such content. For a certificate's purpose it would be easy: the encoding of `CA:FALSE` (`30 00`) can occur almost anywhere, and CA certificates often carry EKU lists. Checking the claim-signing EKU and `CA:FALSE` as byte patterns would not establish that a certificate is authorized for claim signing.

**Proposed: a structural walk of the TBS.** The circuit decodes the DER header (tag and length, including long-form lengths) of each top-level TBS field in order, version, serial number, signature algorithm, issuer, validity, subject, subject public key, then the extensions, and reads every field it uses at the position the walk reaches:

- the subject public key and the validity period, at their parsed positions (this removes today's limitation for them too);
- each extension in turn, as a sequence of its identifier, optional criticality flag, and value;
- **extended key usage:** exactly one extension whose identifier is `id-ce-extKeyUsage`; its value parses as a sequence of identifiers, one of which is C2PA claim signing (`1.3.6.1.4.1.62558.2.1`);
- **basic constraints:** at most one; if present, `cA` must be absent or false.

Requiring exactly one EKU extension matters: a certificate with two would let the prover choose. The walk's cost grows with the maximum number of fields and extensions it handles; each variable-position read costs about 16.5k constraints in today's circuit at a 1,500-byte buffer, so the walk is estimated at a few hundred thousand constraints, to be measured in E2b. The remaining profile checks (key usage, unknown critical extensions, name constraints, policies) stay in [H2](README.md#h2-full-certificate-validation-in-the-circuit) and are listed as shortcuts.

**If the walk is deferred**, the established guarantee is weakened to *a certificate issued by a trusted CA*, with no claim about its purpose, and no pattern check is presented as enforcing it.

### Q6. Time policy

C2PA's rule (§14.8.2): with a valid trusted time stamp, the signer certificate must have been valid at the attested time; without one, it must be valid at the time of validation.

- **With a time stamp (proposed: C2PA semantics).** The verifier validates the token off-circuit against the C2PA TSA trust list and takes `t` from it. The circuit proves that the token's message imprint is the hash of the countersignature structure over the original signature (v2, `sigTst2`) or over the claim (v1, `sigTst`), which both include `P` (D7). The issuing chain is validated at `t`. Result: "the certificate was valid when a trusted TSA attested the signature", which is what C2PA itself establishes. The exact constructions, confirmed on the real sample, are in [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#anatomy-of-a-real-manifest): for v2, the imprint hashes the four-element array `["CounterSignature", P, h'', bstr(serialized signature)]`.
- **Without a time stamp (proposed: refuse).** The anonymizer refuses assets without a trusted time stamp, consistent with starting from `sigTst2` ([Q10](#q10-first-algorithms)). Otherwise the prover would choose `t`, and the proof would show only that the certificate was valid at some time of the prover's choosing, accepting long-expired certificates and making a successful verification much weaker than C2PA validation. That behavior remains available only as an **explicitly selected research mode**, whose results the verifier labels as making no validity claim. Other options for later: the circuit discloses `notAfter` rounded to the day, so the verifier can apply C2PA's validity-now rule at the cost of a coarse fingerprint.

A self-reported date in the claim or metadata is never used as `t`.

### Q7. Time-stamp threat model

The public token's imprint is a hash over private data, so it reveals nothing by itself. But the TSA operator saw the same imprint when the signer's device requested the time stamp, and can match it to that request. For device-signed content, the CA and the TSA are often run by the same organization.

- **Public token (proposed for E2b).** The threat model excludes the TSA operator: it may link an anonymized asset to the original time-stamp request. Cheap: one extra hash of `P` in the circuit (~1.0M constraints at the proposed limit).
- **Hidden token (measured later).** The circuit verifies the TSA's signature over the token, so neither the token nor its imprint is disclosed. It adds a signature verification with the TSA's algorithm (often P-384 or RSA; E1 measures the cost) plus parsing the token. Needed if the CA or TSA operator is in the threat model.

### Q8. Revocation

C2PA staples OCSP responses in the `rVals` unprotected header (§13.5.2); they name the signer certificate, so they are always removed. The circuit does not check revocation of the hidden signer certificate, and the verifier reports this. C2PA treats online OCSP checks as optional (§14.9.2), and short-lived signer certificates (the real sample's last 90 days) bound the exposure. Revocation designs are [H3](README.md#h3-revocation).

### Q9. Assertions and metadata

Under O1 every original assertion stays visible and authenticated, so the anonymizer inspects the claim before proving:

- **Identity assertions** (for example `cawg.identity`) identify the signer by design: refuse, unless O2 is adopted to redact them.
- **Ingredients with their own manifests** carry other signers' certificates: refuse in E2b (anonymizing multi-manifest provenance is out of scope).
- **Everything else** is reported, so the user sees what stays visible.

**Metadata outside the hard binding.** The real sample's `c2pa.hash.data` excludes its EXIF and XMP segments as well as the manifest store, so that metadata (make, model, lens, capture time, and a GPS block) is neither authenticated by the claim nor covered by the proof. The anonymizer reports it in E2b. H6 adds scrubbing: excluded ranges can be overwritten in place at the same length without affecting the binding.

### Q10. First algorithms

E2b starts with what the official-list sample uses for the claim signature: **ES256** (P-256 signer key) with a **`sigTst2`** time stamp, which E2b requires ([Q6](#q6-time-policy)). The issuing CA is P-256 on the test PKI first, then P-384 following E1, as planned in [R2](README.md#r2-anonymizing-real-signed-content). Then `sigTst` (v1, used by interim-list samples) and PS256 claim signatures (RSA signer keys, common on the interim list).

## Implementation (E2b)

The statement is implemented in gnark ([`gnark/`](gnark/)), following E1. Under the defaults above, it needs 4.7 million R1CS constraints at the proposed size limits, against the ~7 million estimated below for circom. The implementation makes four choices this document leaves open:

- **Accepted encodings.** `P` must be `{1: ES256, 33: [signer certificate, ...]}`, with the certificate and its TBS in two-byte DER lengths, as in both real assets and c2pa-rs; the signer certificate's validity times must be UTCTime (2000–2049). Other encodings are refused before proving.
- **The CA's signature** is any valid ECDSA P-384 signature by the issuing CA over the TBS, supplied by the prover, rather than the certificate's own signature field; the statement ("the CA signed this TBS") is the same.
- **The claim signature** must have `r` and `s` below the group order. ECDSA's malleability (`(r, n - s)` is also valid) does not help backdating: a new time stamp over the altered signature attests the current time, at which the certificate must still be valid.
- **The time-stamp token is required and `sigTst2` only** for now (Q6, Q10); assets without one, or with `sigTst`, are refused when preparing the inputs.

## Estimated cost

A rough estimate for planning, to be replaced by E2b's measurements. On the test PKI (P-256 CA), the statement keeps the current circuit's two ECDSA P-256 verifications (one for issuance, one for the claim signature instead of the fresh signature) and adds the `Sig_structure` hash (~1.5M constraints at the proposed limits) and, with a time stamp, the imprint hash (~1.0M). The TBS walk ([Q5](#q5-in-circuit-certificate-checks)) adds a few hundred thousand. That is roughly 7M constraints, against 4.8M today. Whether proving time grows in proportion (about 1.5 times) is an unverified hypothesis: today's time is dominated by loading the proving key and computing the witness, not by the proof. With a P-384 issuing CA, the issuance part changes as measured in E1. All of these figures are for the current circom stack; E1 measured ECDSA in gnark at about a thirteenth of circom's constraints, so the stack chosen in E6 may change them substantially.

## Guarantees and shortcuts

What an E2b result under the defaults may claim, and what it must list as not established ([method](ARCHITECTURE-DECISIONS.md#method)):

| Established | Not established (labelled shortcuts) |
|---|---|
| The claim was signed by a key certified for claim signing (EKU, not a CA, read from the parsed certificate) by an issuing CA on the trust list | Revocation of the signer certificate ([Q8](#q8-revocation), H3) |
| The certificate was valid at the TSA's attested time (a trusted time stamp is required) | Any validity claim in the research mode without a time stamp ([Q6](#q6-time-policy)) |
| The claim and its assertions, including the hard binding to the asset, are the ones originally signed | Full certificate profile (key usage, critical extensions, policies; H2) |
| The time-stamp token covers the original signature (v2) or claim (v1) | Unlinkability from the TSA operator ([Q7](#q7-time-stamp-threat-model)) |
| Neither the signer certificate nor the original signature is disclosed | Metadata outside the hard binding ([Q9](#q9-assertions-and-metadata), H6); the issuing CA's identity (H4); single-party setup (H5) |
