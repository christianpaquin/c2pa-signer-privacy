# Claim Privacy

**Status: proposed, for review.** With the issuer and the time stamp hidden ([H4](HIDING-THE-ISSUER.md), [I6](HIDING-THE-TIME-STAMP.md)), the anonymized asset's unchanged claim is the main disclosure left: on a real device photo, it names the capture software and its build ([DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#with-the-issuer-and-the-time-stamp-hidden-i6)). This note inventories what the claim and its assertions disclose on real samples, checks what the C2PA specification allows, compares the options, and proposes one, backed by a measured spike of its new circuit part. Metadata outside the claim (H6) is covered at the end.

## What the claim discloses

Three real samples, all claim v2 with a single manifest: a device photo (JPEG), a device raw image (DNG), and an AI-generated image (JPEG). Their claims are 377–384 bytes: a CBOR map of five fields, 25 CBOR items, nested three deep.

| Item | Content on the samples | Discloses |
|---|---|---|
| `claim_generator_info` | The signing SDK's name and build number (two different SDKs across the samples) | The vendor, and the software build |
| `instanceID` | A UUID per asset | No source, but a unique identifier: it links every copy and derivative of the original |
| `created_assertions` | Hashed URIs (a URL and a SHA-256) of the hard binding (`c2pa.hash.data`) and the actions (`c2pa.actions.v2`) | Which assertions exist |
| `signature`, `alg` | `self#jumbf=c2pa.signature`, `sha256` | Nothing |
| Actions assertion | `c2pa.created`, a digital source type (computational capture, or trained algorithmic media), and a description: "Created by" the named camera app or AI service | The product (in the description), and whether the content is a camera capture or AI-generated (the source type) |
| Hard binding assertion | The asset's SHA-256, and the excluded byte ranges (12 on the photo) | The content's hash, which the binding needs; the exclusions' layout reflects the writing software |
| The manifest's JUMBF label | `urn:c2pa:` and a UUID, distinct from `instanceID` | A second unique identifier, outside the claim |
| Assertion salts | None on the samples; C2PA allows a random salt in an assertion's description box (`c2sh`) | When present, a unique identifier per assertion, inside the bytes its hash covers |
| Outside the binding | EXIF and XMP (make, model, lens, sometimes location) | The device ([H6](#metadata-outside-the-claim-h6)) |

Two points follow:

- **The claim and the actions name the source, independently.** Hiding only one of them hides nothing.
- **The digital source type is the most valuable disclosure** for a verifier (captured or generated), and the least identifying. An ideal output would keep it and drop the description.

## What the specification allows

From the C2PA 2.5 specification:

- **Redaction does not apply.** A claim may redact assertions of its *ingredients'* manifests only: "A claim's redacted_assertions field shall never include a JUMBF URI to any of its own assertions" (§14.10.2). Actions assertions may never be redacted: "Claim generators shall not redact assertions with a label of c2pa.actions or c2pa.actions.v2" (§8.8), and a validator rejects a claim that does so (`assertion.action.redacted`, §14.10.4.1).
- **The claim's identifying fields are required.** `instanceID` and `claim_generator_info` are required; its `name` must be present (§10.2.1, §14.6.2), and "shall represent the non-human (hardware or software) actor that actually generated the claim" (§10.2.3.2).
- **Signed assertions cannot change.** Assertions "cannot be modified once made as part of a claim" (§8.1). An update manifest can add a later claim, but cannot remove an earlier one's assertions (§11.3.3).
- **A standard manifest needs a hard binding and an actions assertion**: exactly one hard binding (§11.3.2, §14.10.1.2), and at least one actions assertion (§14.10.1.2, `claim.actions.missing`).
- **An assertion's hash** in the claim covers its JUMBF superbox content, without the superbox header (§9.4.2.3). Measured on the samples: 539 bytes for the hard binding, 205 for the actions.

## Options

| Option | Hides the generator and actions? | Keeps the original signature's guarantee? | Notes |
|---|---|---|---|
| **A. Accept and report** (today) | No | Yes | The anonymizer reports what stays visible; fine where the claim's software is generic |
| **B. Redaction** | No | — | Not allowed for a claim's own assertions, nor for actions (above) |
| **C. A new manifest, the original as ingredient** | No | Partly | The ingredient's claim stays in the store (claims cannot be redacted), and its actions cannot be redacted; a new signer appears; the original's signature must still be anonymized ([E8](README.md#e8-ingredient-manifests)) |
| **D. A private claim** (proposed) | Yes | Yes | The original claim becomes a private input; the proof shows it references the assertions disclosed; the output carries a claim written by the anonymizer, listing only those |

Only D hides what the claim discloses, because only the original signer's claim carries the trust, and it cannot be edited or redacted.

## The proposal: a private claim

The statement becomes: *a claim, signed by the holder of a certificate a listed CA issued for claim signing (at a time a listed TSA attested), contains a hashed URI for each of these assertions*. The claim stays private; the verifier learns only the references it is shown, and checks the assertions themselves.

**In the circuit.** The claim is already hashed inside the signature's preimage; it stops being a public input. A new part walks its CBOR, as the circuit walks DER, and proves that its `created_assertions` array holds each public reference (URL and hash). The verifier computes each hash from the assertion's bytes in the asset, so the circuit never hashes assertions.

**In the output.** The anonymizer replaces the claim box with a claim of its own, at the same size, listing only the disclosed assertions: always the hard binding, and others if chosen. The other assertions' boxes are blanked. The verifier derives the public references from this claim's `created_assertions`, checks each assertion's hash and the hard binding (with c2pa, on the copy carrying the placeholder certificate, as today), and checks the proof. The ZK signature, unchanged in form, now proves that the *original* claim referenced exactly what the visible claim lists.

**The spike** ([`statement/claimref.go`](gnark/statement/claimref.go)): the CBOR walk as a gnark gadget, measured on its own.

- It tokenizes the whole claim with a bounded stack (depth 4, up to 64 items), so a reference counts only as an actual entry of the root map's `created_assertions` array.
- **Accepted profile:** byte strings, text strings, arrays, and maps only; lengths in short, 1-byte, or 2-byte forms; containers of fewer than 24 items; exactly one `created_assertions` key; at most one `url`, `hash`, and `alg` per entry, and one `alg` in the claim.
- **The algorithm:** each reference's effective hash algorithm must be SHA-256, as the claim declares it: the entry's own `alg`, or else the claim's (§10.2.2, §12.1). No effective algorithm, another one, or a URL referenced by two entries is refused.
- **URLs** are compared whole: a public URL is at most 64 bytes (the buffer), and must have the encoded URL's exact length.
- **A fixed layout** ([P2](#p2-what-is-disclosed)): four reference slots, slot 0 the hard binding, always used; the others optional, each with an active flag, and all zero when unused.
- **Cost: 510,920 constraints** with the four slots, at a 1 KB claim limit: 7.9% of the hidden-all statement, paid whether the optional slots are used or not. (Measured earlier, with a variable number of slots: 158,484 for one reference and 270,858 for two, about 112,000 per slot.)
- **Tests:**
  - Accepted: the three real claims, each referencing its hard binding (and refused with another hash).
  - Refused: the entry's bytes placed inside a text field; the entry only in `gathered_assertions`; two `created_assertions` keys; `created_assertions` nested in another field, or a map instead of an array; an entry that is not a map; an entry with two `url` keys; a different hash, a longer or shorter URL, or a 31-byte hash; an unsupported item type; a trailing item; a truncated length.
  - URLs: a 64-byte URL accepted; a longer URL whose first 64 bytes match refused, as is a different last byte.
  - Algorithms: accepted with an inherited `sha256`, the entry's `sha256`, or the entry's `sha256` over the claim's `sha384`; refused with the entry's `sha384`, an inherited `sha384`, no algorithm, two claim `alg` keys, two entry `alg` keys, a non-text `alg`, or the URL in two entries.
  - Slots: accepted with no, one, or three optional references; refused with slot 0 unused, or an unused slot carrying a URL length, a hash, or a URL byte, an active flag of 2, or an active empty URL.
  - A mutation check (disabling, one at a time, the length check, the entry-is-a-map check, the URL bound, the algorithm rule, the single-URL rule, and the unused-slot rule) made exactly the matching cases pass.

## Decisions for review

### P1. Scope

- **Proposed: a fourth statement, hiding the issuer, the time stamp, and the claim**, opt-in. Hiding the claim alone, with the issuer or the token disclosed, gains little: they name the same organization.
- It needs its own keys (one more setup, about 1.5 GB). Its circuit can also take the signer certificate's calendar-date check, deferred in #39 to keep earlier keys valid.

### P2. What is disclosed

- **Proposed: whole assertions, chosen by label; the hard binding always**; by default nothing else (`--disclose c2pa.actions.v2`, for example, adds the actions).
- **One circuit for every choice: a fixed layout of four reference slots.** Slot 0 is the hard binding; slots 1–3 are optional, each with a public active flag; an unused slot is all zero, and the verifier builds the same layout from the visible claim (the listed references in order, then zero slots). One key set covers zero to three further disclosures, which covers the real claims (two assertions) with room; the cost of the four slots is paid always. The alternative, a circuit and key set per disclosure count, was rejected: more setups and keys, and the count would select the key set.
- **Not proposed now: disclosing part of an assertion**, such as the digital source type without the description. It needs the assertion private too: hashing its superbox content in the circuit (a SHA-256 over about 205 bytes) and walking its CBOR, an estimated 0.4–0.6M constraints. It is the most valuable refinement (captured or generated, without the product), and a candidate next experiment.

### P3. The output's claim

The claim box must hold a claim, at the original's size. Proposed fields:

- **`instanceID`:** a fresh random UUID per output, so it links to nothing.
- **The manifest's label** (`urn:c2pa:` and a UUID, outside the claim): also replaced by a fresh UUID, of the same length; the claim's `signature` reference is relative (`self#jumbf=c2pa.signature`) and unaffected. Tests check that neither the original label nor the original `instanceID` remains.
- **`claim_generator_info`:** the anonymizer (`c2pa-x509-zk`), never the original's generator.
- **`created_assertions`:** the disclosed assertions' hashed URIs, in the original's form.
- **`signature` and `alg`:** as the original.
- **Actions:** C2PA requires one, but the original's cannot be disclosed in part, and a new one would not be proven. Proposed: when the actions are not disclosed, the anonymizer adds its own actions assertion in `gathered_assertions` (`c2pa.redacted`, "assertions withheld"), outside what the proof covers; the verifier reports it as the anonymizer's, and the proof's references come from `created_assertions` only.

### P4. Conformance

The output already fails standard validation (the private-use algorithm); with a claim the original signer did not sign, it departs further from C2PA's model, where the signed claim is public. The verifier's report must say what is proven: that some claim, signed under the policy's trust, referenced the disclosed assertions. That claim's other contents are not disclosed, nor proven to be anything in particular, beyond the circuit's profile.

### P5. Linkability

- **Removed:** the original `instanceID` and manifest label, the generator's name and build, and the undisclosed assertions, with their salts if any.
- **Remaining:** the hard binding (the content's hash and its exclusions' layout), and the salts of disclosed assertions, which their hashes cover; anyone holding the original still links them, as today.

## Metadata outside the claim (H6)

EXIF and XMP sit in byte ranges the hard binding excludes, so changing them does not break it.

- **Proposed:** the anonymizer scrubs them in place, overwriting the excluded ranges' identifying segments at the same size, by default when the claim is hidden and opt-in otherwise. It reports what it removed, and the tests check that the hard binding still matches and that nothing of the original metadata remains.
- **Independent of the circuit,** so it can come first.
- **Implemented** (#44, `--scrub-metadata`, opt-in; [`scrub.rs`](crates/c2pa-x509-zk-demo/src/scrub.rs)), JPEG for now. Only excluded bytes change, and the scrubber checks that no byte the binding covers did. Each excluded range must be the manifest store (whole APP11 segments, as real assets exclude it, recognized by its structure: the JUMBF transport's instance and sequence numbers, a `jumb` superbox reassembled to exactly its declared length, with nothing after it, and a description box of the C2PA store's type labelled `c2pa`, within it) or one segment's payload holding EXIF, XMP, or extended XMP; anything else is refused, before proving. Exclusions are validated with checked arithmetic, and a refusal changes nothing; a payload counts as already scrubbed only if it is exactly the marker and zeros. A scrubbed payload keeps its marker and length (the binding covers them) and becomes an inert identifier and zeros. Metadata the binding covers is reported as kept.
- **On the real samples:**
  - **The device photo:** its EXIF and all its XMP (12 segments, about 670 KB) are excluded and removed; the vendor's and the model's names then remain only in the manifest store (the claim). Kept, because signed: the ICC profile, the MPF index, and the appended gain-map image (its XMP holds only HDR parameters).
  - **The AI-generated image** binds its XMP and IPTC (APP13): they name the vendor and are signed, so scrubbing cannot remove them, and reports them. For such assets, only the signer can omit them; the private claim does not reach them either, since they are part of the content the hard binding covers.
  - **The edited photo** has two manifests, which the anonymizer refuses ([E8](README.md#e8-ingredient-manifests)).

## Estimated cost

| Part | Constraints | Basis |
|---|---|---|
| The claim reference walk, four slots (the hard binding and up to three others) | 510,920 | Measured (spike), whatever the number used |
| The claim no longer a public input | A few tens of thousands fewer (estimate) | The packing of 1 KB into 33 public elements and its comparison with the preimage, removed |
| **P1 as proposed, over hidden-all** | **About +0.5M (+8%)** | |
| Part of an assertion disclosed (P2, not proposed now) | About +0.4–0.6M | E1's SHA-256 over ~200 bytes, and a CBOR walk |

## Proposed plan

1. **H6, metadata scrubbing**, independent of the circuit (done: #44).
2. **The private-claim statement:** the walk inside the signature's preimage (at the claim's offset, rather than a separate buffer), the statement and its CLI, tests, and the signer certificate's calendar-date check.
3. **The anonymizer and verifier:** the output's claim (P3), blanking undisclosed assertions, `--disclose`, the verifier's references from the visible claim, and the measurement.
4. **Partial disclosure within the actions** (P2), as a separate experiment.

## Guarantees and shortcuts

- **Gained:** the claim's generator, instance identifier, and undisclosed assertions are not disclosed; the disclosed ones are proven to have been referenced by the signed claim.
- **Not gained:** what disclosed assertions themselves say; the content's hash and the binding's layout; anything outside the claim before H6.
- **New reduced profile:** the claim must fit the walk's profile (above), which the three real claims do; claims outside it are refused, not partially verified.
