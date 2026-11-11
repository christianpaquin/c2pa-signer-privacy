# H4: Hiding the Issuing CA

**Status: proposed, for review.** This note designs [roadmap H4](README.md#h4-hiding-the-issuing-ca) before any circuit work, as [E2a](THIRD-PARTY-STATEMENT.md) did for the third-party statement. Each choice is listed under [Decisions for review](#decisions-for-review) with a proposed default.

## The problem

A third-party anonymized asset discloses its issuing CA: the ZK signature carries the issuing chain, which the verifier validates against the trust list ([D4](ARCHITECTURE-DECISIONS.md#d4-where-the-issuing-ca-chain-lives-decided)), and the CA's key is a public input of the proof ([THIRD-PARTY-STATEMENT.md](THIRD-PARTY-STATEMENT.md#public-and-private-inputs)). The anonymity set is everyone that CA certified. On the official C2PA trust list, CAs are run per organization and often per product line or kind of signer (devices, applications, servers), so the CA alone can narrow the signer to an organization's product.

H4 replaces "this CA issued the signer's certificate" with "some CA on the trust list did": the circuit proves that the issuing CA's key is in a Merkle tree built over the trust list, and the verifier rebuilds the tree's root from the list it already trusts. The same building blocks serve [E3](README.md#e3-trust-model-b-merkle-membership) (trust model B), where the tree holds signers instead of CAs.

## What the trust list holds

The official C2PA trust list (`conformance-public` at `a95f2c4`, synced 2026-11-04), by certificate:

| | Signer trust list | TSA trust list |
|---|---|---|
| Certificates | 33, from 19 organizations | 24, from 15 organizations |
| Keys | 28 P-384, 4 RSA-4096, 1 P-521 | 19 P-384, 4 RSA-4096, 1 P-521 |
| Self-signed roots | 21 | 17 |
| Listed intermediates | 12 (11 P-384), all with `pathLenConstraint` 0 | 7 (6 P-384), all with `pathLenConstraint` 0 |
| Certificates per organization | 1 to 6 | 1 to 4 |

Organizations list the intermediates that issue end-entity certificates directly, so a signer's issuing CA is often itself on the list, as in the [real device photo](DEPLOYMENT-FINDINGS.md#r2-anonymizing-a-real-asset) (a one-certificate path).

## What H4 can and cannot hide

Hiding the CA helps only if nothing else in the asset names it more precisely. Three other disclosures matter:

| Disclosure | Hidden by H4? | Notes |
|---|---|---|
| The issuing CA | Yes | The anonymity set becomes every listed CA the circuit supports ([I1](#i1-the-membership-set)) |
| The claim generator and assertions | No | The original claim is kept unchanged, so its hard binding stays valid ([Q1](THIRD-PARTY-STATEMENT.md#q1-output-form)); device claims name the capture software, and actions describe it. Hiding claim content would mean redaction, a different output design ([Q9](THIRD-PARTY-STATEMENT.md#q9-assertions-and-metadata)) |
| The time-stamp authority | No, unless the token is hidden | The public token carries the TSA's certificate, which names its operator; in the real device photo, the TSA is run by the same organization as the CA ([Q7](THIRD-PARTY-STATEMENT.md#q7-time-stamp-threat-model)) |
| The signature algorithm | No | The verifier needs the matching circuit; the anonymity set is limited to CAs with the circuit's key type |

So H4 alone adds little for content from vertically integrated pipelines, where one organization runs the CA, the TSA, and the claim generator: the TSA and the claim already name it. It helps where the CA is narrower than the rest of what the asset discloses: an organization with its own CA, using common signing software and a shared TSA (a newsroom or agency signing with widely used tools, for example). Hiding the TSA as well ([I6](#i6-the-time-stamp-token)) extends it to organizations that also run their own TSA.

## The statement with a hidden CA

The chain of trust of [E2a](THIRD-PARTY-STATEMENT.md#the-chain-of-trust), with the first link moved into the circuit:

| Link | Today (E2b) | With H4 |
|---|---|---|
| Trusted issuer | Off-circuit: the verifier validates the disclosed issuing chain against the trust list at `t`; the CA's key is a public input | **In-circuit:** the CA's key, with its validity period, is a leaf of the Merkle tree whose root `R` is public; `notBefore ≤ t ≤ notAfter`. The verifier rebuilds `R` from its trust list |
| Authorized signer, original signature, claim, time | Unchanged | Unchanged, with the CA's key now private |

What the verifier learns: *the claim in this asset was signed by the holder of a certificate that a CA on trust list `R` issued for claim signing, valid at time `t`*.

| Public | Private (new) |
|---|---|
| The claim bytes, the time `t`, the time-stamp imprint (unchanged) | The issuing CA's key and validity period |
| The trust-list root `R` (replaces the CA's key) | The Merkle path to the CA's leaf |

## Decisions for review

### I1. The membership set

Which certificates become leaves.

- **Every certificate on the signer trust list with the circuit's key type (proposed).** For the current statement, the 28 P-384 certificates, roots and intermediates alike: a listed certificate is a trust anchor, whatever its position in its organization's hierarchy. The verifier admits only certificates that are CAs (basic constraints, key usage) when it builds the tree.
- **Only listed intermediates.** A smaller set (11 P-384), reflecting where issuance actually happens, but excluding organizations that issue end-entity certificates from their root.

Per-key-type trees follow from fixed circuits: an RSA-4096 CA would need the RSA CA circuit ([E1](FEASIBILITY.md#e1-rsa-primitives)) and its own tree, and the algorithm, being disclosed, splits the anonymity set.

### I2. Chain depth

- **The issuing CA is on the list (proposed).** One membership proof replaces the off-circuit chain. Covers the observed real case. Signer certificates issued by an unlisted intermediate are refused, as they would need the next option.
- **One unlisted intermediate.** The circuit also verifies the intermediate's certificate under a listed CA: a second CA signature over a TBS (about 1.5M constraints with P-384 and SHA-384 over 1.5 KB, from E1), its validity, and its basic constraints. About +30% on V1. Worth adding only if real assets need it.

### I3. The leaf and the hash

- **Leaf** = H(CA key, `notBefore`, `notAfter`): the key the circuit verifies the signer certificate with, and the validity period the circuit must now check at `t` (today checked off-circuit). Other properties of the CA certificate (CA flag, key usage, name constraints) are checked by the verifier when it builds the tree; they do not depend on `t`.
- **Hash: Poseidon2 over the proof's scalar field (proposed).** Cheap in-circuit (a few hundred constraints per hash, so a depth-8 path is negligible next to V1's 4.7M), available in gnark (`std/hash/poseidon2`, with `std/accumulator/merkle`). It is curve-specific: BN254 and BLS12-381 keys ([E7](README.md#e7-curve-bn254-vs-bls12-381)) give different roots, so the root is computed by the same Go code as the proof, in the gnark CLI, for prover and verifier alike.
- **SHA-256** would make the root computable by any tool, but costs about 54k constraints per block: about 0.5M for the leaf and a depth-8 path, roughly +10%.

### I4. Tree shape and list updates

- **Fixed depth 8 (proposed):** up to 256 leaves, leaves sorted by hash, empty leaves zero. The list's growth does not change the circuit, and the depth does not reveal the list's size.
- **Updates.** The root changes whenever the trust list does. The ZK signature carries `R` and an identifier of the list version; the verifier accepts `R` if it equals the root of a list version it trusts. Without a history of lists, an asset anonymized under an older list stops verifying when the list changes. Proposed: the verifier takes a set of trusted list versions (the official list is versioned in git), and reports which version matched. Whether a CA removed from the list should still be accepted for content signed while it was listed is a policy question C2PA answers for ordinary validation; the verifier follows it by choosing which versions it trusts.

### I5. The output format

- The ZK signature drops the issuing chain (saving about 1–2 KB, more room for the proof and a hidden token) and carries `R` and the list identifier instead.
- **D4 is revised:** `x5chain` is absent, since no certificate is disclosed. Standard tools that need a signing certificate (c2pa-rs treats its absence as fatal) then fail earlier than today, where they display the issuing CA; display needs the same changes as [H8](README.md#h8-c2patool-support). The critical private-use algorithm still makes the signature fail closed.
- `--issuer` (checking which CA issued the certificate) no longer applies; a verifier wanting a specific CA uses the disclosed form.

### I6. The time-stamp token

For the gain of [What H4 can and cannot hide](#what-h4-can-and-cannot-hide) to hold for organizations that run their own TSA, the token must be hidden too ([Q7](THIRD-PARTY-STATEMENT.md#q7-time-stamp-threat-model), "hidden token"). That means verifying in the circuit the TSA's signature over the token's signed attributes, the TSA certificate under a CA on the TSA trust list (the same membership proof, over a second tree), and parsing the token's `TSTInfo` for `t` and the imprint. Estimated from E1 and E2b, not measured: about 2–2.5M constraints (a CA signature over the TSA certificate, the TSA's signature, and hashes over 1–2 KB of token), roughly +50% on V1.

- **Proposed: separate step.** H4 first, with the public token, stated as a limitation; the hidden token as a second experiment, since its cost is substantial and its value depends on who runs the TSA.

### I7. Disclosed or hidden, per asset

- **Proposed: a choice of the anonymizer,** with two statements (and two key sets): the current one (CA disclosed, `--issuer` possible, cheaper to display) and the H4 one. Disclosing the CA can be useful (a verifier may trust some CAs more), and the choice is visible in the output.
- **Proposed default: the CA disclosed; the hidden CA is opt-in** (an anonymizer flag such as `--hide-issuer`, named at implementation), as for BLS12-381 ([E7](README.md#e7-curve-bn254-vs-bls12-381)). The disclosed form needs only the current trust list, keeps `--issuer`, and displays as today, and the hidden form gains little where the claim and the time-stamp token already name the organization ([What H4 can and cannot hide](#what-h4-can-and-cannot-hide)). Revisit the default if the hidden token (I6) lands and hiding becomes the common need.

## Estimated cost

| Part | Constraints (estimate) | Basis |
|---|---|---|
| Poseidon2 leaf and a depth-8 path | Under 10k | A few hundred per Poseidon2 hash over BN254 |
| Validity check of the CA at `t` | Under 1k | Two comparisons |
| CA key private instead of public | About 0 | Same ECDSA verification |
| **H4, I1–I5 as proposed** | **Under 1% of V1** | |
| Hidden token (I6) | About +2–2.5M | E1 (CA signature over a TBS, P-384 ECDSA), E2b (SHA-256 over the token) |
| One unlisted intermediate (I2) | About +1.5M | E1 |

Verification cost and proof size are unchanged; the ZK signature shrinks by the issuing chain.

## Proposed plan

1. **H4 core (I1–I5 and I7 as proposed, opt-in):** Poseidon2 tree over the P-384 certificates of the signer trust list, built by the gnark CLI; the statement takes `R` instead of the CA's key and checks the CA's validity at `t`; the ZK signature carries `R` and the list identifier; the verifier rebuilds `R` from the trusted list versions. Tests: membership forgery (a key not on the list, a wrong path, a CA outside its validity at `t`), a root from another list, and the existing end-to-end and real-asset tests. Measured with the harness against V1.
2. **Hidden token (I6),** as a separate experiment once H4's core is in.
3. **One unlisted intermediate (I2),** only if real assets need it.

## Guarantees and shortcuts

Unchanged from [E2a](THIRD-PARTY-STATEMENT.md#guarantees-and-shortcuts), except:

- **Gained:** the issuing CA is hidden among the listed CAs of the circuit's key type, against verifiers who do not hold the original asset.
- **Not gained:** the claim's content and, with a public token, the TSA still disclose what they disclose today; for vertically integrated pipelines that is the organization and often the product.
- **New trust in the verifier's list history:** an asset verifies only against a list version the verifier trusts, so trust-list governance (which versions, removals) becomes part of verification.
