# H4: Hiding the Issuing CA

**Status: adopted (PR #34) and implemented, as an opt-in** (the core, I1–I5 and I7): the tree (format version 1) and the hidden-issuer statement in the gnark prover ([`issuertree`](gnark/issuertree/), [`statement/hidden.go`](gnark/statement/hidden.go)); `--hide-issuer` in the anonymizer, `--issuer-policy` in the verifier ([`third_party.rs`](crates/c2pa-x509-zk-demo/src/third_party.rs)). Measured: no cost beyond noise per asset; on the official trust list, the issuer is hidden among 28 P-384 CAs from 18 organizations ([FEASIBILITY.md](FEASIBILITY.md#h4-hiding-the-issuing-ca)). The hidden token (I6) and unlisted intermediates (I2) remain. This note designs [roadmap H4](README.md#h4-hiding-the-issuing-ca), as [E2a](THIRD-PARTY-STATEMENT.md) did for the third-party statement. Each choice is listed under [Decisions for review](#decisions-for-review) with its default.

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

What the verifier learns: *the claim in this asset was signed by the holder of a certificate that was issued for claim signing by some CA of the circuit's key type listed directly in a verifier-approved set `R`, and valid at time `t`*. Two qualifications: H4 proves membership of the **issuing CA**, not of the signer (signer membership is [E3](README.md#e3-trust-model-b-merkle-membership)); and the CA must be **directly listed**, so certificates issued by an unlisted intermediate under a listed root are not covered ([I2](#i2-chain-depth)).

What a membership proof can and cannot express:

| Desired statement | Supported? |
|---|---|
| Issued by some supported CA on the complete approved list | Yes |
| Issued by some CA in an approved subset (for example, the CAs of organizations A, B, and C), without revealing which | Yes, with that subset's root; no new trusted setup, since the root is a public input and the depth is fixed. A proof against the full list's root does not prove membership in a subset: the proof must be made against the subset's root |
| Signed by one of several named individuals or directly trusted signer keys | No: that is signer membership ([E3](README.md#e3-trust-model-b-merkle-membership)) |
| Issued by some CA in an approved subset, without revealing which subset | No: the root identifies the set |

The verifier must approve the root ([I4](#i4-tree-shape-and-verifier-policy)): accepting a root supplied by the asset would let anyone define their own trust list.

| Public | Private (new) |
|---|---|
| The claim bytes, the time `t`, the time-stamp imprint (unchanged) | The issuing CA's key and validity period |
| The trust-list root `R` (replaces the CA's key) | The Merkle path to the CA's leaf |

## Decisions for review

### I1. The membership set

Which certificates become leaves.

- **Every certificate on the signer trust list with the circuit's key type (proposed).** For the current statement, the 28 P-384 certificates, roots and intermediates alike: a listed certificate is a trust anchor, whatever its position in its organization's hierarchy. **Eligibility is unchanged from the disclosed form:** building the tree applies the verifier's existing CA check (`check_ca` in [`trust.rs`](crates/c2pa-x509-zk-demo/src/trust.rs)) to each certificate: a CA certificate, key usage (if any) allowing certificate signing, an extended key usage (if any) allowing C2PA claim signing, no unrecognized critical extension, and a path length allowing it to issue end-entity certificates. Only the validity at `t` moves into the circuit ([I3](#i3-the-leaf-and-the-hash)). **Constraints on the signer's subject cannot be checked** when the subject is hidden: certificates carrying name constraints or policy constraints, critical or not, are left out of the tree (enforcing them in-circuit is out of scope).
- **Only listed intermediates.** A smaller set (11 P-384), reflecting where issuance actually happens, but excluding organizations that issue end-entity certificates from their root.

Per-key-type trees follow from fixed circuits: an RSA-4096 CA would need the RSA CA circuit ([E1](FEASIBILITY.md#e1-rsa-primitives)) and its own tree, and the algorithm, being disclosed, splits the anonymity set.

### I2. Chain depth

- **The issuing CA is on the list (proposed).** One membership proof replaces the off-circuit chain. Covers the observed real case. Signer certificates issued by an unlisted intermediate are refused, as they would need the next option.
- **One unlisted intermediate.** The circuit also verifies the intermediate's certificate under a listed CA: a second CA signature over a TBS (about 1.5M constraints with P-384 and SHA-384 over 1.5 KB, from E1), its validity, and its basic constraints. About +30% on V1. Worth adding only if real assets need it.

### I3. The leaf and the hash

- **Leaf** = H(CA key, `notBefore`, `notAfter`): the key the circuit verifies the signer certificate with, and the validity period the circuit must now check at `t` (today checked off-circuit). The CA's other properties do not depend on `t` and are checked when the tree is built ([I1](#i1-the-membership-set)). The exact encoding is in [Tree format, version 1](#tree-format-version-1).
- **Hash: Poseidon2 over the proof's scalar field (proposed).** Cheap in-circuit (a few hundred constraints per hash, so a depth-8 path is negligible next to V1's 4.7M), available in gnark (`std/hash/poseidon2`, with `std/accumulator/merkle`). It is curve-specific: BN254 and BLS12-381 keys ([E7](README.md#e7-curve-bn254-vs-bls12-381)) give different roots, so the root is computed by the same Go code as the proof, in the gnark CLI, for prover and verifier alike.
- **SHA-256** would make the root computable by any tool, but costs about 54k constraints per block: about 0.5M for the leaf and a depth-8 path, roughly +10%.

### I4. Tree shape and verifier policy

- **Fixed depth 8 (proposed):** up to 256 leaves, built as specified in [Tree format, version 1](#tree-format-version-1). The list's growth does not change the circuit, and the depth does not reveal the list's size.
- **Approved roots.** The verifier is configured with the roots it approves, each built by the verifier itself from a trust-list snapshot or from a subset it approves. The asset's root must equal one of them. The ZK signature also carries an identifier of the list version, but only as a hint for finding the root: it is never trusted, and an asset cannot select a policy through it.
- **Subsets.** An approved subset is a list like any other (for example, the CAs of a few organizations), built into its own root. The root reveals which subset was used, and a narrow subset narrows the anonymity set accordingly; results report the set's size.
- **Older lists and removed CAs.** The root changes whenever the trust list does, and accepting an old root alone does not establish that its CAs were trusted at the signing time. Proposed: each approved snapshot comes with the interval during which it applied (from its effective date until the next snapshot), and the verifier requires the asset's `t` to fall in that interval. A CA removed from the list then stays acceptable for content time-stamped while it was listed, and not after; a verifier wanting stricter treatment (for example, after a CA's compromise) withdraws the affected snapshots from its policy. The official list is versioned in git, which gives the snapshots and their dates.
- **Tests:** a root the verifier did not approve; a list identifier naming one snapshot with the root of another, or a root of an approved snapshot with `t` outside its interval (both rejected); a subset's root accepted only when the verifier approves that subset.

### I5. The output format

- The ZK signature drops the issuing chain (saving about 1–2 KB, more room for the proof and a hidden token) and carries `R` and the list identifier instead.
- **D4 is revised:** `x5chain` is absent, since no certificate is disclosed. Standard tools then fail earlier than today, where they display the issuing CA; display needs the same changes as [H8](README.md#h8-c2patool-support). The critical private-use algorithm still makes the signature fail closed.
- **Our own verifier depends on it too.** Checked with a probe on the mirror fixture (a ZK signature without `x5chain`, same size): c2pa-rs 0.77 does not read the manifest at all ("could not find signing certificate chain in COSE signature"), so the verifier's c2pa checks of the claim's assertions and hard binding would fail. **Requirement:** those checks are preserved, never disabled. Proposed: the verifier validates a local copy of the asset whose ZK signature carries a fixed placeholder certificate (the same for every asset, identifying no one, padded to the same size so the hard binding's exclusions are unchanged), ignoring only the signature and credential codes, as it does today; the output itself carries no certificate. Alternative: validate the assertion hashes and the hard binding directly, which avoids the copy but reimplements part of C2PA validation.
- `--issuer` (checking which CA issued the certificate) no longer applies; a verifier wanting a specific CA uses the disclosed form.

### I6. The time-stamp token

For the gain of [What H4 can and cannot hide](#what-h4-can-and-cannot-hide) to hold for organizations that run their own TSA, the token must be hidden too ([Q7](THIRD-PARTY-STATEMENT.md#q7-time-stamp-threat-model), "hidden token"). That means verifying in the circuit the TSA's signature over the token's signed attributes, the TSA certificate under a CA on the TSA trust list (the same membership proof, over a second tree), and parsing the token's `TSTInfo` for `t` and the imprint. Estimated from E1 and E2b, not measured: about 2–2.5M constraints (a CA signature over the TSA certificate, the TSA's signature, and hashes over 1–2 KB of token), roughly +50% on V1.

- **Proposed: separate step.** H4 first, with the public token, stated as a limitation; the hidden token as a second experiment, since its cost is substantial and its value depends on who runs the TSA. Designed in [HIDING-THE-TIME-STAMP.md](HIDING-THE-TIME-STAMP.md).

### I7. Disclosed or hidden, per asset

- **Proposed: a choice of the anonymizer,** with two statements (and two key sets): the current one (CA disclosed, `--issuer` possible, cheaper to display) and the H4 one. Disclosing the CA can be useful (a verifier may trust some CAs more), and the choice is visible in the output.
- **Proposed default: the CA disclosed; the hidden CA is opt-in** (an anonymizer flag such as `--hide-issuer`, named at implementation), as for BLS12-381 ([E7](README.md#e7-curve-bn254-vs-bls12-381)). The disclosed form needs only the current trust list, keeps `--issuer`, and displays as today, and the hidden form gains little where the claim and the time-stamp token already name the organization ([What H4 can and cannot hide](#what-h4-can-and-cannot-hide)). Revisit the default if the hidden token (I6) lands and hiding becomes the common need.

## Tree format, version 1

Specified so that the root is reproducible and has a single interpretation.

- **Leaf inputs,** in order, each a field element: a domain tag (`1`, leaf), the format version (`1`), a key-type tag (`1`, P-384), the CA key's x coordinate as three 128-bit limbs (most significant first), the y coordinate likewise, then `notBefore` and `notAfter` as Unix seconds (each below 2^64). Coordinates are canonical (below P-384's field modulus) and are never reduced into a single field element, so the encoding is injective. In the circuit, the 128-bit limbs are composed from the emulated key's range-checked 64-bit limbs, with the coordinates asserted canonical.
- **Internal nodes:** H(`2`, left, right). **Empty leaves:** H(`3`). Distinct tags separate the three, so no leaf can equal a node or an empty leaf by construction.
- **Hash:** Poseidon2 with gnark-crypto's default parameters for the proof's scalar field, in gnark's Merkle–Damgård mode (`std/hash/poseidon2`), pinned by the gnark version recorded with the keys. BN254 and BLS12-381 give different roots.
- **Ordering:** leaves sorted by their hash as an integer, ascending; a certificate listed twice (the same key and validity) gives one leaf; the same key with different validity periods (renewals) gives one leaf each. Padding with empty leaves to 256; more than 256 eligible certificates is refused (a new format version).
- **Recorded with the root,** in the ZK signature: the format version, the key type, the proof's curve, and the list identifier (a hint, [I4](#i4-tree-shape-and-verifier-policy)).

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

1. **H4 core (I1–I5 and I7 as proposed, opt-in):** a Poseidon2 tree (version 1) over the eligible P-384 certificates of the signer trust list, built by the gnark CLI; the statement takes `R` instead of the CA's key and checks the CA's validity at `t`; the ZK signature carries `R` and the list identifier; the verifier checks `R` against its approved roots and their intervals, and keeps its c2pa checks through the placeholder copy. Tests: membership forgery (a key not on the list, a wrong path, a CA outside its validity at `t`, a non-canonical coordinate), the policy tests of [I4](#i4-tree-shape-and-verifier-policy), assertion and hard-binding failures still detected without `x5chain`, and the existing end-to-end and real-asset tests. Measured with the harness against V1.
2. **Hidden token (I6),** as a separate experiment once H4's core is in.
3. **One unlisted intermediate (I2),** only if real assets need it.

## Guarantees and shortcuts

Unchanged from [E2a](THIRD-PARTY-STATEMENT.md#guarantees-and-shortcuts), except:

- **Gained:** the issuing CA is hidden among the listed CAs of the circuit's key type, against verifiers who do not hold the original asset.
- **Not gained:** the claim's content and, with a public token, the TSA still disclose what they disclose today; for vertically integrated pipelines that is the organization and often the product. H4 hides which CA's membership was proved; it does not prevent inferring the issuer from the claim, metadata, the token, or a small set. Implementation results must report these residual disclosures and the anonymity set's size.
- **New trust in the verifier's policy:** an asset verifies only against a root the verifier approved, within the interval of its snapshot, so trust-list governance (which snapshots and subsets, removals) becomes part of verification.
