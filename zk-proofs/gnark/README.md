# Third-party statement in gnark (E2b)

The third-party anonymization statement specified in [THIRD-PARTY-STATEMENT.md](../THIRD-PARTY-STATEMENT.md), as a gnark circuit (Groth16 on BN254), with a CLI the Rust tools call. Roadmap item [E2b](../README.md#e2b-third-party-anonymization); gnark was chosen after [E1](../FEASIBILITY.md#e1-p-384-and-sha-384-primitives).

## What the circuit proves

Public inputs, all derived by the verifier from the anonymized asset: the claim (packed 31 bytes per field element, with its length), the issuing CA's P-384 key, the time `t`, and the time stamp's SHA-256 message imprint. Private: the claim signature's `Sig_structure` (which contains the original protected header `P`, and in it the signer certificate), the claim signature, and the CA's signature over the signer certificate's TBS.

| Link ([chain of trust](../THIRD-PARTY-STATEMENT.md#the-chain-of-trust)) | In the circuit |
|---|---|
| Authorized signer | The CA's key verifies an ECDSA P-384 signature over SHA-384 of the TBS. A structural DER walk of the TBS reads, at parsed positions: a v3 certificate, the subject's P-256 key, the validity period (`notBefore <= t <= notAfter`), exactly one extended key usage extension that includes C2PA claim signing, and basic constraints absent or with `cA` false, its sequence decoded like every other field (an encoding the walk does not recognize fails, never passes) ([Q5](../THIRD-PARTY-STATEMENT.md#q5-in-circuit-certificate-checks)) |
| Signer certificate in the header | `P` is `{1: ES256, 33: [signer certificate, ...]}`, and the certificate whose TBS is walked is its first `x5chain` entry |
| Original COSE signature | The signer key verifies the ES256 signature (`r`, `s` in range) over SHA-256 of `["Signature1", P, h'', claim]` |
| Original claim | The claim in the `Sig_structure` equals the public claim, byte for byte, with canonical zero padding |
| Time | The imprint is SHA-256 of `["CounterSignature", P, h'', bstr(bstr(r ‖ s))]`, the `sigTst2` construction confirmed on a real asset ([DEPLOYMENT-FINDINGS](../DEPLOYMENT-FINDINGS.md#anatomy-of-a-real-manifest)) |

Off the circuit, the verifier validates the issuing CA's chain to the trust list at `t`, the time-stamp token (signature, TSA trust list, and that it attests `t` and the imprint), and the claim's assertions and hard binding; that is [PR B of E2b](../README.md#e2b-third-party-anonymization).

**Encodings the circuit accepts**, as both real device-signed assets and c2pa-rs produce them; others are refused:

- `P` is a map of exactly two entries, `alg` (ES256) then `x5chain` (1 to 23 certificates), 256 bytes to the maximum; the signer certificate and its TBS use two-byte DER lengths (256 to 65,535 bytes);
- validity times are UTCTime `YYMMDDHHMMSSZ` for 2000–2049;
- a v3 TBS without issuer or subject unique identifiers, ending with its extensions;
- the CA's signature may be any valid one over the TBS, not necessarily the certificate's own signature field (equivalent for the statement).

**Shortcuts** (listed in the statement's [guarantees](../THIRD-PARTY-STATEMENT.md#guarantees-and-shortcuts)): no revocation; key usage, unknown critical extensions, name constraints, and policies are not checked ([H2](../README.md#h2-full-certificate-validation-in-the-circuit)); the issuing CA must be P-384 (the mirror PKI's and the official list's dominant algorithm); ES256 claim signatures and `sigTst2` only ([Q10](../THIRD-PARTY-STATEMENT.md#q10-first-algorithms)).

**Sizes** ([Q4](../THIRD-PARTY-STATEMENT.md#q4-circuit-size-limits)): `P` 2 KB, claim 1 KB, TBS 1 KB, 16 extensions, 8 key purposes: 4,710,820 constraints and 50 public inputs (34 for the claim, 12 for the CA key, the claim length, the time, and two for the imprint).

## Using it

Requires Go 1.27.3 or later (`go.mod`).

```bash
cd zk-proofs/gnark
go build -o ../target/c2pa-zk-gnark ./cmd/c2pa-zk-gnark

# From a signed, time-stamped asset (for example the mirror fixture; see the main README):
c2pa-x509-zk-statement-inputs --input signed.png --trust-list trust-list.pem --out inputs.json --public-out public.json
../target/c2pa-zk-gnark check  --input inputs.json                 # solve only (~20 s)
../target/c2pa-zk-gnark setup  --keys keys/                        # one-time
../target/c2pa-zk-gnark prove  --keys keys/ --input inputs.json --proof proof.bin
../target/c2pa-zk-gnark verify --keys keys/ --public public.json --proof proof.bin
```

`setup` writes the constraint system, the keys, and `keys.json` (sizes and each file's SHA-256, checked before loading). `check` draws the lookup challenge at random instead of computing it from the proof's commitment, so it tests satisfiability without a proof.

### Proving-key formats (E6)

`setup` writes the proving key compressed; `c2pa-zk-gnark convert-pk --keys DIR` also writes it raw (uncompressed points) and as gnark's binary dump, after loading the compressed key with full point checks. `keys.json` records each file's hash, the gnark version that wrote it, and its source.

```bash
../target/c2pa-zk-gnark prove --keys keys/ --input inputs.json --proof proof.bin                                # default: compressed, full checks
../target/c2pa-zk-gnark prove --keys keys/ --input inputs.json --proof proof.bin --pk-format raw --pk-check none   # opt-in fast path
```

Loading without point checks is refused unless the key's provenance record matches the file and the running gnark version. Every file is streamed twice through a bounded buffer, hashed before parsing and again while parsing; a file that changes in between, or has trailing bytes, is rejected. Measurements and the trade-off: [FEASIBILITY.md](../FEASIBILITY.md#e6-proving-key-loading-in-gnark). The dump is not recommended beyond a disposable local cache.

## Tests

```bash
go test ./...                       # ~35 s: compiles at test sizes and solves
C2PA_ZK_GROTH16=1 go test ./...     # adds a real setup, proof, and verification (~6 min, ~8 GB)
```

- Valid statements are accepted, with both claim header forms.
- Rejected: a changed claim byte or length, imprint, a time just outside validity (the boundaries are inclusive), another CA, a changed claim signature, signer certificate byte, protected header byte, protected length, or CA signature.
- Basic constraints: accepted when absent, empty, with `cA` FALSE written out, or with only a path length; rejected for `cA` TRUE in short and long-form sequences (a valid DER sequence with a 123-byte path length), with a path length, as a BOOLEAN of length 2, with an unexpected first element, or when the sequence does not fill the extension value or the BOOLEAN runs past it.
- Certificate purpose: rejected without the claim-signing purpose, without an extended key usage extension, with the EKU hidden inside another extension, with two EKU extensions, or for a CA certificate; accepted with claim signing alone or among other purposes.
- Components: variable-length SHA-384 against `crypto/sha512` at padding boundaries; UTCTime conversion against Go's `time` (leap days, the 2049 limit) and malformed dates.

Certificates in the tests are built field by field with `encoding/asn1`, since `crypto/x509` refuses to create some of the malformed ones. From the Rust side, `tests/third_party_fixtures.rs` checks that the inputs exported from a real c2pa-signed asset satisfy the statement at the default sizes and that a tampered time does not (`C2PA_ZK_GO=$(which go) cargo test --release --test third_party_fixtures -- --ignored`).
