# Reproducing the Results

How to rebuild the prototype, set up its keys, run every mode, run the tests, and reproduce the measurements and real-asset results of [Milestone 1](MILESTONE-1.md). Commands run from `zk-proofs/`. M0's reproduction is in [M0-BASELINE.md](M0-BASELINE.md#reproduction).

## Requirements

- **Machine:** 32 GB of RAM is comfortable. Key setup peaks at about 11 GB; proving at 6.7–8.5 GB depending on the mode. Each statement's keys take 1.2–2 GB on disk (the fast key path adds about 2.3 GB).
- **Tools:** Rust (stable), Go 1.27.3 or later, the OpenSSL command line (test PKIs, time stamps, token checks), Python 3 (a few helper steps).
- **Time:** about 7–12 minutes per statement's setup, once; 1.5–2.5 minutes per anonymization.
- **Laptops:** keep the machine awake and on AC power for anything long; a sleep stops the processes, and spoils measurements ([Measurements](#measurements)).

## Build

```bash
cargo build --release
(cd gnark && go build -o ../target/c2pa-zk-gnark ./cmd/c2pa-zk-gnark)
```

## Keys

One key set per statement, each from a single-party setup. No key is committed. For self-contained local reproduction, run setup to generate a matching key pair. Independent setups produce different pairs; proofs verify wherever the corresponding trusted verifying key is installed, so verifying someone else's proofs means obtaining their verifying key through a trusted channel, not running a new setup. The paths below are those the tests and this guide use.

**Updating a checkout from before #47,** which tracked M0's verifying keys: Git removes the tracked copies when it applies the change, and a locally regenerated key counts as a local modification to resolve first. If you have an M0 setup to keep, back up `circuits/build/*_native.vk`, `*_native.build.json`, and `*_native.pk` before updating, and put them back afterwards: the same paths are read, and are now ignored.

```bash
./target/c2pa-zk-gnark setup --keys target/gnark-keys                                  # disclosed: 4,710,820 constraints
./target/c2pa-zk-gnark setup --keys target/gnark-keys-hidden --statement hidden-issuer # 4,718,946
./target/c2pa-zk-gnark setup --keys target/gnark-keys-hidden-all --statement hidden-all # 6,458,939
```

Options:

- **The fast key path** ([E6](FEASIBILITY.md#e6-proving-key-loading-in-gnark)): `./target/c2pa-zk-gnark convert-pk --keys DIR` adds the proving key in raw form, with its hash recorded; prove with `--pk-format raw --pk-check none`.
- **BLS12-381** ([E7](FEASIBILITY.md#e7-bls12-381-as-an-option)): `setup --curve bls12-381` (about 120 bits of security instead of about 100).

## The fixture

A test PKI that mirrors a real device deployment (P-384 CAs, a P-256 signer and TSA, a `sigTst2` time stamp from a local TSA), and an asset signed with it:

```bash
./generate-test-pki.sh --mirror fixtures/mirror
./target/release/c2pa-x509-zk-sign --input fixtures/cards.png --output signed.png \
    --cert fixtures/mirror/signer.pem --key fixtures/mirror/signer.key --ca fixtures/mirror/issuing-ca.pem \
    --tsa-cert fixtures/mirror/tsa.pem --tsa-key fixtures/mirror/tsa.key
```

## Each mode

The commands, with the verifier's policies, are in the [README's quick start](README.md#quick-start-third-party-mode): the disclosed mode with `target/gnark-keys`, `--hide-issuer` with `target/gnark-keys-hidden`, and `--hide-issuer --hide-time-stamp` with `target/gnark-keys-hidden-all`. Add `--scrub-metadata` to any of them (it removes nothing from the fixture, a PNG whose only excluded range is the manifest store; see [Real assets](#real-assets)).

What to expect: the anonymizer reports what it hid, what stays visible, and the spare bytes; the verifier prints "Valid" and what was established. The output keeps the input's size.

## Tests

```bash
(cd gnark && go test ./...)                   # Go: the statements and the CLI, both curves (~4 min)
cargo test --release                          # Rust: everything but real proofs (~1 min)
```

Real proofs, opt-in (`--ignored`), each needing its keys and the gnark CLI. Run them by name, one at a time, as below: a bare `cargo test --release -- --ignored` also selects the private-asset and M0 tests, which need other inputs (the private-asset test fails at once without `C2PA_R2_ASSET`), and starts several provers at once.

| Test | Needs | Time |
|---|---|---|
| `third_party_anonymization_end_to_end` | `C2PA_ZK_KEYS` (default `target/gnark-keys`) | ~1.5 min |
| `hidden_issuer_end_to_end` | `C2PA_ZK_HIDDEN_KEYS` (default `target/gnark-keys-hidden`) | ~1.5 min |
| `hidden_all_end_to_end` | `C2PA_ZK_HIDDEN_ALL_KEYS` (default `target/gnark-keys-hidden-all`) | ~1.7 min |
| `anonymized_ingredient_proof_verifies_after_an_edit` | `C2PA_ZK_KEYS` | ~1.5 min |
| `exported_inputs_satisfy_the_gnark_statement` | Go (`C2PA_ZK_GO`, the `go` binary, if not on the path) | ~1 min |
| `real_asset_end_to_end` | A real asset ([Real assets](#real-assets)) | ~2.5 min |
| M0's (`full_e2e_with_real_zk_proof`, `forged_key_*`) | M0's circuit and keys ([M0-BASELINE.md](M0-BASELINE.md#testing-m0)); run separately, with `--test-threads=1` | ~12 min |

```bash
# One at a time: each proof needs up to ~9 GB, and the test runner would otherwise start them together.
cargo test --release -p c2pa-x509-zk-demo --test third_party_fixtures -- --ignored --test-threads=1 \
    third_party_anonymization_end_to_end hidden_issuer_end_to_end hidden_all_end_to_end \
    anonymized_ingredient_proof_verifies_after_an_edit
(cd gnark && C2PA_ZK_GROTH16=1 go test ./statement -run Groth16)   # real Groth16 proofs at test sizes
```

## Measurements

The harness runs each phase in its own process and writes a JSON record ([README](README.md#benchmarks), accounting in [FEASIBILITY.md](FEASIBILITY.md)). With existing keys, setup is not measured:

```bash
B=./target/release/c2pa-x509-zk-bench
$B run --variant third-party --keys target/gnark-keys --out bench/results/DATE/1-disclosed.json
$B run --variant third-party --keys target/gnark-keys-hidden --hide-issuer --out bench/results/DATE/2-hidden-issuer.json
$B run --variant third-party --keys target/gnark-keys-hidden-all --hide-issuer --hide-time-stamp --out bench/results/DATE/3-hidden-all.json
$B run --variant third-party --keys target/gnark-keys --pk-format raw --pk-check none --out bench/results/DATE/4-fast-path.json
```

Each run takes 8–12 minutes: three cold proves (the key files evicted from the page cache first), three warm ones, and verification. How the published figures were obtained:

- **One session, adjacent runs:** this laptop's timings vary by 10–40% across sessions, so modes are compared within a session, with the baseline mode run first and last.
- **Kept awake, with a heartbeat:** on WSL, a PowerShell script holding `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)` keeps Windows from sleeping while the screen may lock; a loop appending `date +%s` to a file every 10 s shows any suspend as a gap. A session with a gap is discarded. Closing the lid or choosing Sleep overrides the keep-awake request.
- **Check the record:** every cold run's observed cache state, the commit (`git_commit`, with no changed tracked files), and the peak memory per phase are in the record.

| Mode | Fixture, per asset (cold) | Peak memory | Record |
|---|---|---|---|
| Disclosed | 72–77 s | 6.7 GiB | [2026-11-11-h4](bench/results/2026-11-11-h4/) (first run) |
| Hidden issuer | 75–77 s | 6.7 GiB | [2026-11-12-i6](bench/results/2026-11-12-i6/) |
| Hidden issuer and time stamp | 97 s | 8.5 GiB | [2026-11-12-i6](bench/results/2026-11-12-i6/) |
| Disclosed, fast key path | 25–33 s | 6.7 GiB | [2026-11-09-e7](bench/results/2026-11-09-e7/) |

## Real assets

The real samples are private and never committed; results are reported in [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md) without the assets themselves. The official trust lists are those of `c2pa-org/conformance-public` (`trust-list/C2PA-TRUST-LIST.pem` and `C2PA-TSA-TRUST-LIST.pem`; the results used commit `a95f2c4`).

**The disclosed mode, as a test:**

```bash
C2PA_R2_ASSET=photo.jpg C2PA_R2_TRUST_LIST=C2PA-TRUST-LIST.pem C2PA_R2_TSA_TRUST_LIST=C2PA-TSA-TRUST-LIST.pem \
    cargo test --release -p c2pa-x509-zk-demo --test third_party_fixtures real_asset_end_to_end -- --ignored --nocapture
```

**Every mode, with the CLIs:** as in the quick start, with the official lists, list names for the hints, and a policy approving them. With everything hidden and metadata scrubbed:

```bash
./target/release/c2pa-x509-zk-anonymizer --third-party \
    --hide-issuer c2pa-official@a95f2c4 --hide-time-stamp c2pa-tsa@a95f2c4 --tsa-trust-list C2PA-TSA-TRUST-LIST.pem \
    --scrub-metadata --keys target/gnark-keys-hidden-all --input photo.jpg --output anonymized.jpg --trust-list C2PA-TRUST-LIST.pem
cat > policy.json <<EOF
{"snapshots": [{"name": "c2pa-official@a95f2c4", "trust_list": "$PWD/C2PA-TRUST-LIST.pem", "from": 0}],
 "tsa_snapshots": [{"name": "c2pa-tsa@a95f2c4", "trust_list": "$PWD/C2PA-TSA-TRUST-LIST.pem", "from": 0}],
 "max_time_window": 86400}
EOF
./target/release/c2pa-x509-zk-verify --input anonymized.jpg --trust-list C2PA-TRUST-LIST.pem \
    --keys target/gnark-keys-hidden-all --issuer-policy policy.json
```

(`from: 0` approves the current lists retrospectively; see [MILESTONE-1.md](MILESTONE-1.md#assumptions-and-reduced-profiles).)

**Real tokens, claims, and metadata, in the circuits and the scrubber:**

| What | Command | Variables |
|---|---|---|
| Real time-stamp tokens satisfy the token gadget | `(cd gnark && go test ./statement -run TestTokensFromAssets -v)` | `C2PA_ZK_TOKENS=token.der:tsa-ca.der[,...]` (the token as stored in `sigTst2`, and its TSA's issuing CA) |
| Real claims reference their hard binding | `(cd gnark && go test ./statement -run TestRealClaims -v)` | `C2PA_ZK_CLAIMS=a.claim.cbor[,...]`, each with `a.claim.hb` holding the hard binding's hash |
| Scrubbing real JPEGs keeps the binding | `cargo test --release -p c2pa-x509-zk-demo --test third_party_fixtures scrubbing_real_assets -- --nocapture` | `C2PA_ZK_SCRUB_ASSETS` (separated as `PATH` is), `C2PA_ZK_SCRUB_STRINGS` (comma-separated strings that must not remain outside the store and signed metadata) |

The tokens, claims, and hard-binding hashes can be extracted from an asset with the library (`original_signature::OriginalSignature::from_asset`, `jumbf::manifest_store`, `jumbf::active_manifest`).

| Real-asset result | Figure | Where |
|---|---|---|
| Disclosed, first photo | 133 s, single run | [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#r2-anonymizing-a-real-asset) |
| Hidden issuer and time stamp, second photo | 141 s; 129 s with scrubbing; single runs | [DEPLOYMENT-FINDINGS.md](DEPLOYMENT-FINDINGS.md#with-the-issuer-and-the-time-stamp-hidden-i6) |
| Anonymity sets on the official lists | Issuer among 28 CAs (18 organizations); TSA among 19 (14) | [FEASIBILITY.md](FEASIBILITY.md#i6-hiding-the-time-stamp-token) |
