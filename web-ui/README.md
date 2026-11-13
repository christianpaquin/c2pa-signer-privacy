# Web UI Demo

A Flask web interface for the BBS Signatures and X.509 + ZK Proofs prototypes. The ZK flow demonstrates Milestone 1; M0, the earlier signer-side prototype, is no longer in the demo.

## Prerequisites

- Python 3.12+
- Built release binaries for both prototypes (see each project's README), including the gnark CLI (`zk-proofs/target/c2pa-zk-gnark`)
- The ZK statements' keys, from a one-time setup per mode ([REPRODUCING.md](../zk-proofs/REPRODUCING.md#keys)): `target/gnark-keys` (disclosed), `target/gnark-keys-hidden` (hidden issuer), `target/gnark-keys-hidden-all` (hidden issuer and time stamp), under `zk-proofs/`. Modes without keys are shown as unavailable. Set `C2PA_ZK_KEYS_ROOT` to use key directories elsewhere (a relative path is taken from where the app is started).
- About 9 GB of free memory for a proof

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install flask
```

## Running

```bash
source venv/bin/activate
python app.py
```

Open [http://localhost:5000](http://localhost:5000).

## Features

- **BBS flow**: Obtain credentials (wallet), sign images, verify signatures
- **ZK flow** ([Milestone 1](../zk-proofs/MILESTONE-1.md), third-party anonymization):
  - **Sign:** a standard C2PA signature (ES256) with a `sigTst2` time stamp from a local TSA, using a test PKI that mirrors a real device deployment (P-384 CAs). The PKI is in `zk-proofs/fixtures/web-pki`, created on first use; the signer certificate is renewed (same key, same trust anchors) when it nears expiry. To start over with new keys, delete that directory, which makes previously anonymized assets untrusted.
  - **Anonymize:** a third party, without the signer's key, replaces the signature with a Groth16 proof (gnark), in one of three modes: disclosed issuer, hidden issuer, or hidden issuer and time stamp (with a 1-hour or 1-day window); optionally scrubbing the unsigned EXIF and XMP (JPEG). Proofs run in the background, one at a time: 1.5–2.5 minutes each, up to ~9 GB of memory ([measurements](../zk-proofs/REPRODUCING.md#measurements)).
  - **Verify:** detects the mode from the asset and checks the proof, the time stamp, the issuing chain or approved issuer tree, and the claim's hard binding, against the demo's trust lists and a policy approving them.
- Image preview on upload and after processing
- Sample image auto-load for quick demos

## Testing

```bash
python -m unittest test_app      # the ZK form handling, without running proofs
```
