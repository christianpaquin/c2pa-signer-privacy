# Web UI Demo

A Flask web interface for the BBS Signatures and X.509 + ZK Proofs prototypes.

## Prerequisites

- Python 3.12+
- Built release binaries for both prototypes (see each project's README)

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
- **ZK flow**: Sign images with X.509/ECDSA, anonymize (replace signature with ZK proof), verify
- Image preview on upload and after processing
- Sample image auto-load for quick demos
- Background processing for ZK proof generation (~2 min)
