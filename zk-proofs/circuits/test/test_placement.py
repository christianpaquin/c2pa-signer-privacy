#!/usr/bin/env python3
"""Fast tests for the certificate field-placement checks in x509_parse.circom.

Compiles P256SpkiInRegion and ValidityInRegion with a small buffer (128 bytes)
and runs circom's witness generator on inputs that must be accepted or
rejected. A rejected input fails witness generation on a constraint.

Requires circom and node. Run from anywhere:
    python3 zk-proofs/circuits/test/test_placement.py
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

CIRCUITS = Path(__file__).resolve().parent.parent
MAX_BYTES = 128

SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200" "04")


def compile_circuit(workdir: Path, name: str, main: str) -> Path:
    source = workdir / f"{name}.circom"
    source.write_text(
        'pragma circom 2.1.6;\n'
        f'include "{CIRCUITS / "x509_parse.circom"}";\n'
        f"component main = {main};\n"
    )
    subprocess.run(
        ["circom", str(source), "--wasm", "-l", str(CIRCUITS), "-l", str(CIRCUITS / "node_modules"),
         "-o", str(workdir)],
        check=True, capture_output=True,
    )
    return workdir / f"{name}_js"


def witness_ok(js_dir: Path, name: str, inputs: dict, workdir: Path) -> bool:
    input_path = workdir / "input.json"
    input_path.write_text(json.dumps(inputs))
    result = subprocess.run(
        ["node", str(js_dir / "generate_witness.js"), str(js_dir / f"{name}.wasm"),
         str(input_path), str(workdir / "witness.wtns")],
        capture_output=True,
    )
    return result.returncode == 0


def spki_bytes(prefix_at: int = 10, mutate: dict | None = None) -> list[int]:
    buf = bytearray(MAX_BYTES)
    field = SPKI_PREFIX + bytes(range(1, 65))  # prefix + X || Y
    buf[prefix_at:prefix_at + len(field)] = field
    for pos, val in (mutate or {}).items():
        buf[pos] = val
    return list(buf)


def validity_bytes(start: int = 20, mutate: dict | None = None) -> list[int]:
    buf = bytearray(MAX_BYTES)
    field = (bytes([0x30, 0x1E])
             + bytes([0x17, 0x0D]) + b"260101000000Z"
             + bytes([0x17, 0x0D]) + b"270101000000Z")
    buf[start:start + len(field)] = field
    for pos, val in (mutate or {}).items():
        buf[pos] = val
    return list(buf)


def marker_only_bytes() -> list[int]:
    # The shape the original circuit accepted: only a 0x04 before the key.
    buf = bytearray(MAX_BYTES)
    buf[36] = 0x04
    buf[37:101] = bytes(range(1, 65))
    return list(buf)


# (name, inputs, should_accept). SPKI field: prefix at 10..36, X at 37, ends at 101.
SPKI_CASES = [
    ("accepts SPKI inside region", dict(bytes=spki_bytes(), spkiXOffset=37, regionStart=4, regionEnd=120), True),
    ("accepts SPKI exactly filling region", dict(bytes=spki_bytes(), spkiXOffset=37, regionStart=10, regionEnd=101), True),
    ("rejects SPKI ending past region", dict(bytes=spki_bytes(), spkiXOffset=37, regionStart=4, regionEnd=100), False),
    ("rejects SPKI starting before region", dict(bytes=spki_bytes(), spkiXOffset=37, regionStart=11, regionEnd=120), False),
    ("rejects wrong curve OID", dict(bytes=spki_bytes(mutate={32: 0x22}), spkiXOffset=37, regionStart=4, regionEnd=120), False),
    ("rejects bare 0x04 marker (original check)", dict(bytes=marker_only_bytes(), spkiXOffset=37, regionStart=4, regionEnd=120), False),
    ("rejects offset whose prefix would start below 0", dict(bytes=spki_bytes(), spkiXOffset=5, regionStart=0, regionEnd=120), False),
]

# Validity field: 30 1E at 20, notBefore tag at 22, notAfter tag at 37, ends at 52.
VALIDITY_CASES = [
    ("accepts Validity inside region", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=37, regionStart=4, regionEnd=120), True),
    ("accepts Validity exactly filling region", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=37, regionStart=20, regionEnd=52), True),
    ("rejects Validity ending past region", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=37, regionStart=4, regionEnd=51), False),
    ("rejects Validity starting before region", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=37, regionStart=21, regionEnd=120), False),
    ("rejects notAfter not adjacent to notBefore", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=38, regionStart=4, regionEnd=120), False),
    ("rejects missing Validity SEQUENCE header", dict(bytes=validity_bytes(mutate={20: 0}), notBeforeOffset=22, notAfterOffset=37, regionStart=4, regionEnd=120), False),
    ("rejects notBefore without trailing Z", dict(bytes=validity_bytes(mutate={36: 0}), notBeforeOffset=22, notAfterOffset=37, regionStart=4, regionEnd=120), False),
]


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        suites = [
            ("p256_spki", f"P256SpkiInRegion({MAX_BYTES})", SPKI_CASES),
            ("validity", f"ValidityInRegion({MAX_BYTES})", VALIDITY_CASES),
        ]
        for name, main_component, cases in suites:
            js_dir = compile_circuit(workdir, name, main_component)
            for label, inputs, should_accept in cases:
                accepted = witness_ok(js_dir, name, inputs, workdir)
                ok = accepted == should_accept
                failures += not ok
                print(f"{'ok  ' if ok else 'FAIL'} {label}")
    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
