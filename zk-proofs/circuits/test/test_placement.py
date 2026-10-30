#!/usr/bin/env python3
"""Fast tests for the certificate field-placement checks in x509_parse.circom.

Compiles P256SpkiInRegion and ValidityInRegion with a small buffer (128 bytes)
and runs circom's witness generator on inputs that must be accepted or
rejected. A rejected input fails witness generation on a constraint.

Requires circom and node. Run from anywhere:
    python3 zk-proofs/circuits/test/test_placement.py
"""

import json
import struct
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


def run_witness(js_dir: Path, name: str, inputs: dict, workdir: Path) -> list[int] | None:
    """Return the witness values, or None if witness generation fails."""
    input_path = workdir / "input.json"
    wtns_path = workdir / "witness.wtns"
    input_path.write_text(json.dumps(inputs))
    result = subprocess.run(
        ["node", str(js_dir / "generate_witness.js"), str(js_dir / f"{name}.wasm"),
         str(input_path), str(wtns_path)],
        capture_output=True,
    )
    return read_wtns(wtns_path) if result.returncode == 0 else None


def read_wtns(path: Path) -> list[int]:
    """Parse a circom .wtns file: section 1 is the header, section 2 the values."""
    data = path.read_bytes()
    assert data[:4] == b"wtns"
    _version, n_sections = struct.unpack_from("<II", data, 4)
    pos, n8, values = 12, None, None
    for _ in range(n_sections):
        section_type, size = struct.unpack_from("<IQ", data, pos)
        body = data[pos + 12:pos + 12 + size]
        if section_type == 1:
            n8 = struct.unpack_from("<I", body)[0]
        elif section_type == 2:
            values = [int.from_bytes(body[i:i + n8], "little") for i in range(0, len(body), n8)]
        pos += 12 + size
    return values


def outputs(witness: list[int], count: int) -> list[int]:
    # Witness layout: the constant 1, then the main component's outputs.
    return witness[1:1 + count]


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
# Accepted cases must also output the 64 key bytes (written as 1..64).
SPKI_CASES = [
    ("accepts SPKI inside region", dict(bytes=spki_bytes(), spkiXOffset=37, regionStart=4, regionEnd=120), True),
    ("accepts SPKI exactly filling region", dict(bytes=spki_bytes(), spkiXOffset=37, regionStart=10, regionEnd=101), True),
    ("rejects SPKI ending past region", dict(bytes=spki_bytes(), spkiXOffset=37, regionStart=4, regionEnd=100), False),
    ("rejects SPKI starting before region", dict(bytes=spki_bytes(), spkiXOffset=37, regionStart=11, regionEnd=120), False),
    ("rejects wrong curve OID", dict(bytes=spki_bytes(mutate={32: 0x22}), spkiXOffset=37, regionStart=4, regionEnd=120), False),
    ("rejects bare 0x04 marker (original check)", dict(bytes=marker_only_bytes(), spkiXOffset=37, regionStart=4, regionEnd=120), False),
    ("rejects offset whose prefix would start below 0", dict(bytes=spki_bytes(), spkiXOffset=5, regionStart=0, regionEnd=120), False),
    ("rejects region extending past the buffer", dict(bytes=spki_bytes(), spkiXOffset=37, regionStart=4, regionEnd=MAX_BYTES + 1), False),
]
SPKI_OUTPUTS = list(range(1, 65))

# Validity field: 30 1E at 20, notBefore tag at 22, notAfter tag at 37, ends at 52.
# Accepted cases must also output the two YYMMDDHHMMSS digit strings.
VALIDITY_CASES = [
    ("accepts Validity inside region", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=37, regionStart=4, regionEnd=120), True),
    ("accepts Validity exactly filling region", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=37, regionStart=20, regionEnd=52), True),
    ("rejects Validity ending past region", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=37, regionStart=4, regionEnd=51), False),
    ("rejects Validity starting before region", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=37, regionStart=21, regionEnd=120), False),
    ("rejects notAfter not adjacent to notBefore", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=38, regionStart=4, regionEnd=120), False),
    ("rejects missing Validity SEQUENCE header", dict(bytes=validity_bytes(mutate={20: 0}), notBeforeOffset=22, notAfterOffset=37, regionStart=4, regionEnd=120), False),
    ("rejects notBefore without trailing Z", dict(bytes=validity_bytes(mutate={36: 0}), notBeforeOffset=22, notAfterOffset=37, regionStart=4, regionEnd=120), False),
    ("rejects region extending past the buffer", dict(bytes=validity_bytes(), notBeforeOffset=22, notAfterOffset=37, regionStart=4, regionEnd=MAX_BYTES + 1), False),
]
VALIDITY_OUTPUTS = list(b"260101000000") + list(b"270101000000")


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        suites = [
            ("p256_spki", f"P256SpkiInRegion({MAX_BYTES})", SPKI_CASES, SPKI_OUTPUTS),
            ("validity", f"ValidityInRegion({MAX_BYTES})", VALIDITY_CASES, VALIDITY_OUTPUTS),
        ]
        for name, main_component, cases, expected_outputs in suites:
            js_dir = compile_circuit(workdir, name, main_component)
            for label, inputs, should_accept in cases:
                witness = run_witness(js_dir, name, inputs, workdir)
                ok = (witness is not None) == should_accept
                if ok and witness is not None:
                    got = outputs(witness, len(expected_outputs))
                    if got != expected_outputs:
                        ok = False
                        label += f" (wrong outputs: {got[:8]}...)"
                failures += not ok
                print(f"{'ok  ' if ok else 'FAIL'} {label}")
    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
