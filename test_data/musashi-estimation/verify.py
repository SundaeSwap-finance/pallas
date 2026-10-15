#!/usr/bin/env python3
"""Verify immutable input bytes and the exact retained regression sources."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2]
metadata = json.loads((Path(__file__).parent / 'provenance.json').read_text())
for name, entry in metadata['files'].items():
    raw = (root / name).read_bytes()
    if entry['encoding'] == 'hex':
        raw = bytes.fromhex(raw.decode())
        expected = entry['sha256_decoded_cbor']
    else:
        expected = entry['sha256']
    assert len(raw) == entry['bytes'], name
    assert hashlib.sha256(raw).hexdigest() == expected, name
for name, digest in metadata['test_sources'].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
lock = Path(__file__).parent / 'Cargo.lock.snapshot'
assert hashlib.sha256(lock.read_bytes()).hexdigest() == metadata['build_lock_sha256']
print(f"Verified {len(metadata['files'])} immutable source files, 3 regression sources and build lock snapshot")
