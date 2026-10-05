#!/usr/bin/env python3
"""Verify decoded capture bytes and retained provenance without extra packages."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / 'provenance.json').read_text())
for name, item in manifest['files'].items():
    raw = (root / name).read_bytes()
    if item['encoding'] == 'hex':
        raw = bytes.fromhex(raw.decode())
    assert hashlib.sha256(raw).hexdigest() == item['sha256'], name
    assert len(raw) == item['bytes'], name
producer = bytes.fromhex((root / 'producer.body.hex').read_text())
assert hashlib.blake2b(producer, digest_size=32).hexdigest() == manifest['producer']['transaction_id']
print('Verified immutable capture bytes, producer identity and extraction provenance.')
