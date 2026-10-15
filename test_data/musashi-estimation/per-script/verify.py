#!/usr/bin/env python3
"""Verify the unchanged captures and exact per-script regression evidence."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

here = Path(__file__).resolve().parent
root = here.parents[2]
subprocess.run([sys.executable, str(here.parent / 'verify.py')], check=True)
metadata = json.loads((here / 'provenance.json').read_text())
for name, digest in metadata['test_sources'].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
for name, entry in metadata['logs'].items():
    assert hashlib.sha256((here / name).read_bytes()).hexdigest() == entry['sha256'], name
lock = here.parent / 'Cargo.lock.snapshot'
assert hashlib.sha256(lock.read_bytes()).hexdigest() == metadata['build_lock_sha256']
print('Verified current per-script regression source, baseline/fixed logs and build lock')
