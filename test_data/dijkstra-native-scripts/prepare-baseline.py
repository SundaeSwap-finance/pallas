#!/usr/bin/env python3
"""Export original production and overlay exactly the final regression tests.
Usage: python3 test_data/dijkstra-native-scripts/prepare-baseline.py /tmp/new-directory
Build with a separate CARGO_TARGET_DIR; see README.md.
"""
import io
import subprocess
import sys
import tarfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=False)
revision = '8efc15bc0207ea85038865c7f8700868bc69e0ba'
archive = subprocess.check_output(['git', 'archive', revision], cwd=root)
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(out, filter='data')
for name in [
    'pallas-validate/src/phase1/dijkstra_native_tests.rs',
    'pallas-validate/src/phase1/dijkstra_transaction_tests.rs',
    'pallas-validate/src/phase2/dijkstra_native_context_tests.rs',
    'test_data/dijkstra-native-scripts/mint.tx.hex',
    'test_data/dijkstra-native-scripts/mint.input.hex',
    'test_data/dijkstra-native-scripts/producer.body.hex',
]:
    target = out / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((root / name).read_bytes())
with (out / 'pallas-validate/src/phase1/mod.rs').open('a') as f:
    f.write('\n#[cfg(all(test, feature = "unstable"))]\nmod dijkstra_native_tests;\n')
with (out / 'pallas-validate/src/phase2/dijkstra.rs').open('a') as f:
    f.write('\n#[cfg(test)]\n#[path = "dijkstra_native_context_tests.rs"]\nmod native_context_tests;\n')
print(f'Original production {revision}, identical regression tests: {out}')
