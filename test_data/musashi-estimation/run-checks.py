#!/usr/bin/env python3
"""Run the repository's Linux checks; retain individual logs outside /tmp."""
import json
import os
from pathlib import Path
import subprocess
import time

root = Path(__file__).resolve().parents[2]
logs = root / 'target/musashi-estimation-checks'
logs.mkdir(parents=True, exist_ok=True)
checks = [
    ('native-tests', 'cargo test --offline --locked -p pallas-validate --features phase2,unstable'),
    ('native-clippy', 'cargo clippy --offline --locked -p pallas-validate --all-targets --features phase2,unstable -- -D warnings'),
    ('fmt', 'cargo fmt --all --check'),
    ('clippy', 'cargo clippy --offline --locked --workspace --all-targets -- -D warnings'),
    ('build', 'cargo build --offline --locked --workspace --all-targets'),
    ('test', 'cargo test --offline --locked --workspace --no-fail-fast'),
    ('blueprint', 'cargo test --offline --locked -p pallas-network -p pallas-network2 --features blueprint'),
    ('unstable', 'cargo test --offline --locked -p pallas-primitives -p pallas-traverse -p pallas-utxorpc -p pallas-validate --features unstable'),
    ('phase2', 'cargo test --offline --locked -p pallas-validate --features phase2'),
    ('no-default', 'cargo check --offline --locked --workspace --all-targets --no-default-features'),
    ('all-features', 'cargo check --offline --locked --workspace --all-targets --all-features'),
    ('isolated', 'cargo check --offline --locked -p pallas-primitives --no-default-features'),
    ('docs', 'cargo doc --offline --locked --workspace --no-deps'),
    ('msrv-check', 'cargo +1.97.0 check --offline --locked --workspace --all-targets'),
    ('msrv-native', 'cargo +1.97.0 test --offline --locked -p pallas-validate --features phase2,unstable'),
]
results = []
for name, command in checks:
    env = dict(os.environ)
    env['CARGO_TERM_COLOR'] = 'never'
    if name == 'docs':
        env['RUSTDOCFLAGS'] = '-D warnings'
    if name.startswith('msrv-'):
        env['CARGO_TARGET_DIR'] = str(root / 'target/musashi-estimation-msrv')
        env['CARGO_PROFILE_DEV_DEBUG'] = '0'
        env['CARGO_INCREMENTAL'] = '0'
    started = time.time()
    print(f'Starting {name}', flush=True)
    with (logs / (name + '.log')).open('w') as output:
        result = subprocess.run(command.split(), cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT)
    results.append(dict(name=name, command=command, exit_code=result.returncode, seconds=round(time.time()-started, 2), log=str((logs/(name+'.log')).relative_to(root))))
    (root / 'test_data/musashi-estimation/checks.json').write_text(json.dumps(results, indent=2)+'\n')
    print(f'{name}: exit {result.returncode}', flush=True)
