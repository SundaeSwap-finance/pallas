#!/usr/bin/env bash
set -euo pipefail
# Offline tests only. Builds an isolated Dolos source tree and never starts a node.
# Usage: CARGO_TARGET_DIR=/path/to/cache ./reproduce-callers.sh PALLAS_CHECKOUT DOLOS_CHECKOUT
# Set CALLER_TEST_FILTER=native_guard_reference to run just the synthetic regression.
pallas_checkout=$(realpath "${1:?Pallas checkout required}")
dolos_checkout=$(realpath "${2:?Dolos checkout required}")
fixture_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=$(mktemp -d "${TMPDIR:-/tmp}/musashi-guard-callers.XXXXXX")
printf 'Isolated caller source: %s\n' "$source_dir"
git -C "$dolos_checkout" archive 7bab64ec58cbdb469ec9ce3b793b6c9edfeb09b0 | tar -x -C "$source_dir"
python3 - "$source_dir/Cargo.toml" "$pallas_checkout" <<'PY'
import json, pathlib, re, sys
manifest = pathlib.Path(sys.argv[1])
pallas = pathlib.Path(sys.argv[2])
pattern = r'^(pallas(?:-[a-z0-9]+)?) = \{ git = "https://github.com/SundaeSwap-finance/pallas", rev = "[0-9a-f]+"'
def local(match):
    return match[1] + ' = { path = ' + json.dumps(str(pallas / match[1]))
text, count = re.subn(pattern, local, manifest.read_text(), flags=re.MULTILINE)
assert count == 13, count
manifest.write_text(text)
PY
cat "$fixture_dir/caller-regression.rs" >> "$source_dir/crates/cardano/tests/dijkstra_ttl.rs"
export PALLAS_GUARD_FIXTURE="$fixture_dir"
export PALLAS_TTL_FIXTURE="$source_dir/test_data/musashi-ttl"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
cd "$source_dir"
# The isolated lockfile resolves local paths; canonical manifests and lockfiles stay unchanged.
cargo test --offline -p dolos-cardano --test dijkstra_ttl "${CALLER_TEST_FILTER:-}"
if [[ -z "${CALLER_TEST_FILTER:-}" ]]; then
    cargo test --offline -p dolos-cardano --lib evaluation_tests
    cargo test --offline -p dolos --lib estimation_
fi
