#!/bin/sh
# Regenerates the vectors of this dir with the generator built at the cardano-ledger commit on line 1 of the vendored Dijkstra CDDL.
# Usage: regen.sh <work dir>
# The work dir keeps the cardano-ledger checkout and the cabal store between runs.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cddl=$here/../../pallas-primitives/src/dijkstra/defs.cddl
rev=$(sed -n '1s/^; Copied from cardano-ledger commit \([0-9a-f]\{40\}\),$/\1/p' "$cddl")
if [ -z "$rev" ]; then
  echo "line 1 of $cddl names no cardano-ledger commit" >&2
  exit 1
fi
seed=1
size=10
work=$(mkdir -p "$1" && cd "$1" && pwd)
image=pallas-dijkstra-ledger-gen:$(sha256sum "$here/generator/Dockerfile" | cut -c1-12)
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker build -t "$image" "$here/generator" >&2
fi
ledger=$work/cardano-ledger
if [ ! -d "$ledger/.git" ]; then
  git init -q "$ledger"
fi
git -C "$ledger" fetch -q --depth 1 https://github.com/IntersectMBO/cardano-ledger "$rev"
git -C "$ledger" checkout -q -f "$rev"
rm -rf "$work/generator"
cp -R "$here/generator" "$work/generator"
echo 'packages: /work/generator' >"$ledger/cabal.project.local"
mkdir -p "$work/cabal-dir"
run() {
  docker run --rm --user "$(id -u):$(id -g)" -v "$work:/work" -e CABAL_DIR=/work/cabal-dir -e HOME=/work -w /work/cardano-ledger "$image" "$@"
}
run sh -c 'cabal update && cabal build dijkstra-ledger-vectors && cp "$(cabal list-bin dijkstra-ledger-vectors)" /work/dijkstra-ledger-vectors' >&2
for kind in tx body wits ppu block eb; do
  for source in arb:10 cddl:30 cddl-plain:30; do
    run /work/dijkstra-ledger-vectors vectors "$kind" "${source%:*}" "${source#*:}" "$seed" "$size"
  done >"$here/$kind.jsonl"
done
