#!/usr/bin/env bash
# Query the node state at one chain point into <out dir>.
#
# Usage: pin_state.sh <out dir> <shelley genesis file>
#
# The queries run between two tip queries and are kept only when both tips
# name the same block, so every file describes the state after that block.
set -euo pipefail

out="$1"
genesis="$2"
mkdir -p "$out"
cp "$genesis" "$out/shelley-genesis.json"

for attempt in 1 2 3 4 5 6 7 8; do
  cardano-cli dijkstra query tip --output-json > "$out/tip.before.json"
  cardano-cli dijkstra query utxo --whole-utxo --output-json --out-file "$out/utxo.json"
  cardano-cli dijkstra query ledger-state --output-json --out-file "$out/ledger-state.json"
  cardano-cli dijkstra query protocol-parameters --output-json --out-file "$out/protocol-parameters.json"
  cardano-cli dijkstra query tip --output-json > "$out/tip.after.json"
  before=$(jq -r .hash "$out/tip.before.json")
  after=$(jq -r .hash "$out/tip.after.json")
  if [ "$before" = "$after" ]; then
    jq '{slot, hash, block}' "$out/tip.after.json" > "$out/point.json"
    echo "pinned on attempt $attempt at $(jq -c . "$out/point.json")"
    exit 0
  fi
  echo "attempt $attempt moved from $before to $after"
done
echo "the tip moved during every attempt" >&2
exit 1
