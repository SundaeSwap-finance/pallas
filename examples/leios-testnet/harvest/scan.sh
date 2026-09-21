#!/bin/sh
# Block fetch one named range from ranges.txt and write its blocks and a row
# per block saying what is in it.
set -e
name="$1"
line=$(/usr/bin/grep "^$name " /opt/build/harvest/out/ranges.txt)
test -n "$line" || { echo "no range named $name"; exit 2; }
set -- $line
from_slot=$2; from_hash=$3; to_slot=$4; to_hash=$5; blocks=$6
echo "scanning $name from $from_slot to $to_slot, $blocks blocks"
cd /opt/build/harvest
RUST_LOG=info ./run.sh /target/release/harvest scan 172.17.0.2:3001 164 \
  "$from_slot" "$from_hash" "$to_slot" "$to_hash" \
  "/out/scan-$name.tsv" "/out/blocks-$name"
