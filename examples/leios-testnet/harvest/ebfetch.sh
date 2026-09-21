#!/bin/sh
# Fetch each endorser block named on stdin as "slot hash" into the raw
# endorser directory, naming each by its announcing slot.
cd /opt/build/harvest
while read slot hash rest; do
  test -n "$slot" || continue
  echo "=== $slot $hash"
  RUST_LOG=warn ./run.sh /target/release/harvest eb 172.17.0.2:3001 164 \
    "$slot" "$hash" /out/eb-raw "eb-$slot" 2>&1 | tail -3
done
