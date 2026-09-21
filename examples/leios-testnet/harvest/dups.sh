#!/bin/sh
# Walk one named range from ranges.txt without writing blocks and report the
# three shapes that make a strict apply reject a block.
set -e
name="$1"
line=$(/usr/bin/grep "^$name " /opt/build/harvest/out/ranges.txt)
test -n "$line" || { echo "no range named $name"; exit 2; }
set -- $line
cd /opt/build/harvest
RUST_LOG=info ./run.sh /target/release/harvest dups 172.17.0.2:3001 164 \
  "$2" "$3" "$4" "$5" "/out/dups-$name.tsv"
