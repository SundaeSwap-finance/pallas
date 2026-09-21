#!/bin/sh
# Hand pick a block whose bytes are real and a hash that is not the block's, so
# the check that every fixture is the bytes the node served has a case that must
# refuse. A run that copies the file anyway means the check is decorative.
#
# Expected verdict, measured 2026-09-21 against slot 1202730 of the
# prototype-2026w36 chain:
#
#   refused probe: the header hashes to
#   2019145196aad7c71fb53ba34f5b02317f221628bbdfe7952cd69c8eefd709bb, the node
#   reported 0000000000000000000000000000000000000000000000000000000000000000
#   exit=5
#
# The matching case that must pass is pickall.sh, where all eleven picks print a
# verified hash and exit 0.
set -e
slot="${1:-1202730}"
src="${2:-blocks-recent}"
zero=0000000000000000000000000000000000000000000000000000000000000000
mkdir -p /opt/build/harvest/out/refuse-probe
cd /opt/build/harvest
set +e
./run.sh /target/release/harvest pick block "/out/$src/$slot.block" "$zero" \
  /out/refuse-probe probe probe_refusal "a hash that is not this block's"
echo "exit=$?"
set -e
echo "files copied, which must be none:"
ls -A /opt/build/harvest/out/refuse-probe
