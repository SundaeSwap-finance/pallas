#!/bin/sh
# Run one cargo command, or one built harvest binary, against a copy of this
# source tree, in the pallas CI image, with a CARGO_HOME and a target directory
# that belong to this run alone so nothing here touches another build.
#
# The container joins the default docker bridge, which is how it reaches a node
# running in another container on the same host.
exec docker run --rm \
  -v /opt/build/harvest/src:/pallas \
  -v /opt/build/harvest/target:/target \
  -v /opt/build/harvest/out:/out \
  -v /opt/build/shared-cargo:/cargo \
  -e CARGO_HOME=/cargo \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_INCREMENTAL=0 \
  -e CARGO_TERM_COLOR=never \
  -e RUST_BACKTRACE=short \
  -e RUST_LOG="${RUST_LOG:-info}" \
  -e HARVEST_TAG="$HARVEST_TAG" \
  -e HARVEST_MAGIC="$HARVEST_MAGIC" \
  -e HARVEST_AT="$HARVEST_AT" \
  -e HARVEST_RELAY="$HARVEST_RELAY" \
  -e HARVEST_TOOL_REV="$HARVEST_TOOL_REV" \
  -e HARVEST_NODE_IMAGE="$HARVEST_NODE_IMAGE" \
  -e HARVEST_TIP_SLOT="$HARVEST_TIP_SLOT" \
  -e HARVEST_TIP_HASH="$HARVEST_TIP_HASH" \
  -w /pallas \
  pallas-ci:1 \
  "$@"
