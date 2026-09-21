#!/bin/sh
# Copy each located candidate into the fixture directory, checking it against
# the hash the node reported for it, and append its provenance entry.
set -e
OUT=/opt/build/harvest/out
FIX=/out/fixtures
rm -rf $OUT/fixtures
mkdir -p $OUT/fixtures

expected() {
  awk -F'\t' -v s="$1" '$2==s {print $3}' $OUT/index.tsv
}

pick_block() {
  slot="$1"; src="$2"; name="$3"; kind="$4"; how="$5"
  h=$(expected "$slot")
  test -n "$h" || { echo "no index row for slot $slot"; exit 3; }
  cd /opt/build/harvest
  ./run.sh /target/release/harvest pick block "/out/$src/$slot.block" "$h" "$FIX" "$name" "$kind" "$how"
}

pick_eb() {
  slot="$1"; name="$2"; kind="$3"; how="$4"
  h=$(awk -F'\t' -v s="$slot" '$2==s {print $7}' $OUT/index.tsv)
  test -n "$h" || { echo "no announcement for slot $slot"; exit 3; }
  cd /opt/build/harvest
  ./run.sh /target/release/harvest pick eb "/out/eb-raw/eb-$slot" "$h" "$slot" "$FIX" "$name" "$kind" "$how"
}

pick_block 1202730 blocks-recent ranking-announce-with-txs ranking_block_announcing_with_transactions \
  "header index rows where the announcement field is set and the block-fetch scan of slots 1200053 to 1220903 counted more than zero transactions"
pick_block 1202752 blocks-recent ranking-announce-quiet ranking_block_announcing_without_transactions \
  "header index rows where the announcement field is set and the same scan counted zero transactions"
pick_block 86855 blocks-erachange pool-registration-bls pool_registration_with_bls_key \
  "block-fetch scan of slots 85505 to 87492, certificate walk naming a pool registration whose bls key slot holds a key"
pick_block 1209593 blocks-recent epoch-boundary-before epoch_boundary_last_block_of_epoch_55 \
  "last indexed block with slot below 1209600, which is epoch 56 times the shelley genesis epochLength of 21600"
pick_block 1209609 blocks-recent epoch-boundary-after epoch_boundary_first_block_of_epoch_56 \
  "first indexed block with slot at or above 1209600"
pick_block 86373 blocks-erachange era-variant-before era_header_variant_6 \
  "last indexed header carrying chain-sync era variant 6, found by walking the index for a variant change"
pick_block 86463 blocks-erachange era-variant-after era_header_variant_7 \
  "first indexed header carrying chain-sync era variant 7, the same variant change"

pick_eb 1219676 endorser-large endorser_block_large \
  "announced sizes in the header index between 11100 and 22200 bytes, which at 36 bytes per body entry is 300 to 600 transactions"
pick_eb 1213880 endorser-small endorser_block_small \
  "smallest announced size in the header index above slot 1190000, one 64 transaction window"
pick_eb 1205632 endorser-repeat-first endorser_block_repeat_first \
  "pairwise comparison of the wire transactions of 23 fetched endorser payloads, this pair shares 15 of them"
pick_eb 1205667 endorser-repeat-second endorser_block_repeat_second \
  "the second of that pair, 15 of its 26 transactions are also in endorser-repeat-first"

ls -la $OUT/fixtures
