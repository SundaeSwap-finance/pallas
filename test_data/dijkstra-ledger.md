# Dijkstra ledger vectors

Values generated from the Dijkstra ledger CDDL, each with the Haskell ledger's
reading of it. `pallas-primitives/tests/dijkstra_ledger_vectors.rs` decodes each
value with pallas and compares every leaf with that reading.

| | |
| --- | --- |
| ledger commit | the commit on line 1 of `pallas-primitives/src/dijkstra/defs.cddl` |
| generator | `dijkstra-ledger/generator`, built at that commit by `dijkstra-ledger/regen.sh <work dir>` |
| sources | `arb`, the ledger's own generators, 10 values per kind, and cuddle over `dijkstraCDDL`, `cddl` with indefinite length encodings and `cddl-plain` with definite lengths only, 30 values per kind each |
| seed and size | seed 1, value `i` drawn at size `1 + i mod 10` |
| kinds | `tx` mempool transaction, `body` transaction body, `wits` witness set, `ppu` protocol parameter update, `block`, `eb` endorser block references |

Each line of `<kind>.jsonl` holds the value as `hex`, its `source` and index
`i`, the `ledger` reading, and the CDDL `rules` the cuddle validator matched
while checking the value against its root rule, with `big_uint` or `big_nint`
for each integer outside the range of `int`. Only values the ledger's
decoder accepts are written. A value pallas reads as the ledger does credits
each of its rules, and the test prints the count for every rule.

The ledger reading writes a leaf as `{"cbor": hex}` of the ledger's own
encoding, a set as `{"set": [...]}`, an ordered set as `{"oset": [...]}` and a
map as `{"map": [[k, v], ...]}`, or `{"omap": ...}` where order counts.
