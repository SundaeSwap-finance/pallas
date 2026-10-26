# Dijkstra generated vectors

Values generated from the Dijkstra ledger CDDL and decoded by the Haskell
ledger, as lowercase hex, no trailing newline. Each one holds at least one
array in its indefinite length form.

| | |
| --- | --- |
| ledger commit | `9df9f98cce86c5f2195142b2c02dd9b39dd9dc7c` |
| spec | `dijkstraCDDL`, the Huddle spec of `cardano-ledger-dijkstra` |
| generator | cuddle over that spec, with its indefinite length encodings |
| seed and count | seed 1, 100 values per kind |

A whole generated value names its kind, its source and its index. A cut value
also names the item path inside that value, written as `[i]` for array element
`i` and `{k}` for map key `k`. A framed value places the cut item inside the
fixed CBOR shown, at `{}`, so that the ledger decodes it as a transaction body
or witness set. Every file below is a value the ledger's decoder for its kind
accepted. The expected values in `pallas-primitives/src/dijkstra/tests.rs`
are what the ledger read from these bytes.

| file | from | item | frame | kind |
| --- | --- | --- | --- | --- |
| ppu-rational-indefinite.hex | ppu, cddl, 10 | whole | none | protocol parameter update |
| relay-indefinite.hex | tx, cddl, 39 | `[0] {4} [0] [8] [4]` | none | relay, cut from a pool registration |
| body-certificate-indefinite.hex | body, cddl, 63 | `{4} [6]` | `a40080018002000481{}` | transaction body |
| body-value-indefinite.hex | body, cddl, 61 | `{1} [3]` | `a300800181{}0200` | transaction body |
| tx-indefinite.hex | tx, cddl-plain, 0 | whole, outer array made indefinite | none | transaction |
| wits-constr-102-indefinite.hex | written by hand | none | `a10482d8669f1903e880ff01` | witness set |
| proposal-hard-fork-indefinite-version.hex | block, cddl, 78 | `[1] [0] [0] [0] {20} [1]` | `a40080018002001481{}` | transaction body |

The `cddl-plain` source is the same generator with definite lengths only. The
witness set was written by hand. It holds one constructor 102 datum,
`d8669f1903e880ff`, whose index and fields are in an indefinite array.
