# dijkstra-pparams-w36.hex

The reply the Musashi testnet node sends to `GetCurrentPParams`, captured over
node to client as raw CBOR, as one line of hex.

| | |
| --- | --- |
| network | Musashi, network magic 164 |
| node image | `ghcr.io/input-output-hk/ouroboros-leios/cardano-node-testnet:prototype-2026w36` |
| ledger the node integrates | cardano-ledger `1587f21a7d1306dc590c2749a5c66232ef66aad0` |
| captured | 2026-09-10T15:40Z |
| chain point | slot 315607, `b4591772a92f936a3114d0f2c3cc77df54e3c87da857ab6392f7f90da52e143f` |
| block number | 15150 |
| era number in the reply | 7 |
| shelley `systemStart` | 2026-09-07T00:00:00Z, epoch second 1788739200 |
| bytes | 3756 |

Captured with a scratch client outside the repository, which acquired the
volatile tip, read the era with `GetCurrentEra`, and asked for
`BlockQuery::GetCBOR(GetCurrentPParams)` so the answer arrives as the bytes the
node wrote rather than as a value this crate re-encoded.

The reply is a definite array of 46 entries, one per element of
`eraPParams @DijkstraEra`, which is what
`DIJKSTRA_PROTOCOL_PARAM_FIELDS` names. The last eleven entries are the ones
cardano-ledger added between `f3104f0` and `1587f21a`, and their bytes here are
byte for byte the fragments `DIJKSTRA_W36_ENTRIES` lists for them, which were
written from the CDDL and the published dijkstra genesis before this capture
existed.

The Musashi testnet is respun every few weeks. This file is a photograph of one
chain and not a schema, so a reply captured after the next respin belongs in a
new file with its own tag and ledger commit rather than as an edit to this one.
