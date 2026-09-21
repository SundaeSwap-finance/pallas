# Harvest drivers

Shell drivers for the `harvest` binary next to this directory. They were run on
a host where a prototype Leios node answers on the default docker bridge at
`172.17.0.2:3001`, with the source copied to `/opt/build/harvest/src`, a target
directory at `/opt/build/harvest/target`, and outputs under
`/opt/build/harvest/out`. Change those paths in `run.sh` to move the whole set.

`run.sh` is the only script that knows about docker. The rest call it.

## Order

1. Build. `./run.sh cargo build --release --features unstable --bin harvest`
2. Index every header, which is cheap and classifies most candidates.
   `./run.sh /target/release/harvest index 172.17.0.2:3001 164 <intersect slot> <intersect hash> /out/index.tsv`
   The index writes one row per header with slot, hash, block number, era
   variant, protocol version, the leios certificate flag and the endorser
   announcement hash and size. An absent version or flag is written as `-`,
   never as a value.
3. Write the ranges to look at into `/out/ranges.txt`, one per line as
   `name from_slot from_hash to_slot to_hash blocks`, then `./scan.sh <name>`
   for each. A scan writes every block of the range and a row saying what is in
   it.
4. `./dups.sh <name>` for the same ranges when the question is whether any
   transaction repeats. It writes no blocks, so it runs over the whole chain
   inside a small disk budget.
5. `./ebfetch.sh < <file of "slot hash" lines>` to pull endorser payloads. Every
   fetch checks the body against the announced hash and size before it writes.
6. `./pickall.sh` to copy the located candidates into a fixture directory,
   checking each against the hash the node reported and appending its
   provenance entry.
7. `./refuse-probe.sh` to show the hash check refuses a file that is not the
   block it claims to be. Its expected output is in the script.

## Measured on 2026-09-21

- 55240 headers indexed in 29 seconds, whole chain from block 0 to slot 1221690.
- 55254 ranking blocks and 5130974 transactions walked for repeats, zero found
  of all three shapes.
- 23 endorser payloads fetched, every one of them hashing to its announcement.
- A housekeeping tick of 20 ms makes the initiator queue a second keepalive
  before the first is confirmed, and the peer then answers one the state no
  longer expects, which the initiator reads as a violation and bans its own peer
  for. A tick of 1000 ms does not, and leios-fetch still completes each window
  in about 35 ms.
