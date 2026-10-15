# Dijkstra native-script validation

This increment supports **top-level, guard-free native scripts** in protocol 12.0
transactions: signatures, all/any/signed-threshold combinations and slot timelocks,
for spending, minting/burning, Reg certificates and withdrawals. Scripts can be
witnesses or references in declared spending/reference inputs, including earlier-era
reference outputs. New outputs may carry guard-free native reference scripts.

Native scripts execute in phase one. They require neither Plutus redeemers/datums
nor collateral, execution budgets or slot-to-POSIX conversion. Their presence does
not activate legacy Plutus draining-withdrawal rules. Reference-script fee and size
limits still apply; the existing `DijkstraProtParams.plutus` container supplies those
fee parameters even for native-only references (its cost model is not required).
All vkey signatures are verified against the original body, including witnesses
not needed by the successful native predicate. Evaluation uses explicit frames to
avoid recursion on deeply nested scripts.

Mixed native/V3 transactions retain the original purpose indices and V3 context
reference-script hashes. Phase two runs only Plutus purposes; it does not validate
native predicates or signatures. Admission callers must still run phase one.
`ScriptRequireGuard`, script guards and scripted subtransactions remain explicitly
unsupported, including guard clauses in otherwise unused native branches. Existing
Plutus-language, forecast, governance and other Dijkstra restrictions remain.
Native timelocks use the signed slot interval, not the current slot alone; normal
transaction interval admission remains lower-inclusive and upper-exclusive.

## Immutable network regression

`mint.tx.hex` is a 364-byte Musashi native mint transaction, ID
`ca60ffd71d5dc8fa94ad7d0103183511004e0d42efd7b3a07e1aa6bfc19e5f69`,
recorded successful in the Dolos expanded archive at slot **1025002**. It mints
100,000,000 units named `tokenA` under policy
`ca301e55320b20409a1b0c554230d5b251d8490fcca870bdf52d654e` with a
single signature native script. There are no Plutus redeemers, certificates,
withdrawals, reference scripts or validity bounds.

`producer.body.hex` is the original body whose hash identifies its sole input
producer `f615fb416d70838b965ff08ae99a60d59e0f723a17918ff7dd1c921f376da52d`.
`mint.input.hex` is that body's output 0. Tests verify the producer hash, exact
output bytes, transaction identity and unchanged signed bytes. The mempool envelope
is extracted/reconstructed from the archive; its signed body and witnesses are
unchanged. These are extracted network data, not synthetic mutations.

Replay uses the existing captured epoch-64 parameters in
`../musashi-phase1/historical-parameters.json` and slot 1025002. The exact
historical parameter state at that earlier slot was not independently recovered;
this is an explicitly constructed replay context. No certificate/account prestate
is needed. Archive success is evidence under Dolos expanded-archive trust, not an
independent node response or proof of current spendability. The accepting node and
archive ingestion build identities are unknown. Network magic is 164, network ID
0. No private signing keys, deployment journals, live submissions or service changes
are involved.

`extract.rs` reproduces extraction using the recorded segment and Dolos dictionary.
Build it as a temporary Cargo binary with local Pallas codec/traverse (`unstable`),
`hex=0.4`, `serde_json=1`, `zstd=0.13`; pass segment path, dictionary path and output
directory. Source revisions, decoded-byte SHA-256 checksums and evidence limitations
are in `provenance.json`. Tests do not require the archive.

## Rule reference and verification

Native predicates follow `evalDijkstraNativeScript` at ledger revision
[`1587f21a7d1306dc590c2749a5c66232ef66aad0`](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/Scripts.hs).
The local pinned source's SHA-256 is recorded in provenance. Guard support is an
explicit subset boundary, not an alternative interpretation of that rule.

```sh
cargo test --offline -p pallas-validate --features unstable,phase2 --lib dijkstra_native
cargo test --offline -p pallas-validate --features unstable --lib dijkstra_native
python3 test_data/dijkstra-native-scripts/verify.py
```

Synthetic tests cover signatures, missing/extraneous scripts, threshold and slot
boundaries, partial withdrawals, registration, reference fees/size/scope, earlier-era
references, noncanonical original hashes, newly published scripts, 4,096-level
nesting, native-only phase two and mixed V3 purpose indexing/datums. They are not
claimed to be network captures. Baseline/fixed runtime logs and the final check
summary are retained alongside this file. See `verification.json` for results and
known limitations; full build logs are in `target/dijkstra-native-checks/`.

To reproduce the original runtime failures, run `prepare-baseline.py` with a new
output directory. Run the first test command there with a separate
`CARGO_TARGET_DIR`. The script exports baseline `8efc15b` and overlays identical
final tests plus test-module declarations only; no production adapters are needed.
The captured admission assertion fails with `non-vkey witnesses` before the fix.
