# Subtransaction UTxO dependencies

`MultiEraTx::requires()` enumerates the UTxOs a caller must load to validate a
transaction. It returns parent spending inputs, reference inputs and collateral,
then each child's spending and reference inputs in body order. It does this for
both validity flags. A child queried directly reports only its own dependencies;
it has no collateral field. Existing duplicate occurrences are preserved.

This lookup contract differs from ledger consumption. `inputs()`,
`reference_inputs()`, `collateral()` and `consumes()` still describe the queried
body. Enumeration does not validate a transaction, resolve missing UTxOs, allow
double spending, or allow a child to spend an output created inside its batch.

## Caller and rule audit

The audit used Pallas `7860599574e6a58c633a7ebf56a9ffa6a3d53577` and Dolos
`479e58a89b0e69f36f210355cb6b045d33f6f459`. Searching both checkouts for
`requires(` found these existing callers:

| Caller | Purpose and compatibility |
| --- | --- |
| Dolos `crates/cardano/src/validate.rs::validate_tx` | Loads inputs before phase one. Its `HashSet<TxoRef>` deduplicates lookups; child inputs must be included even when absent from parent references. |
| Dolos `crates/cardano/src/validate.rs::evaluate_decoded` | Loads script evaluation/estimation context through the same set-based store. Dependency enumeration does not enable scripted batches, which Pallas still rejects. |
| Dolos `src/serve/grpc/submit_tests.rs::estimation_rpc_resolves_pending_and_inflight_outputs_without_mutation` | Uses the list to construct test prestate. No order or duplicate-count assumption. |

There were no production callers inside Pallas. Its existing implementation
concatenated all three parent categories without deduplication or validity
filtering. Preserving that behavior avoids an unrelated stable-era API change.
Only the `unstable` Dijkstra parent adds dependencies; no new caller workaround
is needed.

The pinned upstream ledger
[`SubUtxo.hs`](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/Rules/SubUtxo.hs)
checks each child's spending and reference inputs against `originalUtxo`, and
spending inputs against the evolving UTxO set. Those checks precede the branch
on the parent's phase-two validity. Pallas's native key-batch validator similarly
requires original spending UTxOs and tracks spending across bodies. Its existing
scripted/stateful-child rejection remains in place.

Adjacent scope: Dolos's mempool input reservation/output lookup currently uses
body-local `consumes()`/`produces()`. Pending-child reservations and child-produced
output lookup need a separate audit/fix; expanding `requires()` does not change
those methods. Chain processing has its own explicit subtransaction traversal.

## Captured and synthetic evidence

The captured regression reuses unchanged
[`../dijkstra-subtx.tx`](../dijkstra-subtx.tx), a 728-byte native block transaction
from Musashi. Its original provenance is in
[`../dijkstra-fixtures.md`](../dijkstra-fixtures.md); machine-readable identities,
decoded-byte checksums and unknowns are in [provenance.json](provenance.json).

This capture has one parent spend, two parent references and one collateral,
plus one child spend and one child reference. Both child dependencies also
appear in the parent's references. The test expects all six occurrences in
order: the baseline returns four, and the fix returns six. It proves that the
child is traversed, but does not prove omission of a distinct lookup key; the
capture itself masks that failure after deduplication. Its complete historical
UTxOs and parameters are unavailable, and it remains outside supported native
scripted-batch validation. No captured bytes are modified or re-signed.

Synthetic traversal cases add two children with dependencies absent from the
parent, references repeated within/across bodies, both validity flags, direct
child queries and absent optional fields. A retained Alonzo duplicate-input
fixture checks that earlier-era duplicate behavior stays unchanged. These cases
test enumeration, not signatures or ledger admission.

Dolos's separate `tests/support/musashi_batch_dependencies.rs` constructs a signed
key/ADA batch with two children and **no parent reference inputs**. It checks real
admission and byte/era preservation, missing parent/child/reference UTxOs, and
duplicate spending across children or parent/child. Its synthetic UTxOs and reused
protocol-12 test environment are explicitly not network evidence. Dolos owns
those tests and their verification artifacts.

## Reproduction and boundary

```sh
cargo test -p pallas-traverse --features unstable --test requires
cargo test -p pallas-traverse
```

For the baseline, export the Pallas revision above, copy the unchanged final
`pallas-traverse/tests/requires.rs` into it, and use a separate Cargo target
directory. No production adapter is required. Baseline and fixed test output,
test hashes and check results accompany this report. Full local logs and the
downloaded pinned ledger source are retained in
`target/subtransaction-dependencies/`.

Upstream Musashi node compatibility is a separate question. No live submission,
node replay or independent node acceptance test was performed for the synthetic
batch. A Dolos admission pass establishes the dependency-loading regression only;
it does not establish full Dijkstra support or current node compatibility.
