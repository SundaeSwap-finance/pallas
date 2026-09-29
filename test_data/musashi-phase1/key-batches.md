# Native key-only batch checkpoint

This is the second half of the split of combined checkpoint
`76003a3054ef7aa4a694bd9b0c47868fa17b92c5`. It follows registration-only commit
`c64fdc935707047cb05755eafde5a54b15ce86d0`, documented in
[registration-only.md](registration-only.md). The old combined checkpoint tag is
preserved. The final production code and test modules are byte-identical to that
combined checkpoint; this split does not change their semantics.

## Scope

This commit adds key/ADA subtransactions, per-level signatures over each original
body, half-open validity intervals, key guards and required top-level key guards.
Fees and value conservation apply to the aggregate batch. Spending inputs must
exist in the original UTxO set and must not have been consumed by another level.
A subtransaction's newly created outputs cannot be spent within the same batch.

The first commit contains shared helpers already used by registration. This
second commit adds their batch callers, spent-input tracking, guard checks,
subtransaction field/witness restrictions and `DijkstraInputAlreadySpent`.

Scripted or certificate-bearing subtransactions, registrations combined with subs,
script guards and standalone subtransaction dispatch remain explicitly unsupported.
The reference-script registration subset and its historical-state requirements
are unchanged. The pinned rules and remaining limits are in
[registration-and-batches.md](registration-and-batches.md).

Positive batch coverage uses synthetic, deterministically signed transactions and
UTxOs. The retained real `../dijkstra-subtx.tx` is a script-spending batch and remains
an unsupported rejection fixture; it is not evidence of successful native batch
validation. Its full original UTxO set is unavailable in the portable fixture.
Captured transaction/output bytes and their era labels are unchanged.

## Independent verification

```sh
cargo test --offline -p pallas-validate --features unstable --lib dijkstra_batch_tests -- --nocapture
cargo test --offline -p pallas-validate --features unstable --lib dijkstra_ -- --nocapture
cargo test --offline -p pallas-validate --features unstable,phase2
```

The same five batch tests compile and run on both sides: **0 passed / 5 failed** on
`c64fdc9`, **5 passed** with batch support. The baseline rejects subtransactions;
compilation failures are not reproduction. Prepare the baseline with `git archive
c64fdc935707047cb05755eafde5a54b15ce86d0`, copy `dijkstra_batch_tests.rs` into
`pallas-validate/src/phase1/`, and add its module declaration with
`#[cfg(all(test, feature = "unstable"))]` to `phase1/mod.rs`. No behavior adapter or
production-code change is needed. Use a separate baseline Cargo target directory.
`key-batches-verification.json` and `key-batches-{baseline,fixed}.txt` retain the
results, commands, hashes and precise evidence boundaries.

All 26 focused Dijkstra tests, the full native+phase2 validation suite including
earlier-era integrations, and native Clippy pass after the split. The registration
intermediate also passes Rust 1.88 and workspace all-feature checks. The prior
combined checkpoint's full repository verification remains applicable to the
byte-identical final source; its original reports/logs are retained unchanged.
The known seven `harvest.rs` formatting differences remain unrelated and unfixed.
Full split logs are retained locally in `.git/musashi-s05-split-evidence/`.

Neither native evaluation/S06 nor submission/pin/workaround changes/S07 are part
of this split. No remote branch or tag was changed.
