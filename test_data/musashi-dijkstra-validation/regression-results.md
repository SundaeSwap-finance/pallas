# Regression verification

The identical `dijkstra_transaction_tests.rs` module ran against baseline
`dc2c81dcced2a316c8aacb8155b8b90fee428e08` and the fix in isolated worktrees with
separate Cargo target directories:

```sh
cargo test --offline -p pallas-validate --features phase2,unstable dijkstra_transaction_tests -- --nocapture
```

Baseline: **19 runtime assertion failures**; fixed: **19 passed**. One optional
CLI exporter is ignored in both. The original metadata assertion fails with
`DijkstraUnsupported("auxiliary data")`; the script capture reaches the baseline's
unsupported purpose boundary. `evidence/regression.txt` preserves compact actual
output. `evidence/verification.json` records the test-source hash and checks.

For baseline reproduction, copy this directory and
`pallas-validate/src/phase1/dijkstra_transaction_tests.rs` into a worktree at the
baseline revision; apply `baseline-adapter.patch` with `git apply --unidiff-zero`.
It only adds test wiring, existing helper visibility and an inert account-state
field. Baseline validation behavior is unchanged; failures occur after compilation.

The cleanup also passes all native validation tests (including other eras),
phase-one-only unstable tests, strict Clippy and the optional CLI exporter.
Full formatting retains the same seven pre-existing differences in unchanged
`examples/leios-testnet/src/bin/harvest.rs`; modified Rust files are formatted.
The implementation's earlier workspace/MSRV verification is recorded in commit
`dd9bfcb` and remains historical; this cleanup changes names/docs/fixture selection,
not ledger behavior. Retained captured CBOR bytes are unchanged. Removed replay
artifacts and original full logs remain in that commit and the local handoff archive.
