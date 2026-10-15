# Amaru 0.4 integration experiment: not ready to merge

The unchanged native RealFi settings registration succeeds, but this experiment
**fails the replacement gate**. Do not merge it into `leios-musashi`, change Dolos's
pin, remove workarounds, or interpret a successful capture as complete Dijkstra
support. This is a local experiment, not the S07 integration step.

## Revisions and changes

- Pallas base: `b09918be7b71525d349e7f010d8cffeb3708de4b`.
- Experimental branch: `experiment/amaru-uplc-integration`.
- Native dispatch and regression suite restored from parked Pallas checkpoint
  `3de0b4c27fef179f2b406c922571a6e2d4d86d33`, without its vendored evaluator.
- Evaluator: `amaru-uplc` 0.4.0 and `amaru-kernel` from
  `https://github.com/rodrigomd94/amaru.git`, commit
  `12dba6c181c1774bde47373bb1ce5fe10a672bea`.
- Initial run used the clean local Amaru checkout at that revision; the repeat used
  exact git dependencies fetched read-only. No push was performed by this task.
- The adapter passes the actual protocol to the new decoder/cost model, uses the
  new evaluation API and rejects trailing bytes for V3. Synthetic script builders
  use the new parser signature. Behavioral assertions were retained.
- The old backport-specific integer-range error does not exist in this evaluator;
  its translation was removed for compilation. The corresponding regression still
  requires the same subset rejection and fails, rather than silently widening the
  advertised supported subset.

## Runtime results

`fork-native.txt`: **14 native tests pass; one export helper is intentionally
ignored.** The captured transaction remains
`da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6`.
It consumes **18485 memory / 4805428 CPU**, exactly its original declared budget.
Original CBOR, native input/output eras, UTxOs, redeemer, protocol 12.0 and all 350
historical V3 cost coefficients are retained. Tests cover the certificate index,
input/script resolution, missing/wrong inputs/scripts/redeemers, budget boundaries,
post-bootstrap context and explicit unsupported-feature rejection.

`phase2-regressions.txt`: **33 pass, eight fail, one ignored**:

- Seven earlier-protocol tests fail. The new decoder rejects protocol-9 `case`
  terms and builtin availability calls panic for protocol 9. Amaru's current
  kernel declares protocol 10 as its minimum supported version; this is an
  incompatibility with Pallas's broader historical-era requirements.
- The integer subset test fails because an arithmetic operand outside the prior
  audited range is accepted. This is a failure to preserve the supported subset,
  **not proof of ledger invalidity**: inspected Plutus E/G variants differ on
  integer bounds, and the historical evaluator build remains unknown.

`earlier-era-integrations.txt`: Alonzo 33, Babbage 33 and Byron 10 tests pass;
Conway has 20 passes and two failures due to protocol-8 builtin availability panics.
Shelley/MA 25 and utility four integration tests pass; all 73 phase-one unit
tests also pass. No assertions
were weakened to turn these runtime failures into passes.

## Compiler and checks

Rust 1.88 with phase two **fails before compilation**: Amaru kernel/minicbor-extra/
deps require Rust 1.97, and sysinfo requires 1.95. This is compiler compatibility
evidence, not a runtime bug reproduction. Rust 1.88 without phase two passes.
The functional experiment uses `nightly-2026-09-04`; no compiler-policy change was
made to the main branch. Stable Rust 1.97 itself was not tested.

Crate Clippy with warnings denied and crate docs with warnings denied pass.
Changed-file formatting passes; workspace formatting retains the pre-existing
`examples/leios-testnet/src/bin/harvest.rs` differences. Unrelated formatting
changes were discarded. Complete workspace/platform checks were not pursued after
the concrete runtime/compiler incompatibilities ruled out adoption.

A temporary-filesystem exhaustion interrupted later checks; only this experiment's
build cache was moved to the project disk and affected checks were rerun. Storage
failures are separate from the reproducible runtime failures above.

## Evidence and limits

Captured inputs and their provenance are in `../../musashi-registration/` and
`../../musashi-phase1/registration-epoch64-parameters.json`. The synthetic cases
are explicitly separate test functions in the restored test modules.
`prior-independent-cli-result.txt` and `prior-independent-cli-provenance.json`
retain the previous independent Cardano CLI comparison metadata. Paths inside
that archival provenance refer to the complete comparison artifacts on parked
checkpoint `3de0b4c...`, not newly generated files here. The prior CLI build was
11.2.2.0 / `afa091b4af2795d1d9c46e59145ed16127760f7b`. No new node/CLI comparison
was run in this experiment. Its matching registration units are a comparison with
that retained result; the historical node/evaluator version remains unknown.
The ledger specification remains pinned to
`1587f21a7d1306dc590c2749a5c66232ef66aad0`, distinct from evaluator identity.

S03 remains derived Conway protocol-9 evidence; S04/S05 prove only their scoped
input/phase-one subsets. No phase-one state was committed. There is no claimed
support for V4, scripted subtransactions or unrelated Dijkstra features.

## Reproduce and next decision

Copy `dependency-lock.txt` to the worktree root as `Cargo.lock` when reproducing
these exact dependencies. Full commands and exit codes are in `verification.json`.
The native suite command is:

```sh
cargo +nightly-2026-09-04 test -p pallas-validate --features phase2,unstable \
  --lib phase2::dijkstra_evaluation_tests -- --nocapture
```

Before reintegration, decide whether to accept the newer compiler requirement and
provide earlier-protocol evaluator support (or retain a separate legacy backend),
then resolve the integer-range policy against the supported ledger/evaluator
semantics. Rerun unchanged native and earlier-era gates after those changes.
The current experiment alone is not sufficient to choose a production dependency.
