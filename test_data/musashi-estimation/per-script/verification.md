# Verification — independent per-script limits

Baseline: `2fafb1a40f8b9e6a24b6de5e97a92195a913a6db` on `leios-musashi`, with the
initial shared allowance. Canonical Dolos stays at
`b26c8a7cc547e2242b6698b634300acd40fb7a04` on `leios-musashi` with production code
and pins unchanged. Fresh read-only remote tips remain Pallas `952167c57fff4433dbdc0fac40e145e8dae32795`
and Dolos `11d8ede20209db4156f8d055d007f37bb77646a0`. No publication.

Identical regression source, separate baseline/fixed build outputs:
**baseline 12 pass / 2 runtime failures; fixed 14 pass**. No API adapter.
The baseline rejects the second script when its independent estimate should
succeed: once after a successful first execution, once after a first script
failure. The unchanged native capture still reports **18,485 memory /
4,805,428 steps**. Structural, declared-budget enforcement and earlier-era controls
remain green. No capture bytes or cost coefficients changed.

Commands, exit codes, timing, full-log hashes and test counts are retained in
`checks.json` and `verification.json`. Full logs remain in
`target/musashi-estimation-per-script-checks`; essential runtime proof and
provenance are committed alongside this document.

| Check | Result |
| --- | --- |
| Full native validation (`phase2,unstable`) | 274 passed, 3 ignored; 147 unit + 127 integration passes |
| Native strict Clippy and native docs with warnings denied | Passed |
| Workspace build and strict Clippy | Passed |
| Workspace tests, local sockets enabled | 1,036 passed, 19 ignored |
| Blueprint network suite | 392 passed, 8 ignored |
| Unstable feature suite | 669 passed, 1 ignored |
| Phase-two-only suite | 162 passed, 1 ignored |
| Workspace no-default/all-feature checks; isolated primitives | Passed |
| Workspace docs with warnings denied | Passed |
| Rust 1.97 workspace check and native suite | Passed; 274 tests passed, 3 ignored |
| Changed Rust formatting; whitespace; capture/source/lock checksums | Passed |

The only remaining gate failure is the **same seven pre-existing formatting
differences** in unchanged `examples/leios-testnet/src/bin/harvest.rs`, confirmed
byte-identical to baseline. This file was not changed. Initial implementation
checks and shared-cap test assertions remain archived in the parent directory,
with their prior checkpoint preserved. New tracked logs omit only ANSI/trailing
whitespace; raw output remains in the local gate directory.

macOS/Windows verification and new independent node evaluation were unavailable.
The earlier offline CLI result still corroborates the original capture's units;
no exact Blockfrost deployment equivalence is claimed. Historical node/evaluator
identities remain unknown. Successful estimates can exceed the transaction maximum
in aggregate, so they are not admission approval; declared-budget validation is
unchanged. Dolos integration, pins, RPC tests and publication remain deferred.
