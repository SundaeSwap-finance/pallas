Historical verification for the initial shared-allowance commit
`2fafb1a40f8b9e6a24b6de5e97a92195a913a6db`. Current per-script verification is
in [per-script/verification.md](per-script/verification.md).

# Verification — 2026-10-02

Baseline: Pallas `952167c57fff4433dbdc0fac40e145e8dae32795`, clean
`leios-musashi`. Dolos was and remains clean at
`b26c8a7cc547e2242b6698b634300acd40fb7a04` on `leios-musashi`; only its ignored local
Musashi plan is updated for handoff. Read-only remote tips were Pallas `952167c…`
and Dolos `11d8ede20209db4156f8d055d007f37bb77646a0`. No remote writes.
The containing fix commit and local `musashi-fix-20261002-estimation-v1` tag are
recorded by full revision in that plan. This evidence accompanies the implementation.

Identical test sources (hashes in `provenance.json`) with separate build outputs:

- Baseline: **3 passed, 10 runtime failures**, using only the documented
  new-API forwarding adapter. Eight failures exercise estimation/budget/context
  behavior, one the missing non-unit failure message, one the new API's explicit
  earlier-era boundary. Unchanged/unsigned capture and structural-error controls pass.
- Fixed: **13 passed**, including unchanged execution at **18,485 memory /
  4,805,428 steps**. The existing `evaluate_tx` still fails zero/insufficient
  declared budgets and rejects excessive aggregate declarations.

Full commands, exit codes, durations and log hashes are in `checks.json`,
`network-checks.json` and `verification.json`. On Linux, Rust 1.98.1:

| Check | Result |
| --- | --- |
| Native validation with `phase2,unstable` | 273 passed, 3 ignored (146 unit + 127 integration passes) |
| Native strict Clippy and native docs with warnings denied | Passed |
| Workspace all-target build and strict Clippy | Passed |
| Workspace tests | 1,024 passed initially; 12 socket-denial failures in three targets. All 12 passed on targeted rerun with local loopback enabled. Total 1,036 passed, 19 ignored |
| Blueprint network tests | 392 passed, 8 ignored with loopback enabled; initial sandbox denial retained |
| Unstable feature suite | 669 passed, 1 ignored |
| Phase-two-only validation suite | 162 passed, 1 ignored |
| Workspace no-default/all-feature checks; isolated primitives no-default | Passed |
| Workspace docs with warnings denied | Passed |
| Rust 1.97 workspace check and native validation suite | Passed; 273 tests passed, 3 ignored |
| Changed Rust formatting; diff whitespace | Passed |
| Existing captured fixture verifier; new provenance/source/lock verifier | Passed |

The sole remaining repository check failure is **pre-existing**: seven
`cargo fmt --all --check` diffs in unchanged
`examples/leios-testnet/src/bin/harvest.rs`. The file is byte-identical to baseline;
its hash and full formatting output are retained. No unrelated formatting fix was
made. The socket failures were environmental (`PermissionDenied: Operation not
permitted` on bind), not source regressions. Reruns used test-only local connections;
no production services or live transactions were involved. The workspace math suite
completed successfully and was not repeated for the network reruns.

macOS/Windows runs and new independent live-node evaluation were unavailable.
The earlier retained offline CLI comparison supplies independent original-budget
corroboration; historical accepting node/evaluator identities remain unknown.
Existing ignored tests remain ignored. Native supported features and builtin subset
are unchanged, including rejection of Trace. This is not full Dijkstra support,
current spendability, successful submission, or Dolos RPC integration evidence.

Essential baseline/fixed logs, provenance, locked build input, adapters and summaries
are retained alongside tests. Full local gate logs remain under
`target/musashi-estimation-checks`; nothing essential exists only in `/tmp`.
Next integration API: `pallas_validate::phase2::estimate_tx` with `phase2,unstable`;
Dolos must preserve report fields and map RPC purposes explicitly. Submission keeps
phase one and budget-enforcing `evaluate_tx`. No pin/workaround changes occurred.

Tracked text logs omit ANSI control codes and trailing whitespace/blank EOF lines.
Original raw logs remain in `target/musashi-estimation-checks/raw-*`.
