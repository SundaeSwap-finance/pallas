# S06 integration with the published Amaru fork

Native Dijkstra uses `https://github.com/rodrigomd94/amaru.git` at exact commit
`e122ffb2018196ba9c57f42b70b94ada603d3fbc`, published by the user on the existing
`fix/uplc-protocol-semantics` branch. Both `amaru-uplc-native` (0.4.0) and
`amaru-kernel` are pinned to that revision. Earlier eras retain registry
`amaru-uplc =0.1.0`. There are no local path/Git overrides in the final dependency.
Rust 1.97 is the declared workspace minimum and CI exercises native phase two.

## History reconciliation

Local merge `f93997869bca2fa40940f89d3c0bf362fccff191` combines tested S06 checkpoint
`fee0fac2cf7ad3fde2e19eae96d618ec1d4f52ca` with published Pallas
`a5f93ea58900020058ae22f5108f97b7d69f9373`. The remote history was restacked;
its phase-one fixes are patch-equivalent to the earlier checkpoint, while its
networking updates and removal of the old follow layer are retained.

Before adding this report, the merge index was verified byte-for-byte as the
published tree plus the exact S06 diff from `4be4fb2171a73bdb04994c8472e76f601d41318f`
to `fee0fac...`. That diff contains only validation phase-two code, its evidence,
dependency/compiler configuration, CI, README and changelog. Its SHA-256 is
`52074f2fa04dddccbf1acdabc956ebde07cabfd8d342df0bca6eded62c40a030`.
The follow-up changes only the dependency URI/comment and evidence/documentation.
No networking implementation was ported from the old branch, no commits were
rebased, and no historical tag was moved. Both histories remain ancestors.
The canonical Pallas branch can advance by fast-forward to this integration.

## Verification

The merged tree passes all 241 native/earlier-era validation tests. After the user
published Amaru, the same tests were repeated against the dependency fetched from
GitHub and pass again. The remote-pin run also passes strict crate Clippy, crate
docs with warnings denied, and the all-features workspace check. The final lockfile
and `resolved-evaluators.json` record the actual Git source and registry backend.

Linux repository checks on the merged source pass: workspace build, workspace tests
(with the socket retry described below), Clippy, docs, both feature extremes,
isolated primitives, unstable tests, blueprint tests and phase2-only tests.
The original workspace/blueprint runs hit sandbox `PermissionDenied` while opening
local sockets in pallas-network's plexer test. The socket-enabled retry passed the
workspace excluding pallas-math, whose 19 unit tests had already passed (including
the slow golden test); math doctests passed separately. Blueprint tests also pass
with sockets enabled. These environment failures are not ledger regressions.

Workspace formatting still reports exactly seven pre-existing differences in
`examples/leios-testnet/src/bin/harvest.rs`; no source formatting was changed by the
portable-pin step. No hosted CI, macOS or Windows result is claimed. The full Amaru
workspace passed on its pinned nightly (3824 passed / 29 ignored); stable 1.97
coverage applies to its evaluator/kernel dependencies and Pallas integration.

`verification.json` lists all commands/results and artifact checksums. The initial
local-pin preparation snapshot is retained in `preparation-verification.json`;
`dependency-lock-local.txt` and `portable-pin.patch` are historical preparation
artifacts. Use **`dependency-lock-published.txt`** for the final source. The patch
was applied with `git apply --unidiff-zero` and is no longer a pending operation.
To reproduce the final evaluation gate, copy the published lock to root Cargo.lock:

```sh
cargo +1.97.0 test -p pallas-validate --features phase2,unstable
cargo +1.97.0 clippy -p pallas-validate --all-targets --features phase2,unstable -- -D warnings
```

## Evidence and boundaries

All supported/unsupported boundaries from [the evaluator report](../dual-evaluator/README.md)
remain in force: protocol 12.0, top-level V3 `Reg` reference scripts, the audited
35-builtin list, checked key/ADA input/output shapes, declared reference inputs and
no datum or upper validity bound. Other languages, purposes and transaction features
are rejected explicitly, including V4, witness scripts, scripted subtransactions,
mint, withdrawals and governance. General V3 `UnReg` refund encoding does not imply
native unregistration evaluation support.

Original captured transaction
`da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6`, native output
eras, UTxOs, redeemer, declared budgets, protocol 12 and all 350 cost coefficients
are unchanged. The real settings validator succeeds at **18485 memory / 4805428 CPU**.
Captured, extracted and synthetic baseline/fixed/CLI evidence remain clearly labeled
in the existing reports. The ledger specification is pinned to
`1587f21a7d1306dc590c2749a5c66232ef66aad0`; historical node/evaluator builds remain
unknown. No new CLI or live-node comparison was performed for this URI-only change.

S03 is derived Conway protocol-9 evidence; S04 proves scoped inputs; S05 proves
only its documented phase-one subset. No provisional registration state is committed.
This is scoped S06 completion, not full Dijkstra support, S07, Dolos integration
or submission. Canonical Dolos remains `c431ca8dbaa40af31a715fda498505d9a9415105`
with its original pin/workarounds. Read-only inspection found remote
`abe2642391006e7e5439a00493d41db5da280a02` already pins Pallas `a5f93ea...`;
that remote Dolos history was not applied here. The private reference is untouched.
The assistant has made no remote writes; the user publishes Pallas separately.
