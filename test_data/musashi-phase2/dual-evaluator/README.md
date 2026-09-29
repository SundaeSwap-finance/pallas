# Two evaluators: passing local Rust 1.97 experiment

The original RealFi settings registration and earlier-era regressions pass together.
This supersedes the failed single-evaluator experiment in
[../amaru-integration](../amaru-integration/README.md). It remains isolated on
`experiment/amaru-uplc-integration`; it is not merged into `leios-musashi` and is
not a Dolos integration or submission result.

## Implementation and dependency status

Earlier eras retain registry `amaru-uplc =0.1.0` and their existing evaluator.
Native Dijkstra uses the distinct `amaru-uplc-native` alias, version 0.4.0, with
`amaru-kernel`. The native adapter is in `native_evaluator.rs`; no caller-side
Conway wrapper, native era relabeling, protocol downgrade or parameter truncation
is used. Shared context translation still follows the actual protocol.

The new backend is pinned to local Amaru commit
`e122ffb2018196ba9c57f42b70b94ada603d3fbc` on `experiment/rust197-compat`, parent
`12dba6c181c1774bde47373bb1ce5fe10a672bea`. The parent is published on the user's
fork; the new commit is **local only**. The manifest deliberately uses
`file:///home/rodrigo/projects/amaru`. This is an experimental local dependency,
not a portable published pin. `amaru-candidate.patch` preserves all seven changed
files independently of that worktree (apply with `git apply --unidiff-zero`). The original Amaru worktree/branch is
unchanged; the candidate is in `/home/rodrigo/projects/amaru-stable-compat`.

Stable Rust 1.97 originally failed on two compact-collection mutable-borrow loops.
The candidate promotes their storage before returning the mutable tree borrow.
Its evaluator also enforces the selected D/E integer operands described below.
Pallas's root Rust policy remains 1.88; this experiment's phase-two dependency
requires 1.97. No main-branch compiler-policy change has been made.

## Evidence and supported subset

Unchanged captured transaction:
`da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6`.
This registers RealFi's application settings validator. Original CBOR, native
output eras, UTxOs, redeemer, declared budgets, protocol 12.0 and the complete
350-entry V3 cost vector remain in the existing registration/phase-one fixtures.
The real script succeeds at exactly **18485 memory / 4805428 CPU**. No captured
payload or historical parameter file changed in this experiment.

The supported native subset remains protocol 12.0, top-level `Reg` certificates
with V3 reference scripts, ADA/key spending inputs and outputs, declared reference
inputs (including script addresses), no datum or upper validity bound, and the
35 builtins listed explicitly in `native_evaluator.rs`. Certificate indices count
the full certificate list. Only spending/reference inputs supply scripts, with
each output decoded under its original era. Checked shared V3 fields are projected
into the existing context representation. Integer operands outside the audited
range return an explicit unsupported-subset error.

Other languages (including V4), purposes/certificate kinds, witness scripts,
scripted subtransactions (indeed all subtransactions in phase two), script guards,
required top-level guards, direct deposits, account intervals, mint, withdrawals,
governance, datum/multiasset outputs and other unsupported features are rejected.
The general V3 encoder covers explicit registration deposits and unregistration
refunds after bootstrap; native **evaluation** does not thereby support `UnReg`.
The synthetic context tests cover protocols 9/10/11/12, amounts 0/1/2000000/u64::MAX,
all three certificate-purpose occurrences and legacy amount-less certificates.

S03 remains explicitly derived Conway protocol-9 execution. S04 proves scoped
input handling; S05 proves only its documented phase-one subset. Successful phase
one does not authorize committing provisional state. This experiment neither
establishes full Dijkstra support nor executes S07.

## Runtime reproduction and integer rules

The unchanged phase-two assertions at checkpoint `93888fb7e20552b5ba270332acf36e9b494be3df`
produce 33 passes / eight failures / one ignored, plus two Conway integration
failures. The earlier report retains those build logs. After restoring the legacy
backend, `baseline-dual-runtime.txt` records 113 unit passes / one runtime failure /
one ignored: out-of-range integer arithmetic still succeeds. The final exact git
pin produces **114 unit passes / one ignored and 127 integration passes**, with one
ignored doctest (`fixed-pallas-tests.txt`). Behavioral assertions were not weakened.

The two new direct Amaru integer tests also run before the fix: one passes and one
fails at runtime (`baseline-amaru-integers.txt`). The fixed full UPLC suite has
**1067 passes**; five compact-collection tests pass. `baseline-stable-compile.txt`
is a separate compiler compatibility failure, never counted as runtime reproduction.
Baseline and fixed logs are separate artifacts.

Pinned ledger specification: `1587f21a7d1306dc590c2749a5c66232ef66aad0`. This is
**not** the identity of the historical accepting node/evaluator, which is unknown.
The associated Plutus 1.68 source at
[`9e17e2404dc6988c908b1fea099dde202df73b6a`](https://github.com/IntersectMBO/plutus/blob/9e17e2404dc6988c908b1fea099dde202df73b6a/plutus-core/plutus-core/src/PlutusCore/Default/Builtins.hs)
uses `CInteger` for selected arithmetic/comparison operands under D/E semantics.
Its [Cardano universe](https://github.com/IntersectMBO/plutus/blob/9e17e2404dc6988c908b1fea099dde202df73b6a/plutus-core/plutus-core/src/PlutusCore/Default/Universe/Cardano.hs)
defines **[-2^262143, 2^262143-1]**. Add/subtract/multiply/divide/quotient/remainder/
mod/less-than/less-or-equal use the bound on both operands. Legacy-language
`consByteString` uses it in D; V3 retains its byte-range rule. Arithmetic results,
`equalsInteger` and `iData` are unrestricted. Tests cover both signed endpoints,
both operand positions, V1/V2/V3 and protocols 10/11/12. Later F/G semantics are
not inferred from D/E, and the historical evaluator is not identified from source.

## Fresh independent offline CLI comparison

`cli-integer/` contains synthetic phase-two diagnostics based on the captured
transaction shape, with replaced script, certificate hash, reference script and
budget. They are **not new network captures**; signatures and transaction-size
validity are not claimed. Nothing was submitted. The era-history file is synthetic;
export rejects validity bounds, so it cannot influence the script's time context.
The retained historical protocol-12 parameters keep all 350 coefficients.

CLI 11.2.2.0, revision `afa091b4af2795d1d9c46e59145ed16127760f7b`, is independent
of Amaru. With B=2^262143:

| Case | Pallas fixed | CLI | Memory / CPU if successful |
|---|---|---|---|
| add(B-1, 0) | success | success | 5297 / 1997208 |
| add(B, 0) | unsupported range | integer out of bounds | — |
| add(-B, 0) | success | success | 5297 / 1997208 |
| add(-B-1, 0) | unsupported range | integer out of bounds | — |
| equals(B, B) | success | success | 1501 / 2561443 |
| iData(B) | success | success | 1032 / 159399 |

`positive-outside/` retains the **before-fix** disagreement: Pallas succeeds while
CLI rejects the integer. `positive-outside-fixed/` uses identical transaction CBOR
and now rejects it. `controls.json`, tx/UTxO envelopes and complete stdout/stderr
retain the results. Cosmetic envelope descriptions identify synthetic data;
CBOR is untouched. Log normalization and hashes are recorded separately.
For the real capture and builtin casing, matching independent CLI results remain
in the prior checkpoint/report; they were not rerun here. No live-node evaluation
or historical evaluator-build comparison is available.

## Reproduce

Use Rust 1.97.0 and the local Amaru candidate object at the manifest path, with
`dependency-lock.txt` copied to root `Cargo.lock`. Once the user publishes the
candidate, the local git URL can be replaced by the fork URL at the same revision;
that publication/adoption has not occurred. To reproduce the direct Amaru runtime
baseline, apply just the test-file hunk of `amaru-candidate.patch` to parent
`12dba6c...` and run the integer tests on its pinned nightly. Use a separate target
directory from the fixed tree. The complete patch builds/tests on stable 1.97
with `CARGO_ENCODED_RUSTFLAGS=''` overriding Amaru's nightly compiler flags.

```sh
cargo +1.97.0 test -p pallas-validate --features phase2,unstable --no-fail-fast
cargo +1.97.0 clippy -p pallas-validate --all-targets --features phase2,unstable -- -D warnings
```

Replay any retained CLI case with:

```sh
cardano-cli dijkstra transaction calculate-plutus-script-cost offline \
  --start-time-utc 2026-09-07T00:00:00Z \
  --era-history-file cli-integer/synthetic-era-history.json \
  --protocol-params-file cli-integer/parameters.json \
  --utxo-file cli-integer/positive-inside/settings.utxos.json \
  --tx-file cli-integer/positive-inside/settings.tx.json
```

`compare-integer-controls.py` regenerates the six fixed diagnostics into the new
directory specified by `MUSASHI_COMPARISON_OUT`; `CARDANO_CLI` selects the binary.
Machine-readable `verification.json` records the remaining repository checks,
commands, exceptions and exact revisions. Linux checks do not establish macOS or
Windows support. Workspace formatting has seven pre-existing harvest.rs differences.
Amaru workspace tests remain blocked by missing `libclang.so` in RocksDB, while
changed-crate tests, Clippy and docs pass.

**Next:** review/adopt the 1.97 phase-two requirement and publish the new Amaru
candidate only with explicit authorization (or user publication); replace the local
URI with a portable exact pin, then reintegrate the tested Pallas change. S06
remains partial on `leios-musashi` until that integration. Dolos pin/workarounds,
S07, submission and the private reference remain untouched.
