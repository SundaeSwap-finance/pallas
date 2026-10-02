Historical documentation for commit `2fafb1a40f8b9e6a24b6de5e97a92195a913a6db`.
Run these initial-policy reproduction steps from that revision. For the current
per-script policy, see [README.md](README.md).

# Native Dijkstra execution-unit estimation

`pallas_validate::phase2::estimate_tx(&tx, &pparams, &utxos, &slots)` is an
opt-in API behind `phase2,unstable`. It estimates native Dijkstra transactions
without final key witnesses or adequate declared budgets. `evaluate_tx` and
`phase2::tx::eval_tx` still enforce native declared budgets. Earlier eras return
`WrongEra` from the new API; their existing evaluation path is untouched.

Each redeemer receives the remaining active `max_tx_ex_units` memory/steps,
in native pointer order. Consumption, including failed executions, is subtracted
with saturation. Exact equality is allowed. An exhausted execution has
`success=false`, the machine's failure message and actual reported consumption;
the charge that crosses a limit can exceed that limit. Subsequent redeemers still
receive the remainder, never a fresh transaction allowance. Therefore all entries
must succeed for a usable transaction estimate. Successful reports cannot total
more than the protocol transaction maximum. Limits outside the backend's signed
64-bit range reject explicitly. This API does not estimate transactions requiring
more than that aggregate allowance by running each script with a fresh maximum.

No transaction/body/witness rewriting occurs during estimation. Script resolution,
input errors, exact required redeemers, native output decoding, contexts, full cost
models and existing unsupported-feature checks share the original code path.
Reports retain purpose/index, units, success, messages and logs. Native V3 non-unit
returns now get an explicit failure message (they already failed). Trace remains
an unsupported builtin; tests verify empty logs without broadening evaluator support.

## Evidence

The smallest registration case is the unchanged captured RealFi **settings**
registration `da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6`.
“Settings” names an application validator, not a ledger concept. The existing
fixture helper extracts it from the 1,292-byte block at slot 1401365 and resolves
native outputs from its 4,951-byte producer block at 1401345. Captured CBOR is
unchanged and not duplicated here. Historical epoch-64 protocol-12.0 parameters
retain every one of the 350 raw V3 coefficients. Exact expected execution is
18,485 memory / 4,805,428 steps, agreeing with retained prior offline CLI evidence.
Original capture provenance, hashes and expected-result limitations are linked
in `provenance.json`; byte hashes are over decoded CBOR, not hex text.

All derivatives are generated only in tests and labelled synthetic. They do not
claim valid signatures/integrity hashes, phase-one acceptance or submission.
Coverage includes unchanged and unsigned capture, zero/insufficient/excessive
budgets, unsigned plus zero budgets, explicit and non-unit script failures,
missing inputs/scripts/redeemers, extraneous redeemers, individual/aggregate
execution boundaries, backend limit conversion, original body hash in context,
redeemer-data sensitivity, purpose/index reporting for all four supported purposes,
and the explicit earlier-era API boundary. The full validation suite separately
covers existing phase-one enforcement, Conway evaluation and older-era rules.

Same final assertions on baseline `952167c57fff4433dbdc0fac40e145e8dae32795`:
**3 pass, 10 runtime failures**. Fixed: **13 pass**. `baseline.log` and `fixed.log`
retain output, including the intended zero-budget failure (`Out of budget`,
100 memory / 100 steps). The baseline-only new-API adapter delegates directly to
unchanged `evaluate_tx`; it does not alter budget checks. The earlier-era boundary
failure establishes the new API's explicit scope, not a pre-existing Conway bug.
The non-unit-message failure establishes the report improvement. Compilation
errors are not counted as reproductions.

## Reproduction

From a checkout containing this change, create a separate baseline source tree:

```sh
mkdir -p target/musashi-estimation-baseline-source
git archive 952167c57fff4433dbdc0fac40e145e8dae32795 | tar -x -C target/musashi-estimation-baseline-source
cp test_data/musashi-estimation/Cargo.lock.snapshot target/musashi-estimation-baseline-source/Cargo.lock
cp pallas-validate/src/phase2/dijkstra_estimation_tests.rs target/musashi-estimation-baseline-source/pallas-validate/src/phase2/
cp pallas-validate/src/phase2/dijkstra_evaluation_tests.rs target/musashi-estimation-baseline-source/pallas-validate/src/phase2/
cp pallas-validate/src/phase1/dijkstra_transaction_tests.rs target/musashi-estimation-baseline-source/pallas-validate/src/phase1/
patch -d target/musashi-estimation-baseline-source -p1 < test_data/musashi-estimation/baseline-adapter.patch
CARGO_TARGET_DIR="$PWD/target/musashi-estimation-baseline-build" CARGO_PROFILE_DEV_DEBUG=0 cargo test --manifest-path target/musashi-estimation-baseline-source/Cargo.toml --offline --locked -p pallas-validate --features phase2,unstable --lib estimation_ -- --nocapture
cargo test --offline --locked -p pallas-validate --features phase2,unstable --lib estimation_ -- --nocapture
```

Dependencies must already be cached for `--offline`. The retained lock snapshot
is identical in both builds; the workspace intentionally does not track its root
Cargo.lock. Build outputs are separate. `run-checks.py` runs current Linux CI
commands and writes `checks.json`; full local logs live under
`target/musashi-estimation-checks`. Essential regression evidence is tracked here.
See `verification.md` for final check results and limitations.

Next Dolos work should call `phase2::estimate_tx` for native estimation, preserve
these reports and explicitly map purposes to RPC enums. Submission must retain
phase one plus budget-enforcing `evaluate_tx`. No Dolos production code, pins,
services, private workaround reference or remote refs were changed here.
