# Independent per-script estimation limits — 2026-10-02

User requested the per-script policy after the Blockfrost/Ogmios comparison.
`estimate_tx` now gives every redeemer the active protocol's full transaction
execution-unit maximum. A preceding execution or failure cannot reduce a later
script's allowance. Each execution is finite, but the sum of successful estimates
may exceed the transaction maximum. This does not weaken `evaluate_tx`: declared
aggregate and individual budgets are still enforced there. Existing supported
eras, scripts, contexts, historical cost models and all error checks are unchanged.

The source-policy comparison is the independent mapping of redeemers in
[the inspected ledger helper](https://github.com/IntersectMBO/cardano-ledger/blob/54e24ba4858b5f5cb4c5f6f0adfa3d7cae669b7a/eras/alonzo/impl/src/Cardano/Ledger/Alonzo/Plutus/Evaluate.hs#L275-L389).
This is not evidence of Blockfrost's exact deployed build or native Dijkstra
support, and no new live-node comparison was made.

## Runtime regression

Same final test source on the shared-allowance baseline
`2fafb1a40f8b9e6a24b6de5e97a92195a913a6db`: **12 pass / 2 runtime failures**.
Fixed: **14 pass**. No API adapter or baseline production changes.

The synthetic aggregate case uses the existing captured registration fixture,
replaces its validator with a constant-unit script, and creates two script
certificates after a key certificate. Each independently needs **500 memory /
64,100 steps**. Both must succeed even when their sum exceeds the transaction
limit. Individual memory/CPU exhaustion and zero limits still fail. Declaring the
measured budgets causes budget-enforcing evaluation to accept exact aggregate
equality and reject a one-unit memory/CPU excess.

A second synthetic case makes the first script fail its redeemer check and the
second succeed with its full allowance. This independently fails on the baseline
because the first failure drains the second allowance. Purpose/index, consumed
units and failure messages are asserted. All original unchanged-capture,
unsigned/zero-budget, structural-error and context-preservation cases still pass.
Original captured execution remains **18,485 memory / 4,805,428 steps**.

Captures and historical parameters are reused unchanged from the initial fixture.
All mutations exist only in tests; they are phase-two evidence, not valid signatures,
integrity hashes or accepted transactions. `provenance.json` records source hashes,
network/state limitations, synthetic derivations and normalized log checksums.

## Reproduce

From this checkout, with dependencies already cached:

```sh
mkdir -p target/musashi-estimation-per-script-baseline
git archive 2fafb1a40f8b9e6a24b6de5e97a92195a913a6db | tar -x -C target/musashi-estimation-per-script-baseline
cp test_data/musashi-estimation/Cargo.lock.snapshot target/musashi-estimation-per-script-baseline/Cargo.lock
cp pallas-validate/src/phase2/dijkstra_estimation_tests.rs target/musashi-estimation-per-script-baseline/pallas-validate/src/phase2/
CARGO_TARGET_DIR="$PWD/target/musashi-estimation-baseline-build" CARGO_PROFILE_DEV_DEBUG=0 cargo test --manifest-path target/musashi-estimation-per-script-baseline/Cargo.toml --offline --locked -p pallas-validate --features phase2,unstable --lib estimation_ -- --nocapture
cargo test --offline --locked -p pallas-validate --features phase2,unstable --lib estimation_ -- --nocapture
```

Baseline and fixed build outputs are separate. The baseline target reuses prior
immutable dependencies; changed baseline crate sources were rebuilt. The retained
lock input is unchanged. `baseline.log` and `fixed.log` omit only ANSI/trailing
whitespace; raw logs remain in `target/musashi-estimation-per-script-checks`.
`run-checks.py` records repository checks in `checks.json`; final results are in
`verification.md`. Previous shared-cap evidence remains under the parent directory,
including its original assertion source; no historical checkpoint was moved.

Dolos integration, dependency-pin updates and RPC tests remain future work at the
user's request. No services, submissions or remote ref changes are involved.
