# Native Dijkstra execution-unit estimation

`pallas_validate::phase2::estimate_tx(&tx, &pparams, &utxos, &slots)` is an
opt-in API behind `phase2,unstable`. It estimates native Dijkstra transactions
without final key witnesses or adequate declared budgets. `evaluate_tx` and
`phase2::tx::eval_tx` still enforce native declared budgets. Earlier eras return
`WrongEra` from the new API; their existing evaluation path is untouched.

Each redeemer **independently receives the full active `max_tx_ex_units` limit**.
Previous executions, including failures, do not reduce the next allowance.
Exact per-script equality is allowed. An exhausted execution has `success=false`,
the machine's failure message and actual consumption, including the charge that
crosses the limit. Unrepresentable backend limits reject explicitly.

Successful estimates can sum above the transaction limit. Builders must check the
aggregate before constructing a valid transaction. For example, two scripts can
each need 60% of the maximum and both be estimated successfully, even though their
combined 120% cannot pass admission. Existing budget-enforcing evaluation still
rejects excessive aggregate declarations and insufficient individual allowances.

Estimation does not rewrite the transaction. Script resolution, input errors,
exact required redeemers, native output decoding, original body hash/context,
redeemer data, all historical cost-model coefficients and unsupported-feature
checks share the original code path. Reports retain purpose/index, units, success,
messages and logs. Native V3 non-unit returns have an explicit failure message.
Trace remains unsupported; no evaluator support was broadened.

Current policy regression evidence, reproduction and checks:
[per-script/README.md](per-script/README.md). This per-script policy supersedes the
initial shared transaction allowance at commit
`2fafb1a40f8b9e6a24b6de5e97a92195a913a6db`.

The smallest registration capture is the unchanged RealFi **settings** transaction
`da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6`.
“Settings” is an application validator, not a ledger concept. Its exact expected
execution remains **18,485 memory / 4,805,428 steps** with native inputs and all
350 historical protocol-12.0 V3 cost coefficients. Synthetic derivatives do not
claim valid signatures, integrity hashes, ledger acceptance or submission.

Initial evidence remains historical and reproducible: `baseline.log`, `fixed.log`,
`provenance.json`, `verification.md` and `README.initial.md` describe the first
shared-allowance implementation, not the current policy. `initial-estimation-tests.rs`
preserves its assertion source byte-for-byte; `verify.py` verifies those archived
assertions and unchanged captures. To reproduce that original 13-test suite, use
checkout `2fafb1a40f8b9e6a24b6de5e97a92195a913a6db` and its README instructions.
Its logs, assertion source and checkpoint tag are preserved. Published history is unchanged.

Dolos integration remains pending. Its estimation path should call `estimate_tx`,
preserve report fields and explicitly map RPC purposes. Submission must retain
phase one plus budget-enforcing `evaluate_tx`. No Dolos production code, dependency
pins, services, private workaround reference or remote refs were changed.
