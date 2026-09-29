# S06: V3 deposit/refund translation; native evaluation incomplete

**S06 is incomplete.** The production change fixes protocol-aware V3 certificate
context encoding. Native Dijkstra evaluation remains unsupported (`WrongEra`).
The native candidate is preserved as a reproducible patch, but is **not installed
in production**: a runtime counterexample disproved its protocol-12 compatibility.
No submission, Dolos pin change, workaround removal, or remote write occurred.

## Production change and ledger rules

Conway protocol 9 omits explicit `Reg` deposits and `UnReg` refunds from V3
contexts. Later protocols include `Just amount`. The same rule now reaches all
three occurrences: the transaction certificate list, redeemer-purpose map and
active script purpose. `execute_script` supplies the actual protocol major to
encoding. Legacy amount-less certificates stay `Nothing`; V1/V2 encoding stays
unchanged. The old protocol-unaware `ToPlutusData` API retains its bootstrap
encoding; callers constructing contexts directly must use
`to_plutus_data_with_protocol` for later protocols.

Pinned ledger specification: `1587f21a7d1306dc590c2749a5c66232ef66aad0`.
[Conway TxInfo.hs](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/TxInfo.hs#L570)
retains the protocol-9 omission.
[Dijkstra TxInfo.hs](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/TxInfo.hs#L424)
builds V3 contexts and translates explicit amounts without that historical bug.
The historical node/evaluator build is **unknown**, not the specification revision.

Synthetic `v3_deposit_context_tests.rs` checks both certificate forms at protocols
9, 10, 11 and 12; amounts 0, 1, 2,000,000 and `u64::MAX`; all three occurrences;
legacy certificates; and actual execution of a validator requiring the amount.
These are encoding/caller tests, not historical native evaluation claims.

```sh
cargo test --offline -p pallas-validate --features unstable,phase2 --lib v3_deposit_context_tests -- --nocapture
```

The **same three tests** compile/run on baseline `4be4fb2` and the final source:
**1 passed / 2 runtime failures → 3 passed**. Baseline failures are the missing
`Just` at protocol 10 and a script failing with `Empty list` when it reads that
missing amount. `context-baseline.txt`, `context-fixed.txt` and
`verification.json` retain results. Baseline preparation: extract `4be4fb2`, apply with `git apply --unidiff-zero`
`context-baseline-preparation.patch`, and copy the final test module. The patch
adds only module wiring, crate-internal test visibility and a new method that
calls the old encoder while ignoring protocol. It preserves baseline behavior.
Use separate Cargo target directories for baseline and fixed trees.

## Native subset proposed before implementation

The attempted extension targeted protocol 12.0, native top-level `Reg`
certificates with V3 reference scripts, key/ADA spending inputs and outputs,
reference inputs including script addresses, no datum and no upper validity bound
(forecast state unavailable). Key certificates could precede script certificates;
indices counted the entire list. Only declared spending/reference inputs supplied
scripts; unrelated UTxOs and collateral could not supply them.

The candidate rejected other languages/purposes/certificate kinds, witness scripts,
subtransactions, script guards, required top-level guards, direct deposits, account
intervals, mint, withdrawals and governance fields. It decoded outputs under their
original eras and projected checked V3 TxOut fields into the existing shared
context representation. No native CBOR was decoded as a Conway transaction or
relabeled at the caller. It passed the **full 350-entry** historical vector and
original declared budgets to the evaluator, without truncation or protocol downgrade.

The candidate's static builtin list contained the 35 builtins in the captured
script. **That was insufficient to establish a correct supported subset.** Its
coefficient audit passed, but protocol-dependent semantics did not. The entire
native implementation was therefore removed from production, not advertised as
supported. The patch is research evidence, not a deployment workaround.

## Captured and extracted evidence

Reuse the unchanged native settings registration
`da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6`,
RealFi's application settings-validator stake registration, included successfully
at slot 1401365. Original transaction, redeemer and producer outputs remain under
`../musashi-registration`; full historical protocol-12 parameters and genesis
remain under `../musashi-phase1`. Their provenance identifies network magic 164,
Pallas harvest revision, independently indexed block identities, archive trust
limits and decoded-byte hashes. No new capture, keys or private journal was added.

The candidate executed the original script with native UTxOs and the full model:
**18,485 memory / 4,805,428 CPU**, exactly the original declared budget. Changing
the startup coefficient changed the charge and exhausted the unchanged budget.
Original registration ignores the tested redeemer-data mutation; a synthetic
validator separately checks that invalid redeemer data fails. Budget-zero and
one-unit-short cases, bad indices/purposes, script/input failures, unsupported
languages/features and earlier-era synthetic input labels were exercised.

These observations are **candidate execution evidence, not a completed native
protocol-12 proof**. S03 remains derived Conway protocol-9 execution; S04 scoped
input handling; S05 only its documented phase-one subset. Successful phase one
never authorizes committing provisional registration state. No integration/S07
claim follows from this session.

## Reproduced evaluator incompatibility

`amaru-uplc 0.1.0` (crate checksum in `provenance.json`) chooses builtin semantics
from language alone. Its current upstream `39c82af9b23e2d611f1eac4a905b5e421c755631`
was inspected read-only and did not provide the needed protocol-aware replacement.
The pinned ledger requires `plutus-ledger-api >=1.68` and uses a September-2
package index. Plutus **1.68.0.0** selects semantics E for V3 from protocol 11,
including a 65,536-byte operand limit for relevant byte-string builtins:
[V3 evaluation context](https://github.com/IntersectMBO/plutus/blob/1.68.0.0/plutus-ledger-api/src/PlutusLedgerApi/V3/EvaluationContext.hs),
[builtin semantics](https://github.com/IntersectMBO/plutus/blob/1.68.0.0/plutus-core/plutus-core/src/PlutusCore/Default/Builtins.hs),
[byte-string limit](https://github.com/IntersectMBO/plutus/blob/1.68.0.0/plutus-core/plutus-core/src/PlutusCore/Default/Universe/Cardano.hs).
This dependency constraint is not identification of the historical node binary.

A small synthetic script repeatedly doubles a one-byte constant, then passes the
result to `blake2b_256` and returns unit. The value is constructed internally, so
the large operand is not a transaction-size artifact. Correct behavior is failure
on an oversized operand. The candidate incorrectly returns **success**, charging
45,976 memory / 144,888,665 CPU. `candidate-semantic-gap.txt` records the runtime
failure of the correct assertion. This is not a compilation failure. Protocol-11
casing on builtin values is another unaudited gap; it has source evidence, not a
separate runtime reproduction here.

The 35-builtin coefficient audit checked 125 coefficients against the captured
named/raw cost response. It does not establish semantics. `cost-model-audit.json`
and its standard-library-only `audit-cost-model.py` retain the result. The full
vector was passed; the dependency internally maps only its 251-entry prefix for
this length. Unsupported suffix builtins were rejected by the candidate, but that
did not fix the demonstrated existing-builtin semantics difference.

Aiken `uplc` at release 1.1.23 and current revision
`bacbeb35fbc9f1db93cd2e1e93fb1d93053acb4a` has explicit protocol-aware evaluation.
Its declared Rust minimum is **1.94.1**, above this checkout's required **1.88**.
No dependency/compiler change was made. Current Plutus master was also inspected
and introduces further Dijkstra semantics; it is explicitly not substituted for
the pinned ledger or the unknown historical evaluator.

No independent node evaluation result or exact evaluator-build comparison was
available in retained evidence. `cardano-cli` and `cardano-node` were absent from
PATH. Successful captured inclusion and matching declared units are useful evidence,
but do not substitute for that comparison.

## Reproduce the rejected candidate

Extract baseline `4be4fb2171a73bdb04994c8472e76f601d41318f` into a separate directory,
then apply `native-candidate.patch` with `git apply --unidiff-zero`. It contains the candidate production and test
sources, including the subsequent semantic counterexample. It does not alter any
captured payloads or historical parameters. Run:

```sh
cargo test --offline -p pallas-validate --features unstable,phase2 --lib native_registration_executes_with_historical_budget -- --nocapture
cargo test --offline -p pallas-validate --features unstable,phase2 --lib native_registration_protocol12_bytestring_operand_boundary -- --nocapture
```

The first succeeds; the second must expose the candidate's incorrect success.
Before discovering that counterexample, the candidate phase-two suite had **31
passed**, against **18 passed / 13 runtime failures** on the prepared baseline.
`candidate-baseline-preparation.patch` adds only test wiring and an old-behavior
encoding adapter (apply with `--unidiff-zero`). Copy the two candidate test modules after applying the candidate
patch in another tree. The counterexample was added afterward: those 31-test logs
do not include it. `candidate-captured-and-boundary-tests.txt` and
`candidate-baseline.txt` are historical intermediate results, never final acceptance.

## Verification and exact next task

`verification.json` separates candidate checks from final production checks.
Linux repository gates were exercised, including Rust 1.88, phase-two/earlier-era
regressions, feature matrices, docs and Clippy. The known pre-existing seven
formatting differences in `examples/leios-testnet/src/bin/harvest.rs` remain;
changed source is formatted. Sandbox socket failures were rerun with local sockets.
macOS/Windows were not run. Full local logs are retained in
`.git/musashi-s06-evidence/`; essential runtime evidence is tracked here.

**Next remains S06:** select/backport a protocol-12-capable evaluator compatible
with the compiler requirement (or obtain an explicit compiler-policy decision),
prove operand bounds and casing plus complete model handling, then restore native
dispatch and repeat unchanged-capture runtime/budget tests and negative boundaries.
Record independent node comparison if obtainable and exact evaluator identity when
known. Only then reconsider S06 completion. S07, submission, Dolos pin changes and
workaround removal remain separate and were not executed.
