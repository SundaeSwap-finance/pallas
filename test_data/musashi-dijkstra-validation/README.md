# Native Dijkstra metadata, multiasset and V3 validation

Regression fixtures for protocol **12.0**, Musashi magic **164**, network ID **0**.
The implementation validates original native bytes and never changes the era or
cost model. Run from the repository root with dependencies already cached:

```sh
cargo test --offline -p pallas-validate --features phase2,unstable dijkstra_transaction_tests
python3 test_data/musashi-dijkstra-validation/verify-fixtures.py
```

## Why these captures are retained

| Capture | Distinct regression |
| --- | --- |
| `order.tx.hex`, `order-producer.body.hex`, `order.input.hex` | Exact metadata rejection and its input; tests verify the original body hash, producer hash and output bytes. Exercises multiasset transfer into an inline-datum script output, which does not execute a script. |
| `mint-batch.tx.hex`, `mint-batch-inputs.json`, `batch-inputs/` | One transaction exercises V3 spending, minting and withdrawals, witness/reference scripts, integrity, fees, budgets and collateral in both phases. All 12 UTxOs are required spending/reference/collateral context; scripts dominate the fixture size. |
| `account-state.json`, `account-history.json`, `replay-context.json` | Explicit historical prestate and references to existing portable parameter/genesis fixtures. No unknown state is replaced with defaults. |

These are RealFi V1.1 transactions used as examples, not application-specific
validation rules. “Order” and “treasury” name spending validators; “protocol” and
“protocolMint” name script reward credentials; “settings” is configuration in a
reference UTxO; the mint proxy authorizes policy mint/burn. “Batch” here means one
application transaction, not a Dijkstra subtransaction batch. Source revisions,
public payload review, body hashes and decoded-byte checksums are in
`provenance.json`. No keys or private journals are included.

The metadata transaction was rejected with `DijkstraUnsupported("auxiliary data")`.
Its positive replay uses the exact retained input, historical parameters and a
stipulated slot; current input spendability and parameters are unknown. The script
transaction is archived at slot **1404987**, with reconstructed registered zero
balances from the canonical archive account history. This depends on Dolos's
expanded-archive trust; it is not an independent node state dump or consensus replay.
Neither replay establishes current node acceptance or an application's lifecycle.

Synthetic tests cover invalid commitments/quantities, mint and burn conservation,
script/datum/pointer authorization, V3 optional datums and purpose contexts,
explicit account state, signatures, collateral and fee/budget boundaries. Test-only
keys are deterministic; unrelated commitments/signatures are recomputed on mutation.
Additional application-flow replays are unnecessary for these ledger-rule regressions.

## Rules and supported boundary

Rules are pinned to cardano-ledger
[`1587f21a7d1306dc590c2749a5c66232ef66aad0`](https://github.com/IntersectMBO/cardano-ledger/tree/1587f21a7d1306dc590c2749a5c66232ef66aad0):
Dijkstra `Rules/{Utxow,Utxo,Entities}`, `UTxO`, `TxInfo`; Shelley UTXOW;
Alonzo UTXOW/UTxO/TxWits; Babbage UTXOW; Mary Value and binary decoding.

- Metadata hashes original auxiliary CBOR. Original body bytes remain signed.
  Asset conservation is per policy/name; protocol-12 map/quantity constraints apply.
- Redeemers use sorted spend inputs/policies, original certificate positions and
  ledger reward-account order (network, script before key, hash). A V3 spend may
  omit a datum; a present datum hash requires its matching witness (CIP-0069).
- Integrity hashes original redeemer/datum bytes and all 350 V3 language-view
  coefficients. Dijkstra's V3 translation shares common field representations;
  native transactions are never decoded as Conway.
- `CertState::dijkstra_account_balances`: absent means unknown; `None` means known
  unregistered; `Some(coin)` means registered. V3 withdrawals must drain the account
  in Dijkstra legacy mode. Key-only withdrawals may be partial. State changes are
  provisional until phase two succeeds.
- Exact rational execution/reference fees, non-distinct reference sizes, declared
  and actual budgets, script success, signatures and collateral remain enforced.
  Collateral assets must return exactly; only its ADA difference pays collateral.

Use `unstable,phase2` for newly carried/published V3 script well-formedness checks.
Without `phase2`, those new scripts reject explicitly. Phase-two evaluation alone
is not admission validation. The audited protocol-12 backend adds
`SubtractInteger`, `MultiplyInteger` and `LessThanByteString`; its other builtin
and integer-operand restrictions remain. The retained transaction matches the
independent CLI for all five purposes (`cli-comparison.json`).

Guard-free native scripts are additionally supported; see
[the native-script fixtures](../dijkstra-native-scripts/README.md).

Explicit exclusions remain: other Plutus languages, script guards, governance,
direct deposits/account intervals, non-Reg certificates, scripted/stateful
subtransactions, bootstrap/pointer addresses, auxiliary scripts and Plutus upper
validity bounds without forecast state. This is not full Dijkstra conformance.

## Evidence reproduction

`regression-results.md` records identical baseline/fixed tests and the API-only
baseline adapter. Tests use only committed files. The capture tool
`extract-archive.rs` is retained to audit provenance: create a temporary Cargo
binary with local Pallas codec/traverse (`unstable`), `serde_json=1`, `hex=0.4`,
`zstd=0.13`; run in release mode with archive directory, Dolos dictionary, output
directory and `archive-targets.json`. Original archive segment/dictionary checksums
are in the referenced parameter-history manifest; the archive is not needed to test.
Extracted block transaction envelopes are reconstructed; committed signed envelopes
match the original retained payloads byte-for-byte.

Optional independent offline evaluation with the CLI revision in the comparison:

```sh
export DIJKSTRA_FIXTURE_EXPORT=/tmp/dijkstra-cli-replay
cargo test --offline -p pallas-validate --features phase2,unstable export_dijkstra_cli_comparison -- --ignored
cardano-cli dijkstra transaction calculate-plutus-script-cost offline \
  --start-time-utc 2026-09-07T00:00:00Z \
  --era-history-file test_data/musashi-phase2/dual-evaluator/cli-integer/synthetic-era-history.json \
  --protocol-params-file test_data/musashi-phase2/dual-evaluator/cli-integer/parameters.json \
  --utxo-file "$DIJKSTRA_FIXTURE_EXPORT/mint-batch.utxos.json" \
  --tx-file "$DIJKSTRA_FIXTURE_EXPORT/mint-batch.tx.json"
```

The synthetic era-history interpreter has no effect on the captured transaction's
unbounded validity interval; the exact protocol-12 cost vector is preserved.
