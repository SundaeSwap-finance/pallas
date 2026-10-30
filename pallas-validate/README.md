# Pallas Validate

Phase-1 (and optionally phase-2) Cardano transaction validation against
the live ledger rules. Useful for clients that want to reject
ill-formed or unenforceable transactions locally before submitting them,
or to replay historical chains and confirm conformance with the protocol
specification.

## Usage

```rust
use pallas_validate::phase1::validate_tx;

validate_tx(&tx, tx_index, &env, &utxos, &mut cert_state)?;
```

`validate_tx` dispatches on the era encoded in `Environment.prot_params`
and routes to the matching era-specific validator (`validate_byron_tx`,
`validate_shelley_ma_tx`, `validate_alonzo_tx`, `validate_babbage_tx`,
`validate_conway_tx`).

## Overview

With `unstable,phase2`, native Dijkstra uses the earlier-era slot-to-POSIX-time
conversion semantics, with checked arithmetic. Construct `utils::DijkstraTimeContext`
from known `EraTime` segments and the validation slot, then pass it to
`phase2::evaluate_tx_with_time` or `estimate_tx_with_time`.
`estimate_tx_calls_with_time` additionally preserves builtin-call reports. Historical and known
future era mappings are preserved; later slots extend the final known mapping.
Finite lower bounds are inclusive and upper bounds exclusive, in milliseconds.

Phase one checks the validity slots without requiring consensus forecast state.
`phase1::validate_tx_with_time` additionally checks that both endpoints can be
converted using a context based at the validation slot. Dolos passes the same
context to phase one and phase two. The `SlotConfig` API remains available for
a single affine mapping. Neither API imposes a current-epoch cutoff; full
consensus forecast enforcement is a separate concern.

The focused capture and its current proof limitations are documented in
[`test_data/musashi-ttl`](../test_data/musashi-ttl/README.md). The V3 evaluator
retains upstream support for cost models of any length, including the captured
251- and 350-entry models, without padding or changing the script-integrity commitment.

- `phase1` — phase-1 (structural / rule-based) validation, with one module
  per era: `byron`, `shelley_ma`, `alonzo`, `babbage`, `conway`. Top-level
  entry points are `validate_tx` (single tx) and `validate_txs`
  (LEDGERS sequence rule).
- `phase2` — phase-2 (Plutus script execution) validation. Behind the
  `phase2` cargo feature.
- `utils` — the shared input types every validator takes:
  `Environment`, `UTxOs`, `CertState`, `MultiEraProtocolParameters`, and
  the unified `ValidationError` / `ValidationResult` types.

## Feature flags

- `phase2` — pulls in Plutus script execution and exposes the `phase2`
  module.

## Further reading

- [`docs/byron.md`](docs/byron.md), [`docs/shelleyMA.md`](docs/shelleyMA.md),
  [`docs/alonzo.md`](docs/alonzo.md), [`docs/babbage.md`](docs/babbage.md)
  — mathematical specifications, one per era.
- [`tests/README.md`](tests/README.md) — test-suite layout and how to
  reproduce the per-era fixtures.
