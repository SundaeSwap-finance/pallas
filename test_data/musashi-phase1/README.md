# Native Dijkstra phase-one validation

The current supported subset includes the initial key/ADA transfer path and the
[native registration extension](registration-only.md). The sections
below preserve the initial transfer checkpoint and its red/green evidence.
Registration now accepts with explicit prestate and complete parameters for the
documented subset; default state still rejects.

## Initial transfer scope, established before implementation

Rules follow cardano-ledger `1587f21a7d1306dc590c2749a5c66232ef66aad0`,
not an identified historical node binary. The remote node version is unknown;
the captured config's minimum version `11.1.0.164-prototype-2026w36` and N2N
handshake version 15 do not identify the running binary.

The supported subset is protocol **12.0**, top-level key-authorized ADA-only
transfers with Shelley base/enterprise addresses, no datum/reference script,
and optional validity bounds and network ID. Definite two-element legacy outputs and map outputs with only address/value
fields are supported. Native Dijkstra body, witnesses, output eras and original hashes are
used directly. No Conway transaction view is constructed. Earlier-era UTxOs can
supply the same key/coin subset through traversal, without changing their eras.

Reject certificates (historical certificate state unavailable), withdrawals,
governance/treasury/donations, mint, collateral, reference inputs, scripts,
script data, auxiliary data, guards, required top-level guards, direct deposits,
account-balance intervals, subtransactions and unsuccessful block transactions.
Bootstrap, pointer and script addresses and multiasset values are outside this
initial subset. Rejection is conservative even for an otherwise harmless field.
Default account/certificate state is never used to justify stateful acceptance.

Pinned rules: Dijkstra `Tx.hs::toCBORForSizeComputation` serializes a three-element
array (body, witnesses, auxiliary data/null), excluding any supplied validity or
block success flag. `Rules/Utxo.hs` requires inputs, fees, value conservation,
output minimum coin/maximum value size, networks, transaction size and validity.
Allegra `Scripts.hs::inInterval` uses `[lower, upper)`. Babbage's minimum coin
is `(160 + serialized output size) * coinsPerUTxOByte`; it is not value size in
words. Dijkstra `Rules/Utxow.hs` verifies every supplied signature and requires
input payment keys. Reference/script fees and execution costs are zero only
because this subset excludes their sources. Forecast translation is needed by
the pinned Alonzo rule only when redeemers exist, which this subset rejects.

## Captured evidence

The control transfer is
`f4ed3784097149431498b0df6ceaf13b3a531df88838d1f8f39df1269eb54b20`,
successfully included at slot 1400007, index 0. Its unchanged spending input is
Dijkstra output 1 of `884c9befc41220fbfb2026a79e2a0a293797a0de0f29f6e3ce13977fe7329e6f`.
That producer was endorser transaction 23, announced at 1391831 and certified at
1391855. Its wire envelope has no outcome flag; certification and subsequent
successful spending provide outcome evidence.

Files are extracted without CBOR changes from the retained S00 bundle at local
backup commit `472c235eca7597c96cb95e77fe1b7b0080fce791`,
`test_data/musashi-submission`. Binary payloads are represented as lowercase hex;
checksums in `payload-provenance.json` hash decoded bytes, not text.
`historical-parameters.json` is a named-field excerpt of the captured Dolos
epoch-64 response (cost models omitted because this subset cannot use them).
No input amounts, output eras, signed bytes or historical parameters are altered.

The registration capture and its state reconstruction remain documented in
`../musashi-registration`. Settings means the RealFi application's settings
validator. Its shared deposit, certificate witness and input tests are prior
scoped proofs, not full native registration validation. The initial native route rejected it pending historical certificate-state supply
and remaining native phase-one rules; the linked extension supplies those rules
for the unchanged settings registration. Native evaluation and post-bootstrap
V3 deposit/refund translation remain S06; submission, pins and workaround removal
remain S07.

## Reproduction and limits

The regression module is `pallas-validate/src/phase1/dijkstra_tests.rs`. It calls
`validate_txs` with `MultiEraTx::Dijkstra`, explicit Dijkstra protocol parameters,
`acnt: None`, original Dijkstra input output, and historical slot 1400007. The
unchanged 196-byte mempool transaction and 197-byte block representation both
pass. The fixture integrity test verifies decoded-byte checksums, indexed header
hashes, full block-body commitments, successful control inclusion, endorser
certification, selected wire commitment, producer identity, and the original
output slice. `provenance.json` records sources and remaining evidence limits.

```sh
cargo test --offline -p pallas-validate --features unstable --lib dijkstra_tests -- --nocapture
cargo test --offline -p pallas-validate --features unstable,phase2
```

Baseline is **baafb53cab4a31a7e8e529a31aeadde953da7ed0**. Extract it with
`git archive` into a separate directory, apply `baseline-preparation.patch` with `git apply --unidiff-zero`, and
copy the final `dijkstra_tests.rs` and this fixture directory. The preparation
adds only the new parameter/error vocabulary and test wiring, plus a rejecting
`Dijkstra` parameter match arm (`TxAndProtParamsDiffer`); it adds no validator.
This compatibility preparation is necessary to compile identical assertions
against the new parameter API. It preserves the baseline's lack of a native
validation route. Use a separate Cargo target, for example:

```sh
CARGO_TARGET_DIR=/tmp/pallas-phase1-baseline-target CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test --offline -p pallas-validate --features unstable --lib dijkstra_tests -- --nocapture
```

The baseline compiles, fixture integrity passes, and the unchanged control's
expected acceptance fails at `TxAndProtParamsDiffer`. These are runtime assertion
failures, not compiler errors. Exact results and gate outcomes are in
`verification.json`; recorded logs are tracked alongside it. The fixed run uses
the canonical checkout target, separately from baseline artifacts.

All negative body/output/context mutations are **synthetic**, in memory. Validity
bounds and map-output positive tests are re-signed with a deterministic test key;
no private signing material is retained. Other negative cases check the precise
pre-signature rejection they target. Earlier-era input representations are
synthetic; existing earlier-era transaction suites supply the caller regressions.

This checkpoint completes the control-transfer subset, **not all of S05**.
The exact remaining S05 task is native registration phase one: supply explicit
historical certificate prestate, implement `Reg` state/deposit validation and
native certificate script/witness/redeemer, collateral, language, integrity and
full-fee checks under protocol 12. The settings capture now reaches an explicit
`DijkstraCertificateStateUnavailable` rejection with its original UTxOs, rather
than being accepted with default state. S01/S02 alone do not supply these missing
native prerequisites. The small Dijkstra parameter type intentionally contains
only parameters consumed by transfers; adding scripts will require its extension.

Historical parameter evidence trusts the Dolos archive. Independent historical
node parameter comparison and the exact historical node/evaluator identity remain
unavailable. This is phase-one validation of a declared subset, not a consensus
replay or state application: the caller supplies resolved unspent outputs and the
validation slot. All Dolos pins/workarounds and the read-only RealFi reference are
preserved. No S06/S07 implementation or publication is included.
