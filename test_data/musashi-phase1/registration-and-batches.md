# Native registration and key-authorized batches

For the subsequent native metadata, multiasset and Plutus V3 extension, see
[native Dijkstra validation](../musashi-dijkstra-validation/README.md). The subset below describes this
historical checkpoint, not the current complete supported subset.

This report preserves combined checkpoint `76003a3` and its original verification.
Its implementation is now split into [registration](registration-only.md) and
[key-only batches](key-batches.md), with separate red/green reports. Final source
and the original payloads are unchanged; the historical combined tag is preserved.

This continuation extends S05, starting from `1af163ecfa94515477c24f97180dc1aaf849023c`.
It keeps that transfer checkpoint and its evidence intact. Rules are pinned to
cardano-ledger `1587f21a7d1306dc590c2749a5c66232ef66aad0`; the historical node
binary version remains unknown. No phase-two execution or Dolos integration is
part of this change.

## Supported extension, defined before implementation

- Native top-level explicit `Reg` certificates, with key credentials or Plutus V3
  scripts supplied by original reference UTxOs. Every credential requires explicit
  known prestate (`Unregistered` or `Registered`); an absent entry means unknown,
  never unregistered. Validate protocol deposit, prestate and author/pointer rules.
  State changes are staged and committed to the caller's validation state only on
  phase-one success. They remain provisional until phase two succeeds.
- Registration reference scripts retain native output identity and bytes. Accept
  V3 reference scripts only; no witness-carried Plutus scripts or script outputs.
  Ledger UTxOs are trusted already-admitted outputs, so their script well-formedness
  is an input precondition. Validate exact certificate redeemer set, historical
  language view/script-integrity hash, aggregate declared budgets, execution fees,
  reference fees/size and collateral/return/required payment signatures. Datums,
  script spending, minting, withdrawals and other certificate kinds stay explicit
  unsupported cases. Plutus transactions with validity upper bounds require era
  forecast state not currently provided, and reject explicitly.
- Key-authorized ADA subtransactions, with key guards and optional required
  top-level key guards. Validate original per-level signatures, validity and
  outputs; require each input in original UTxO and prevent consumption twice
  across the batch. Subtransaction outputs cannot become inputs inside that same
  batch, since the pinned SUBUTXO rule also checks original UTxO membership.
  The top-level fee and value preservation apply to the whole batch; individual
  subtransactions need not balance. Scripted or certificate-bearing subtransactions
  remain rejected, as do batches combining the registration extension with subs.
  Standalone subtransaction dispatch lacks parent context and remains rejected.

Pinned sources: Dijkstra Rules/{Ledger,SubLedgers,SubLedger,SubUtxo,SubUtxow,Utxow},
Dijkstra UTxO/TxBody/Rules/Certs, Conway Rules/Deleg and Tx reference-fee rules,
Alonzo TxWits (original redeemer bytes for integrity). Dijkstra top-level CERT
inherits Conway registration state/deposit checks; subcertificate rules are
separate and are deliberately not inferred from top-level rules.

## Evidence boundaries

The existing settings registration at slot 1401365 supplies unchanged native
transaction, spending/collateral and reference output bytes. Its explicit
unregistered prestate is reconstructed from the retained S00 frozen archive,
under that archive's trust boundary. The archived epoch-64 V3 cost vector hashes
to the transaction's original script-integrity hash without protocol conversion.
Additional Dijkstra reference-fee limits originate in captured genesis; a targeted
archive proposal scan checks whether these fields were proposed for change.
Independent node parameter comparison and full consensus replay remain unavailable.

The existing `../dijkstra-subtx.tx` is a real script-spending batch, with a key
guard and a spending redeemer. It is **not** a captured key-only batch and will
remain an explicit unsupported case. Positive key-only batch tests are synthetic
and re-signed with deterministic test keys; no native network batch acceptance
claim follows from them. Registration supplies the real before/after acceptance
regression for this continuation. Original payloads are never edited to fit scope.

## Result and replay

The unchanged native settings registration passes `validate_txs` with its original
Dijkstra spending/collateral output and V3 reference output. The original control
transfer still passes. Settings is RealFi's application settings validator; the
other retained `protocol` registration registers four application validators.
This continuation's full native acceptance claim covers **settings only**. The
protocol capture still has scoped deposit evidence; its complete reference UTxOs
are not packaged in these native phase-one tests.

The 350-entry epoch-64 V3 cost model produces the original integrity hash
`c4aebcfa833c9d1cd63d4109435cc98eda5114912ae3c68724d94a0fccc1876d`.
No protocol-9 translation or script execution occurs. Linear size fees use the
427-byte original mempool representation. Execution fees round up once after
summing both rational prices; reference fees round down once after summing tiers.
Tests cover the exact fee threshold and a synthetic reference-fee tier boundary.

`CertState::dijkstra_registrations` is an explicit knowledge map. Missing credentials
reject as unknown; the caller must supply state appropriate to the validation slot.
Successful registration marks that credential registered. Updates are staged until
phase one succeeds and remain **provisional pending phase two**; a caller must not
commit ledger state solely on this validator's result. No account, pool, reward,
governance or historical certificate state is synthesized.

Run from the Pallas root:

```sh
cargo test --offline -p pallas-validate --features unstable --lib dijkstra_ -- --nocapture
cargo test --offline -p pallas-validate --features unstable,phase2
```

The final first command reports **26 passed**. On checkpoint
`1af163ecfa94515477c24f97180dc1aaf849023c`, the same 26 assertions report
**12 passed / 14 failed**, including unchanged registration rejection as
`DijkstraCertificateStateUnavailable` and supported batch rejection as
`DijkstraUnsupported("subtransactions")`. Both builds compile and execute.
`registration-baseline-validation.txt` and `registration-fixed-validation.txt`
retain the runtime evidence; `registration-verification.json` records all checks.

To prepare the baseline, extract that commit using `git archive` into a separate
directory. Apply `registration-baseline-preparation.patch` with `git apply --unidiff-zero`.
Copy the two new test modules (`dijkstra_registration_tests.rs` and
`dijkstra_batch_tests.rs`) and the `registration-*.json` fixtures into it. The patch
adds parameter/state/error vocabulary, test helpers/module declarations and an
**unused** certificate-state argument to the old native function. It preserves
its validation behavior. The older transfer tests' unsupported expectations are
updated identically in both builds to reflect the new supported scope.
Use distinct `CARGO_TARGET_DIR` values for baseline and fixed trees; the recorded
baseline used `/tmp/musashi-s05-registration/baseline-target`, while the fixed
checkout used its normal `target`. Baseline debug info was disabled for disk use.

## Durable evidence and remaining limits

`registration-provenance.json` records payload relationships, source revisions,
checksums, rule URLs and evidence types. The original transaction/output payloads
remain in `../musashi-registration` and are not rewritten. The newly retained
parameter response, certificate-state reconstruction/history and genesis files
are byte-identical extractions from S00 backup commit
`472c235eca7597c96cb95e77fe1b7b0080fce791`, under `test_data/musashi-submission`.
Certificate absence is established by the explicit reconstruction, never by an
empty runtime map. Original certificate-history scan and Shelley genesis hashes
are retained alongside that reconstruction.

`registration-parameter-history.json` reports the new read-only scan of the same
frozen archive: 69,466 frames and 63,158 continuous canonical headers, slots
12–1,404,987. The only two governance proposals are cost-model replacement at slot
780 and protocol-12 hard fork at slot 45,527. Neither changes the Dijkstra
reference-fee fields, supporting the captured genesis values under the archive
trust boundary. The exact scanner is `registration-parameter-history-scanner.rs`,
adapted from the retained S00 certificate scanner; it uses the original S00 fixture
manifest/genesis, the recorded zstd dictionary and snapshot segments. Its standalone
crate uses local `pallas-codec`, `pallas-traverse` with `unstable`, `hex 0.4`,
`serde_json 1`, `sha2 0.10`, and `zstd 0.13`. It takes archive directory, dictionary,
S00 fixture directory and output directory as its four arguments. Full snapshot
segments remain local evidence, not portable test dependencies.

The archive is Dolos's expanded view, not an independent node ledger-state dump,
full consensus replay or proof of every endorser commitment. The historical node
build remains unknown. Positive batches are synthetic; the real scripted batch
is an unchanged rejection fixture, and its full UTxOs/history are unavailable in
the portable fixture. Unsupported forms reject explicitly; this is a scoped S05
completion, not a complete Dijkstra ledger implementation.

S04 remains scoped input handling. S03's captured-script execution remains an
explicitly derived Conway protocol-9 proof. Native evaluation and protocol-aware
post-bootstrap V3 deposit/refund translation remain S06. Submission, dependency
pins and workaround removal remain S07. Neither step was executed here.

Repository-required checks passed on Linux: workspace build, Clippy with warnings
denied, docs with warnings denied, unstable and phase-two tests, blueprint tests,
feature matrices, isolated no-default primitives and Rust 1.88. The final native
suite with phase two enabled includes all earlier-era validation tests. The initial
sandbox run denied socket creation; the permitted local-socket retries passed.
The 19-test math suite passed in 250.05 seconds and was excluded from that retry.
`cargo fmt --all --check` still reports the same seven pre-existing formatting
differences in `examples/leios-testnet/src/bin/harvest.rs`; changed files are
formatted. macOS/Windows CI was not run locally. Full logs and pinned source copies
are retained at `.git/musashi-s05-registration-evidence/`; the tracked report and
red/green logs are sufficient to identify each result without that local directory.
The two proposal frames from the archive scan are also retained as descriptive
`registration-parameter-proposal-slot*.block.hex` files, with decoded-byte hashes
and their extracted-evidence classification in the provenance.

Tracked runtime logs omit trailing blank lines only; full original stdout is retained locally.
